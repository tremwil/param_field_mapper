#include "mass_instruction_patcher.hpp"
#include "instr_utils.h"

#include <mem/module.h>

#include <Windows.h>
#include <spdlog/spdlog.h>

#include "core/panic.h"

namespace pfm {

bool MassInstructionPatcher::prepare_module(intptr_t module_base) {
    if (module_pseudo_branch_targets.contains(module_base))
        return true;

    if (!rwe_modules.contains(module_base)) {
        DWORD old_protect;
        VirtualProtect((LPVOID)module_base, mem::module::nt(module_base).size, PAGE_EXECUTE_READWRITE, &old_protect);
        rwe_modules.insert(module_base);
    }

    SPDLOG_INFO("Finding potential JMP targets for module at {:x}...", module_base);
    std::vector<intptr_t> pseudo_branch_targets;
    if (!instr_utils::jmp_targets_heuristic(module_base, pseudo_branch_targets)) {
        return false;
    }
    SPDLOG_INFO("Done, found {:L} potential targets", pseudo_branch_targets.size());
    
    SPDLOG_INFO("Computing program-wide CFG. If obfuscation is involved, dissassembly errors expected!");
    auto ex_tbl = cfg_utils::get_exception_table((uint8_t*)module_base);
    for (const auto& rf: ex_tbl) {
        auto cinfo = (UNWIND_INFO*)(module_base + rf.UnwindInfoAddress);
        if (cinfo->Flags & UNW_FLAG_CHAININFO) continue;
        cfg.walk((intptr_t)module_base + rf.BeginAddress, true);
    }
    SPDLOG_INFO("Done, walked {} functions in exception table", ex_tbl.size());

    module_pseudo_branch_targets[module_base] = std::move(pseudo_branch_targets);
    return true;
}

ExtendFlowGraphResult MassInstructionPatcher::light_prepare_if_required(
    intptr_t instruction_addr, CONTEXT* thread_ctx)
{
    hde64s disasm;
    if (hde64_disasm((void*)instruction_addr, &disasm) & F_ERROR) {
        return ExtendFlowGraphResult::DissassemblyFailed;
    }
    size_t code_len = disasm.len;

    // Instruction already visited, no need to walk a second time
    if (cfg.visited_instruction(instruction_addr)) 
        return ExtendFlowGraphResult::Success;

    // If the module this code lies in has been "prepared", we can do additional checks to further
    // minimize the risk of encountering an instruction we cannot "rewalk" to with current CFG capabilities
    intptr_t module_base;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 
        | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)instruction_addr, (HMODULE*)&module_base) 
        && module_pseudo_branch_targets.contains(module_base))
    {
        auto& jmp_targets_heuristic = module_pseudo_branch_targets[module_base];
        auto jmp_point = std::upper_bound(jmp_targets_heuristic.begin(), 
            jmp_targets_heuristic.end(), instruction_addr);
        
        // Not found
        if (jmp_point == jmp_targets_heuristic.end()) return ExtendFlowGraphResult::Success;
         // Confirmed false positive (doesn't match instruction boundary)
        if (*jmp_point < instruction_addr + code_len) return ExtendFlowGraphResult::Success; 
        // Instruction would not prevent insertion of a JMP REL32
        if (*jmp_point >= instruction_addr + 5) return ExtendFlowGraphResult::Success;
    }
    if (!rwe_modules.contains(module_base)) {
        // First, make module RWE
        SPDLOG_DEBUG("Making memory of module at {:x} RWE", module_base);
        DWORD old_protect;
        VirtualProtect((LPVOID)module_base, mem::module::nt(module_base).size, PAGE_EXECUTE_READWRITE, &old_protect);
        rwe_modules.insert(module_base);
    }
    
    // If a JMP REL32 can fit, we don't care
    if(code_len <= 5) 
        return ExtendFlowGraphResult::Success;

    auto fun_begin = cfg_utils::find_function(instruction_addr, thread_ctx->Rsp);
    if (fun_begin) {
        SPDLOG_DEBUG("Found function begin {:x} for instruction at {:x}", fun_begin, instruction_addr);
    }
    else {
        SPDLOG_ERROR("Failed to find function start for instruction at {:x}", instruction_addr);
        return ExtendFlowGraphResult::FunctionStartNotFound;
    }

    if (!cfg.walk(fun_begin, false)) {
        SPDLOG_ERROR("Failed to compute control flow graph for instruction at at {:x}", instruction_addr);
        return ExtendFlowGraphResult::FlowGraphComputationFailed;
    }
    if (cfg.visited_instruction(instruction_addr)) {
        SPDLOG_INFO("Success of flow analysis back to original instruction at {:x}", instruction_addr);
        return ExtendFlowGraphResult::Success;
    }
    else {
        SPDLOG_ERROR("Flow analysis failed to re-discover access instruction at {:x}", instruction_addr);
        return ExtendFlowGraphResult::InstructionNotRediscovered;
    }
}

intptr_t MassInstructionPatcher::jmp_hook(intptr_t addr, intptr_t hook) {
    auto& arena = arena_pool.get_or_create_arena((void*)addr);
    auto result = trampoline::gen_trampoline(arena, [&]{
        // movabs rax, hook
        arena.write<uint16_t>(0xB848);
        arena.write(hook);
        // jmp rax
        arena.write<uint16_t>(0xe0ff); 
    }, (uint8_t*)addr, false, &cfg);

    if (!result) return 0;
    else {
        update_reloc_maps(result.address_map);
        return (intptr_t)trampoline::mapped_addr(result.address_map, (uint8_t*)addr);
    }
}

intptr_t MassInstructionPatcher::instruction_hook(
    intptr_t addr, std::function<void(HookArena&, const AddressMap&)> codegen, bool replace)
{
    auto& arena = arena_pool.get_or_create_arena((void*)addr);
    intptr_t emit_addr = 0;

    auto result = trampoline::gen_trampoline(arena, [&](const AddressMap& addr_map) {
        emit_addr = (intptr_t)arena.ptr();
        codegen(arena, addr_map);
    }, (uint8_t*)addr, replace, &cfg);

    if (!result) return 0;
    else {
        update_reloc_maps(result.address_map);
        return emit_addr;
    }
}

void MassInstructionPatcher::update_reloc_maps(const AddressMap& addr_map) {
    for (const auto& [prv, reloc] : addr_map) {
        auto it = inverse_relocations_map.find(prv);
        if (it != inverse_relocations_map.end()) {
            relocations_map[it->second] = reloc;

            auto nh = inverse_relocations_map.extract(it);
            nh.key() = reloc;
            inverse_relocations_map.insert(std::move(nh));
        }
        else {
            relocations_map[prv] = reloc;
            inverse_relocations_map[reloc] = prv;
        }
    }
}

} // namespace pfm