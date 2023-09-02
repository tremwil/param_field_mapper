#include "control_flow_graph.h"

#include "core/panic.h"

#include "mem/mem.h"
#include "mem/module.h"
#include "zydis/Zydis.h"

#include <algorithm>
#include <initializer_list>
#include <libloaderapi.h>
#include <winnt.h>

template<class S> 
void update_key(S& map, typename S::const_iterator& it, const typename S::key_type& new_key) {
    auto nh = map.extract(it);
    nh.key() = new_key;
    map.insert(std::move(nh));
};

namespace pfm
{
    bool CFG::remove_instruction(intptr_t addr) {
        auto it = instructions.find(addr);
        if (it == instructions.end()) return false;

        remove_branch(addr);
        instructions.erase(it);
        return true;
    }

    bool CFG::add_branch(intptr_t addr, BranchType type, std::initializer_list<intptr_t> targets) {
        if (branches.contains(addr)) return false;

        // Since we're adding a branch here, the instruction should be considered visited 
        instructions.insert(addr);

        auto branch = std::make_unique<Branch>(addr, type);
        for (auto target: targets) {
            auto it = branch_targets.find(target);
            if (it == branch_targets.end()) {
                auto tgt = std::make_unique<BranchTarget>(target);
                tgt->branches.insert(branch.get());
                branch->targets.push_back(tgt.get());

                branch_targets[target] = std::move(tgt);
            }
            else {
                it->second->branches.insert(branch.get());
                branch->targets.push_back(it->second.get());
            }
        }
        branches[addr] = std::move(branch);
        return true;
    }

    bool CFG::remove_branch(intptr_t addr) {
        auto it = branches.find(addr);
        if (it == branches.end()) return false;

        auto& branch = it->second;
        for (auto& tgt: branch->targets) {
            tgt->branches.erase(branch.get());
            // Remove empty branch targets
            if (tgt->branches.empty()) {
                branch_targets.erase(tgt->address);
            }
        }
        branches.erase(it);
        return true;
    }

    bool CFG::relocate(intptr_t old_addr, intptr_t new_addr) {
        // If we don't know about any instruction at old_addr, fail
        auto instr_it = instructions.find(old_addr);
        if (instr_it == instructions.end()) return false;

        if (old_addr == new_addr) return true;

        // Relocate the instruction
        instructions.erase(instr_it);
        instructions.insert(new_addr);

        // Relocate branches
        auto branch_it = branches.find(old_addr);
        if (branch_it != branches.end()) {
            branch_it->second->address = new_addr;
            update_key(branches, branch_it, new_addr);
        }

        auto target_it = branch_targets.find(old_addr);
        if (target_it != branch_targets.end()) {
            target_it->second->address = new_addr;
            update_key(branch_targets, target_it, new_addr);
        }
        return true;
    }

    bool CFG::walk(intptr_t addr) {
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        ZydisDecodedInstruction instruction;
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands;

        std::vector<intptr_t> dfs_stack { addr };

        while (!dfs_stack.empty()) {
            intptr_t addr = dfs_stack.back();
            dfs_stack.pop_back();

            // Already visited
            if (instructions.contains(addr)) continue;
            instructions.insert(addr);

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)addr, 
                ZYDIS_MAX_INSTRUCTION_LENGTH, &instruction, operands.data()))) 
            {
                SPDLOG_ERROR("Zydis failed to decompile instruction at {:x}", addr);
                return false;
            }

            auto implicit_branch = addr + instruction.length;
            auto jmp_type = BranchType::Uncond;
            switch (instruction.meta.category)
            {
            case ZYDIS_CATEGORY_RET:
                // SPDLOG_TRACE("{:x} RET", addr);
                add_branch(addr, BranchType::Ret, {});
                break;
            case ZYDIS_CATEGORY_COND_BR:
            case ZYDIS_CATEGORY_CALL:
                jmp_type = instruction.meta.category == ZYDIS_CATEGORY_CALL ? BranchType::Call : BranchType::Cond;
                dfs_stack.push_back(implicit_branch);
                [[fallthrough]];
            case ZYDIS_CATEGORY_UNCOND_BR: {
                // Compute new RIP, if possible
                // Note the optimization: if the jmp goes to the next instruction, there's no "real" branch in the CFG
                ZyanU64 out_addr;
                auto has_modrm = instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM;
                if (!has_modrm 
                    && ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[0], addr, &out_addr)) 
                    && out_addr != implicit_branch 
                    && !IsBadReadPtr((void*)out_addr, 8)) 
                {
                    add_branch(addr, jmp_type, { (intptr_t)out_addr });
                    dfs_stack.push_back(out_addr);
                    // SPDLOG_TRACE("{:x} {} {:x}", addr, jmp_type == BranchType::Cond ? "JCC" : "JMP", out_addr);
                }
                break;
            }
            default:
                dfs_stack.push_back(implicit_branch);
                break;
            }
        }
        return true;
    }
}

namespace pfm::cfg_utils {
    std::span<RUNTIME_FUNCTION> get_exception_table(uint8_t* module_base) {
        auto mod = mem::module::nt(module_base);
        auto& opt_header = mod.nt_headers().OptionalHeader;
        auto ex_tbl_data_dir = opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        mem::region text_section { nullptr, 0 };
        for (const auto& section : mod.section_headers()) {
            if (std::strcmp((const char*)section.Name, ".text")) continue;
            text_section = { 
                module_base + section.VirtualAddress, section.Misc.VirtualSize
            };
            break;
        }

        return { 
            (RUNTIME_FUNCTION*)((intptr_t)module_base + ex_tbl_data_dir.VirtualAddress),
            ex_tbl_data_dir.Size / sizeof(RUNTIME_FUNCTION)
        };
    }

    intptr_t find_function(intptr_t code, intptr_t known_rsp) {
        // Fetch the exception table of the module the code lies in

        uint8_t* module_base;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | 
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (const char*)code, (HMODULE*)&module_base))
        {
            return 0;
        }
        mem::region text_section { nullptr, 0 };
        for (const auto& section : mem::module::nt(module_base).section_headers()) {
            if (std::strcmp((const char*)section.Name, ".text")) continue;
            text_section = { 
                module_base + section.VirtualAddress, section.Misc.VirtualSize
            };
            break;
        }
        auto ex_tbl = get_exception_table(module_base);

        // Binary search over the exception table to try and find the function

        DWORD code_ibo32 = code - (intptr_t)module_base;
        auto entry_it = std::upper_bound(ex_tbl.begin(), ex_tbl.end(), 
            IMAGE_RUNTIME_FUNCTION_ENTRY { .EndAddress = code_ibo32 }, 
            [](const auto& v, const auto& e) { return v.EndAddress < e.EndAddress; });

        if (entry_it != ex_tbl.end() && code_ibo32 >= entry_it->BeginAddress) {
            // Found it, now walk chaininfo until we find the original function
            auto info = &*entry_it;
            auto cinfo = (UNWIND_INFO*)(module_base + info->UnwindInfoAddress);
            while (cinfo->Flags & UNW_FLAG_CHAININFO) {
                info = &cinfo->ChainedRuntimeFunction();
                cinfo = (UNWIND_INFO*)(module_base + info->UnwindInfoAddress);
            }
            return (intptr_t)module_base + info->BeginAddress;
        }
        else if (known_rsp != 0 && text_section.size) {
            // If not present in the exception table and we know where code should be, 
            // assume we have a leaf function. Then the call instruction is at [RSP] - 5.
            mem::region call { *(uint8_t**)known_rsp - 5, 5 };
            // Invalid mem or not a CALL REL32 instruction
            if (!text_section.contains(call) || call.start.at<uint8_t>(0) != 0xe8)
                return 0;
            
            // Then the call target should be our function
            intptr_t tgt = call.start.as<intptr_t>() + 5 + call.start.at<int32_t>(1);
            return text_section.contains(tgt) ? tgt : 0;
        }
        else {
            return 0;
        }
    }
}