#include "param_field_mapper.h"
#include "core/utils.h"
#include "hooks/control_flow_graph.h"
#include "hooks/instr_utils.h"
#include "arxan_disabler.h"

#include "hooks/trampoline.h"
#include "spdlog/spdlog.h"
#include "zydis/Zydis.h"

#include "mem/pattern.h"

#include <Windows.h>
#include <algorithm>
#include <conio.h>
#include <excpt.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <winnt.h>
#include <winternl.h>

void suspend_threads()
{
    typedef NTSTATUS(*NtGetNextThread_t)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
        ULONG Flags, PHANDLE NewThreadHandle);

    auto NtGetNextThread = (NtGetNextThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtGetNextThread");

    HANDLE hThread = NULL;
    while (true) {
        NTSTATUS err = NtGetNextThread(GetCurrentProcess(), hThread, THREAD_ALL_ACCESS, 0, 0, &hThread);
        if (err >= 0x40000000u) break;
        if (GetThreadId(hThread) != GetCurrentThreadId())
            SuspendThread(hThread);
    }
}

namespace pfm
{
    bool ParamFieldMapper::init() {
        std::lock_guard lock(mutex);

        if (is_init) return false;

        arxan_disabler::disable_code_restoration();

        SPDLOG_INFO("Finding potential JMP targets...");
        if (!instr_utils::jmp_targets_heuristic(nullptr, jmp_targets_heuristic)) {
            Panic("JMP targets heuristic failed");
        }
        SPDLOG_INFO("Done, found {:L} potential targets", jmp_targets_heuristic.size());

        SPDLOG_INFO("Computing program-wide CFG...");
        uint8_t* module_base = (uint8_t*)GetModuleHandle(NULL);
        auto ex_tbl = cfg_utils::get_exception_table(module_base);
        for (const auto& rf: ex_tbl) {
            auto cinfo = (UNWIND_INFO*)(module_base + rf.UnwindInfoAddress);
            if (cinfo->Flags & UNW_FLAG_CHAININFO) continue;
            flow_graph.walk((intptr_t)module_base + rf.BeginAddress);
        }
        SPDLOG_INFO("Done, walked {} functions in exception table", ex_tbl.size());

        SPDLOG_INFO("Waiting for params...");
        auto param_repo = FD4ParamRepository::wait_until_loaded();
        SPDLOG_INFO("Params loaded");

        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);

        shift = 0;
        size_t num_params = 0;
        size_t normal_param_mem = 0; // Just for stats
        size_t no_shift_req_mem = 0; // Total required memory outside of shift between trap and true param files
        
        for (auto& file_cap : param_repo->param_container) {
            num_params++;
            normal_param_mem += file_cap.param_file_size;
            auto file = file_cap.param_file;
            shift = std::max(shift, file_cap.param_file_size +  sysinfo.dwPageSize);
            no_shift_req_mem += 
                sysinfo.dwPageSize + // Alignment requirements to put the row data start on a page boundary
                16 + // to accomodate fromsoft shitcode writing sorted id table offsets before param file 
                file_cap.param_file_size + // "true" file copy we redirect instructions to
                16 + // alignment requirements of offset to sorted id table
                8 * file->row_count; // sorted id table memory
        }
        shift = utils::align_up(shift, 16); // Force 16-byte alignment to shift, to avoid unaligned access
        committed_remap_mem = no_shift_req_mem + shift * num_params;

        SPDLOG_DEBUG("Required file shift = {}, memory = {:L} bytes ({:.1f}x increase)", 
            shift, committed_remap_mem, (double)committed_remap_mem / normal_param_mem);
        
        auto alloc_base = (uint8_t*)VirtualAlloc(NULL, committed_remap_mem, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!alloc_base) {
            Panic("VirtualAlloc failed, error = {:08x}", GetLastError());
        }
        remap_arena = { alloc_base, committed_remap_mem };

        hook_memcpy();
        AddVectoredExceptionHandler(TRUE, &ParamFieldMapper::veh_thunk);
        for (auto& file_cap: param_repo->param_container) {
            remap_param_file(file_cap);
        }

        SPDLOG_DEBUG("Final remap memory = {:L} bytes ({:.1f}x increase)", 
            committed_remap_mem, (double)committed_remap_mem / normal_param_mem);

        is_init = true;
        return true;
    }

    void ParamFieldMapper::hook_memcpy() {
        mem::pattern memcpy_aob { "4c 8b d9 4c 8b d2 49 83 f8 10 0f 86 ?? ?? ?? ?? 49 83 f8 20" };

        auto memcpy_addr = mem::scan(memcpy_aob, utils::main_module_section<".text">()).as<uint8_t*>();
        if (!memcpy_addr) {
            Panic("Failed to find memcpy function");
        }

        auto& arena = hook_arena_pool.get_or_create_arena(memcpy_addr);
        auto jmp_hook_info = arena.gen_jmp_hook(memcpy_addr, (void*)&memcpy_hook_thunk);
        orig_memcpy = (decltype(orig_memcpy))jmp_hook_info.trampoline;

        SPDLOG_INFO("Hooked memcpy at {:x}", (intptr_t)memcpy_addr);
    }

    void ParamFieldMapper::remap_param_file(ParamFileCap& file_cap) {
        // We create a memory block with the following structure:
        // alloc base
        // "true" trap param file start ... trap param file ID table end
        // noaccess memory pages covering rest of trap param file
        // garbage re-sort of ID table for binary search (fromsoft please)
        // "true" param file copy to direct reads to

        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);

        auto file = file_cap.param_file;
        std::span file_bytes { (uint8_t*)file, file_cap.param_file_size };

        // Someone at fromsoft should never be allowed to write code again
        // For some reason instead of binary searching over the ID/name offset/row offset table,
        // they create a (id, ParamRow) pair array, store it 16 bytes *BEFORE* the param file,
        // and binary search on that instead!?!?!?!?!?!?!?
        //
        // We'll have to copy it over too
        std::span sorted_table { 
            (uint8_t*)file + utils::align_up(*(int32_t*)((intptr_t)file - 16), 16), 8ull * file->row_count
        };

        RemappedParamFile remap;
        remap.file_cap = &file_cap;
        remap.param_name = utils::wide_string_to_string(file_cap.resource_name);
        
        // Copy and shift param files

        size_t id_table_end_ofs = file->id_table_end_offset();
        remap_arena.advance(id_table_end_ofs + 16);
        remap_arena.align(sysinfo.dwPageSize);

        remap.noaccess_mem_start = remap_arena.ptr();
        remap_arena.advance(-id_table_end_ofs);

        remap.trap_file = (ParamFile*)remap_arena.ptr();
        remap_arena.write(file_bytes);

        auto unused_pages_start = utils::align_up(remap_arena.ptr(), sysinfo.dwPageSize);
        remap_arena.advance(shift - file_bytes.size());

        // Save on memory by decommitting unused pages until proper shift offset
        auto unused_pages_end = utils::align_down(remap_arena.ptr(), sysinfo.dwPageSize);
        if (unused_pages_end > unused_pages_start) {
            VirtualFree(unused_pages_start, unused_pages_end - unused_pages_start, MEM_DECOMMIT);
            committed_remap_mem -= unused_pages_end - unused_pages_start;
        }

        remap.true_file = (ParamFile*)remap_arena.ptr();
        remap_arena.write(file_bytes);

        // Copy sorted table
        
        size_t sorted_table_ofs = utils::align_up(remap_arena.ptr() - (uint8_t*)remap.trap_file, 16);
        remap.sorted_table_start = (uint8_t*)remap.trap_file + sorted_table_ofs;
        remap_arena.seek_ptr(remap.sorted_table_start);
        remap_arena.write(sorted_table);
        *(int32_t*)((intptr_t)remap.trap_file - 16) = sorted_table_ofs;
        *(int32_t*)((intptr_t)remap.trap_file - 12) = file->row_count;

        if (remap_arena.is_eof()) {
            Panic("Ran out of remap memory while remapping param {}", remap.param_name);
        }
        
        // Compute row table we'll use to binary search for which row we're currently into
        
        if (auto sz = remap.trap_file->row_size()) {
            remap.row_size = *sz;
            remap.trap_file->for_each_row<char>([&remap](uint32_t id, void* row, const char* name) {
                remap.row_ends.push_back((intptr_t)row + remap.row_size);
            });
            std::sort(remap.row_ends.begin(), remap.row_ends.end());
        }
        else {
            Panic("Cannot determine row size of {}", remap.param_name);
        }

        // Set protection of noaccess "trap" memory pages, apply and store remap

        DWORD old_protect;
        size_t noaccess_mem_size = utils::align_up(file_cap.param_file_size - id_table_end_ofs, sysinfo.dwPageSize);
        if (!VirtualProtect(remap.noaccess_mem_start, noaccess_mem_size, PAGE_NOACCESS, &old_protect)) {
            Panic("VirtualProtect failed, error = {:08x}", GetLastError());
        }
        
        SPDLOG_DEBUG("Remapped param {} (row size {}) [{:p} -> {:p}]", remap.param_name, remap.row_size,
            (void*)remap.trap_file, (void*)remap.true_file);

        file_cap.param_file = remap.trap_file;
        remaps[(intptr_t)remap.trap_file + file_cap.param_file_size] = std::move(remap);
    }

    LONG ParamFieldMapper::veh(EXCEPTION_POINTERS* eptrs) {
        std::lock_guard lock(mutex);

        auto ecode = eptrs->ExceptionRecord->ExceptionCode;
        auto ctx = eptrs->ContextRecord;
        auto code_address = (intptr_t)eptrs->ExceptionRecord->ExceptionAddress;
        auto accessed_addr = (intptr_t)eptrs->ExceptionRecord->ExceptionInformation[1];

        if (ecode == EXCEPTION_ILLEGAL_INSTRUCTION) {
            suspend_threads();
            Panic("Attempted to execute illegal instruction at {:x}. Possible relocation edge case?", code_address);
        }
        else if (ecode != EXCEPTION_ACCESS_VIOLATION)
            return EXCEPTION_CONTINUE_SEARCH;

        // Sanity check to make sure an access violation doesn't occur in a previously patched instruction
        if (patches.contains(code_address)) {
            SPDLOG_DEBUG("Previously patched instruction at {:x}", code_address);
            _getch();
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // In hot multithreaded code, a second thread might hit the instruction before patches are observed.
        // To avoid patching twice, we keep track of existing patches
        auto rip_fix = patch_map.find(code_address);
        if (rip_fix != patch_map.end()) {
            SPDLOG_DEBUG("Thread {:x} was waiting at previously patched code location {:x}, redirecting to {:x}",
                GetCurrentThreadId(), code_address, rip_fix->second);
            ctx->Rip = rip_fix->second;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        auto remap_it = remaps.upper_bound(accessed_addr);
        if (remap_it == remaps.end() || accessed_addr < (intptr_t)remap_it->second.noaccess_mem_start) {
            SPDLOG_CRITICAL("Access violation outside of noaccess param memory at {:x}", code_address);
            return EXCEPTION_CONTINUE_SEARCH; 
        }
        auto& remapped_file = remap_it->second;
        
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)code_address, 
            ZYDIS_MAX_INSTRUCTION_LENGTH, &instruction, operands))) 
        {
            Panic("Zydis failed to decompile instruction at {:x}", code_address);
        }

        uint8_t load_size_bits = 0;
        int32_t old_disp = 0;
        for (int i = 0; i < instruction.operand_count; i++) {
            if (operands[i].type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
            load_size_bits = operands[i].size;
            old_disp = operands[i].mem.disp.has_displacement ? operands[i].mem.disp.value : 0;
            break;
        }
        if (load_size_bits == 0 || (load_size_bits & 7)) {
            Panic("Unsupported load size for instruction at {:x} ({} bits)", code_address, load_size_bits);
        }

        if (auto ofs = remapped_file.field_offset(accessed_addr)) {
            SPDLOG_TRACE("{:x} accessed offset {} in param {} (width {})", 
                code_address, *ofs, remapped_file.param_name, load_size_bits);
        }
        else {
            SPDLOG_TRACE("{:x} accessed non-row data {:x} in param {}", code_address, accessed_addr, remapped_file.param_name);
        }

        uint8_t patched_code[ZYDIS_MAX_INSTRUCTION_LENGTH];
        auto patched_code_size = instr_utils::gen_new_disp(
            patched_code, (uint8_t*)code_address, old_disp + shift);

        if (patched_code_size == 0) {
            Panic("Failed to patch displacement of instruction at {:x}", code_address);
        }

        SPDLOG_TRACE("{:n} -> {:n}", 
            spdlog::to_hex((uint8_t*)code_address, (uint8_t*)code_address + instruction.length),
            spdlog::to_hex(patched_code, patched_code + patched_code_size));

        // If we can, simply patch the instruction in-place
        // if (patched_code_size == instruction.length) {
        //     std::memcpy((void*)code_address, patched_code, patched_code_size);
        //     patches.insert(code_address);
        //     return EXCEPTION_CONTINUE_EXECUTION;
        // }

        // Otherwise, create a trampoline

        // Check for jmp targets inside the relocation window. If present, must perform CFG analysis
        if (instruction.length < 5) {
            auto jmp_point = std::upper_bound(jmp_targets_heuristic.begin(), jmp_targets_heuristic.end(), code_address);
            if (jmp_point != jmp_targets_heuristic.end()
                && *jmp_point >= code_address + instruction.length  // Confirmed false positive
                && *jmp_point < code_address + 5) // Instruction would prevent insertion of a JMP REL32
            {
                SPDLOG_WARN("relocating at {:x} may lead to a mid-instruction jmp", code_address);

                if (!flow_graph.visited_instruction(code_address)) {
                    auto fun_begin = cfg_utils::find_function(code_address, ctx->Rsp);
                    if (fun_begin) {
                        SPDLOG_DEBUG("Found function begin {:x} for instruction at {:x}", fun_begin, code_address);
                    }
                    else Panic("Failed to find function start for instruction at {:x}", code_address);
                
                    if (!flow_graph.walk(fun_begin)) {
                        Panic("Failed to compute control flow graph for instruction at at {:x}", code_address);
                    }
                    if (flow_graph.visited_instruction(code_address)) {
                        SPDLOG_INFO("Success of flow analysis back to original instruction at {:x}", code_address);
                    }
                    else {
                        Panic("Flow analysis failed to re-discover access instruction at {:x}", code_address);
                    }
                }
            }
        }

        auto& hook_arena = hook_arena_pool.get_or_create_arena((void*)code_address);

        uint8_t original_code[ZYDIS_MAX_INSTRUCTION_LENGTH];
        std::memcpy(original_code, (uint8_t*)code_address, instruction.length);

        intptr_t final_patch_address = 0; 
        auto gen_patch = [&]{ 
            final_patch_address = (intptr_t)hook_arena.ptr();
            hook_arena.gen_cond_access_hook(original_code, patched_code,
                (uintptr_t)remap_arena.buffer().data(), 
                (uintptr_t)remap_arena.buffer().data() + remap_arena.buffer().size());
        };

        /// Update flow graph while building trampoline if required
        auto cfg = flow_graph.visited_instruction(code_address) ? &flow_graph : nullptr;
        auto result = trampoline::gen_trampoline(hook_arena, gen_patch, (uint8_t*)code_address, true, cfg);
        if (!result) {
            Panic("Trampoline generation at {:x} failed", code_address);
        }
        
        ctx->Rip = final_patch_address;
        patch_map[code_address] = final_patch_address;
        patches.insert(final_patch_address);
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
}