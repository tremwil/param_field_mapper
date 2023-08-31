#include "hook_arena.h"
#include "instr_utils.h"
#include "spdlog/spdlog.h"

#include <psapi.h>
#include <vector>

using namespace std::literals;
using namespace pfm::utils;

namespace pfm
{ 
    void HookArena::init(intptr_t mod_begin, intptr_t mod_end, size_t hook_mem_size)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        // Round size and boundaries to allocation granularity (64KB)
        size_t gran = si.dwAllocationGranularity;
        size_t desired_size = (hook_mem_size + gran - 1) & ~(gran - 1);
        size_t region_start = mod_begin & ~(gran - 1);
        size_t region_end = (mod_end + gran - 1) & ~(gran - 1);

        // compute lowest possible allocation address (note that the [0, 64K) block is not usable)
        const intptr_t max_dist = (intptr_t)1 << 31;
        intptr_t addr = std::max(region_end - max_dist, (uintptr_t)si.dwAllocationGranularity);

        // Search free region closest to target module to allocate our hook memory at,
        // starting at lowest possible address that admits a REL32 jmp
        MEMORY_BASIC_INFORMATION minfo;
        while (VirtualQuery((void*)addr, &minfo, sizeof(minfo))) {
            intptr_t base = (intptr_t)minfo.BaseAddress;
            intptr_t size = (intptr_t)minfo.RegionSize;
            addr = base + size;

            // Memory is not free
            if (minfo.State != MEM_FREE) continue;

            // not enough space for the memory block
            if (size < desired_size) continue;

            intptr_t chosen_base = 0;
            // Case 1: below the region and furthest address in range
            if (addr <= region_start && region_end + desired_size - addr <= max_dist) {
                chosen_base = addr - desired_size;
            }
            // Case 2: above the region and furthest address in range
            else if (base >= region_end && base + desired_size - region_start <= max_dist) {
                chosen_base = base;
            }
            // range of pages is not suitable
            else continue;

            alloc_base = (uint8_t*)VirtualAlloc((void*)chosen_base, desired_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            begin = alloc_base;
            end = begin + desired_size;
            current = begin;
            return;
        }
    }

    HookArena::HookArena() : LiteMemStream(std::span<uint8_t>()) { }

    HookArena::HookArena(intptr_t region_base, size_t region_size, size_t hook_mem_size) : HookArena()
    {
        init(region_base, region_base + region_size, hook_mem_size);
    }

    HookArena::HookArena(const char* target_module, size_t hook_mem_size) : HookArena()
    {
        intptr_t mod_begin = (intptr_t)GetModuleHandleA(target_module);
        if (mod_begin == 0) return;

        MODULEINFO mi;
        GetModuleInformation(GetCurrentProcess(), (HMODULE)mod_begin, &mi, sizeof(mi));
        intptr_t mod_end = mod_begin + mi.SizeOfImage;

        init(mod_begin, mod_end, hook_mem_size);
    }

    HookArena::HookArena(void* address, size_t hook_mem_size) : HookArena() {
        intptr_t mod_begin;
        if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)address,
            (HMODULE*)&mod_begin
        )) {
            return;
        }

        MODULEINFO mi;
        GetModuleInformation(GetCurrentProcess(), (HMODULE)mod_begin, &mi, sizeof(mi));
        intptr_t mod_end = mod_begin + mi.SizeOfImage;

        init(mod_begin, mod_end, hook_mem_size);
    }

    HookArena::~HookArena()
    {
        if (alloc_base) {
            VirtualFree((LPVOID)alloc_base, 0, MEM_FREE);
        }
    }

    bool HookArena::can_patch(intptr_t addr)
    {
        auto dist = std::abs(addr - (intptr_t)begin);
        if (dist < std::abs(addr - (intptr_t)end)) dist = std::abs(addr - (intptr_t)end);
        return dist < (1LL << 31);
    }

    JmpHookInfo HookArena::gen_jmp_hook(void* addr, void* hook_code)
    {
        intptr_t hook_start = (intptr_t)current;

        // setup absolute jump thunk 
        // movabs rax, hook
        write<uint16_t>(0xB848);

        void** hook_address = (void**)current;
        write(hook_code);

        // jmp rax
        write<uint16_t>(0xe0ff);

        // Generate trampoline
        return { gen_trampoline(hook_start, (intptr_t)addr, 0), hook_address };
    }

    void** HookArena::gen_call_hook(void* addr, void* hook_code)
    {
        auto trampoline = current;

        // setup absolute jump trampoline 
        // movabs rax, hook
        write<uint16_t>(0xB848);
        void** hook_address = (void**)current;
        write(hook_code);

        // jmp rax
        write<uint16_t>(0xe0ff);

        // Write call hook to trampoline
        patch_memory(addr, 5, [&]() {
            *(int32_t*)((intptr_t)addr + 1) = (intptr_t)trampoline - ((intptr_t)addr + 5);
        });

        return hook_address;
    }

    intptr_t HookArena::gen_cond_access_hook(uint8_t* original, uint8_t* patched, uintptr_t region_begin, uintptr_t region_end)
    {
        hde64s disasm_orig;
        hde64_disasm(original, &disasm_orig);

        hde64s disasm_patched;
        hde64_disasm(patched, &disasm_patched);

        if (!(disasm_orig.flags & F_MODRM))
            return 0;

        intptr_t tramp_start = (intptr_t)current;

        // mov rax, qword ptr [rsp - 8]
        // mov rbx, qword ptr [rsp - 16]
        // popf
        constexpr auto restore_registers = "\x48\x8B\x44\x24\xF8\x48\x8B\x5C\x24\xF0\x9D"sv;

        // pushf
        // mov qword ptr [rsp - 8], rax
        // mov qword ptr [rsp - 16], rbx
        write("\x9C\x48\x89\x44\x24\xF8\x48\x89\x5C\x24\xF0"sv);

        // lea rax, {mod/rm expression}
        instr_utils::gen_lea(this, &disasm_orig);

        // movabs rbx, region_begin
        write<uint16_t>(0xBB48);
        write(region_begin);
        // cmp rax, rbx
        write("\x48\x39\xD8"sv);

        // jl normal_behavior
        write<uint8_t>(0x7C);
        write<uint8_t>(17 + sizeof(restore_registers) - 1 + disasm_patched.len);

        // movabs rbx, region_begin
        write<uint16_t>(0xBB48);
        write(region_end);
        // cmp rax, rbx
        write("\x48\x39\xD8"sv);

        // jae normal_behavior
        write<uint8_t>(0x73);
        write<uint8_t>(2 + sizeof(restore_registers) - 1 + disasm_patched.len);

        // {restore registers}
        write(restore_registers);
        // {patched_instruction}
        write(std::span { patched, disasm_patched.len });

        // jmp end
        write<uint8_t>(0xEB);
        write<uint8_t>(sizeof(restore_registers) - 1 + disasm_orig.len);

        /* normal_behavior: */

        // {restore registers}
        write(restore_registers);
        // {orig_instruction}
        write(std::span { original, disasm_orig.len });

        /* end: */
        return tramp_start;
    }

    TrampolineInfo HookArena::gen_trampoline(intptr_t hook_start, intptr_t addr, int num_overwrite)
    {
        intptr_t overwrite_sz = 0;
        for (int i = 0; i < num_overwrite; i++)
        {
            hde64s disasm;
            hde64_disasm((void*)(addr + overwrite_sz), &disasm);
            overwrite_sz += disasm.len;
        }

        std::vector<char*> to_move;
        std::vector<hde64s> to_move_disasm;

        intptr_t copy_block_start = addr + overwrite_sz;
        intptr_t copy_block_end = copy_block_start;
        while (copy_block_end - addr < 5)
        {
            hde64s disasm;
            hde64_disasm((void*)copy_block_end, &disasm);
            to_move_disasm.push_back(disasm);
            to_move.push_back((char*)copy_block_end);
            copy_block_end += disasm.len;
        }

        intptr_t ret = to_move.empty() ? copy_block_start : (intptr_t)current;

        std::span modified { (uint8_t*)addr, (uint8_t*)copy_block_end };
        TrampolineInfo tramp_info {
            .trampoline = (void*)ret,
            .modified_code = modified,
            .old_code = { modified.begin(), modified.end() }
        };

        // Move code to have enough place to insert the JMP REL32
        struct reloc { int i_tgt;  int32_t* imm; };
        std::vector<uint8_t*> new_addresses;
        std::vector<reloc> relocs;

        for (int i = 0; i < to_move.size(); i++)
        {
            char* instr = to_move[i];
            hde64s& disasm = to_move_disasm[i];

            new_addresses.push_back(current);
            write(std::span { instr, disasm.len });

            // If using relative addressing, use gadget to redirect to new address 
            if (disasm.flags & F_RELATIVE)
            {
                int32_t rel_offset = (disasm.flags & F_IMM8) ? (int8_t)disasm.imm.imm8 : disasm.imm.imm32;
                intptr_t original_loc = (intptr_t)instr + disasm.len + rel_offset;

                // make original jmp/jcc/call point to jmp rel32 thunk
                if (disasm.flags & F_IMM8) *(current - 1) = 2;
                else *(int32_t*)(current - 4) = 2;

                // Write rel8 and rel32 jmps
                write<uint16_t>(0x05EB);
                write<uint8_t>(0xE9);
                write<int32_t>(original_loc - (intptr_t)(current + 4));

                // Search for index of instruction we are jumping to
                for (int j = 0; j < to_move.size(); j++)
                {
                    if ((intptr_t)to_move[j] == original_loc)
                    {   // Within copy block, add relocations spot
                        relocs.push_back({ j, (int32_t*)(current - 4) });
                        break;
                    }
                }
            }
        }
        // Do relocations, if any
        for (const auto& r : relocs)
            *r.imm = (intptr_t)new_addresses[r.i_tgt] - (intptr_t)(r.imm + 1);

        patch_memory(tramp_info.modified_code, [&](){
            // Fill overwrite block + moved block with NOPs
            std::memset((void*)addr, 0x90, copy_block_end - addr);

            // Jump to hook
            *(uint8_t*)(addr) = 0xE9; // JMP REL32 -> to tramp
            *(int32_t*)(addr + 1) = hook_start - (addr + 5);
        });

        // JMP back from hook
        write<uint8_t>(0xE9); // JMP REL32 -> end of copy block
        write<int32_t>(copy_block_end - (intptr_t)(current + 4));

        return tramp_info;
    }

    HookArena& HookArenaPool::get_or_create_arena(void *hook_site)
    {
        for (auto& arena: arenas) {
            if (arena.can_patch((intptr_t)hook_site)) {
                return arena;
            }
        }
        SPDLOG_TRACE("Creating new hook arena for hook site {:p}", hook_site);
        auto& arena = arenas.emplace_back(hook_site, hook_mem_size);
        
        if (arena.is_eof()) {
            Panic("Failed to find suitable location for hook memory arena for address {:p}", hook_site);
        }
        return arena;
    }
}