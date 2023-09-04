#include "trampoline.h"
#include "core/utils.h"
#include "hde/hde64.h"
#include "hooks/trampoline.h"

#include <processthreadsapi.h>
#include <stdint.h>
#include <unordered_map>

namespace pfm::trampoline
{
    struct Reloc {
        uint8_t* tgt;
        uint8_t* instr_begin;
        uint8_t* instr_end;
        uint8_t imm_size;
    };

    RelocResult relocate(LiteMemStream& mem_stream, std::span<uint8_t> code_block, std::optional<uint8_t*> ip) {
        std::vector<Reloc> relocs;
        AddressMap address_map;

        intptr_t ip_ofs = ip.value_or(code_block.data()) - code_block.data();
        hde64s disasm;
        for (auto instr = code_block.data(); instr < code_block.data() + code_block.size(); instr += disasm.len) {
            if (hde64_disasm(instr, &disasm) & F_ERROR) {
                SPDLOG_ERROR("HDE failed to decompile instruction at {:x}", (intptr_t)instr);
                return { .success = false };
            }
            if (instr + disasm.len > code_block.data() + code_block.size()) {
                SPDLOG_ERROR("Instruction at {:x} goes outside of provided code block", (intptr_t)instr);
                return { .success = false };
            }

            address_map[instr] = mem_stream.ptr(); 
            Reloc r { .instr_begin = mem_stream.ptr() };
            mem_stream.write(std::span { instr, disasm.len });
            r.instr_end = mem_stream.ptr();

            if (disasm.flags & F_RELATIVE) {
                intptr_t ofs = (int64_t)disasm.imm.imm64;
                r.imm_size = 8;
                if (disasm.flags & F_IMM8) { ofs = (int8_t)disasm.imm.imm8; r.imm_size = 1; }
                if (disasm.flags & F_IMM16) { ofs = (int16_t)disasm.imm.imm16; r.imm_size = 2; }
                if (disasm.flags & F_IMM32) { ofs = (int32_t)disasm.imm.imm32; r.imm_size = 4; }

                r.tgt = instr + disasm.len + ofs + ip_ofs;

                // If instruction has a rel8 or rel16 imm, widen using jmp rel32 thunk
                if (r.imm_size < 4) {
                    std::memcpy(r.instr_end - r.imm_size, "\x02\0", r.imm_size);
                    mem_stream.write({ 0xEB, 0x05, 0xE9 });
                    mem_stream.write<uint32_t>(0);

                    r.instr_begin = mem_stream.ptr() - 5;
                    r.instr_end = mem_stream.ptr();
                    r.imm_size = 4;
                }
                relocs.push_back(r);
            }
            // RIP-relative MODRM instruction
            else if ((disasm.flags & F_MODRM) && disasm.modrm_mod == 0 && disasm.modrm_rm == 0b101) {
                r.tgt = instr + disasm.len + (int32_t)disasm.disp.disp32 + ip_ofs;
                r.imm_size = 4;
                relocs.push_back(r);
            }
        }

        for (const auto& r: relocs) {
            const auto imm = mapped_addr(address_map, r.tgt) - r.instr_end;
            std::memcpy(r.instr_end - r.imm_size, &imm, r.imm_size);
        }

        return { .success = !mem_stream.is_eof(), .address_map = std::move(address_map) };
    }

    RelocResult gen_trampoline(LiteMemStream& arena, CodegenFunc codegen, uint8_t* insert_pos, bool replace, CFG* cfg, AddressMap* old_map) {
        auto disasm_at = [](auto loc, hde64s* disasm) {
            if (hde64_disasm((const void*)loc, disasm) & F_ERROR) {
                SPDLOG_ERROR("HDE failed to decompile instruction at {:x}", (intptr_t)loc);
                return false;
            }
            return true;
        };

        // Disassemble first 5 bytes
        hde64s disasm; 
        std::vector<intptr_t> instructions;
        size_t size_disasm = 0, size_first;
        for (; size_disasm < 5; size_disasm += disasm.len) {
            auto instr = insert_pos + size_disasm;
            if (!disasm_at(instr, &disasm)) return { .success = false };
            if (size_disasm == 0) size_first = disasm.len;
            instructions.push_back((intptr_t)instr);
        }

        // JMP target handling
        std::vector<Reloc> jmp_relocs;
        if (cfg) {
            for (auto instr : std::span { instructions.data(), instructions.size() }.subspan(1)) {
                auto tgt = cfg->get_target_at(instr);
                if (!tgt) continue;
                for (const auto& branch : tgt->branches) {
                    if (!disasm_at(branch->address, &disasm))
                        return { .success = false };

                    if (!(disasm.flags & F_RELATIVE)) {
                        SPDLOG_ERROR("Cannot fixup mid-instruction jmp for non-relative branch at {:x} with target {:x}", branch->address, instr);
                        return { .success = false };
                    }

                    Reloc r { 
                        .tgt = (uint8_t*)instr,
                        .instr_begin = (uint8_t*)branch->address,
                        .instr_end = (uint8_t*)branch->address + disasm.len,
                        .imm_size = (uint8_t)((disasm.flags & (2 * F_IMM64 - 1)) / F_IMM8)
                    };

                    // If branch is also within the deleted/relocated area, we don't need to do anything
                    if (r.instr_begin >= insert_pos && r.instr_end <= insert_pos + size_disasm) {
                        continue;
                    }

                    // If instruction has a rel8 or rel16 imm, we need to create a jmp rel32 thunk.
                    // This requires generating another trampoline...
                    if (r.imm_size < 4) {
                        // Copy the instruction to the stack. gen_trampoline might move it!
                        uint8_t instr_copy[15];
                        std::memcpy(instr_copy, r.instr_begin, disasm.len);

                        auto thunk_res = gen_trampoline(arena, [&](const AddressMap& map) {
                            arena.write(std::span { instr_copy, disasm.len });
                            std::memcpy(arena.ptr() - r.imm_size, "\x02\0", r.imm_size);
                            arena.write({ 0xEB, 0x05, 0xE9 });
                            arena.write<uint32_t>(mapped_addr(map, r.tgt) - (arena.ptr() + 4));
                        }, (uint8_t*)branch->address, true, cfg, old_map);

                        if (!thunk_res) return thunk_res;

                        // After the above, everything we've already done may have been invalidated. 
                        // Go to where our insert pos has (potentially) been relocated, and restart from there
                        auto new_insert = mapped_addr(thunk_res.address_map, insert_pos);
                        return gen_trampoline(arena, codegen, new_insert, replace, cfg, &thunk_res.address_map);
                    }
                    else jmp_relocs.push_back(r);
                }
            }

            // Delete to-be-relocated instructions from the CFG
            for (auto instr: instructions) {
                cfg->remove_instruction(instr);
            }
        }

        // Relocate the original code
        auto code_to_reloc = !replace ? 
            std::span { insert_pos, size_disasm } : 
            std::span { insert_pos + size_first, size_disasm - size_first };
        
        auto reloc_start = arena.ptr();
        auto reloc_res = relocate(arena, code_to_reloc);
        if (!reloc_res) return reloc_res;

        // Write jmp back to original code
        arena.write<uint8_t>(0xE9);
        arena.write<int32_t>(insert_pos + size_disasm - arena.ptr() - 4);

        AddressMap addr_map;
        if (old_map) addr_map = *old_map;
        // Combine address maps
        for (auto& [k, v] : addr_map) {
            auto it = reloc_res.address_map.find(v);
            if (it != reloc_res.address_map.end()) {
                v = it->second;
            }
        }
        for (const auto& kv : reloc_res.address_map) {
            addr_map.insert(kv);
        }

        // Generate the code block
        auto code = arena.ptr();
        codegen(addr_map);

        // Generate jmp to relocated code
        arena.write<uint8_t>(0xE9);
        arena.write<int32_t>(reloc_start - arena.ptr() - 4);
        
        FlushInstructionCache(GetCurrentProcess(), reloc_start, arena.ptr() - reloc_start);

        // Fixup jmps
        for (const auto& r : jmp_relocs) {
            // Modify branch to target relocated code
            const auto updated_tgt = mapped_addr(reloc_res.address_map, r.tgt);
            const auto imm = updated_tgt - r.instr_end;

            // POTENTIAL DATA RACE (仕方ない)
            std::memcpy(r.instr_end - r.imm_size, &imm, r.imm_size); // TODO: Change by single write
            FlushInstructionCache(GetCurrentProcess(), r.instr_begin, r.instr_end - r.instr_begin);

            // Fixup CFG (safety: jmp relocs only exist when cfg is not null)
            const auto bt = cfg->get_branch_at((intptr_t)r.instr_begin)->type;
            cfg->remove_branch((intptr_t)r.instr_begin);
            cfg->add_branch((intptr_t)r.instr_begin, bt, { (intptr_t)updated_tgt });
        }

        // Write JMP to code inside instruction - POTENTIAL DATA RACE (仕方ない)
        *insert_pos = 0xE9;
        *(int32_t*)(insert_pos + 1) = code - (insert_pos + 5);
        std::memset(insert_pos + 5, 0x90, size_disasm - 5);
        FlushInstructionCache(GetCurrentProcess(), insert_pos, size_disasm);

        // Re-walk CFG to update changes to program flow
        if (cfg) cfg->walk((intptr_t)insert_pos);

        reloc_res.success = !arena.is_eof();
        return { .success = true, .address_map = std::move(addr_map) };
    }
}