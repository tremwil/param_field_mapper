#include "instr_utils.h"
#include "hde/hde64.h"
#include "hooks/instr_utils.h"
#include <winnt.h>

#include <set>
#include <thread>

namespace pfm::instr_utils
{
    bool gen_lea(LiteMemStream* out_stream, hde64s* instr)
    {
        if (!(instr->flags & F_MODRM))
            return false;

        // Set REX.W (64bit dest) and clear REX.R (makes rax -> r8)
        //printf("REX: %02X\n", instr->rex);
        out_stream->write<uint8_t>((instr->rex & 0b01001011) | 0b01001000);
        out_stream->write<uint8_t>(0x8d);

        // Clear modrm.reg to 0 for rax
        out_stream->write<uint8_t>(instr->modrm & 0b11000111);
        if (instr->flags & F_SIB) out_stream->write<uint8_t>(instr->sib);

        if (instr->flags & F_DISP8)
            out_stream->write<uint8_t>(instr->disp.disp8);
        else if (instr->flags & F_DISP32)
            out_stream->write<uint32_t>(instr->disp.disp32);

        return true;
    }

    int32_t get_disp(uint8_t* instr) 
    {
        hde64s disasm;
        hde64_disasm(instr, &disasm);

        if (!(disasm.flags & F_MODRM))
            return 0;

        if (disasm.flags & F_DISP8) return (int8_t)disasm.disp.disp8;
        if (disasm.flags & F_DISP16) return (int16_t)disasm.disp.disp16;
        if (disasm.flags & F_DISP32) return (int16_t)disasm.disp.disp32;
        else return 0;
    }

    size_t gen_new_disp(uint8_t* instr_out, uint8_t* instr, int32_t new_disp)
    {
        hde64s disasm;
        hde64_disasm(instr, &disasm);

        if (!(disasm.flags & F_MODRM))
            return 0;

        int32_t imm_size = 0;
        if (disasm.flags & F_IMM8) imm_size = 1;
        else if (disasm.flags & F_IMM16) imm_size = 2;
        else if (disasm.flags & F_IMM32) imm_size = 4;
        else if (disasm.flags & F_IMM64) return 0; // Not supported

        int32_t imm_offset = disasm.len - imm_size;
        int32_t disp_offset = imm_offset;

        if (disasm.modrm_mod == 1) disp_offset -= 1;
        if (disasm.modrm_mod == 2) disp_offset -= 4;

        int32_t new_instr_size = disp_offset + imm_size + 4;
        int32_t modrm_byte = disp_offset - ((disasm.flags & F_SIB) ? 2 : 1);

        memcpy(instr_out, instr, disasm.len);
        memcpy(instr_out + disp_offset + 4, instr + imm_offset, imm_size);

        instr_out[modrm_byte] = (disasm.modrm & 0x3F) | 0x80;
        *(uint32_t*)(instr_out + disp_offset) = new_disp;

        return new_instr_size;
    }

    bool jmp_targets_heuristic(intptr_t mod_base, std::vector<intptr_t>& targets)
    {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mod_base;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)mod_base + dos->e_lfanew);

        IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) || strcmp((char*)sections[i].Name, ".text")) continue;

            uint8_t* base = (uint8_t*)mod_base + sections[i].VirtualAddress;
            uint8_t* end = base + sections[i].Misc.VirtualSize;

            hde64s instr, jmp_check;
            std::set<intptr_t> targets_set;
            for (uint8_t* cptr = base; cptr < end; cptr++)
            {
                uint8_t* cins = cptr;
                if (hde64_disasm(cins, &instr) & F_ERROR) continue;
                if (!(instr.flags & F_RELATIVE) || !(instr.flags & (F_IMM8 | F_IMM32))) continue;

                // Check if instruction is "legit" by requiring that it also points to a sequence of valid instruction
                uint8_t* jmp_target = cins + instr.len + ((instr.flags & F_IMM8) ? (int8_t)instr.imm.imm8 : (int32_t)instr.imm.imm32);
                if (jmp_target < base || jmp_target >= end) continue;
                if (hde64_disasm(jmp_target, &jmp_check) & F_ERROR) continue;

                targets_set.insert((intptr_t)jmp_target);
            }
            targets.assign(targets_set.begin(), targets_set.end());
            return true;
        }
        return false;
    }
}

