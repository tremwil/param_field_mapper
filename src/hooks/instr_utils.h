#pragma once
#include "core/lite_mem_stream.h"
#include "hde/hde64.h"
#include <vector>

namespace pfm::instr_utils
{
    /// Emits a LEA instruction that writes the address accessed by instr to RAX.
    /// Returns false if the instruction does not use MOD.R/M addressing.
    bool gen_lea(LiteMemStream* out_stream, hde64s* instr);

    /// Get the displacement of a mod.rm instruction. 
    int32_t get_disp(uint8_t* instr);

    /// Patches the input instruction's displacement field.
    /// This may make the instruction longer. New instruction size will be returned, or 0 on fail.
    size_t gen_new_disp(uint8_t* instr_out, uint8_t* instr, int32_t new_disp);

    /// Populates a map of all potential JMP/JCC/CALL instructions targets, ordered for binary search.
    /// False positives will be present, the point is to avoid doing CFG analysis of the entire image.
    bool jmp_targets_heuristic(intptr_t mod_base, std::vector<intptr_t>& targets);
};