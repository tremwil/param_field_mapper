#include "field_deduction.hpp"
#include <intrin.h>

#include "fst/param_file.h"
#include "core/panic.h"

#include "param_access_flags.hpp"
#include <spdlog/spdlog.h>

namespace pfm {

void DeducedParamdef::clear_deductions() {
    fields.clear();
    for (auto& c : offset_data) { c = {}; }
}

void DeducedParamdef::update_deductions(bool log_updates) {
    const auto pf = remapped_file->true_file;
    const auto row_size = remapped_file->row_size;

    fields.clear();
    offset_data.resize(row_size);
    std::vector<ParamAccessFlagsTally> offset_counts(row_size);

    for (size_t i = 0; i < pf->row_count; i++) {
        auto row = (ParamAccessFlags*)pf->row_data_at(i) + remapped_file->flags_shift() - remapped_file->file_shift();
        for (size_t j = 0; j < row_size; j++) {
            offset_counts[j].increment(row[j]);
        }
    }

    uint8_t field_bytes_left = 0;
    for (size_t i = 0; i < row_size; i++) {
        const auto& tally = offset_counts[i];
        auto& ofs_flags = offset_data[i];

        if (field_bytes_left > 0) field_bytes_left--;
        if (tally.is_zero()) continue;

        // SPDLOG_DEBUG("{} 0x{:03x}: (s {} u {} f {} 1 {} 2 {} 4 {} 8 {} sib {}) ofs_flags: {:b}",
        //     remapped_file->param_name, i, tally.type_signed, tally.type_unsigned, tally.type_float,
        //     tally.size_1, tally.size_2, tally.size_4, tally.size_8, tally.uses_sib, *(uint8_t*)&ofs_flags);

        auto [size, size_conflict] = tally.deduce_size();
        if (size == 0) {
            Panic("Got zero size in nonzero offset flags block at 0x{:03x} in {}. This is impossible!",
                i, remapped_file->param_name);
        }

        if (size_conflict && !ofs_flags.size_conflict) {
            if (log_updates) SPDLOG_WARN("Size conflict for {} at offset 0x{:03x} (1: {}, 2: {}, 4: {}, 8: {})", 
                remapped_file->param_name, i, tally.size_1, tally.size_2, tally.size_4, tally.size_8);

            ofs_flags.size_conflict = true;   
        }

        auto [type, type_conflict] = tally.deduce_base_type();
        if (type_conflict && !ofs_flags.base_type_conflict) {
            if (log_updates) SPDLOG_WARN("Type conflict for {} at offset 0x{:03x} (s: {}, u: {}, f: {})", 
                remapped_file->param_name, i, tally.type_signed, tally.type_unsigned, tally.type_float);

            ofs_flags.base_type_conflict = true;
        }

        bool was_unk_int = ofs_flags.unk_int;
        ofs_flags.unk_int = type == FieldBaseType::UnkInt;

        if (field_bytes_left > 0 && !ofs_flags.intersect) {
            SPDLOG_WARN("Field conflict for {} at offset 0x{:03x}: {}{} overlaps previous access", 
                remapped_file->param_name, i, field_base_type_to_chr(type), 8 * size);

            ofs_flags.intersect = true;
        }
        
        if (!ofs_flags.active_field && field_bytes_left == 0) {
            if (log_updates) SPDLOG_DEBUG("Deduced {}{: <2} at offset 0x{:03x} in {}", 
                field_base_type_to_chr(type), 8 * size, i, remapped_file->param_name);
            
            ofs_flags.active_field = true;
        }
        field_bytes_left = std::max(field_bytes_left, size);

        if (ofs_flags.intersect) 
            continue;

        if (log_updates && was_unk_int && !ofs_flags.unk_int) {
            SPDLOG_DEBUG("Updated {}{: <2} at offset 0x{:03x} in {}", 
                field_base_type_to_chr(type), 8 * size, i, remapped_file->param_name);  
        }

        fields.push_back({
            .offset = i,
            .size_bytes = size,
            .type = type,
            .maybe_array = tally.uses_sib > 0,
        });
    }
}

} // namespace pfm