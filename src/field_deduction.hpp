#pragma once
#include "param_access_flags.hpp"
#include "param_remapping.hpp"

namespace pfm {

struct DeducedField {
    size_t offset;
    uint8_t size_bytes;
    FieldBaseType type;
    bool maybe_array = false;
};

struct FieldOffsetFlags {
    bool base_type_conflict : 1 = false; // Multiple type bits set for offset
    bool size_conflict      : 1 = false; // Multiple size bits set for offset
    bool intersect          : 1 = false; // Intersects a field before itself
    bool unk_int            : 1 = false; // Is an untyped integer
    bool active_field       : 1 = false; // Is an recognized field
};

struct DeducedParamdef {
    const RemappedParamFile* remapped_file;
    std::vector<DeducedField> fields;
    std::vector<FieldOffsetFlags> offset_data; 

    void clear_deductions();
    void update_deductions(bool log_updates = false);
};

} // namespace pfm