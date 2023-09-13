#pragma once
#include "param_access_flags.hpp"
#include "param_remapping.hpp"

namespace pfm {

/// Tally of param access flag values over multiple rows. 
/// The information used for field type deduction.
struct ParamAccessFlagsTally {
    uint16_t type_signed = 0;
    uint16_t type_unsigned = 0;
    uint16_t type_float = 0;
    uint16_t size_1 = 0;
    uint16_t size_2 = 0;
    uint16_t size_4 = 0;
    uint16_t size_8 = 0;
    uint16_t uses_sib = 0;

    /// Returns size which appeared the most, and a bool indicating if a conflict exists.
    inline std::pair<uint8_t, bool> deduce_size() const noexcept {
        uint16_t sizes[4] { size_1, size_2, size_4, size_8 };
        uint16_t max = 0;
        uint8_t max_i = 0, num_positive = 0;
        for (uint8_t i = 0; i < 4; i++) {
            num_positive += (sizes[i] > 0);
            if (sizes[i] > max) {
                max_i = i;
                max = sizes[i];
            }
        }
        return { (num_positive > 0) << max_i, num_positive != 1 };
    }

    /// Returns type which appeared the most, and a bool indicating if a conflict exists.
    /// If no (strong) type was ever logged, returns FieldBaseType::UnkInt
    inline std::pair<FieldBaseType, bool> deduce_base_type() const noexcept {
        uint16_t types[3] { type_signed, type_unsigned, type_float };
        uint16_t max = 0;
        uint8_t max_i = 0, num_positive = 0;
        for (uint8_t i = 0; i < 3; i++) {
            num_positive += (types[i] > 0);
            if (types[i] > max) {
                max_i = i;
                max = types[i];
            }
        }
        auto t = static_cast<FieldBaseType>(max_i + (num_positive > 0));
        return { t, num_positive > 1 };
    }

    /// Increments the tally counts 
    inline void increment(const ParamAccessFlags& access_flags_byte) noexcept {
        type_signed += access_flags_byte.type_signed;
        type_unsigned += access_flags_byte.type_unsigned;
        type_float += access_flags_byte.type_float;
        size_1 += access_flags_byte.size_1;
        size_2 += access_flags_byte.size_2;
        size_4 += access_flags_byte.size_4;
        size_8 += access_flags_byte.size_8;
        uses_sib += access_flags_byte.uses_sib;
    }

    inline bool is_zero() const noexcept {
        static const std::array<uint8_t, sizeof(*this)> zero {};
        return !std::memcmp(this, zero.data(), sizeof(*this));
    }
};

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