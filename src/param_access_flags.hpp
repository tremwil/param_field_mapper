#pragma once
#include <result/result.hpp>
#include <array>

namespace pfm {

/// Information about an instruction that accessed param which is stored in a copy of the param file. 
/// Used for field type deduction.
struct ParamAccessFlags { 
    bool type_signed: 1;     // Set for sign-extended loads
    bool type_unsigned : 1;  // Set for zero-extended loads
    bool type_float : 1;     // Set for 1-element single-precision xmm loads (i.e. movss)
    bool size_1 : 1;         // Set for 1-byte loads
    bool size_2 : 1;         // Set for 2-byte loads
    bool size_4 : 1;         // Set for 4-byte loads
    bool size_8 : 1;         // Set for 8-byte loads
    bool uses_sib : 1;       // Set if instruction uses SIB addressing

    enum class Error {
        Success,
        DissassemblyFailure,
        NoMemOperands,
        BadLoadSize,
        IsSimd,
    };

    operator uint8_t() const noexcept {
        return *reinterpret_cast<const uint8_t*>(this);
    }

    static inline ParamAccessFlags from_byte(uint8_t val) noexcept {
        return *reinterpret_cast<ParamAccessFlags*>(&val);
    }

    /// Generates access flag bits given an instruction. If the instruction is unsuitable for 
    /// type deduction, returns an empty optional. 
    static cpp::result<ParamAccessFlags, Error> from_instruction(const uint8_t* instruction_bytes);
};
static_assert(sizeof(ParamAccessFlags) == 1, "ParamAccessFlags is not 1 byte in size");

/// Base type of a param value. 
enum class FieldBaseType : uint8_t {
    UnkInt = 0,
    Signed = 1,
    Unsigned = 2,
    Float = 3
};

inline char field_base_type_to_chr(FieldBaseType f) {
    return "isufXXXX"[static_cast<uint8_t>(f) & 7];
}

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
        return { (num_positive > 1) << max_i, num_positive != 1 };
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

} // namespace pfm