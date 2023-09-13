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

} // namespace pfm