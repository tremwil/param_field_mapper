#include "param_access_flags.hpp"
#include "zydis/Zydis.h"

namespace pfm {

cpp::result<ParamAccessFlags, ParamAccessFlags::Error>
ParamAccessFlags::from_instruction(const uint8_t *instruction_bytes) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)instruction_bytes, 
        ZYDIS_MAX_INSTRUCTION_LENGTH, &instruction, operands))) 
    {
        return cpp::fail(Error::DissassemblyFailure);
    }
    
    ZydisDecodedOperand* mem_op = nullptr;
    for (int i = 0; i < instruction.operand_count; i++) {
        if (operands[i].type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
        mem_op = operands + i;
        break;
    }
    if (mem_op == nullptr) {
        return cpp::fail(Error::NoMemOperands);   
    }
    if (mem_op->element_count > 1) {
        return cpp::fail(Error::IsSimd);
    }

    ParamAccessFlags flags {
        .uses_sib = (instruction.attributes & ZYDIS_ATTRIB_HAS_SIB) != 0,
    };
    switch (mem_op->element_size) {
        case 8: flags.size_1 = true; break;
        case 16: flags.size_2 = true; break;
        case 32: flags.size_4 = true; break;
        case 64: flags.size_8 = true; break;
        default: return cpp::fail(Error::BadLoadSize);
    }

    // Fromsoft doesn't use 64-bit integer types in params!
    if (flags.size_8 && mem_op->element_type != ZYDIS_ELEMENT_TYPE_FLOAT64) {
        return cpp::fail(Error::IsSimd); // Should make a new error but idc
    }
    
    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOVSX || instruction.mnemonic == ZYDIS_MNEMONIC_MOVSXD) {
        flags.type_signed = true; 
    }
    
    switch (mem_op->element_type) {
        case ZYDIS_ELEMENT_TYPE_FLOAT32:
        case ZYDIS_ELEMENT_TYPE_FLOAT64: flags.type_float = true; break;
        case ZYDIS_ELEMENT_TYPE_UINT: flags.type_unsigned = true; break;
        default: break;
    }

    return flags;
}

} // namespace pfm