#include "param_field_mapper.h"
#include "core/panic.h"
#include "core/utils.h"
#include "fst/fd4_param_repository.h"

#include <Windows.h>
#include <zydis/Zydis.h>

namespace pfm
{
    bool ParamFieldMapper::init() {
        SPDLOG_INFO("Waiting for params...");
        auto param_repo = FD4ParamRepository::wait_until_loaded();
        SPDLOG_INFO("Params loaded");

        for (const auto& file_cap : param_repo->param_container) {
            auto name = utils::wide_string_to_string(file_cap.resource_name);
            auto param_file = file_cap.param_file;

            SPDLOG_DEBUG("FSIZE {:08x} RCNT {:04x} RSIZE {:08x} NAME {}", 
                file_cap.param_file_size,
                param_file->row_count,
                param_file->row_size().value_or(0),
                name
            );
        }

        AddVectoredExceptionHandler(TRUE, &ParamFieldMapper::veh_thunk);
        return true;
    }

    LONG ParamFieldMapper::veh(EXCEPTION_POINTERS* ex) {

        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        
        auto status = ZydisDecoderDecodeFull(&decoder, ex->ExceptionRecord->ExceptionAddress, 16, &instruction, operands);
        if (!ZYAN_SUCCESS(status)) {
            Panic("Zydis failed to decompile instruction");
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }
}