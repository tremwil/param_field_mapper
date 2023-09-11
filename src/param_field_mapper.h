#pragma once

#include <set>
#include <map>
#include <string_view>
#include <unordered_map>

#include "core/lite_mem_stream.h"
#include "core/singleton.h"
#include "core/timer.h"

#include "fst/fd4_param_repository.h"
#include "hooks/hook_arena.h"
#include "hooks/control_flow_graph.h"
#include "hooks/mass_instruction_patcher.hpp"
#include "paramdef_typemap.h"

#include "field_deduction.hpp"

namespace pfm
{
    struct PFMConfig {
        int dump_interval_ms = 10000;
        bool print_original_addresses = false;
        bool print_upheld_fields = true;
        bool dump_original_addresses = true;
        bool load_existing_defs = true;
        bool dump_simd_accesses = true;
        ParamdefParsingOptions def_parse_options {};
        ParamdefSerializeOptions def_serialize_options {};
    };

    class ParamFieldMapper : public Singleton<ParamFieldMapper> 
    {
    public:
        void init(const PFMConfig& config = {});

        void* adjust_param_ptr(void* param_data_ptr) {
            if (!remaps_done) return param_data_ptr;
            
            const uint8_t* remap_begin = remaps.reserved_memory_block.buffer().data();
            const uint8_t* remap_end = remap_begin + remaps.reserved_memory_block.buffer().size();
            uint8_t* data_ptr = (uint8_t*)param_data_ptr;
            return (remap_begin <= data_ptr && data_ptr < remap_end) ? data_ptr + remaps.file_shift : data_ptr;
        }

    protected: 
        ParamFieldMapper() = default;

    private:
        std::mutex mutex;
        bool initialized = false;
        bool remaps_done = false;
        bool remaps_queued = false;

        PFMConfig config;

        std::unordered_map<intptr_t, intptr_t> patch_map;
        
        RemappedParamBlock remaps;
        MassInstructionPatcher patcher;

        std::unordered_map<std::string, DeducedParamdef> defs;

        Timer def_dump_timer;

        void* (*orig_memcpy)(void*, void*, size_t); 
        void* (*orig_param_lookup)(SoloParamRepository*, uint32_t, uint32_t);

        void do_param_remaps();

        void load_existing_defs();

        void dump_defs();

        void hook_solo_param_lookup();

        void* solo_param_hook(SoloParamRepository* solo_param, uint32_t bucket, uint32_t index_in_bucket);

        void hook_memcpy();

        void gen_access_hook(LiteMemStream& arena, uint8_t* code, ParamAccessFlags flags);

        LONG veh(EXCEPTION_POINTERS* ex);

        void* memcpy_hook(void* dest, void* src, size_t size) {
            return orig_memcpy(dest, adjust_param_ptr(src), size);
        }

        static LONG veh_thunk(EXCEPTION_POINTERS* ex) {
            return ParamFieldMapper::get().veh(ex);
        }

        static void* memcpy_hook_thunk(void* dest, void* src, size_t size) {
            return get().memcpy_hook(dest, src, size);
        }

        static void* solo_param_hook_thunk(SoloParamRepository* solo_param, uint32_t bucket, uint32_t index_in_bucket) {
            return get().solo_param_hook(solo_param, bucket, index_in_bucket);
        }
    };
}