#pragma once

#include <set>
#include <map>
#include <string_view>
#include <unordered_map>

#include "core/singleton.h"
#include "core/timer.h"

#include "fst/fd4_param_repository.h"
#include "hooks/hook_arena.h"
#include "hooks/control_flow_graph.h"
#include "paramdef_typemap.h"

namespace pfm
{
    struct RemappedParamFile 
    {
        ParamFileCap* file_cap;

        ParamFile* trap_file;
        ParamFile* true_file;

        uint8_t* noaccess_mem_start;
        uint8_t* sorted_table_start;

        size_t row_size;

        // Map out param row end pointers, to avoid the assumption that
        // row data is ordered or even contiguous in memory 
        // (though it appears to always be the case)
        std::vector<intptr_t> row_ends;
        std::string param_name;

        std::optional<size_t> field_offset(intptr_t field_ptr) const {
            auto it = std::upper_bound(row_ends.begin(), row_ends.end(), field_ptr);
            return (it != row_ends.end() && field_ptr + row_size >= *it) ?
                std::optional(field_ptr + row_size - *it) : std::nullopt;
        };
    };

    class ParamFieldMapper : public Singleton<ParamFieldMapper> 
    {
    public:
        void do_code_analysis();
        void do_param_remaps();

    protected: 
        ParamFieldMapper() = default;

    private:
        std::mutex mutex;
        bool code_analysis_done = false;
        bool remaps_done = false;

        std::unordered_set<intptr_t> patches;
        std::unordered_map<intptr_t, intptr_t> patch_map;

        HookArenaPool hook_arena_pool;
        LiteMemStream remap_arena;
        
        size_t committed_remap_mem = 0;
        
        // Required shift between trap and true param files
        size_t shift = 0;

        std::vector<intptr_t> jmp_targets_heuristic;
        CFG flow_graph;
        
        // Remapped param files, indexed by their end pointer,
        // so we can use map::upper_bound to search
        std::map<intptr_t, RemappedParamFile> remaps;
        std::unordered_map<std::string, ParamdefTypemap> defs;
        std::mutex def_copy_mutex;

        Timer def_dump_timer;

        uint8_t* (*orig_memcpy)(uint8_t*, uint8_t*, size_t); 

        void dump_defs();

        void hook_memcpy();

        void alloc_param_remap_mem(FD4ParamRepository* param_repo);

        void remap_param_file(ParamFileCap& file_cap);

        void extend_flow_graph_if_required(intptr_t code_address, size_t code_len, CONTEXT* thread_ctx);

        void update_field_maps(intptr_t code_addr, intptr_t access_addr, CONTEXT* thread_ctx);

        LONG veh(EXCEPTION_POINTERS* ex);

        static LONG veh_thunk(EXCEPTION_POINTERS* ex) {
            return ParamFieldMapper::get().veh(ex);
        }

        uint8_t* memcpy_hook(uint8_t* dest, uint8_t* src, size_t size) {
            const uint8_t* remap_begin = remap_arena.buffer().data();
            const uint8_t* remap_end = remap_begin + remap_arena.buffer().size();
            if (remap_begin <= src && src < remap_end) {
                return orig_memcpy(dest, src + shift, size);
            }
            else return orig_memcpy(dest, src, size);
        }

        static uint8_t* memcpy_hook_thunk(uint8_t* dest, uint8_t* src, size_t size) {
            return get().memcpy_hook(dest, src, size);
        }
    };
}