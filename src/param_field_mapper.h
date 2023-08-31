#pragma once

#include <set>
#include <map>
#include <unordered_map>

#include "core/singleton.h"
#include "fst/fd4_param_repository.h"
#include "hooks/hook_arena.h"
#include "hooks/control_flow_graph.h"

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
        bool init();

    protected: 
        ParamFieldMapper() = default;

    private:
        std::mutex mutex;
        bool is_init = false;

        std::unordered_set<intptr_t> patches;
        HookArenaPool hook_arena_pool;
        LiteMemStream remap_arena;
        size_t committed_remap_mem = 0;
        
        // Required shift between trap and true param files
        size_t shift = 0;

        std::vector<intptr_t> jmp_targets_heuristic;
        CFG flow_graph;
        
        // Remapped param files, indexed by their end pointer,
        // so we can use map::upper_bound
        std::map<intptr_t, RemappedParamFile> remaps;

        void remap_param_file(ParamFileCap& file_cap);
        LONG veh(EXCEPTION_POINTERS* ex);

        static LONG veh_thunk(EXCEPTION_POINTERS* ex) {
            return ParamFieldMapper::get().veh(ex);
        }
    };
}