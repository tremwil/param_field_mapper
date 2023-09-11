#pragma once
#include "fst/res_cap.h"
#include "core/lite_mem_stream.h"

#include <result/result.hpp>

namespace pfm {

struct ParamFileRemapError {
    enum Enum {
        Success,
        NoRowSize,
        MemoryBlockExhausted,
        VirtualAllocReserveFail,
        VirtualAllocCommitFail,
        VirtualProtectFail,
        SortedTableOffsetOverflow
    };

    inline ParamFileRemapError() = default;
    inline ParamFileRemapError(const Enum& value) : value(value) {}
    inline operator Enum() { return value; } const
    inline bool operator==(const Enum& o) const { return value == o; }
    inline bool operator==(const ParamFileRemapError& o) const { return value == o.value; }

    std::string message() const;

private:
    Enum value;
};

struct RemapRepoError {
    std::optional<std::string> failed_param;
    ParamFileRemapError error;

    std::string message() const;
};

/// Remapping of the memory of a param file to support access monitoring and field type deduction.
struct RemappedParamFile {
    std::string param_name;
    size_t row_size = 0;

    ParamFileCap* file_cap = nullptr;

    ParamFile* trap_file = nullptr; // File with noaccess memory to catch instructions
    ParamFile* true_file = nullptr; // File that stores "real", live param data
    uint8_t* flags_file = nullptr; // Memory region where hooked instructions will log accesses

    // Address where innaccessible memory pages start in the trap file
    uint8_t* noaccess_mem_start = nullptr;

    // Address where FS's sorted ID table (the one pointed to by a relative offset before the param file) is stored
    // Here we place it after all 3 files
    uint8_t* sorted_table_start = nullptr;

    // Total amount of memory committed to accomodate this remap (for stats only)
    size_t committed_size = 0;

    /// Replaces the game's original param file with the trap file pointer, "priming" the remap.
    inline void replace_original_file() const {
        file_cap->param_file = trap_file;
    };

    inline size_t file_shift() const {
        return (uintptr_t)true_file - (uintptr_t)trap_file;
    }

    inline size_t flags_shift() const {
        return flags_file - (uint8_t*)trap_file;
    }

    /// Tries to remap a param file's memory, but doesn't swap the param file pointer just yet.
    static cpp::result<RemappedParamFile, ParamFileRemapError> 
    try_remap(ParamFileCap* file_cap, LiteMemStream& reserved_mem, size_t file_shift, size_t flags_shift);
};

struct RemappedParamBlock {
    std::vector<RemappedParamFile> remapped_files;
    LiteMemStream reserved_memory_block;

    size_t file_shift = 0;
    size_t flags_shift = 0;

    ResRepository<ParamFileCap>* param_repo = nullptr;

    /// Remaps all param files in the given param repository. 
    cpp::result<void, RemapRepoError> remap_repo(ResRepository<ParamFileCap>* param_repo);

    /// Fetches the total amount of memory committed for param remaps.
    size_t total_committed_mem() const;

    /// Frees allocated remap memory and clears the list of remapped files.
    /// Returns false if VirtualFree fails.
    bool clear_remaps();

    ~RemappedParamBlock();
};

} // namespace pfm