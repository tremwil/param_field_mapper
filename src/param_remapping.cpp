#include "param_remapping.hpp"
#include "fst/param_file.h"
#include "core/utils.h"

#include <Windows.h>
#include <numeric>

namespace pfm {

std::string ParamFileRemapError::message() const {
    switch (value) {
        case Enum::MemoryBlockExhausted: return "Ran out of reserved memory";
        case Enum::SortedTableOffsetOverflow: return "Sorted table offset would overflow";
        case Enum::VirtualAllocCommitFail: return fmt::format("VirtualAlloc failed to commit memory (error {:08x})", GetLastError());
        case Enum::VirtualAllocReserveFail: return fmt::format("VirtualAlloc failed to reserve memory (error {:08x})", GetLastError());
        case Enum::VirtualProtectFail: return fmt::format("VirtualProtect failed (error {:08x})", GetLastError());
        case Enum::NoRowSize: return "Param row size could not be computed";
        default: return "Unknown remap error";
    }
}

std::string RemapRepoError::message() const {
    if (error == ParamFileRemapError::VirtualAllocReserveFail) {
        return error.message();
    }
    else return fmt::format("{} while remapping param {}", error.message(), failed_param.value_or("Unknown"));
}

cpp::result<RemappedParamFile, ParamFileRemapError> RemappedParamFile::try_remap(
    ParamFileCap *file_cap, LiteMemStream &reserved_mem, size_t file_shift, size_t flags_shift)
{
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    auto file = file_cap->param_file;
    std::span file_bytes { (uint8_t*)file, file_cap->param_file_size };

    // Someone at fromsoft should never be allowed to write code again
    // For some reason instead of binary searching over the ID/name offset/row offset table,
    // they create a (id, ParamRow) pair array, store it 16 bytes *BEFORE* the param file,
    // and binary search on that instead!?!?!?!?!?!?!?
    //
    // We'll have to copy it over too
    std::span sorted_table { 
        (uint8_t*)file + utils::align_up(*(int32_t*)((intptr_t)file - 16), 16), 8ull * file->row_count
    };

    RemappedParamFile remap {
        .param_name = utils::wide_string_to_string(file_cap->resource_name),
        .file_cap = file_cap
    };

    if (auto rz = file->row_size()) {
        remap.row_size = *rz;
    }
    else {
        return cpp::fail(ParamFileRemapError::NoRowSize);
    }

    // Setup page alignment and trap file start pointer

    size_t id_table_end_ofs = file->id_table_end_offset();
    reserved_mem.advance(id_table_end_ofs + 16);
    reserved_mem.align(sysinfo.dwPageSize);

    remap.noaccess_mem_start = reserved_mem.ptr();
    reserved_mem.advance(-id_table_end_ofs);

    remap.trap_file = (ParamFile*)reserved_mem.ptr();

    // Commit memory and write param data to memory

    if (reserved_mem.is_eof()) return cpp::fail(ParamFileRemapError::MemoryBlockExhausted);
    if (!VirtualAlloc(reserved_mem.ptr() - 16, 16 + file_bytes.size(), MEM_COMMIT, PAGE_READWRITE)) {
        return cpp::fail(ParamFileRemapError::VirtualAllocCommitFail);
    }
    remap.committed_size += 16 + file_bytes.size();
    reserved_mem.write(file_bytes);

    reserved_mem.seek_ptr((uint8_t*)remap.trap_file + file_shift);
    remap.true_file = (ParamFile*)reserved_mem.ptr();

    if (reserved_mem.is_eof()) return cpp::fail(ParamFileRemapError::MemoryBlockExhausted);
    if (!VirtualAlloc(reserved_mem.ptr(), file_bytes.size(), MEM_COMMIT, PAGE_READWRITE)) {
        return cpp::fail(ParamFileRemapError::VirtualAllocCommitFail);
    }
    remap.committed_size += file_bytes.size();
    reserved_mem.write(file_bytes);

    reserved_mem.seek_ptr((uint8_t*)remap.trap_file + flags_shift);
    remap.flags_file = reserved_mem.ptr();

    if (reserved_mem.is_eof()) return cpp::fail(ParamFileRemapError::MemoryBlockExhausted);
    if (!VirtualAlloc(remap.flags_file, file_bytes.size(), MEM_COMMIT, PAGE_READWRITE)) {
        return cpp::fail(ParamFileRemapError::VirtualAllocCommitFail);
    }
    remap.committed_size += file_bytes.size();
    // No need to write anything for flags file, MEM_COMMIT will init to zero when page is faulted in
    reserved_mem.advance(file_bytes.size());

    // Compute sorted table offset and write sorted table pointers
    
    size_t sorted_table_ofs = utils::align_up(reserved_mem.ptr() - (uint8_t*)remap.trap_file, 16);
    if (sorted_table_ofs > INT_MAX) {
        return cpp::fail(ParamFileRemapError::SortedTableOffsetOverflow);
    }

    *(int32_t*)((intptr_t)remap.trap_file - 16) = sorted_table_ofs;
    *(int32_t*)((intptr_t)remap.trap_file - 12) = file->row_count;

    // Copy sorted table 

    remap.sorted_table_start = (uint8_t*)remap.trap_file + sorted_table_ofs;
    reserved_mem.seek_ptr(remap.sorted_table_start);

    if (reserved_mem.is_eof()) return cpp::fail(ParamFileRemapError::MemoryBlockExhausted);
    if (!VirtualAlloc(reserved_mem.ptr(), sorted_table.size(), MEM_COMMIT, PAGE_READWRITE)) {
        return cpp::fail(ParamFileRemapError::VirtualAllocCommitFail);
    }
    remap.committed_size += sorted_table.size();
    reserved_mem.write(sorted_table);

    if (reserved_mem.is_eof()) {
        return cpp::fail(ParamFileRemapError::MemoryBlockExhausted);
    }

    // Set protection of noaccess "trap" memory pages, apply and store remap

    DWORD old_protect;
    size_t noaccess_mem_size = file_cap->param_file_size - id_table_end_ofs;
    if (!VirtualProtect(remap.noaccess_mem_start, noaccess_mem_size, PAGE_NOACCESS, &old_protect)) {
        return cpp::fail(ParamFileRemapError::VirtualProtectFail);
    }

    return remap;
};

cpp::result<void, RemapRepoError> RemappedParamBlock::remap_repo(ResRepository<ParamFileCap>* param_repo) {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    clear_remaps(); // Clear old remaps first, if any
    this->param_repo = param_repo;

    size_t max_param_size = 0, no_shift_req_mem = 0, num_params = 0;
    for (const auto& file_cap: *param_repo) {
        num_params++;
        max_param_size = std::max(max_param_size, file_cap.param_file_size);
        no_shift_req_mem +=
            sysinfo.dwPageSize + // Alignment requirements to put the row data start on a page boundary
            16 + // to accomodate fromsoft shitcode writing sorted id table offsets before param file 
            file_cap.param_file_size + // "true" file copy we redirect instructions to
            16 + // alignment requirements of offset to sorted id table
            8 * file_cap.param_file->row_count; // sorted id table memory
    }

    file_shift = utils::align_up(max_param_size + sysinfo.dwPageSize, 16); // 16-byte align just to be sure
    flags_shift = utils::align_up(file_shift + max_param_size, 16);

    size_t required_block_size = no_shift_req_mem + flags_shift * num_params;
    auto alloc_base = (uint8_t*)VirtualAlloc(NULL, required_block_size, MEM_RESERVE, PAGE_READWRITE);
    if (!alloc_base) {
        return cpp::fail(RemapRepoError { .error = ParamFileRemapError::VirtualAllocReserveFail });
    }
    reserved_memory_block = { alloc_base, required_block_size };

    for (auto& file_cap: *param_repo) {
        auto remap_result = RemappedParamFile::try_remap(&file_cap, reserved_memory_block, file_shift, flags_shift);
        if (remap_result.has_error()) {
            return cpp::fail(RemapRepoError { 
                .failed_param = utils::wide_string_to_string(file_cap.resource_name),
                .error = remap_result.error() 
            });
        }
        remapped_files.push_back(*remap_result);
    }
    return {};
}

size_t RemappedParamBlock::total_committed_mem() const {
    size_t total = 0;
    for (const auto& f : remapped_files) {
        total += f.committed_size;
    }
    return total;
}

bool RemappedParamBlock::clear_remaps() {
    if (!reserved_memory_block.ptr()) return true;

    if (!VirtualFree(reserved_memory_block.ptr(), 0, MEM_RELEASE))
        return false;

    file_shift = 0;
    flags_shift = 0;
    param_repo = nullptr;
    remapped_files.clear();
    reserved_memory_block = {};
    
    return true;
}

RemappedParamBlock::~RemappedParamBlock() {
    clear_remaps();
}

} // namespace pfm