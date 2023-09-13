#include "param_field_mapper.h"
#include "hde/hde64.h"
#include "hooks/instr_utils.h"
#include "arxan_disabler.h"

#include "mem/pattern.h"
#include "param_access_flags.hpp"
#include "spdlog/fmt/bin_to_hex.h"
#include "spdlog/spdlog.h"
#include "xml_paramdef.hpp"

#include <Windows.h>

#include <excpt.h>
#include <winnt.h>
#include <winternl.h>

// For debugging purposes
void suspend_threads()
{
    typedef NTSTATUS(*NtGetNextThread_t)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
        ULONG Flags, PHANDLE NewThreadHandle);

    auto NtGetNextThread = (NtGetNextThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtGetNextThread");

    HANDLE hThread = NULL;
    while (true) {
        NTSTATUS err = NtGetNextThread(GetCurrentProcess(), hThread, THREAD_ALL_ACCESS, 0, 0, &hThread);
        if (err >= 0x40000000u) break;
        if (GetThreadId(hThread) != GetCurrentThreadId())
            SuspendThread(hThread);
    }
}

namespace pfm
{
    void ParamFieldMapper::init(const PFMConfig& config) {
        std::lock_guard lock(mutex);
        if (initialized) return;

        this->config = config;

        load_existing_defs();

        patcher.prepare_module((intptr_t)GetModuleHandleA(nullptr));
        hook_solo_param_lookup();

        SPDLOG_INFO("Waiting for params to be loaded...");
        initialized = true;
    }

    void ParamFieldMapper::do_param_remaps() {
        std::lock_guard lock(mutex);
        std::lock_guard lock_defs(defs_mutex);

        if (remaps_done) return;

        auto& param_repo = FD4ParamRepository::instance()->param_container;
        auto res = remaps.remap_repo(&param_repo);
        if (!res) {
            SPDLOG_CRITICAL(res.error().message());
        }

        SPDLOG_INFO("Done, remapped {} params. file = +{:x}, flags = +{:x}", 
            remaps.remapped_files.size(), remaps.file_shift, remaps.flags_shift);

        SPDLOG_INFO("Remap block size: {:L} bytes, Committed: {:L} bytes",
            remaps.reserved_memory_block.buffer().size(), remaps.total_committed_mem());

        AddVectoredExceptionHandler(TRUE, &ParamFieldMapper::veh_thunk);
        hook_memcpy();

        for (const auto& f: remaps.remapped_files) {
            auto [it, inserted] = serialized_defs.insert(std::make_pair(f.param_name, Paramdef {
                .param_name = f.param_name
            }));
            auto& def = it->second;
            if (!inserted && def.row_size != f.row_size) {
                Panic("Row size of existing def for {} ({}) does not match computed value ({})",
                    f.param_name, def.row_size, f.row_size);
            }

            def.data_version = f.true_file->paramdef_data_version;
            def.big_endian = f.true_file->is_big_endian;
            def.unicode = f.true_file->is_unicode();
            def.row_size = f.row_size;

            // std::string_view param_type { f.true_file->param_type() };
            // if (!def.param_type.has_value() && !param_type.empty() &&
            //     !std::any_of(param_type.begin(), param_type.end(), [](auto c) { return c < '!' || c > 'z'; })) 
            // {
            //     def.param_type = param_type;
            // }

            deduced_defs[f.param_name] = { .remapped_file = &f };
            f.replace_original_file();
        }

        def_dump_timer.interval() = config.dump_interval_ms;
        def_dump_timer.start([this] { dump_defs(); });

        def_deduce_timer.interval() = config.deduce_interval_ms;
        def_deduce_timer.start([this] {
            std::lock_guard lock(defs_mutex);
            for (auto& [k, d]: deduced_defs) {
                d.update_deductions(true);
            }
        });

        remaps_done = true;
    }

    void ParamFieldMapper::load_existing_defs() {
        std::lock_guard lock(defs_mutex);
        SPDLOG_INFO("Loading existing paramdefs...");

        auto dump_path = utils::dll_folder() / "paramdefs";
        fs::create_directory(dump_path);

        size_t num_loaded = 0;
        for (const auto& f : fs::directory_iterator(dump_path)) {
            if (!f.is_regular_file() || f.path().extension() != ".xml") {
                SPDLOG_WARN("{} is not an XML paramdef, skipping", f.path().string());
                continue;
            }
            if (auto def = Paramdef::from_xml(f.path().string(), config.def_parse_options)) {
                serialized_defs[def->param_name] = std::move(*def);
                num_loaded++;
                SPDLOG_TRACE("Loaded paramdef {}", f.path().string());
            }
        }
        SPDLOG_INFO("Loaded {} existing XML paramdefs", num_loaded);
    }

    void ParamFieldMapper::dump_defs() {
        std::lock_guard lock(defs_mutex);

        auto dump_path = utils::dll_folder() / "paramdefs";
        fs::create_directory(dump_path);

        for (auto& [k, d]: deduced_defs) {
            if (!serialized_defs.contains(k)) continue;

            auto& sd = serialized_defs[k];
            sd.fields.clear();
            for (const auto& f : d.fields) {
                DefField df { .type_size_bytes = f.size_bytes };
                
                if (f.maybe_array) df.info = DefField::Array(1);
                
                if (f.type == FieldBaseType::UnkInt) df.type = DefField::ValueType::UnkInt;
                else if (f.type == FieldBaseType::Signed) df.type = DefField::ValueType::Sint;
                else if (f.type == FieldBaseType::Unsigned) df.type = DefField::ValueType::Uint;
                else if (f.type == FieldBaseType::Float) df.type = DefField::ValueType::Float;

                sd.fields[f.offset * 8] = std::move(df);
            }

            sd.serialize_to_xml((dump_path / (k + ".xml")).string(), config.def_serialize_options);
        }
        SPDLOG_INFO("Dumped {} paramdefs to disk", deduced_defs.size());
    }

    void ParamFieldMapper::hook_solo_param_lookup() {
        mem::pattern lookup_aob { "81 fa 07 01 00 00 7d ?? 48 63 d2 48 8d 04 d2" };
        
        auto lookup_addr = mem::scan(lookup_aob, utils::main_module_section<".text">()).as<intptr_t>();
        if (!lookup_addr) {
            Panic("Failed to find SoloParamRepository::getParamResCapById function");
        }

        orig_param_lookup.store(patcher.jmp_hook(lookup_addr, &solo_param_hook_thunk), std::memory_order_release);
        orig_param_lookup.notify_all();

        if (!orig_param_lookup) {
            Panic("Failed to JMP hook SoloParamRepository::getParamResCapById function at {:x}", lookup_addr);
        }

        SPDLOG_INFO("Hooked SoloParamRepository lookup at {:x}", lookup_addr);
    }

    void* ParamFieldMapper::solo_param_hook(SoloParamRepository* solo_param, uint32_t bucket, uint32_t index_in_bucket) {
        if (!remaps_queued) {
            auto params = FD4ParamRepository::instance()->param_container;

            // TODO: Incremental remapping or cross-checking with regulation on disk
            // instead of hardcoding param count
            size_t num_params = std::distance(params.begin(), params.end());
            if (num_params >= 271) {
                remaps_queued = true;
                std::thread([this]{
                    Sleep(500);
                    do_param_remaps();   
                }).detach();
            }
        }
        orig_param_lookup.wait(nullptr, std::memory_order_acquire);
        return orig_param_lookup.load(std::memory_order_relaxed)(solo_param, bucket, index_in_bucket);
    }

    void ParamFieldMapper::hook_memcpy() {
        mem::pattern memcpy_aob { "4c 8b d9 4c 8b d2 49 83 f8 10 0f 86 ?? ?? ?? ?? 49 83 f8 20" };

        auto memcpy_addr = mem::scan(memcpy_aob, utils::main_module_section<".text">()).as<intptr_t>();
        if (!memcpy_addr) {
            Panic("Failed to find memcpy function");
        }

        orig_memcpy.store(patcher.jmp_hook(memcpy_addr, &memcpy_hook_thunk), std::memory_order_release);
        orig_memcpy.notify_all();

        if (!orig_memcpy) {
            Panic("Failed to JMP hook game memcpy function at {:x}", memcpy_addr);
        }

        SPDLOG_INFO("Hooked memcpy at {:x}", memcpy_addr);
    }

    void ParamFieldMapper::gen_access_hook(LiteMemStream& arena, uint8_t* original, ParamAccessFlags flags) {
        using namespace std::literals;

        hde64s disasm_orig;
        hde64_disasm(original, &disasm_orig);
        
        if (disasm_orig.flags & F_ERROR) {
            Panic("Failed to dissassemble: {:n}", spdlog::to_hex(original, original + disasm_orig.len));
        }
        if (!(disasm_orig.flags & F_MODRM)) {
            Panic("Attempted to generate access hook for non MODRM instruction: {:n}", 
                spdlog::to_hex(original, original + disasm_orig.len));
        }

        uint8_t patched[15];
        auto patched_code_size = instr_utils::gen_new_disp(
            patched, original, instr_utils::get_disp(original) + remaps.file_shift);

        if (patched_code_size == 0) {
            Panic("Failed to patch displacement of instruction: {:n}", 
                spdlog::to_hex(original, original + disasm_orig.len));
        }

        const size_t LOCK_OR_LEN = flags ? 8 : 0;

        // pushf
        // mov qword ptr [rsp - 8], rax
        // mov qword ptr [rsp - 16], rbx
        constexpr auto save_registers = "\x9C\x48\x89\x44\x24\xF8\x48\x89\x5C\x24\xF0"sv;

        // mov rax, qword ptr [rsp - 8]
        // mov rbx, qword ptr [rsp - 16]
        // popf
        constexpr auto restore_registers = "\x48\x8B\x44\x24\xF8\x48\x8B\x5C\x24\xF0\x9D"sv;

        // {save registers}
        arena.write(save_registers);

        // lea rax, [modrm]
        if (!instr_utils::gen_lea(&arena, &disasm_orig)) {
            Panic("Failed to generate LEA for instruction: {:n}", 
                spdlog::to_hex(original, original + disasm_orig.len));    
        }

        // movabs rbx, region_begin
        arena.write<uint16_t>(0xBB48);
        arena.write(remaps.reserved_memory_block.buffer().data());
        // cmp rax, rbx
        arena.write("\x48\x39\xD8"sv);

        // jl normal_behavior
        arena.write<uint8_t>(0x7C);
        arena.write<uint8_t>(17 + restore_registers.size() + patched_code_size + LOCK_OR_LEN);

        // movabs rbx, end
        arena.write<uint16_t>(0xBB48);
        arena.write(remaps.reserved_memory_block.buffer().data() + remaps.reserved_memory_block.buffer().size());
        // cmp rax, rbx
        arena.write("\x48\x39\xD8"sv);

        // jae normal_behavior
        arena.write<uint8_t>(0x73);
        arena.write<uint8_t>(2 + restore_registers.size() + patched_code_size + LOCK_OR_LEN);

        if (flags) {
            // lock or byte ptr [rax + flags_shift], FLAGS
            arena.write("\xf0\x80\x88"sv);
            arena.write<int32_t>(remaps.flags_shift);
            arena.write(flags);
        }

        // {restore registers}
        arena.write(restore_registers);
        // {patched_instruction}
        arena.write(std::span { patched, patched_code_size });

        // jmp end
        arena.write<uint8_t>(0xEB);
        arena.write<uint8_t>(restore_registers.size() + disasm_orig.len);

        /* normal_behavior: */

        // {restore registers}
        arena.write(restore_registers);
        // {orig_instruction}
        arena.write(std::span { original, disasm_orig.len });

        // end:
    }

    LONG ParamFieldMapper::veh(EXCEPTION_POINTERS* eptrs) {
        std::lock_guard lock(mutex);

        auto ecode = eptrs->ExceptionRecord->ExceptionCode;
        auto ctx = eptrs->ContextRecord;
        auto code_address = (intptr_t)eptrs->ExceptionRecord->ExceptionAddress;
        auto accessed_addr = (intptr_t)eptrs->ExceptionRecord->ExceptionInformation[1];

        if (ecode == EXCEPTION_ILLEGAL_INSTRUCTION) {
            suspend_threads();
            Panic("Attempted to execute illegal instruction at {:x}. Possible relocation edge case?", code_address);
        }
        else if (ecode != EXCEPTION_ACCESS_VIOLATION)
            return EXCEPTION_CONTINUE_SEARCH;

        mem::region param_mem {
            remaps.reserved_memory_block.buffer().data(), 
            remaps.reserved_memory_block.buffer().size()
        };
        // Check if patch is in range
        if (!param_mem.contains(accessed_addr)) {
            SPDLOG_CRITICAL("Access violation outside of param memory at {:x}", code_address);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // In hot multithreaded code, a second thread might hit the instruction before patches are observed.
        // To avoid patching twice, we keep track of existing patches
        auto rip_fix = patch_map.find(code_address);
        if (rip_fix != patch_map.end()) {
            SPDLOG_DEBUG("Thread {:x} was waiting at previously patched code location {:x}, redirecting to {:x}",
                GetCurrentThreadId(), code_address, rip_fix->second);
            ctx->Rip = rip_fix->second;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        auto prepare_result = patcher.light_prepare_if_required(code_address);
        if (prepare_result != ExtendFlowGraphResult::Success) {
            Panic("Critical error during CFG extension");
        }

        // Copy the instruction to avoid relocations
        uint8_t original_code[15];
        std::memcpy(original_code, (uint8_t*)code_address, 15);

        auto rflags = ParamAccessFlags::from_instruction((uint8_t*)code_address);
        if (rflags == cpp::fail(ParamAccessFlags::Error::IsSimd)) {
            SPDLOG_WARN("{:x} is a SIMD load, ignoring...", code_address);
        }
        else if (!rflags) {
            Panic("Failed to compute access flags for instruction at {:x}", code_address);
        }
        auto flags = rflags.value_or(ParamAccessFlags{});

        auto hook_addr = patcher.instruction_hook(
            code_address, [&](auto& a, const auto& _) { gen_access_hook(a, original_code, flags); }, true);

        if (!hook_addr) {
            Panic("Failed to generate instruction hook at {:x}", code_address);
        }
        
        ctx->Rip = hook_addr;
        patch_map[code_address] = hook_addr;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
}