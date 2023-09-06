#include "core/utils.h"
#include "param_field_mapper.h"
#include "arxan_disabler.h"

#include "paramdef_typemap.h"

#include "spdlog/common.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include <Windows.h>
#include <errhandlingapi.h>
#include <exception>
#include <handleapi.h>
#include <stdexcept>
#include <stdio.h>
#include <winnt.h>
#include <winternl.h>

#include <iostream>
#include <toml11/toml.hpp>

using namespace pfm;
using namespace spdlog;
using namespace std::chrono_literals;

typedef NTSTATUS (NTAPI *pNtGetNextThread)(
        HANDLE ProcessHandle,
        HANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Flags,
        PHANDLE NewThreadHandle
);

typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
        IN HANDLE ThreadHandle,
        IN DWORD ThreadInformationClass,
        OUT PVOID ThreadInformation,
        IN ULONG ThreadInformationLength,
        OUT PULONG ReturnLength OPTIONAL
);

#define ThreadQuerySetWin32StartAddress 9

BOOL hijack_suspended_main_thread(void* hook, uintptr_t (**original_entry_point)())
{
    HMODULE exe_base = GetModuleHandle(nullptr);
    auto* dos = (IMAGE_DOS_HEADER*)exe_base;
    auto* nt = (IMAGE_NT_HEADERS64*)((uintptr_t)exe_base + dos->e_lfanew);
    uintptr_t proc_entry_point = (uintptr_t)exe_base + nt->OptionalHeader.AddressOfEntryPoint;

    if (original_entry_point)
        *original_entry_point = (uintptr_t(*)())proc_entry_point;

    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto NtGetNextThread = (pNtGetNextThread)GetProcAddress(ntdll, "NtGetNextThread");
    auto NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");

    HANDLE hproc = GetCurrentProcess(), hthread = nullptr;
    while (NT_SUCCESS(NtGetNextThread(hproc, hthread, THREAD_ALL_ACCESS, 0, 0, &hthread))) {
        uintptr_t thread_entry_point = 0;
        if (NT_SUCCESS(NtQueryInformationThread(hthread, ThreadQuerySetWin32StartAddress, &thread_entry_point, sizeof(thread_entry_point), nullptr)) &&
            thread_entry_point == proc_entry_point) {

            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_FULL;

            if (!GetThreadContext(hthread, &ctx))
                return FALSE;

#ifdef _X86_
            uintptr_t ins_ptr = ctx.Eip;
#else
            uintptr_t ins_ptr = ctx.Rip;
#endif
            // Make sure the process was created suspended (thread still on RtlUserThreadStart)
            if (ins_ptr != (DWORD64)GetProcAddress(ntdll, "RtlUserThreadStart"))
                return FALSE;

#ifdef _X86_
            // __stdcall convention
            *(uintptr_t*)(ctx.Esp + 4) = (uintptr_t)hook;
#else
            ctx.Rcx = (uintptr_t)hook;
#endif
            return SetThreadContext(hthread, &ctx);
        }
    }
    return FALSE;
}

void create_console() {
    if (!GetConsoleWindow() && !AllocConsole()) {
        Panic("AllocConsole failed (error 0x{:x})", GetLastError());
    }

    // std::cout, std::clog, std::cerr, std::cin
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    std::cout.clear();
    std::clog.clear();
    std::cerr.clear();
    std::cin.clear();

    // std::wcout, std::wclog, std::wcerr, std::wcin
    HANDLE hConOut = CreateFile(TEXT("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hConIn = CreateFile(TEXT("CONIN$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
    SetStdHandle(STD_ERROR_HANDLE, hConOut);
    SetStdHandle(STD_INPUT_HANDLE, hConIn);
    std::wcout.clear();
    std::wclog.clear();
    std::wcerr.clear();
    std::wcin.clear();
}

void bootstrap(bool is_entry_hook) {
    create_console();
    
    std::locale::global(std::locale("en_us.UTF-8"));
    set_pattern("[%T.%e] %^[%l]%$ [%s] %v");
    set_level(level::level_enum::debug);

    if (!is_entry_hook) {
        SPDLOG_WARN("DLL was injected without launcher. Arxan has already run; code analysis coverage will not be as good!");
    }
    else {
        // Since we're entry hooking, Arxan hasn't set the game's memory to RWE yet. Do it now
        auto main_module = mem::module::main();
        DWORD old_protect;
        if (!VirtualProtect(main_module.start.as<void*>(), main_module.size, PAGE_EXECUTE_READWRITE, &old_protect)) {
            Panic("Failed to change memory protection of game code (error {:08X})", GetLastError());
        }
    }

    PFMConfig config;
    try {
        auto config_path = utils::dll_folder() / "config.toml";
        auto tbl = toml::parse(config_path);

        fs::path log_file_path = toml::find<std::string>(tbl, "log_file", "path");
        if (!log_file_path.empty() && !log_file_path.is_absolute()) {
            log_file_path = utils::dll_folder() / log_file_path;
        }
        if (!log_file_path.empty()) {
            auto file_log = create<sinks::basic_file_sink_mt>("file_log", log_file_path.string());
            file_log->set_level(level::from_str(toml::find<std::string>(tbl, "log_file", "log_level")));
            file_log->set_pattern("[%T.%e] %^[%l]%$ [%s] %v");
            file_log->flush_on(level::critical);
            flush_every(5s);
        }

        default_logger()->set_level(level::from_str(toml::find<std::string>(tbl, "console", "log_level")));
        config.print_original_addresses = toml::find<bool>(tbl, "console", "print_original_addresses");
        config.print_upheld_fields = toml::find<bool>(tbl, "console", "print_upheld_fields");

        config.dump_interval_ms = toml::find<uint32_t>(tbl, "dumps", "interval");
        config.dump_original_addresses = toml::find<bool>(tbl, "dumps", "dump_original_addresses");
        config.dump_simd_accesses = toml::find<bool>(tbl, "dumps", "dump_simd_accesses");

        auto& def_parse_opts = toml::find(tbl, "defs", "parsing");
        config.def_parse_options = {
            .unnamed_field_regex = toml::find<std::string>(def_parse_opts, "unnamed_field_regex"),
            .untyped_memory_regex = toml::find<std::string>(def_parse_opts, "untyped_memory_regex"),
            .ignore_comments = toml::find<bool>(def_parse_opts, "ignore_comments"),
            .ignore_param_types = toml::find<bool>(def_parse_opts, "ignore_param_types")
        };
        auto& def_dump_opts = toml::find(tbl, "defs", "serialization");
        config.def_serialize_options = {
            .store_accesses = toml::find<bool>(def_dump_opts, "store_accesses"),
            .store_type_confidence = toml::find<bool>(def_dump_opts, "store_type_confidence")
        };
    }
    catch (std::exception& e) {
        Panic("Encountered exception {} while parsing config file: {}", typeid(e).name(), e.what());
    }

    arxan_disabler::disable_code_restoration();
    ParamFieldMapper::get().init(config);
}

static uintptr_t(*ORIGINAL_ENTRY_POINT)();
uintptr_t __stdcall hooked_entry_point() {
    bootstrap(true);
    return ORIGINAL_ENTRY_POINT();
}

DWORD __stdcall thread_entry_point(LPVOID lParam) {
    bootstrap(false);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD call_reason, LPVOID reserved) {
    DisableThreadLibraryCalls(module);
    if (call_reason != DLL_PROCESS_ATTACH) { 
        return TRUE;
    }
    if (hijack_suspended_main_thread((void*)hooked_entry_point, &ORIGINAL_ENTRY_POINT)) {
        return TRUE;
    }
    else {
        auto handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_entry_point, module, 0, NULL);
        return handle != INVALID_HANDLE_VALUE;
    }
};