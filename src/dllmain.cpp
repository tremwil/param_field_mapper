#include "core/utils.h"
#include "param_field_mapper.h"
#include "arxan_disabler.h"

#include "spdlog/common.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include <Windows.h>
#include <errhandlingapi.h>
#include <exception>
#include <handleapi.h>
#include <processenv.h>
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

// Export a function other DLLs can use to read param data safely 
extern "C" __declspec(dllexport) void* adjust_param_ptr(void* param_data_ptr) {
    return pfm::ParamFieldMapper::get().adjust_param_ptr(param_data_ptr);
}

void bootstrap(bool is_entry_hook) {
    create_console();
    
    std::locale::global(std::locale("en_us.UTF-8"));
    set_pattern("[%T.%e] %^[%l]%$ [%s] %v");
    set_level(level::trace);

    PFMConfig config;
    try {
        auto config_path = utils::dll_folder() / "config.toml";
        auto tbl = toml::parse(config_path);

        default_logger()->sinks().front()->set_level(level::from_str(toml::find<std::string>(tbl, "console", "log_level")));
        config.print_original_addresses = toml::find<bool>(tbl, "console", "print_original_addresses");
        config.print_upheld_fields = toml::find<bool>(tbl, "console", "print_upheld_fields");

        fs::path log_file_path = toml::find<std::string>(tbl, "log_file", "path");
        if (!log_file_path.empty() && !log_file_path.is_absolute()) {
            log_file_path = utils::dll_folder() / log_file_path;
        }
        if (!log_file_path.empty()) {
            auto file_sink = std::make_shared<sinks::basic_file_sink_mt>(log_file_path.string());
            file_sink->set_level(level::from_str(toml::find<std::string>(tbl, "log_file", "log_level")));
            default_logger()->sinks().push_back(file_sink);
        }

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
            .conflict_comments = toml::find<bool>(def_dump_opts, "conflict_comments"),
            .unk_int_prefix = toml::find<std::string>(def_dump_opts, "unk_int_prefix")
        };
    }
    catch (std::exception& e) {
        Panic("Encountered exception {} while parsing config file: {}", typeid(e).name(), e.what());
    }

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

    flush_on(level::critical);
    flush_every(5s);

    arxan_disabler::disable_code_restoration();
    ParamFieldMapper::get().init(config);

    /// Allow fetching the function from an env var, since the DLL name might be changed
    SetEnvironmentVariableA("PFM_ADJUST_PARAM_PTR_ADDRESS", 
        fmt::format("{:x}", (uintptr_t)&adjust_param_ptr).c_str());
}

/* Bootstrapping methods */

// Main thread hijacking
static uintptr_t(*ORIGINAL_ENTRY_POINT)();
uintptr_t __stdcall hooked_entry_point() {
    bootstrap(true);
    return ORIGINAL_ENTRY_POINT();
}

// CreateThread
DWORD __stdcall thread_entry_point(LPVOID lParam) {
    bootstrap(false);
    return 0;
}

// ME2 extension
class ModEngineExt {
    virtual void on_attach() {
        SPDLOG_INFO("ME2 attach");
    };
    virtual void on_detach() {
        SPDLOG_INFO("ME2 detach");
    };
    virtual const char* id() {
        return "param_field_mapper";
    };
};

static ModEngineExt ME2_EXTENSION;
extern "C" __declspec(dllexport) bool modengine_ext_init(void* connector, ModEngineExt** extension) {
    *extension = &ME2_EXTENSION;
    bootstrap(true);
    return true;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD call_reason, LPVOID reserved) {
    DisableThreadLibraryCalls(module);
    wchar_t buff[256];

    if (call_reason != DLL_PROCESS_ATTACH) { 
        return TRUE;
    }
    if (hijack_suspended_main_thread((void*)hooked_entry_point, &ORIGINAL_ENTRY_POINT)) {
        return TRUE;
    }
    // If the game was launched with ME2, wait for it to call modengine_ext_init instead of 
    // falling back to CreateThread bootstrapping
    else if (!GetEnvironmentVariableW(L"MODENGINE_CONFIG", buff, sizeof(buff))) {
        auto handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_entry_point, module, 0, NULL);
        return handle != INVALID_HANDLE_VALUE;
    }
    return TRUE;
};