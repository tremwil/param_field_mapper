#include "param_field_mapper.h"
#include "spdlog/common.h"
#include "spdlog/sinks/wincolor_sink.h"
#include "spdlog/spdlog.h"
#include <Windows.h>
#include <stdio.h>
#include <iostream>

using namespace pfm;
using namespace spdlog;

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

DWORD main_thread(HMODULE module) {
	create_console();	

	std::unordered_map<int, char> cont{{1, 'a'}, {2, 'b'}, {3, 'c'}};
    // Extract node handle and change key
    auto nh = cont.extract(1);
    nh.key() = 4;
	
  	std::locale::global(std::locale("en_us.UTF-8"));
	set_pattern("[%T.%e] %^[%l]%$ [%s] %v");
	set_level(level::level_enum::trace);
	flush_on(level::level_enum::err);

	auto console_sink = spdlog::create<spdlog::sinks::wincolor_stdout_sink_mt>("default");
	set_default_logger(console_sink);

	ParamFieldMapper::get().init();
	return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD call_reason, LPVOID reserved) {
	DisableThreadLibraryCalls(module);
	if (call_reason == DLL_PROCESS_ATTACH) {
		auto handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)main_thread, module, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE)
			printf("Failed to create DLL thread (error = %lu)\n", GetLastError());
	};
	return TRUE;
};