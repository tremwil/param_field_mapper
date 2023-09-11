#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

#define Panic(FMT, ...) \
	pfm::panic(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, fmt::format(FMT, __VA_ARGS__))

#define PFM_PANIC_MSG "The following unrecoverable error was encountered:\n\n [{}:{}] {}\n\nThe game process will be terminated."

namespace pfm
{
	[[noreturn]] inline void panic(spdlog::source_loc loc, const std::string& msg) {
		std::string msg_full = fmt::format(PFM_PANIC_MSG, loc.filename, loc.line, msg);
		spdlog::log(loc, spdlog::level::critical, msg);
		spdlog::shutdown(); // So that file loggers flush

		MessageBeep(MB_ICONERROR);
		MessageBoxA(NULL, msg_full.c_str(), "Critical Error", MB_ICONERROR | MB_OK);
		__debugbreak();
		ExitProcess(0);
	}
}