#include "utils.h"
#include <iostream>

namespace pfm::utils
{
	fs::path dll_folder()
	{
		struct S
		{
			fs::path path;

			S() {
				HINSTANCE dll_handle;
				if (!GetModuleHandleEx(
					GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
					TEXT(""), &dll_handle)) {
					Panic("GetModuleHandleEx failed during Sekiro Online folder path query (error 0x{:x})", GetLastError());
				}

				constexpr int path_max_sz = std::max(MAX_PATH, 1024);
				TCHAR dll_path[path_max_sz];
				DWORD n_written = 0;

				if ((n_written = GetModuleFileName(dll_handle, dll_path, path_max_sz)) && n_written >= path_max_sz) {
					Panic("GetModuleFileName failed during Sekiro Online folder path query (error 0x{:x})", GetLastError());
				}

				path = fs::path(dll_path).parent_path();
				if (!fs::exists(path) || !fs::is_directory(path)) {
					Panic("Folder \"{0}\" does not exist. Make sure you followed installation instructions carefully!", path.generic_string());
				}
			}
		};

		static S lazy_path;
		return lazy_path.path;
	}

	std::wstring string_to_wide_string(std::string_view string)
	{
		if (string.empty()) {
			return L"";
		}

		const auto size_needed = MultiByteToWideChar(CP_UTF8, 0, string.data(), (int)string.size(), nullptr, 0);
		if (size_needed <= 0) {
			throw std::runtime_error("MultiByteToWideChar() failed: " + std::to_string(size_needed));
		}

		std::wstring result(size_needed, 0);
		MultiByteToWideChar(CP_UTF8, 0, string.data(), (int)string.size(), &result.at(0), size_needed);
		return result;
	}

	std::string wide_string_to_string(std::wstring_view wide_string)
	{
		if (wide_string.empty()) {
			return "";
		}

		const auto size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_string.data(), (int)wide_string.size(), nullptr, 0, nullptr, nullptr);
		if (size_needed <= 0) {
			throw std::runtime_error("WideCharToMultiByte() failed: " + std::to_string(size_needed));
		}

		std::string result(size_needed, 0);
		WideCharToMultiByte(CP_UTF8, 0, wide_string.data(), (int)wide_string.size(), &result.at(0), size_needed, nullptr, nullptr);
		return result;
	}
}