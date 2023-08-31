#pragma once
#include <Windows.h>
#include <filesystem>
#include <span>

#include "panic.h"
#include "template_utils.h"

#include "mem/module.h"

namespace pfm
{
	namespace fs = std::filesystem;

	/// Struct which will run the given lambda on construction. This is useful for RAII initialization when one 
	/// of the fields may require a global resource to be initialized, for example.
	struct RAIILambda
	{
		template<std::invocable<> F>
		RAIILambda(F lambda)
		{
			lambda();
		}
	};

#define PFM_ENUM_CLASS_BITWISE_NEG(E) \
	constexpr E operator~ (E e) \
	{ \
		using T = std::underlying_type<E>::type; \
		return static_cast<E>(~static_cast<T>(e)); \
 	}; \

#define PFM_ENUM_CLASS_BITWISE_BIN(E, OP) \
	constexpr E operator OP (E lhs, E rhs) \
	{ \
		using T = std::underlying_type<E>::type; \
		return static_cast<E>(static_cast<T>(lhs) OP static_cast<T>(rhs)); \
	}; \
	constexpr E& operator OP ## = (E& lhs, const E& rhs) \
	{ \
		using T = std::underlying_type<E>::type; \
		return lhs = static_cast<E>(static_cast<T>(lhs) OP static_cast<T>(rhs));; \
	};

	/// Implements bitwise operators for the given enum class.
#define PFM_BITWISE_ENUM(E) \
	PFM_ENUM_CLASS_BITWISE_NEG(E); \
	PFM_ENUM_CLASS_BITWISE_BIN(E, &); \
	PFM_ENUM_CLASS_BITWISE_BIN(E, |); \
	PFM_ENUM_CLASS_BITWISE_BIN(E, ^);

	namespace detail
	{
		template<typename T> struct ArgType;
		template<typename T, typename U> struct ArgType<T(U)> { using Type = U; };
	}

	template<class T>
	struct AbstractClassWrapper
	{
		void** vftable;

		T* operator->() 
		{
			return (T*)this;
		}
	};

#define PFM_STR_MERGE_IMPL(a, b) a##b
#define PFM_STR_MERGE(a, b) PFM_STR_MERGE_IMPL(a, b)
#define PFM_MAKE_PAD(size)           \
    PFM_STR_MERGE(_pad, __COUNTER__) \
    [size]
#define PFM_DEFINE_MEMBER_N(type, name, offset) \
    struct { \
		unsigned char PFM_MAKE_PAD(offset);     \
		SO::detail::ArgType<void(type)>::Type name;   \
    }

	namespace utils
	{
		/// returns the path to the folder containing the DLL. 
		/// This should always succeed; the function panics if the path cannot be found.
		fs::path dll_folder();

		/// Converts a UTF-8 string to UTF-16.
		std::wstring string_to_wide_string(std::string_view string);

		/// Converts a UTF-16 string to UTF-8.
		std::string wide_string_to_string(std::wstring_view wide_string);

		// Get a particular code section of the main module of the process, and cache it for later querying.
		template<FixedString name = ".text">
		const mem::region& main_module_section()
		{
			static mem::region region = [] {
				auto main_module = mem::module::main();

				mem::pointer section_begin = nullptr;
				mem::pointer section_end = nullptr;

				for (const auto& section : main_module.section_headers()) {
					if (strncmp((char*)section.Name, name, sizeof(section.Name))) {
						if (section_begin == nullptr) continue;
						else break;
					}
					else if (section_begin == nullptr) {
						section_begin = main_module.start.add(section.VirtualAddress);
						section_end = section_begin.add(section.Misc.VirtualSize);
					}
					// Handle contiguous sections with the same name (e.g. multiple .data sections)
					else if (section_end == main_module.start.add(section.VirtualAddress)) {
						section_end += section.Misc.VirtualSize;
					}
					else break;
				}
				if (section_begin == nullptr) {
					Panic("{} section does not exist in main executable module", name);
				}
				else {
					return mem::region(section_begin, section_end - section_begin);
				}
			}();
			return region;
		}

		template<std::invocable<> F>
		void patch_memory(mem::pointer address, size_t size, F fun) 
		{
			auto lpvoid = address.as<LPVOID>();
			DWORD old_protect;
			VirtualProtect(lpvoid, size, PAGE_EXECUTE_READWRITE, &old_protect);
			fun();
			VirtualProtect(lpvoid, size, old_protect, &old_protect);
		}

		template<std::invocable<> F>
		void patch_memory(std::span<uint8_t> region, F fun)
		{
			patch_memory(region.data(), region.size(), fun);
		}

		constexpr inline bool is_power_of_2(size_t n) {
			return (n & (n-1)) == 0;
		}

		constexpr inline size_t align_up(size_t n, size_t alignment)
		{
			if (is_power_of_2(alignment)) {
				return (n + alignment - 1) & ~(alignment - 1);
			}
			else {
				size_t m = n + alignment - 1;
				return m - (m % alignment);
			}
		}

		constexpr inline size_t align_down(size_t n, size_t alignment)
		{
			if (is_power_of_2(alignment)) {
				return n & ~(alignment - 1);
			}
			else {
				return n - (n % alignment);
			}
		}

		template<typename T>
		inline T* align_up(T* ptr, size_t alignment)
		{
			return (T*)align_up((size_t)ptr, alignment);
		}

		template<typename T>
		inline T* align_down(T* ptr, size_t alignment)
		{
			return (T*)align_down((size_t)ptr, alignment);
		}

		template<typename E>
		constexpr bool test_enum(E a, E b)
		{
			using T = typename std::underlying_type<E>::type;
			return (static_cast<T>(a) & static_cast<T>(b)) != 0;
		}

		/// Waits until atomic changes to a value different from expected. Returns true if the wait succeeded, 
		/// false in case of timeout.
		template<typename T>
		bool atomic_wait(T& atomic, const T& expected, uint32_t timeout_ms = -1) {
			using namespace std::chrono;
			auto t = steady_clock::now();

			// We use WaitOnAddress instead of std::atomic::wait because we want to have control over the timeout 
			int32_t elapsed = 0; 
			while (atomic == expected && elapsed < timeout_ms) {
				WaitOnAddress((volatile void*)&atomic, (void*)&expected, sizeof(T), timeout_ms - elapsed);
				elapsed = (uint32_t)duration_cast<milliseconds>(steady_clock::now() - t).count();
			}
			return elapsed < timeout_ms;
		}

		template<typename T>
		void atomic_wake(T& atomic) {
			WakeByAddressSingle((void*)&atomic);
		}

		template<typename T>
		void atomic_wake_all(T& atomic) {
			WakeByAddressAll((void*)&atomic);
		}
	}
}