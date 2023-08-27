#pragma once
#include <string>
#include <string_view>
#include <concepts>
#include <type_traits>

namespace pfm
{
	/// Compile-time string wrapper which can be an argument to a template. 
	template<size_t N>
	struct FixedString
	{
		char buf[N + 1]{};
		constexpr FixedString(char const* s)
		{
			for (unsigned i = 0; i != N; ++i) buf[i] = s[i];
		}

		constexpr FixedString(const std::string& s)
		{
			for (unsigned i = 0; i != N && i < s.length(); ++i) buf[i] = s[i];
		}

		constexpr operator char const* () const { return buf; }
		constexpr operator std::string_view() const { return buf; }

		constexpr bool operator==(const FixedString& lhs)
		{
			for (unsigned i = 0; i != N; ++i)
				if (buf[i] != lhs.buf[i]) return false;
			return true;
		}
	};
	template<size_t N> FixedString(char const (&)[N])->FixedString<N - 1>;

	template<class T>
	constexpr bool IS_LITERAL = false;

	template<class Chr, size_t N>
	constexpr bool IS_LITERAL<Chr const (&)[N]> = true;

	template<class Lambda, int = (Lambda{}(), 0) >
	constexpr bool is_constexpr_helper(Lambda) { return true; }
	constexpr bool is_constexpr_helper(...) { return false; }

	/// member-to-function pointer to regular function pointer
	template<class T>
	struct MemberFnTraits;

	template<class T, class Ret, class... Args>
	struct MemberFnTraits<Ret(T::*)(Args...)>
	{
		using TRet = Ret;
		using TCall = Ret(T*, Args...);
		using TSig = Ret(Args...);
	};

	template<typename T>
	concept Hashable = requires(T a) {
		{ std::hash<T>{}(a) } -> std::convertible_to<std::size_t>;
	};

#ifdef __clang__
#define PFM_IS_CONSTEXPR(EXPR) pfm::is_constexpr_helper([] { \
	_Pragma("clang diagnostic push") \
	_Pragma("clang diagnostic ignored \"-Wunused-value\"") \
	EXPR; \
	_Pragma("clang diagnostic pop") \
	})
#else
#define PFM_IS_CONSTEXPR(EXPR) SO::is_constexpr_helper([] { EXPR; })
#endif
}