#pragma once
#include <cstdint>
#include <string_view>

namespace pfm {

	/// Contiguous dynamic array, fromsoft's std::vector.
	template<class T>
	struct DLVector
	{
		T* _vec_begin;
		T* _vec_end;
		T* _buffer_end;

		inline T* begin() const
		{
			return _vec_begin;
		}

		inline T* end() const
		{
			return _vec_end;
		}

		inline size_t size() const
		{
			return _vec_end - _vec_begin;
		}

		inline size_t capacity() const
		{
			return _buffer_end - _vec_begin;
		}

		inline T* data() const
		{
			return _vec_begin;
		}
	};

	/// String type with an optimization for small strings used across Dantelion.
	/// May be merely the bottom part of the entire class. 
    template<class TChar>
    struct DLBasicString
    {
        union
        {
            TChar in_place[16 / sizeof(TChar)];
            TChar* ptr;
        };
        size_t length;
        size_t capacity;

		const TChar* c_str() const {
			return (length >= 16 / sizeof(TChar)) ? ptr : in_place; 
		}
        
        operator const TChar*() const {
            return c_str();
        }

		operator std::basic_string_view<TChar>() const {
			return std::basic_string_view<TChar>(c_str(), c_str() + length);
		}
    };

    using DLString = DLBasicString<char>;
    using DLWString = DLBasicString<wchar_t>;

	/// String type which stores some kind of hash.
	template<class Traits>
	struct FD4BasicHashString
	{
		void** vtable;
		void* allocator;
		union
        {
            typename Traits::Char in_place[Traits::INLINE_BUFFER_SIZE / sizeof(typename Traits::Char)];
            typename Traits::Char* ptr;
        };
        size_t length;
        size_t capacity;
		size_t unk_one;
		uint32_t hash;
		bool requires_rehash;

		const typename Traits::Char* c_str() const {
            return (length >= Traits::INLINE_BUFFER_SIZE  / sizeof(typename Traits::Char)) ? ptr : in_place; 
        }

		operator const typename Traits::Char*() const {
            return (length >= Traits::INLINE_BUFFER_SIZE  / sizeof(typename Traits::Char)) ? ptr : in_place; 
        }

		operator std::basic_string_view<typename Traits::Char>() const {
			return std::basic_string_view<typename Traits::Char>(c_str(), c_str() + length);
		}
	};

	/// Traits used by FD4BasicHashStrings used to name resources. 
	struct FD4ResNameHashStringTraits {
		using Char = wchar_t;
		static constexpr size_t INLINE_BUFFER_SIZE = 16;
	};

	/// A FD4BasicHashString used to name resources. 
	using FD4ResHashString = FD4BasicHashString<FD4ResNameHashStringTraits>;
	static_assert(sizeof(FD4ResHashString) == 0x40, "FD4ResHashString size mismatch");
}