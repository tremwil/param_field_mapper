#pragma once

#include <iostream>
#include <span>
#include <optional>

namespace SO
{
    /// Simple stream over a span of bytes in memory. 
	struct LiteMemStream
	{
	protected:
		uint8_t* begin;
		uint8_t* end;
		uint8_t* current;

	public:
		constexpr LiteMemStream(std::span<uint8_t> buffer) : begin(buffer.data()), end(buffer.data() + buffer.size()), current(buffer.data()) {}
		constexpr LiteMemStream(uint8_t* begin, uint8_t* end) : begin(begin), end(end), current(begin) {}
		constexpr LiteMemStream(uint8_t* data, size_t size) : begin(data), end(data + size), current(data) {}

		constexpr bool is_eof() const noexcept {
			return current >= end;
		}

		constexpr std::span<uint8_t> buffer() const noexcept {
			return std::span(begin, end);
		}

		constexpr std::span<uint8_t> consumed() const noexcept {
			return std::span(begin, current);
		}

		constexpr std::span<uint8_t> remaining() const noexcept {
			return std::span(current, end);
		}

		bool seek(size_t position) noexcept {
			if (position < (size_t)end - (size_t)begin) {
				current = begin + position;
				return true;
			}
			return false;
		}

		bool advance(size_t num_bytes) noexcept {
			current += num_bytes;
			return current < end;
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline const T* peek() const noexcept
		{
			return current + sizeof(T) > end ? nullptr : (const T*)current;
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline T* peek() noexcept
		{
			return current + sizeof(T) > end ? nullptr : (T*)current;
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline bool peek(T& out) const noexcept
		{
			if (current + sizeof(T) > end) return false;
			else {
				out = *(const T*)current;
				return true;
			}
		}

		template<typename T, size_t N> requires std::is_standard_layout<T>::value
		constexpr inline bool peek(std::span<T, N>& out) const noexcept
		{
			if (current + N * sizeof(T) > end) return false;
			else {
				out = std::span<T, N>(current);
				return true;
			}
		}

		template<typename T, size_t N> requires std::is_standard_layout<T>::value
		constexpr inline std::optional<std::span<T, N>> peek() const noexcept
		{
			if (current + N * sizeof(T) > end) return std::nullopt;
			else return std::span<T, N>(current);
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline bool peek(std::span<T>& out, size_t n) const noexcept
		{
			if (current + n * sizeof(T) > end) return false;
			else {
				out = std::span<T>(current, current + n * sizeof(T));
				return true;
			}
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline std::optional<std::span<T>> peek(size_t n) const noexcept
		{
			if (current + n * sizeof(T) > end) return std::nullopt;
			else return std::span<T>(current, current + n * sizeof(T));
		}

		template<typename T, size_t N> requires std::is_standard_layout<T>::value
		constexpr inline bool peek(std::array<T, N>& out, size_t n = N) const noexcept
		{
			if (n > N || current + n * sizeof(T) > end) return false;
			else {
				std::copy(current, current + n * sizeof(T), out.begin());
				return true;
			}
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline T* read() noexcept
		{
			if (current + sizeof(T) <= end) {
				auto ptr = (T*)current;
				current += sizeof(T);
				return ptr;
			}
			else return nullptr;
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline bool read(T& out) noexcept
		{
			if (current + sizeof(T) <= end) {
				out = *(T*)current;
				current += sizeof(T);
				return true;
			}
			else return false;
		}

		template<typename T, size_t N> requires std::is_standard_layout<T>::value
		constexpr inline bool read(std::span<T, N>& out) noexcept
		{
			if (current + N * sizeof(T) > end) return false;
			else {
				out = std::span<T, N>((T*)current);
				current += N * sizeof(T);
				return true;
			}
		}

		template<typename T, size_t N> requires std::is_standard_layout<T>::value
		constexpr inline std::optional<std::span<T, N>> read() noexcept
		{
			if (current + N * sizeof(T) > end) return std::nullopt;
			else {
				auto out = std::span<T, N>((T*)current);
				current += N * sizeof(T);
				return out;
			}
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline bool read(std::span<T>& out, size_t n) noexcept
		{
			if (current + n * sizeof(T) > end) return false;
			else {
				auto start = (T*)current;
				out = std::span<T>(start, (T*)(current += n * sizeof(T)));
				return true;
			}
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline std::optional<std::span<T>> read(size_t n) noexcept
		{
			if (current + n * sizeof(T) > end) return std::nullopt;
			else {
				auto start = (T*)current;
				return std::span<T>(start, (T*)(current += n * sizeof(T)));
			}
		}

		template<typename T, size_t N> requires std::is_standard_layout<T>::value
		constexpr inline bool read(std::array<T, N>& out, size_t n = N) noexcept
		{
			if (n > N || current + n * sizeof(T) > end) return false;
			else {
				auto start = (T*)current;
				std::copy(start, (T*)(current += n * sizeof(T)), out.begin());
				return true;
			}
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline bool write(const T& val) noexcept
		{
			if (current + sizeof(T) <= end) {
				*(T*)current = val;
				current += sizeof(T);
				return true;
			}
			else return false;
		}

		template<typename T> requires std::is_standard_layout<T>::value
		constexpr inline bool write(const std::span<T>& val) noexcept
		{
			if (current + val.size() * sizeof(T) <= end) {
				std::copy(val.begin(), val.end(), (std::remove_const_t<T>*)current);
				current += val.size() * sizeof(T);
				return true;
			}
			else return false;
		}

		template<typename It, typename T = typename std::iterator_traits<It>::value_type> requires std::is_standard_layout<T>::value
		constexpr inline bool write(It first, It last) noexcept
		{
			// Should be iterator_traits<It>::difference_type but we have to compare it later
			size_t num = std::distance(first, last);

			if (current + num * sizeof(T) <= end) {
				std::copy(first, last, (std::remove_const_t<T>*)current);
				current += num * sizeof(T);
				return true;
			}
			else return false;
		}
	};
}