#pragma once
#include "core/core.h"
#include <string_view>

namespace pfm
{
	class FD4SingletonFinder : public Singleton<FD4SingletonFinder>
	{
	public:
		/// Gets the static address which stores the address of the singleton with the given name, 
		/// or nullptr if it could not be found 
		void** address_of(const std::string_view class_name) const;

		/// Gets the instance pointer to the given singleton, or nullptr if not found/instantiated.
		void* instance_of(const std::string_view class_name) const;

	protected:
		FD4SingletonFinder();

	private:
		std::unordered_map<std::string_view, void**> singleton_addresses;
	};

	/// Template base class to auto-generate convenience method for accessing game singleton (FD4Singleton) classes.
	template<class T, FixedString name>
	struct FD4Singleton
	{
		static constexpr const char* class_name = name;

		/// Prevent instantiating anything derived from a FD4Singleton

		FD4Singleton() = delete;
		FD4Singleton(FD4Singleton&) = delete;
		FD4Singleton(FD4Singleton&&) = delete;
		FD4Singleton operator=(FD4Singleton&) = delete;

		/// Tries to obtain the static address of this FD4Singleton, if it exists. Returns a null pointer otherwise.
		static T** static_address()
		{
			static T** static_address = (T**)FD4SingletonFinder::get().address_of(name.buf);
			return static_address;
		}

        // Get a (potentially null) pointer to the FD4Singleton instance. Panics if the singleton static address could not be found.
		static T* instance_unchecked()
		{
			static T** static_address = []{
				T** addr = FD4Singleton::static_address();
				if (addr == nullptr) {
					Panic("static address of FD4Singleton \"{}\" not found", name.buf);
				}
				return addr;
			}();
			return *static_address;
		}

		// Get a pointer to the FD4Singleton instance, waiting until it is initialized if necessary.
		static T* wait_for_instance()
		{
			using namespace std::chrono_literals;

			auto ins = instance_unchecked();
			for (; !ins; ins = instance_unchecked()) {
				std::this_thread::sleep_for(1ms);
			}
			return ins;
		} 

		/// Get a pointer to the FD4Singleton instance. Panics if the singleton static address could not be found,
        /// or the singleton is not yet initialized. 
		static T* instance()
		{
			auto instance = FD4Singleton::instance_unchecked();
            if (instance == nullptr) Panic("Attempted to fetch uninitialized FD4Singleton \"{}\"", name.buf);
            return instance;
		}
	};
}