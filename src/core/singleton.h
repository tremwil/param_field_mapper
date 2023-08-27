#pragma once
#include <shared_mutex>
#include <type_traits>
#include "panic.h"
#include "template_utils.h"

namespace pfm
{
	template<class T>
	/// Lazily instantiated static lifetime object.
	class Singleton
	{
	private:
		Singleton(Singleton const&) = delete;
		Singleton(Singleton const&&) = delete;
		Singleton& operator=(Singleton const&) = delete;

		static std::atomic_bool instantiated;

	protected:
		Singleton() { 
			if (instantiated.exchange(true)) {
				Panic("Attempted to instantiate {} twice", typeid(Singleton).name());
			}
			SPDLOG_TRACE("Instantiating {}", typeid(Singleton).name());
		}
	public:
		/// Get a reference to the instance of this singleton.
		static inline T& get() {
			// Ugly trick to avoid needing to do friend class Singleton<T> every time
			struct Instantiatable : public T {};
			static Instantiatable instance;
			return (T&)instance;
		}

		/// Check if the singleton has been instantiated.
		static inline bool is_instantiated() {
			return instantiated.load();
		}

		/// Force the instantiation of the singleton. Just a Get() call with a more informative name. 
		static void instantiate() {
			get();
		}
	};
	template<class T>
	std::atomic_bool Singleton<T>::instantiated {false};

	/// Class with a constructor that will block until the singleton T is instantiated. This is
	/// useful for RAII initialization when another field has a non-RAII depdendency on the singleton.
	template<class T> requires std::is_base_of<Singleton<T>, T>::value
	struct SingletonDep
	{
		SingletonDep()
		{
			T::instantiate();
		}
	};
}