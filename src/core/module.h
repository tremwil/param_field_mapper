#pragma once
#include "singleton.h"

#include <synchapi.h>

#include <concepts>
#include <unordered_map>
#include <unordered_set>

namespace pfm
{
	// Module implementing a specific Sekiro Online functionality, of which only a single instance may exist at any time. 
	// Differs from a Singleton<T> in that it only exists as long as it is referenced.
	// *Panics* if instantiated more than once. This can occur if a cicular dependency exists. 
	template<class T> class Module;

	template<class T>
	concept IModule = requires {
		std::derived_from<T, Module<T>>;
		{ T::get_or_create() } -> std::same_as<std::shared_ptr<T>>;
		{ T::get_if_exists() } -> std::same_as<std::shared_ptr<T>>;
		{ T::wait_for_unload(0) } -> std::same_as<bool>;
	};

	class ModuleRegistry : public Singleton<ModuleRegistry>
	{
	public:
		// Wait until all modules have been unloaded, for the given time.
		// Returns true if the all modules have been unloaded before the timeout.
		inline bool wait_for_all_unloaded(uint32_t timeout_ms = -1)
		{
			using namespace std::chrono;
			auto t = steady_clock::now();

			// We use WaitOnAddress instead of std::atomic::wait because we want to have control over the timeout 
			int val = n_instantiated.load(std::memory_order_acquire);
			while (val != 0 && (uint32_t)duration_cast<milliseconds>(steady_clock::now() - t).count() < timeout_ms) {
				WaitOnAddress(&n_instantiated, &val, sizeof(int), timeout_ms);
				val = n_instantiated.load(std::memory_order_acquire);
			}
			return (uint32_t)duration_cast<milliseconds>(steady_clock::now() - t).count() < timeout_ms;
		}

	protected:
		inline void increment_module_count()
		{
			n_instantiated.fetch_add(1, std::memory_order_release);
		}

		inline void decrement_module_count()
		{
			if (n_instantiated.fetch_sub(1, std::memory_order_release) == 1)
				WakeByAddressAll(&n_instantiated);
		}

		ModuleRegistry() = default;
		template<class T>
		friend class Module;

		std::atomic_int n_instantiated = 0;
	};

	template<class T> class Module
	{
	public:
		// Fetches a shared pointer to the module, or creates it.
		// If this is the only pointer to this module, destorying the shared pointer will lead to the destruction of the module. 
		static std::shared_ptr<T> get_or_create()
		{
			if (auto shared = instance_ptr.lock()) {
				return shared;
			}
			else {
				std::lock_guard lock(mutex);

				// Check if the module was constructed by another thread while we were waiting on the lock
				if ((shared = instance_ptr.lock())) {
					return shared;
				}
				else {
					struct Instantiatable : public T {}; // To allow the constructor to be protected without `friend class` spam
					shared = std::make_shared<Instantiatable>();
					instance_ptr = shared;
					return shared;
				}
			}
		}

		// Fetches a shared pointer to the module, if it is currently instantiated. Otherwise, returns a null shared pointer.
		inline static std::shared_ptr<T> get_if_exists()
		{
			return instance_ptr.lock();
		}

		// Wait until the module is unloaded, or the given timeout. Returns true if the module was unloaded before the timeout.
		inline static bool wait_for_unload(uint32_t timeout_ms = -1)
		{
			using namespace std::chrono;
			auto t = steady_clock::now();

			// We use WaitOnAddress instead of std::atomic::wait because we want to have control over the timeout 
			bool one = true;
			while (instantiated.load(std::memory_order_acquire) != 0 && 
				(uint32_t)duration_cast<milliseconds>(steady_clock::now() - t).count() < timeout_ms) 
			{
				WaitOnAddress(&instantiated, &one, sizeof(bool), timeout_ms);
			}
			return (uint32_t)duration_cast<milliseconds>(steady_clock::now() - t).count() < timeout_ms;
		}

	protected:
		Module()
		{
			if (instantiated.exchange(true)) {
				Panic("Two instances of {} cannot exist simultaneously. Make sure there are no circular dependencies", typeid(Module).name());
			}
			ModuleRegistry::get().increment_module_count();
			SPDLOG_TRACE("Instantiating {}", typeid(Module).name());
		}

		~Module()
		{
			if (!instantiated.exchange(false)) {
				Panic("~{} called, but it was never instantiated", typeid(Module).name());
			}
			WakeByAddressAll(&instantiated);
			ModuleRegistry::get().decrement_module_count();
			SPDLOG_TRACE("Destroying {}", typeid(Module).name());
		}

	private:
		Module(Module const&) = delete;
		Module(Module const&&) = delete;
		Module& operator=(Module const&) = delete;

		static std::recursive_mutex mutex;
		static std::weak_ptr<T> instance_ptr;
		static std::atomic_bool instantiated;
	};
	template<class T>
	std::recursive_mutex Module<T>::mutex;
	template<class T>
	std::weak_ptr<T> Module<T>::instance_ptr;
	template<class T>
	std::atomic_bool Module<T>::instantiated{ false };

	// RAII owning dependency to a Module.
	template<IModule T> class ModulePtr
	{
	public:
		T* operator->() const
		{
			return module_ref.get();
		}

		T& operator*() const
		{
			return *module_ref;
		}

		T* get() const { return module_ref.get(); }

	private:
		std::shared_ptr<T> module_ref{ T::get_or_create() };
	};

	// Weak (non-owning) pointer to a Module. Must be locked via the lock() method to obtain a shared pointer to the module.
	template<IModule T> class WeakModulePtr
	{
	public:
		std::shared_ptr<T> lock()
		{
			return T::get_if_exists();
		}
	};
}