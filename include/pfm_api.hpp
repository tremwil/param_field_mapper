#include <atomic>
#include <cstdlib>

extern "C" __stdcall uint32_t GetEnvironmentVariableA(
    const char* lpName, 
    char* lpBuffer, 
    uint32_t nSize
);

namespace pfm {
    namespace detail {
        static const char* const PFM_API_ADDR_ENV_VAR = "PFM_ADJUST_PARAM_PTR_ADDRESS";

        using adjust_param_ptr_t = void* (*)(void*);
        static std::atomic<adjust_param_ptr_t> cached_adjust_param_ptr = nullptr;
    }

    /// Given a pointer to some data inside a param file, will return an adjusted address 
    /// to read the "true" file without triggering an access violation.
    static void* adjust_param_ptr(void* param_data_ptr) {
        using namespace detail;

        if (auto func = cached_adjust_param_ptr.load(std::memory_order_acquire)) {
            return func(param_data_ptr);
        }

        char buffer[32];
        if (!::GetEnvironmentVariableA(PFM_API_ADDR_ENV_VAR, buffer, sizeof(buffer))) 
            return param_data_ptr;

        auto func = (adjust_param_ptr_t) ::strtoull(buffer, nullptr, 16);
        if (!func) return param_data_ptr;

        cached_adjust_param_ptr.store(func, std::memory_order_release);
        return func(param_data_ptr);
    }
}