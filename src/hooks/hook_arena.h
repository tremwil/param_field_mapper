#pragma once
#include "core/core.h"
#include "core/lite_mem_stream.h"

namespace pfm
{
    struct TrampolineInfo
    {
        void* trampoline = nullptr;
        std::span<uint8_t> modified_code;
        std::vector<uint8_t> old_code;

        /// Restores the modified code. 
        inline void restore() {
            utils::patch_memory(modified_code, [&](){
                std::copy(old_code.begin(), old_code.end(), modified_code.data());
            });
        }
    };

    struct JmpHookInfo : public TrampolineInfo {
        void** hook_address = nullptr;
    };

    /// Class implementing generation of different types of assembly patches for hooks.
    class HookArena : public LiteMemStream
    {
    protected:
        uint8_t* alloc_base = 0; // base of allocated region

    public:
        HookArena();

        /// Create a hook generator given a target memory region and desired hook memory size.
        HookArena(intptr_t region_base, size_t region_size, size_t hook_mem_size);

        /// Create a hook generator given a target module and desired hook memory size.
        /// Invalid module name returns an object with 0 allocated memory.
        HookArena(const char* target_module, size_t hook_mem_size);

        /// Create a hook arena given an address and desired hook memory size. The arena will be in range
        /// of all patches to other code in the same module. 
        HookArena(void* address, size_t hook_mem_size);

        ~HookArena();

        /// Initialize the bulk assembly patcher given a target memory range and desired hook memory size.
        void init(intptr_t mod_begin, intptr_t mod_end, size_t hook_mem_size);

        /// Check if the patcher can patch the given address (i.e. the entire hook memory is within JMP REL32 range).
        bool can_patch(intptr_t addr);

        /// Hook the function starting at the given address. Returns a struct containing hook information. 
        JmpHookInfo gen_jmp_hook(void* addr, void* hook_code);

        /// Generates a call hook redirecting a call at a given address to hook_code.
        /// Returns the address in hook memory at which the hook address is written. 
        void** gen_call_hook(void* addr, void* hook_code);

        /// Generates a hook that runs the patched instruction if the address accessed by the original instruction is within a 
        /// region. Returns the address of the start of the hook, or 0 on failure.
        intptr_t gen_cond_access_hook(uint8_t* original, uint8_t* patched, uintptr_t region_begin, uintptr_t region_end);

        /// Create a JMP trampoline to code previously written to hook memory. Will overwrite num_overwrite instructions at addr. 
        /// Moves other instructions that would be overwritten by the JMP automatically (using relocate). 
        /// Returns a data structure containing information about the trampoline.
        TrampolineInfo gen_trampoline(intptr_t hook_start, intptr_t addr, int num_overwrite);
    };

    class HookArenaPool
    {
        std::vector<HookArena> arenas;
        size_t hook_mem_size;

    public:
        HookArenaPool(size_t hook_mem_size = 1 << 22) : hook_mem_size(hook_mem_size) {};

        /// Fetch a `HookArena` which can be used to patch code at the given location.
        /// IMPORTANT: The returned hook arena lives as long as the pool, so make sure to hold a shared pointer to it!
        HookArena& get_or_create_arena(void* hook_site);
    };
}