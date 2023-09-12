#pragma once
#include "control_flow_graph.h"
#include "hook_arena.h"
#include "hooks/trampoline.h"
#include "trampoline.h"

#include <functional>
#include <unordered_map>

// Forward declare context to avoid Windows.h imclude
struct _CONTEXT;

namespace pfm {

enum class ExtendFlowGraphResult {
    Success,
    DissassemblyFailed,
    FlowGraphComputationFailed,
    FunctionStartNotFound,
    InstructionNotRediscovered
};

class MassInstructionPatcher {
    CFG cfg; // Stores entire process-wide CFG (incrementally built)
    HookArenaPool arena_pool;

    AddressMap relocations_map;
    AddressMap inverse_relocations_map;

    std::unordered_map<intptr_t, std::vector<intptr_t>> module_pseudo_branch_targets;
    std::unordered_set<intptr_t> rwe_modules;

    void update_reloc_maps(const AddressMap& relocs);

public:
    MassInstructionPatcher() = default;

    /// Prepares a module for mass hooking. This computes pseudo branch target addresses
    /// for the module, and adds to the flow graph by walking the module's entry point and 
    /// every function in the module's exception table, if it was not previously done. 
    /// Note that in many cases, incrementally computing the flow graph with 
    /// `extend_flow_graph_if_required` will be sufficient. 
    bool prepare_module(intptr_t module_base);

    /// Incrementally builds up the CFG and pseudo branch targets if necessary for hooking, 
    /// and makes module memory RWE if not already done. 
    /// To handle leaf functions, the thread context must be provided.
    ExtendFlowGraphResult light_prepare_if_required(intptr_t instruction_addr, _CONTEXT* thread_ctx = nullptr);

    /// Creates a JMP hook to some function, returning the trampoline adddress. Does not save register context; 
    /// hence it should not be used on arbitrary instructions, only function prologues!
    intptr_t jmp_hook(intptr_t addr, intptr_t hook);

    template<class R, class... A>
    using Func = R (*)(A...);

    template<class R, class... A>
    inline Func<R, A...> jmp_hook(intptr_t addr, Func<R, A...> hook) {
        return reinterpret_cast<Func<R, A...>>(jmp_hook(addr, reinterpret_cast<intptr_t>(hook)));
    }

    /// Inserts code generated by `codegen` in the program flow at `addr`. If `replace` is true, will 
    /// overwrite the original instruction present at this location. 
    /// Note that relocations may have already occured before `codegen` is evaluated. If it relies on 
    /// pre-relocation addresses, use the address `AddressMap` parameter to fetch updated addresses.
    intptr_t instruction_hook(intptr_t addr, std::function<void(HookArena&, const AddressMap&)> codegen, bool replace = false);

    /// Returns the actual address of a (potentially) relocated instruction, given its original one.
    template<class Ptr>
    inline Ptr relocated_address(Ptr addr) const {
        auto it = relocations_map.find(reinterpret_cast<uint8_t*>(addr));
        return it == relocations_map.end() ? addr : reinterpret_cast<Ptr>(it->second);
    }

    /// Returns the original address of a (potentially) relocated instruction, given its actual one.
    template<class Ptr>
    inline Ptr original_address(Ptr addr) const {
        auto it = relocations_map.find(reinterpret_cast<uint8_t*>(addr));
        return it == relocations_map.end() ? addr : reinterpret_cast<Ptr>(it->second);
    }
};

} // namespace pfm