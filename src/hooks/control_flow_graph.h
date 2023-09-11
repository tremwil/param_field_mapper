#pragma once
#include <initializer_list>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include <span>

namespace pfm
{
    enum class BranchType {
        Call,     /// Call instruction. targets.first(), function is assumed to return.
        Uncond,   /// Unconditional branch. targets.first().
        Cond,     /// Conditional branch. targets.first() is taken branch, implicit branch is not stored.
        Switch,   /// Indirect jmp into a switch table. Can have any number of targets.
        Ret       /// Return branch. Target is not resolved.
    };

    /// A generic graph node/vertex which also stores an address.
    struct Branch {
        intptr_t address;
        BranchType type;
        std::vector<struct BranchTarget*> targets;
        
        Branch(intptr_t addr, BranchType type) : address(addr), type(type) {}
    };

    struct BranchTarget {
        intptr_t address;
        std::unordered_set<struct Branch*> branches;

        BranchTarget(intptr_t addr) : address(addr) {}
    };

    /// Incrementally computed control flow graph which does not follow function calls or indirect JMPs.
    class CFG 
    {
    public:
        inline bool visited_instruction(intptr_t address) const {
            return instructions.contains(address);
        }

        inline const Branch* get_branch_at(intptr_t address) const {
            auto it = branches.find(address);
            return it == branches.end() ? nullptr : it->second.get();
        }

        inline const BranchTarget* get_target_at(intptr_t address) const {
            auto it = branch_targets.find(address);
            return it == branch_targets.end() ? nullptr : it->second.get();
        }

        /// Marks the given instruction address as visited. 
        /// Does *not* walk the control flow from addr. If you want to do so, call `walk` instead.
        inline void add_instruction(intptr_t addr) {
            instructions.insert(addr);
        }

        /// Marks the given instruction as non-visited, and removes its targets if it is a branch.
        bool remove_instruction(intptr_t addr);

        /// Add a new branch to the CFG, marking the instruction as visited.
        /// Does *not* mark the targets as visited. To do so, call add_instruction on `addr` and each of the `targets` first.
        /// Fails if a branch already exists at the given address.
        bool add_branch(intptr_t addr, BranchType type, std::initializer_list<intptr_t> targets);

        /// Removes a branch from the CFG.
        /// Does *not* mark the instruction as non-visited! Call `remove_instruction` instead to do so.
        bool remove_branch(intptr_t addr);

        /// Update the graph to reflect changes to the address at which an instruction is located.
        /// This should be called when relocating instructions and/or branches.
        bool relocate(intptr_t old_addr, intptr_t new_addr);

        /// Walk the control flow of code starting at `addr`, following relative branches but not calls or indirect JMPs.
        bool walk(intptr_t addr, bool follow_calls = true);

    private:
        std::unordered_map<intptr_t, std::unique_ptr<Branch>> branches;
        std::unordered_map<intptr_t, std::unique_ptr<BranchTarget>> branch_targets;
        std::unordered_set<intptr_t> instructions;
    };

    struct RUNTIME_FUNCTION {
        uint32_t BeginAddress;
        uint32_t EndAddress;
        uint32_t UnwindInfoAddress;
    };

    struct UNWIND_CODE {
        uint8_t OffsetInProlog;
        uint8_t UnwindOperationCode: 4;
        uint8_t OperationInfo: 4;
    };

    struct UNWIND_INFO {
        uint8_t Version: 3;
        uint8_t Flags: 5;
        uint8_t SizeOfProlog;
        uint8_t CountOfUnwindCodes;
        uint8_t FrameRegister: 4;
        uint8_t FrameOffset: 4; 
        UNWIND_CODE UnwindCodes[1];

        RUNTIME_FUNCTION& ChainedRuntimeFunction() {
            return *(RUNTIME_FUNCTION*)(UnwindCodes + CountOfUnwindCodes);
        }

        uint32_t& ExceptionHandler() {
            return *(uint32_t*)(UnwindCodes + CountOfUnwindCodes);
        }
    };

    namespace cfg_utils {
        std::span<RUNTIME_FUNCTION> get_exception_table(uint8_t* module_base);

        /// Attempt to find the start address of a function given the address of an 
        /// instruction it contains. If RSP is known (i.e. in the context of a suspended thread), may work with leaf functions as well.
        /// Returns 0 on failure.
        intptr_t find_function(intptr_t code, intptr_t known_rsp = 0);
    }
}