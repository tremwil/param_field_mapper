#pragma once
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <span>

namespace pfm
{
    /// Incrementally computed control flow graph which does not follow function calls.
    class CFG 
    {
    public:
        struct Node {
            intptr_t address;
            std::unordered_set<Node*> in;
            std::unordered_set<Node*> out;

            Node(intptr_t addr) : address(addr) {}
        };
   
        bool walk_function(intptr_t addr);

        inline Node* node_at(intptr_t address) const {
            auto it = nodes.find(address);
            return it == nodes.end() ? nullptr : it->second.get();
        }

    private:
        std::unordered_map<intptr_t, std::unique_ptr<Node>> nodes;
        bool walk_function_internal(intptr_t addr, std::span<uint8_t> module_text);
    };

    namespace cfg_utils {
        /// Attempt to find the start address of a function given the address of an 
        /// instruction it contains. If RSP is known (i.e. in the context of a suspended thread), 
        /// may work with leaf functions as well.
        /// Returns 0 on failure.
        intptr_t find_function(intptr_t code, intptr_t known_rsp = 0);
    }
}