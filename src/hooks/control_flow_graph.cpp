#include "control_flow_graph.h"

#include "core/panic.h"

#include "mem/mem.h"
#include "mem/module.h"
#include "zydis/Zydis.h"

#include <algorithm>
#include <libloaderapi.h>
#include <winnt.h>

namespace pfm
{
    bool CFG::walk_function_internal(intptr_t addr, std::span<uint8_t> module_text) {
        // If addr was already visited, we already walked the function
        if (nodes.contains(addr)) {
            return true;    
        }

        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        ZydisDecodedInstruction instruction;
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands;

        mem::region module_text_reg { module_text.data(), module_text.size() };

        std::vector<intptr_t> dfs_stack { addr };
        nodes.emplace(std::make_pair(addr, std::make_unique<Node>(addr)));

        auto add_edge = [&](Node* from, intptr_t addr_to) {
            if (nodes.contains(addr_to)) {
                auto& node = nodes[addr];
                node->in.insert(from);
                from->out.insert(node.get());
            }
            else {
                auto node = std::make_unique<Node>(addr_to);
                node->in.insert(from);
                from->out.insert(node.get());

                nodes.emplace(std::make_pair(addr_to, std::move(node)));
                dfs_stack.push_back(addr_to);
            }
        };

        while (!dfs_stack.empty()) {
            intptr_t addr = dfs_stack.back();

            dfs_stack.pop_back();

            auto node = nodes[addr].get();
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)addr, 
                ZYDIS_MAX_INSTRUCTION_LENGTH, &instruction, operands.data()))) 
            {
                SPDLOG_ERROR("Zydis failed to decompile instruction at {:x}", addr);
                return false;
            }

            switch (instruction.meta.category)
            {
            case ZYDIS_CATEGORY_RET:
                break;
            case ZYDIS_CATEGORY_COND_BR:
                add_edge(node, addr + instruction.length);
                [[fallthrough]];
            case ZYDIS_CATEGORY_UNCOND_BR:
                // Compute new RIP, if possible
                ZyanU64 out_addr;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[0], addr, &out_addr))) {
                    add_edge(node, out_addr);
                }
                break;
            default:
                add_edge(node, addr + instruction.length);
                break;
            }
        }
        return true;
    }

    bool CFG::walk_function(intptr_t addr) {
        HMODULE module_base;
        if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (const char*)addr, &module_base)) 
        {
            SPDLOG_ERROR("Failed to query module base at address {:x}", addr);
            return false;
        }

        auto m = mem::module::nt(module_base);
        for (const auto& section : m.section_headers()) {
            if (std::strcmp((const char*)section.Name, ".text")) continue;
            std::span module_text { 
                (uint8_t*)module_base + section.VirtualAddress, section.Misc.VirtualSize 
            };
            return CFG::walk_function_internal(addr, module_text);
        }

        SPDLOG_ERROR("Module at {:x} has no .text section", (intptr_t)module_base);
        return false;
    }

    namespace cfg_utils {
        intptr_t find_function(intptr_t code, intptr_t known_rsp) {
            // Fetch the exception table of the module the code lies in

            HMODULE mhandle;
            if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | 
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (const char*)code, &mhandle))
            {
                return 0;
            }

            auto mod = mem::module::nt(mhandle);
            auto& opt_header = mod.nt_headers().OptionalHeader;
            auto ex_tbl_data_dir = opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

            mem::region text_section { nullptr, 0 };
            for (const auto& section : mod.section_headers()) {
                if (std::strcmp((const char*)section.Name, ".text")) continue;
                text_section = { 
                    (uint8_t*)mhandle + section.VirtualAddress, section.Misc.VirtualSize
                };
                break;
            }

            std::span ex_tbl { 
                (IMAGE_RUNTIME_FUNCTION_ENTRY*)((intptr_t)mhandle + ex_tbl_data_dir.VirtualAddress),
                ex_tbl_data_dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)
            };

            // Binary search over the exception table to try and find the function

            DWORD code_ibo32 = code - (intptr_t)mhandle;
            auto entry_it = std::upper_bound(ex_tbl.begin(), ex_tbl.end(), 
                IMAGE_RUNTIME_FUNCTION_ENTRY { .EndAddress = code_ibo32 }, 
                [](const auto& v, const auto& e) { return v.EndAddress < e.EndAddress; });

            if (entry_it != ex_tbl.end() && code_ibo32 >= entry_it->BeginAddress) {
                return (intptr_t)mhandle + entry_it->BeginAddress;
            }
            else if (known_rsp != 0 && text_section.size) {
                // If not present in the exception table and we know where code should be, 
                // assume we have a leaf function. Then the call instruction is at [RSP] - 5.
                mem::region call { *(uint8_t**)known_rsp - 5, 5 };
                // Invalid mem or not a CALL REL32 instruction
                if (!text_section.contains(call) || call.start.at<uint8_t>(0) != 0xe8)
                    return 0;
                
                // Then the call target should be our function
                intptr_t tgt = call.start.as<intptr_t>() + 5 + call.start.at<int32_t>(1);
                return text_section.contains(tgt) ? tgt : 0;
            }
            else {
                return 0;
            }
        }
    }
}