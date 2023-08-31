/**
 * @file arxan_disabler.cpp
 * @note The method used to disable Arxan code restoration patches used 
 * here was shared to me by LukeYui. All credit for finding it goes to them.
 */

#include "arxan_disabler.h"
#include "core/utils.h"

#include <corecrt_wconio.h>
#include <mem/pattern.h>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>

namespace pfm::arxan_disabler
{
    void disable_code_restoration() {
        SPDLOG_INFO("Patching ARXAN code restoration routines... {:x}", (intptr_t)&disable_code_restoration);
        auto module_text = utils::main_module_section<".text">();

        // mov ECX, flag
        // call FUN
        // MOVSS [static_addr], XMM0
        mem::pattern flag_pat { "B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? F3 0F 11 05 ?? ?? ?? ??" };
        
        // JC SHORT_OFFSET
        // LEA REG, [MEM]
        mem::pattern jc_pat { "72 ?? 48 8D ?? ?? ?? ?? ??" };

        auto flag_setters = mem::scan_all(flag_pat, module_text);
        size_t num_patched = 0;

        for (const auto& flag_setter : flag_setters) {
            auto flag_id = flag_setter.at<uint32_t>(1);
            SPDLOG_TRACE("Flag {:08x} set by {:p}", flag_id, flag_setter.as<void*>());

            // make into unconditional jump to skip the code restoration
            if (auto jc = mem::scan(jc_pat, { flag_setter, 0x80 })) {
                utils::patch_memory({ jc.as<uint8_t*>(), 1 }, [jc] {
                    *jc.as<uint8_t*>() = 0xEB;
                });
                num_patched++;
            }
            else SPDLOG_WARN("JC not found for flag {:08x}", flag_id);
        }

        SPDLOG_INFO("Sucessfully patched {}/{} code restoration routines", num_patched, flag_setters.size());
    }
}