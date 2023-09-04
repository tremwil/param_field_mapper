#include "fd4_singleton.h"
#include "mem/pattern.h"
#include "mem/module.h"

#include <algorithm>

std::optional<std::string_view> get_printable_cstr_at(void* addr, size_t min_len, size_t max_len)
{
    // Check if string is null terminated
    auto len = strnlen((char*)addr, max_len);
    if (len < min_len || len == max_len) return std::nullopt;

    std::string_view str((char*)addr, len);

    // Check if string is printable
    if (std::any_of(str.begin(), str.end(), [](char c) { return c < '!' || c > 'z'; }))
        return std::nullopt;

    return str;
}

namespace pfm
{
    void** FD4SingletonFinder::address_of(const std::string_view class_name) const
    {
        auto i = singleton_addresses.find(class_name);
        return (i == singleton_addresses.end()) ? nullptr : i->second;
    }

    void* FD4SingletonFinder::instance_of(const std::string_view class_name) const
    {
        auto i = singleton_addresses.find(class_name);
        return (i == singleton_addresses.end()) ? nullptr : *i->second;
    }

    FD4SingletonFinder::FD4SingletonFinder()
    {        
        mem::pattern pat(
            "48 8b ? ? ? ? ? "  //  0 MOV REG, [MEM]
            "48 85 ? "          //  7 TEST REG, REG
            "75 2e "            // 10 JNZ +2e
            "48 8d 0d ? ? ? ? " // 12 LEA RCX, [runtime_class_metadata]
            "e8 ? ? ? ? "       // 19 CALL get_singleton_name
            "4c 8b c8 "         // 24 MOV R9, RAX
            "4c 8d 05 ? ? ? ? " // 27 LEA R8, [%s:未初期化のシングルトンにアクセスしました]
            "ba ?? 00 00 00 "   // 34 MOV EDX, ??
            "48 8d 0d ? ? ? ? " // 39 LEA RCX, [file_path]
            "e8 ? ? ? ?"        // 46 CALL log_thunk
        );
        mem::default_scanner scanner(pat);

        auto text_section = utils::main_module_section<".text">();
        auto data_section = utils::main_module_section<".data">();
        auto rdata_section = utils::main_module_section<".rdata">();

        for (auto candidate : scanner.scan_all(text_section)) {
            // Check static address in module
            auto static_addr = candidate.add(7 + *candidate.add(3).as<int32_t*>());
            if (!data_section.contains(static_addr)) continue;

            // Check if FD4Singleton header path is there
            auto filepath_ptr = candidate.add(46 + *candidate.add(42).as<int32_t*>());
            if (!rdata_section.contains(filepath_ptr)) continue;

            // Check if FD4Singleton path string is valid
            auto mabye_path = get_printable_cstr_at(filepath_ptr.as<void*>(), 10, 256);
            if (!mabye_path.has_value() || !mabye_path.value().ends_with("FD4Singleton.h"))
                continue;

            // Check if runtime_class_metadata is in range
            auto runtime_class_metadata = candidate.add(19 + *candidate.add(15).as<int32_t*>()).as<void*>();
            if (!data_section.contains(runtime_class_metadata)) continue;

            // Check if get_singleton_name is in range
            auto get_singleton_name = candidate.add(24 + *candidate.add(20).as<int32_t*>())
                .as<const char*(*)(void*)>();

            if (!text_section.contains(get_singleton_name)) continue;

            // Try to query the name
            if (auto name_ptr = get_singleton_name(runtime_class_metadata)) {
                auto name = std::string_view(name_ptr);
                auto i = name.rfind("::");
                auto no_namespace_name = name.substr(i == -1 ? 0 : i + 2);

                auto prv_entry = singleton_addresses.find(no_namespace_name);
                if (prv_entry == singleton_addresses.end()) {
                    SPDLOG_TRACE("{} -> {:x}", no_namespace_name, static_addr.as<uintptr_t>());
                    singleton_addresses[no_namespace_name] = static_addr.as<void**>();
                }
                else if (prv_entry->second != static_addr.as<void**>()) {
                    SPDLOG_WARN("Address mismatch for singleton {} : {:p} vs {:p}",
                        no_namespace_name, (void*)prv_entry->second, static_addr.as<void*>());
                }
            }
        }
    }
}