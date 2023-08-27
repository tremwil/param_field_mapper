#pragma once
#include "fst/dlut.h"
#include <concepts>
#include <optional>

namespace pfm
{
    template<class Offset>
    struct ParamRow {
        uint32_t id;
        Offset data_offset;
        Offset name_offset;
    };

    struct ParamFile {
        uint32_t strings_offset;
        uint16_t short_data_offset;
        uint16_t unk06;
        uint16_t paramdef_data_version;
        uint16_t row_count;

#pragma pack(push, 4)
        union 
        {
            char param_type_buffer[0x20];
            struct 
            {
                uint32_t pad_0c;
                uint64_t param_type_offset;
                uint64_t pad_14;
            };
        };
#pragma pack(pop)

        bool is_big_endian;
        uint8_t format_flags_2d;
        uint8_t format_flags_2e;
        uint8_t paramdef_format_version;

        inline size_t id_table_offset() const {
            return ((format_flags_2d & 3) == 3 || (format_flags_2d & 4)) ? 0x40 : 0x30;
        }

        inline bool is_64_bit() const {
            return format_flags_2d & 4;
        }

        inline bool is_unicode() const {
            return format_flags_2e & 1;
        }

        inline const char* param_type() const {
            if (format_flags_2d & 0x80) {
                return (const char*)this + param_type_offset;
            }
            else {
                return param_type_buffer;
            }
        }

        template<class Offset>
        ParamRow<Offset>* id_table() const {
            return (ParamRow<Offset>*)((uint8_t*)this + id_table_offset());
        }

        inline uint32_t row_id_at(size_t index) const {
            return is_64_bit() ? id_table<uint64_t>()[index].id : id_table<uint32_t>()[index].id;
        }

        inline void* row_data_at(size_t index) const {
            return (uint8_t*)this + (is_64_bit() ? 
                id_table<uint64_t>()[index].data_offset : 
                id_table<uint32_t>()[index].data_offset);
        }

        inline std::optional<size_t> row_size() const {
            if (this->row_count == 0) return std::nullopt;

            auto data_end = (format_flags_2d & 0x80) ? param_type_offset : strings_offset;
            return (uint8_t*)this + data_end - (uint8_t*)row_data_at(this->row_count - 1);
        }

        template<class Char>
        inline const Char* row_name_at(size_t index) const {
            auto offset = is_64_bit() ? 
                id_table<uint64_t>()[index].name_offset : 
                id_table<uint32_t>()[index].name_offset;

            return (const Char*)((uint8_t*)this + offset);
        }

        template<class Char, std::invocable<uint32_t, void*, const Char*> F>
        inline void for_each_row(F fun) const {
            if (is_64_bit()) {
                auto tbl = id_table<uint64_t>();
                for (int i = 0; i < row_count; i++) {
                    void* data = (uint8_t*)this + tbl[i].data_offset;
                    auto name = (const Char*)((uint8_t*)this + tbl[i].name_offset);
                    fun(tbl[i].id, data, name); 
                }
            }
            else {
                auto tbl = id_table<uint32_t>();
                for (int i = 0; i < row_count; i++) {
                    void* data = (uint8_t*)this + tbl[i].data_offset;
                    auto name = (const Char*)((uint8_t*)this + tbl[i].name_offset);
                    fun(tbl[i].id, data, name); 
                }
            }
        }
    };
}