#pragma once
#include <map>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>
#include <memory>
#include <variant>

#include "core/template_utils.h"

// Forward declare XML types
namespace pugi {
    class xml_node;
    class xml_document;
}

namespace pfm
{
    struct DefField {
        enum class ValueType: int {
            Uint = 0,       // u8, u16, etc.
            Bool = 1,       // b8, b16, b32, etc. (alias for uint)
            Dummy = 2,      // dummy8, dummy16, etc. (alias for u8)
            UnkInt = 3,     // Integer type with unknown signedness (i8, i16, i32, etc.)
            Sint = 4,       // s8, s16, etc.
            Fixstr = 5,     // fixstr/fixstrW (alias for s8/s16)
            Float = 8,      // f32, f64.
            Angle = 9,      // angle32/angle64 (alias for float/double)
        };

        // Field info for a non-array, non-bitfield field (nothing)
        struct Normal {
            constexpr bool operator==(const Normal& o) const noexcept { return true; }
        };

        // Field info for an array field
        struct Array {
            size_t size;
            constexpr explicit Array(size_t size) noexcept : size(size) {};
            constexpr operator size_t() const noexcept { return size; }
            constexpr bool operator==(const Array& o) const noexcept { return o.size == size; }
        };

        // Field info for a bitfield
        struct Bitfield {
            size_t width;
            constexpr explicit Bitfield(size_t width) noexcept : width(width) {};
            constexpr operator size_t() const noexcept { return width; }
            constexpr bool operator==(const Bitfield& o) const noexcept { return o.width == width; }
        };

        /// Name of the field, if any was provided. A field whose name has been set
        /// is considered known, and the mapper will not attempt to deduce its type.
        std::optional<std::string> name;

        /// Type size in bits, i.e. 2 for a u16 or u16 bitfield
        size_t type_size_bytes;
        /// Value type (signed, unsigned, float, etc)
        ValueType type; 
        /// Field information
        std::variant<Normal, Array, Bitfield> info;

        /// If field was parsed from a paramdef file, the <Field> node it came from.
        std::shared_ptr<pugi::xml_node> node;

        inline size_t total_size_bits() const {
            return std::visit(Overloaded {
                [this](Normal) { return 8 * type_size_bytes; },
                [this](Array arr) { return 8 * type_size_bytes * arr.size; },
                [](Bitfield bf) { return bf.width; }
            }, info);
        }

        static std::optional<DefField> from_field_decl(std::string_view decl);

        static std::string offset_name(const std::string& base, size_t byte_offset, std::optional<size_t> bit_offset = {});

        std::string as_fs_type_name(std::string_view unk_int_prefix = "i") const;

        std::string as_struct_field_decl(const std::string& fallback_name, std::string_view unk_int_prefix = "i") const;

        inline bool operator==(const DefField& o) const noexcept {
            return name == o.name && type == o.type && semantically_equal(o);
        }

        inline static ValueType to_base_type(ValueType v) {
            return static_cast<ValueType>(static_cast<int>(v) & ~3);
        }

        /// Checks if this field is semantically equal to another, i.e. represents 
        /// its memory in the same way. 
        inline bool semantically_equal(const DefField& o) const noexcept {
            return to_base_type(type) == to_base_type(o.type) 
                && type_size_bytes == o.type_size_bytes
                && info == o.info;
        }
    };

    struct ParamdefSerializeOptions {
        bool conflict_comments = true;
        std::string unk_int_prefix = "i";
    };

    struct ParamdefParsingOptions {
        /// Regex used to determine if a field should be considered unknown/unamed and thus
        /// susceptible to type overrules via automatic deduction
        std::string unnamed_field_regex = "unk_.*";
        /// Regex used to determine if a field should be considered "untyped memory" and thus 
        /// ignored 
        std::string untyped_memory_regex = "untyped_.*";
        /// If true, will ignore comments (and thus delete them when reserializing) 
        bool ignore_comments = false;
        /// If true, will ignore param types (and thus use the ones in param files instead)
        bool ignore_param_types = false;
    };

    /// A paramdef without field names.
    struct Paramdef {
        std::string param_name;
        std::optional<std::string> param_type;
        
        int data_version = 1;
        bool big_endian = false;
        bool unicode = true;
        int format_version = 100;

        size_t row_size;
        std::map<size_t, DefField> fields;

        /// If loaded via serialize_to_xml, will be set to the parsed document.
        std::shared_ptr<pugi::xml_document> document;

        static std::optional<Paramdef> from_xml(const std::string& path, const ParamdefParsingOptions& options = {});

        /// Creates an XML paramdef from the def.
        void serialize_to_xml(const std::string& path, const ParamdefSerializeOptions& options = {}) const;
    };
}