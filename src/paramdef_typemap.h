#pragma once
#include <map>
#include <optional>
#include <string>
#include <vector>
#include <memory>

#include "pugixml/pugixml.hpp"

namespace pfm
{
    enum class ValueType {
        Unsigned, // u8, u16, etc.
        Signed,   // s8, s16, etc.
        Float,    // f32, f64, etc.
    };

    struct DefField {
        std::optional<std::string> name; /// Name of the field, if any was provided.
        std::vector<intptr_t> accesses; /// Instructions that accessed the field. 

        /// Type size in bits, i.e. 16 for a u16 bitfield
        size_t type_size_bits;
        /// Bit width of the element, i.e. 5 for `u32 bitfield: 5` 
        size_t elem_size_bits;
        /// Value type (signed, unsigned, float, str)
        ValueType type; 
        /// Field is a bitfield
        bool is_bitfield = false;
        /// For compat with existing defs; remaps s8 to fixstr and s16 to fixstrW 
        bool is_fixstr = false;
        /// For compat with existing defs; remaps u8 to dummy8 
        bool is_dummy8 = false;

        std::optional<size_t> array_size; /// If set, def is an array with a certain size.

        /// If field was parsed from a paramdef file, the <Field> node it came from.
        std::optional<pugi::xml_node> node;

        /// Used to resolve type conflicts. Arbitrary scale of how confident the type resolver is.
        int type_certainty = 0;

        inline size_t size_bytes() const {
            return array_size.value_or(1) * elem_size_bits / 8; 
        }

        inline size_t size_bits() const {
            return array_size.value_or(1) * elem_size_bits; 
        }

        inline size_t type_size_bytes() const {
            return type_size_bits / 8;
        }

        static std::string offset_name(const std::string& base, size_t bit_offset);

        std::string as_fs_type_name() const;

        std::string as_struct_field_decl(const std::string& fallback_name) const;

        inline bool operator ==(const DefField& o) const noexcept {
            return type_size_bits == o.type_size_bits 
                && elem_size_bits == o.elem_size_bits 
                && type == o.type 
                && array_size == o.array_size
                && name == o.name;
        }

        /// Checks if this field is semantically equal to another, i.e. represents 
        /// its memory in the same way. 
        inline bool semantically_equal(const DefField& o) const noexcept {
            return elem_size_bits == o.elem_size_bits 
                && type == o.type 
                && array_size.value_or(1) == o.array_size.value_or(1);
        }
    };

    struct ParamdefSerializeOptions {
        bool store_accesses = true;
        bool store_type_confidence = true;
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

    
    enum class DefAddFieldResult {
        Added,
        AlreadyExists,
        ConflictRejected,
        ConflictAccepted
    };

    /// A paramdef without field names.
    struct ParamdefTypemap {
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

        static std::optional<ParamdefTypemap> from_xml(const std::string& path, const ParamdefParsingOptions& options = {});

        /// Creates an XML paramdef from the def.
        void serialize_to_xml(const std::string& path, const ParamdefSerializeOptions& options = {}) const;

        /// Tries to add a field to the typemap. If there is a conflict, returns
        /// iterator to the conflicting field. Otherwise, returns the end iterator.
        /// The second element of the pair indicates if insertion took place.
        std::pair<decltype(fields)::iterator, DefAddFieldResult> 
        try_add_field(size_t bit_offset, const DefField& field);
    };
}