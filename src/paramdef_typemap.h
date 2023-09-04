#pragma once
#include <map>
#include <optional>
#include <string>

namespace pfm
{
    enum class ValueType {
        Unsigned,
        Signed,
        Float
    };

    struct DefField {
        size_t size_bytes;
        ValueType type;
        int type_certainty = 0;

        std::string as_fs_type_name() const {
            char prefix;
            switch (type) {
                case ValueType::Unsigned:
                    prefix = 'u'; break;
                case ValueType::Signed:
                    prefix = 's'; break;
                case ValueType::Float:
                    prefix = 'f'; break;
            }
            return prefix + std::to_string(8 * size_bytes);
        }

        bool operator ==(const DefField& o) const noexcept {
            return size_bytes == o.size_bytes && type == o.type;
        }
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

        /// Creates an XML paramdef from the def.
        void serialize_to_xml(const std::string& path) const;

        /// Tries to add a field to the typemap. If there is a conflict, returns
        /// iterator to the conflicting field. Otherwise, returns the end iterator.
        /// The second element of the pair indicates if insertion took place.
        std::pair<decltype(fields)::const_iterator, bool> try_add_field(size_t offset, const DefField& field);
    };
}