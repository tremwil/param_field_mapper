#pragma once
#include <map>
#include <optional>
#include <string>

namespace pfm
{
    enum class DefFieldModifier {
        Unsigned,
        Signed,
        Float
    };

    struct DefField {
        uint8_t size_bytes;
        DefFieldModifier modifier;

        std::optional<std::string> as_fs_type_name() {
            char prefix;
            switch (modifier) {
                case DefFieldModifier::Unsigned:
                    prefix = 'u'; break;
                case DefFieldModifier::Signed:
                    prefix = 's'; break;
                case DefFieldModifier::Float:
                    prefix = 'f'; break;
            }
            return prefix + std::to_string(8 * size_bytes);
        }
    };

    class ParamdefTypemap {
        size_t row_size;
        std::map<size_t, DefField> fields;
    };
}