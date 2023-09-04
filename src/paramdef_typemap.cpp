#include "paramdef_typemap.h"
#include <dependencies/pugixml/pugixml.hpp>
#include <spdlog/fmt/fmt.h>

using namespace pugi;

namespace pfm
{
    void ParamdefTypemap::serialize_to_xml(const std::string& path) const {
        xml_document doc;

        auto paramdef = doc.append_child("PARAMDEF");
        paramdef.append_attribute("XmlVersion").set_value(2);
        paramdef.append_child("ParamType").text().set(param_type.value_or(param_name).c_str());
        paramdef.append_child("DataVersion").text().set(data_version);
        paramdef.append_child("BigEndian").text().set(big_endian ? "True" : "False");
        paramdef.append_child("Unicode").text().set(unicode ? "True" : "False");
        paramdef.append_child("FormatVersion").text().set(format_version);

        auto xml_fields = paramdef.append_child("Fields");

        size_t prv_field_end = 0;
        for (const auto& [offset, field] : fields) {
            // Insert padding if necessary
            if (prv_field_end < offset) {
                auto fname = fmt::format("dummy8 untyped_{:03x}[{}]", prv_field_end, offset - prv_field_end);
                xml_fields.append_child("Field").append_attribute("Def").set_value(fname.c_str());
            }

            auto fname = fmt::format("{} unk_{:03x}", field.as_fs_type_name(), offset);
            xml_fields.append_child("Field").append_attribute("Def").set_value(fname.c_str());
            prv_field_end = offset + field.size_bytes;
        }
        if (prv_field_end < row_size) {
            auto fname = fmt::format("dummy8 untyped_{:03x}[{}]", prv_field_end, row_size - prv_field_end);
            xml_fields.append_child("Field").append_attribute("Def").set_value(fname.c_str());
        }
        doc.save_file(path.c_str());
    }

    std::pair<decltype(ParamdefTypemap::fields)::const_iterator, bool>
    ParamdefTypemap::try_add_field(size_t offset, const DefField& field) {
        auto next_field = fields.upper_bound(offset);
        auto prev_field = next_field == fields.begin() ? 
            fields.end() : std::prev(next_field);

        auto intersects_field = [&](auto& it) {
            if (it == fields.end()) {
                return false;
            }
            int64_t max_start = std::max(it->first, offset);
            int64_t min_end = std::min(it->first + it->second.size_bytes, offset + field.size_bytes);
            return min_end - max_start > 0;
        };
        
        if (prev_field != fields.end() && prev_field->first == offset) {
            auto& f = prev_field->second;
            if (f.type == field.type) {
                f.type_certainty = std::max(f.type_certainty , field.type_certainty);
                return std::make_pair(fields.end(), false);
            }
            // In this case, favor this field but only if it doesn't intersect the next one
            else if (field.type_certainty > f.type_certainty) {
                if (intersects_field(next_field))
                    return std::make_pair(next_field, false);

                f = field;
                return std::make_pair(fields.end(), true);
            }
            // If certainty is equal, favor the smaller field
            else if (field.type_certainty == f.type_certainty && field.size_bytes < f.size_bytes) {
                f = field;
                return std::make_pair(fields.end(), true);
            }
            else return std::make_pair(prev_field, false);
        }

        if (intersects_field(prev_field)) 
            return std::make_pair(prev_field, false);

        if (intersects_field(next_field))
            return std::make_pair(next_field, false);
        
        fields[offset] = field;
        return std::make_pair(fields.end(), true);
    }
}