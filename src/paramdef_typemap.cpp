#include <regex>
#include <filesystem>

#include "paramdef_typemap.h"
#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

#include "core/utils.h"

using namespace pugi;
using namespace std::string_view_literals;

namespace pfm
{
    std::string DefField::as_fs_type_name() const {
        if (type == ValueType::Signed && is_fixstr) {
            if (elem_size_bits == 8) return "fixstr";
            if (elem_size_bits == 16) return "fixstrW";
        }
        if (type == ValueType::Unsigned && elem_size_bits == 8 && is_dummy8) {
            return "dummy8";
        }
        char prefix;
        switch (type) {
            case ValueType::Unsigned:
                prefix = 'u'; break;
            case ValueType::Signed:
                prefix = 's'; break;
            case ValueType::Float:
                prefix = 'f'; break;
        }
        return prefix + std::to_string(elem_size_bits);
    }

    std::string DefField::as_struct_field_decl(const std::string& fallback_name) const {
        auto fname = name.value_or(fallback_name);
        auto tname =  as_fs_type_name();

        if (array_size.has_value()) return fmt::format("{} {}[{}]", tname, fname, array_size.value());
        else if (is_bitfield) return fmt::format("{} {}: {}", tname, fname, elem_size_bits);
        else return fmt::format("{} {}", tname, fname);
    }

    std::string DefField::offset_name(const std::string& base_name, size_t bit_offset) {
        if (bit_offset % 8) return fmt::format("{}_{:03x}_{}", base_name, bit_offset / 8, bit_offset % 8);
        else return fmt::format("{}_{:03x}", base_name, bit_offset / 8);
    }
    
    std::optional<ParamdefTypemap> ParamdefTypemap::from_xml(const std::string &path, const ParamdefParsingOptions& options) {
        std::regex field_regex { 
            R"(^([\w\d_]+)\s+([\w\d_]+)\s*(?:\[([\w\d]+)\]|:\s*([\w\d]+))?\s*(=.*)?$)" 
        };

        std::regex r_unknown(options.unnamed_field_regex), r_untyped(options.untyped_memory_regex);

        xml_document doc;
        xml_parse_result result = doc.load_file(path.c_str(), 
            options.ignore_comments ? parse_default : parse_comments);
        
        if (!result) {
            SPDLOG_ERROR("Failed to parse {}: {}", path, result.description());
            return std::nullopt;
        }

        auto pdef_node = doc.child("PARAMDEF");
        if (pdef_node.empty()) {
            SPDLOG_ERROR("{} does not contain a PARAMDEF node", path);
            return std::nullopt;
        }

        ParamdefTypemap def { 
            .param_name = std::filesystem::path(path).stem().string()
        };

        if (auto node = pdef_node.child("ParamType")) {
            if (!options.ignore_param_types) def.param_type = node.text().as_string();
        }
        if (auto node = pdef_node.child("DataVersion")) {
            def.data_version = node.text().as_int(1);
        }
        if (auto node = pdef_node.child("BigEndian")) {
            def.big_endian = node.text().as_bool(false);
        }
        if (auto node = pdef_node.child("Unicode")) {
            def.unicode = node.text().as_bool(true);
        }
        if (auto node = pdef_node.child("FormatVersion")) {
            def.format_version = node.text().as_int(100);
        }

        auto fields_node = pdef_node.child("Fields");
        if (!fields_node) {
            SPDLOG_ERROR("{} has no Fields node", path);
            return std::nullopt;
        };

        size_t bit_size = 0;
        std::optional<size_t> last_bitfield_start;
        for (auto node : fields_node.children()) {
            if (node.type() != xml_node_type::node_element) continue;

            if (node.name() != "Field"sv) {
                SPDLOG_WARN("Field node \"{}\" in {} is not named \"Field\", ignoring", node.name(), path);
                continue;
            }
            auto field_decl = node.attribute("Def").value();
            if (field_decl == ""sv) {
                SPDLOG_WARN("Ignoring field with missing Def attribute in {}", path);
                continue;
            }

            std::cmatch match;
            if (!std::regex_match(field_decl, match, field_regex)) {
                SPDLOG_ERROR("Invalid field declaration \"{}\" in {}", field_decl, path);
                continue;
            }

            DefField field {
                .node = node,
            };

            bool is_untyped = false;
            try {
                auto type = match.str(1);
                if (type == "fixstr") {
                    field.is_fixstr = true;
                    field.type_size_bits = 8;
                    field.type = ValueType::Signed;
                }
                else if (type == "fixstrW") {
                    field.is_fixstr = true;
                    field.type_size_bits = 16;
                    field.type = ValueType::Signed;
                }
                else if (type == "dummy8") {
                    field.is_dummy8 = true;
                    field.type_size_bits = 8;
                    field.type = ValueType::Unsigned;
                }
                else if (type.length() > 1) {
                    if (type[0] == 'u') field.type = ValueType::Unsigned;
                    else if (type[0] == 's') field.type = ValueType::Signed;
                    else if (type[0] == 'f') field.type = ValueType::Float;
                    else {
                        SPDLOG_ERROR("Unknown field type for def \"{}\" in {}", field_decl, path);
                        return std::nullopt;
                    }
                    field.type_size_bits = std::stoull(type.substr(1), nullptr);
                }

                auto name = match.str(2);
                if (std::regex_match(name, r_untyped))
                    is_untyped = true;
                else if (!std::regex_match(name, r_unknown)) {
                    field.name = name;
                }

                if (!match.str(3).empty()) {
                    field.array_size = std::stoull(match.str(3), nullptr, 0);
                }
                if (!match.str(4).empty()) {
                    field.is_bitfield = true;
                    field.elem_size_bits = std::stoull(match.str(4), nullptr, 0);
                }
                else {
                    field.elem_size_bits = field.type_size_bits;
                }
            } catch (std::invalid_argument& ex) { 
                SPDLOG_ERROR("Invalid number in field \"{}\" (param {}): ", field_decl, path);
                return std::nullopt;
            }

            // If field was customized, set it in stone
            field.type_certainty = 
                (field.name.has_value() || field.is_bitfield || field.is_fixstr || field.array_size.value_or(1) > 1) ? 
                INT_MAX : node.attribute("TypeConfidence").as_int(0);

            auto bit_offset = bit_size;
            if (last_bitfield_start.has_value()) {
                if (!field.is_bitfield) {
                    bit_offset = utils::align_up(bit_size, 8);
                    last_bitfield_start = std::nullopt;
                }
            }
            else if (field.is_bitfield) {
                last_bitfield_start = bit_offset;
            }
            
            bit_size = bit_offset + field.size_bits();
            if (!is_untyped) def.fields[bit_offset] = field;
        }
        def.row_size = utils::align_up(bit_size, 8) / 8;
        def.document = std::make_shared<xml_document>(std::move(doc));
        return def;
    }

    void ParamdefTypemap::serialize_to_xml(const std::string& path, const ParamdefSerializeOptions& options) const {
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

        auto pad_if_required = [&](size_t offset) {
            if (prv_field_end >= offset) return;

            auto prv_byte = utils::align_up(prv_field_end, 8);
            if (prv_byte != prv_field_end) {
                auto filled = std::min(prv_byte, offset);
                auto n = fmt::format("dummy8 {}: {}", DefField::offset_name("untyped", filled), filled - prv_field_end);
                xml_fields.append_child("Field").append_attribute("Def").set_value(n.c_str());
            }
            if (prv_byte >= offset) return;
            auto last_byte = utils::align_down(offset, 8);
            if (last_byte != prv_byte) {
                auto n = fmt::format("dummy8 {}[{}]", DefField::offset_name("untyped", prv_byte), (last_byte - prv_byte) / 8);
                xml_fields.append_child("Field").append_attribute("Def").set_value(n.c_str());
            }
            if (offset > last_byte) {
                auto n = fmt::format("dummy8 {}: {}", DefField::offset_name("untyped", last_byte), offset - last_byte);
                xml_fields.append_child("Field").append_attribute("Def").set_value(n.c_str());     
            }
        };

        for (const auto& [offset, field] : fields) {
            // Insert padding if necessary
            pad_if_required(offset);

            // Make comment that contains instructions that accessed this field
            xml_node comment_node;
            if (field.node && field.node->previous_sibling().type() == xml_node_type::node_comment) {
                comment_node = xml_fields.append_copy(field.node->previous_sibling());
            }
            else if (!field.accesses.empty()) {
                comment_node = xml_fields.append_child(xml_node_type::node_comment);
            }
            if (comment_node && options.store_accesses) {
                std::string as_str = comment_node.value(), final_val = as_str;
                for (const auto& access : field.accesses) {
                    auto addr = fmt::format("{:x}", access);
                    if (as_str.find(addr) == std::string::npos) {
                        final_val += " " + addr;
                    }
                }
                comment_node.set_value(final_val.c_str());
            }
            
            xml_node node = field.node ? xml_fields.append_copy(*field.node) : xml_fields.append_child("Field");
            auto def_attr = node.attribute("Def");
            if (!def_attr) def_attr = node.append_attribute("Def");

            def_attr.set_value(field.as_struct_field_decl(DefField::offset_name("unk", offset)).c_str());

            // If the type isn't set in stone, add type confidence info
            if (options.store_type_confidence && field.type_certainty < INT_MAX) {
                auto confidence = node.attribute("TypeConfidence");
                if (!confidence) confidence = node.append_attribute("TypeConfidence");
                confidence.set_value(field.type_certainty);
            }
            else {
                node.remove_attribute("TypeConfidence");
            }

            prv_field_end = offset + field.size_bits();
        }
        pad_if_required(8 * row_size);
        doc.save_file(path.c_str());
    }

    std::pair<decltype(ParamdefTypemap::fields)::iterator, DefAddFieldResult>
    ParamdefTypemap::try_add_field(size_t offset, const DefField& field) {
        auto next_field = fields.upper_bound(offset);
        auto prev_field = next_field == fields.begin() ? 
            fields.end() : std::prev(next_field);

        auto intersects_field = [&](auto& it) {
            if (it == fields.end()) {
                return false;
            }
            int64_t max_start = std::max(it->first, offset);
            int64_t min_end = std::min(it->first + it->second.size_bits(), offset + field.size_bits());
            return min_end - max_start > 0;
        };
        
        if (prev_field != fields.end() && prev_field->first == offset) {
            auto& f = prev_field->second;
            if (f.type == field.type && field.size_bits() == f.size_bits()) {
                f.type_certainty = std::max(f.type_certainty , field.type_certainty);
                return std::make_pair(prev_field, DefAddFieldResult::AlreadyExists);
            }
            // In this case, favor this field but only if it doesn't intersect the next one
            else if (field.type_certainty > f.type_certainty) {
                if (intersects_field(next_field))
                    return std::make_pair(next_field, DefAddFieldResult::ConflictRejected);

                auto ac = std::move(f.accesses); // TODO: Fix stupid
                f = field;
                f.accesses = std::move(ac);

                return std::make_pair(prev_field, DefAddFieldResult::ConflictAccepted);
            }
            // If certainty is equal, favor the smaller field
            else if (field.type_certainty == f.type_certainty && field.size_bits() < f.size_bits()) {
                auto ac = std::move(f.accesses); // TODO: Fix stupid
                f = field;
                f.accesses = std::move(ac);
                return std::make_pair(prev_field, DefAddFieldResult::ConflictAccepted);
            }
            else return std::make_pair(prev_field, DefAddFieldResult::ConflictRejected);
        }

        if (intersects_field(prev_field)) 
            return std::make_pair(prev_field, DefAddFieldResult::ConflictRejected);

        if (intersects_field(next_field))
            return std::make_pair(next_field, DefAddFieldResult::ConflictRejected);
        
        auto it = fields.emplace(std::make_pair(offset, field)).first;
        return std::make_pair(it, DefAddFieldResult::Added);
    }
}