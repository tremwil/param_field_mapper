#include <regex>
#include <filesystem>

#include "xml_paramdef.hpp"

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>
#include <pugixml/pugixml.hpp>

#include "core/utils.h"

using namespace pugi;
using namespace std::string_view_literals;

namespace pfm
{
    std::string DefField::as_fs_type_name(std::string_view unk_int_prefix) const {
        std::string bits = std::to_string(8 * type_size_bytes);
        switch (type) {
            case ValueType::Fixstr: return type_size_bytes == 1 ? "fixstr" : "fixstrW";
            case ValueType::Angle: return "angle" + bits;
            case ValueType::Dummy: return "dummy" + bits;
            case ValueType::Float: return "f" + bits;
            case ValueType::Uint: return "u" + bits;
            case ValueType::Bool: return "b" + bits;
            case ValueType::Sint: return "s" + bits;
            case ValueType::UnkInt: return unk_int_prefix.data() + bits;
        }
    }

    std::string DefField::as_struct_field_decl(const std::string& fallback_name, std::string_view unk_int_prefix) const {
        auto fname = name.value_or(fallback_name);
        auto tname = as_fs_type_name(unk_int_prefix);

        return std::visit(Overloaded {
            [&](Normal) { return fmt::format("{} {}", tname, fname); },
            [&](Array arr) { return fmt::format("{} {}[{}]", tname, fname, arr.size); },
            [&](Bitfield bf) { return fmt::format("{} {}: {}", tname, fname, bf.width); }
        }, info);
    }

    std::string DefField::offset_name(const std::string& base_name, size_t byte_offset, std::optional<size_t> bit_offset) {
        if (bit_offset) return fmt::format("{}_{:03x}_{}", base_name, byte_offset, *bit_offset);
        else return fmt::format("{}_{:03x}", base_name, byte_offset);
    }

    std::optional<DefField> DefField::from_field_decl(std::string_view decl) {
        static const std::regex field_regex { 
            R"(^([\w\d_]+)\s+([\w\d_]+)\s*(?:\[([\w\d]+)\]|:\s*([\w\d]+))?\s*(=.*)?$)" 
        };

        std::cmatch match;
        if (!std::regex_match(decl.data(), match, field_regex)) {
            return std::nullopt;
        }

        size_t tsz = 0;
        auto ts = match.str(1);
        auto tsv = std::string_view { ts };
        ValueType type;
        
        if (tsv == "fixstr") { type = ValueType::Fixstr; tsz = 1; tsv = tsv.substr(6); }
        else if (tsv == "fixstrW") { type = ValueType::Fixstr; tsz = 2; tsv = tsv.substr(7); }
        else if (tsv.starts_with("angle")) { type = ValueType::Angle; tsv = tsv.substr(5); }
        else if (tsv.starts_with("dummy")) { type = ValueType::Dummy; tsv = tsv.substr(5); }
        else if (tsv.starts_with('b')) { type = ValueType::Bool; tsv = tsv.substr(1); }
        else if (tsv.starts_with('u')) { type = ValueType::Uint; tsv = tsv.substr(1); }
        else if (tsv.starts_with('s')) { type = ValueType::Sint; tsv = tsv.substr(1); }
        else if (tsv.starts_with('f')) { type = ValueType::Float; tsv = tsv.substr(1); }
        else return std::nullopt;

        if (tsz); // if type size was already set, do not check it
        // Do it this way because we don't want to accept garabge like `u73`  
        else if (tsv == "8") { tsz = 1; }
        else if (tsv == "16") { tsz = 2; }
        else if (tsv == "32") { tsz = 4; }
        else if (tsv == "64") { tsz = 8; }
        else return std::nullopt;

        auto name = match.str(2);
        std::variant<Normal, Array, Bitfield> info;

        if (!match.str(3).empty()) {
            size_t sz = ::strtoull(match.str(3).c_str(), nullptr, 0);
            if (sz == 0) return std::nullopt;
            info = Array(sz);
        }
        else if (!match.str(4).empty()) {
            size_t w = ::strtoull(match.str(4).c_str(), nullptr, 0);
            if (w == 0 || w > 8 * tsz) return std::nullopt;
            info = Bitfield(w);
        }

        return DefField {
            .name = name,
            .type_size_bytes = tsz,
            .type = type,
            .info = info
        };
    }
    
    std::optional<Paramdef> Paramdef::from_xml(const std::string &path, const ParamdefParsingOptions& options) {
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

        Paramdef def { 
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

        size_t ibyte = 0, ibit = 0, bitfield_tsz = 0;

        for (auto node : fields_node.children()) {
            if (node.type() != xml_node_type::node_element) continue;

            if (node.name() != "Field"sv) {
                SPDLOG_WARN("Field node \"{}\" in {} is not named \"Field\", ignoring", node.name(), path);
                continue;
            }
            auto field_decl = node.attribute("Def").value();
            if (field_decl == ""sv) {
                SPDLOG_ERROR("Field with missing Def attribute in {}", path);
                return std::nullopt;
            }

            auto field_opt = DefField::from_field_decl(field_decl);
            if (!field_opt) {
                SPDLOG_ERROR("Invalid field declaration \"{}\" in {}", field_decl, path);
                return std::nullopt;
            }
            field_opt->node = std::make_shared<xml_node>(node);

            bool is_untyped_padding = !std::holds_alternative<DefField::Bitfield>(field_opt->info) 
                && std::regex_match(*field_opt->name, r_untyped);

            if (std::regex_match(*field_opt->name, r_unknown)) {
                field_opt->name = std::nullopt;
            }

            auto bit_ofs = 8 * ibyte + ibit;
            if (const auto bf = std::get_if<DefField::Bitfield>(&field_opt->info)) {
                if (!bitfield_tsz) {
                    ibit = 0; bitfield_tsz = field_opt->type_size_bytes;
                }
                // Bitfield base type has different size of field goes past base type boundary: 
                // start a new register as per MSVC bitfield rules
                if (field_opt->type_size_bytes != bitfield_tsz || ibit + bf->width > 8 * bitfield_tsz) {
                    ibyte += bitfield_tsz;
                    bitfield_tsz = field_opt->type_size_bytes;
                    ibit = 0;
                }
                ibit += bf->width;
            }
            else {
                ibyte += bitfield_tsz;
                bitfield_tsz = 0;
                ibyte += field_opt->total_size_bits() / 8;
            }

            if (!is_untyped_padding) {
                def.fields[bit_ofs] = *field_opt;
            }
        }
        def.row_size = ibyte + bitfield_tsz;
        def.document = std::make_shared<xml_document>(std::move(doc));
        return def;
    }

    void Paramdef::serialize_to_xml(const std::string& path, const ParamdefSerializeOptions& options) const {
        xml_document doc;

        auto paramdef = doc.append_child("PARAMDEF");
        paramdef.append_attribute("XmlVersion").set_value(2);
        paramdef.append_child("ParamType").text().set(param_type.value_or(param_name).c_str());
        paramdef.append_child("DataVersion").text().set(data_version);
        paramdef.append_child("BigEndian").text().set(big_endian ? "True" : "False");
        paramdef.append_child("Unicode").text().set(unicode ? "True" : "False");
        paramdef.append_child("FormatVersion").text().set(format_version);

        auto xml_fields = paramdef.append_child("Fields");

        size_t bf_start = 0, prv_ofs_end = 0, bitfield_bit_width = 0;
        auto pad_if_required = [&](size_t offset, size_t new_bitfield_tsz) {
            // Bit padding
            if (bitfield_bit_width) {
                if (offset - bf_start > bitfield_bit_width) {
                    auto w = prv_ofs_end - bf_start;
                    auto n = fmt::format("dummy{} {}: {}", bitfield_bit_width, 
                        DefField::offset_name("untyped", bf_start / 8, prv_ofs_end - bf_start), w);
                    
                    xml_fields.append_child("Field").append_attribute("Def").set_value(n.c_str());
                    bf_start += bitfield_bit_width;
                }
            }
            else if (new_bitfield_tsz) {
                bf_start = offset;
                bitfield_bit_width = 8 * new_bitfield_tsz;
            }

            if (offset > prv_ofs_end) {
                auto n = fmt::format("dummy8 {}[{}]", DefField::offset_name("untyped", prv_ofs_end / 8), (offset - prv_ofs_end) / 8);
                xml_fields.append_child("Field").append_attribute("Def").set_value(n.c_str());
            }
        };

        for (const auto& [offset, field] : fields) {
            // Insert padding if necessary
            pad_if_required(offset, std::holds_alternative<DefField::Bitfield>(field.info) ? field.type_size_bytes : 0);
            prv_ofs_end = offset + field.total_size_bits();

            // Keep field comments
            if (field.node && field.node->previous_sibling().type() == xml_node_type::node_comment) {
                xml_fields.append_copy(field.node->previous_sibling());
            }
            
            xml_node node = field.node ? xml_fields.append_copy(*field.node) : xml_fields.append_child("Field");
            auto def_attr = node.attribute("Def");
            if (!def_attr) def_attr = node.append_attribute("Def");

            std::optional<size_t> bit_ofs = bitfield_bit_width ? std::optional(offset - bf_start) : std::nullopt;
            def_attr.set_value(field.as_struct_field_decl(
                DefField::offset_name("unk", offset / 8, bit_ofs), options.unk_int_prefix).c_str());
        }
        pad_if_required(8 * row_size, 0);
        doc.save_file(path.c_str());
    }
}