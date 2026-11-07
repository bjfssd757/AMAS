#include <AMAStatic/binary.hpp>
#include <fstream>
#include <glaze/glaze.hpp>
#include <spdlog/spdlog.h>

namespace AMS = AMAStatic;

int AMS::Binary::Analyse() {
    if (!rz_core_file_open(m_core, m_path.c_str(), 0, 0)) {
        rz_core_free(m_core);
        return -1;
    }
    rz_core_bin_load(m_core, nullptr, 0);


    std::string imports_raw = get_json_rz(_INT_RZ_CMD_IMPORT_TABLE_JSON);
    auto err = glz::read_json(m_imports, imports_raw);
    if (err) throw std::runtime_error("Could not parse imports json.");

    std::string strings_raw = get_json_rz(_INT_RZ_CMD_STRINGS_JSON);
    err = glz::read_json(m_strings, strings_raw);
    if (err) {
        std::string formatted_err = glz::format_error(err, strings_raw);
        spdlog::error("[Glaze Error Strings]: " + formatted_err);
        throw std::runtime_error(
            "Could not parse strings json. Reason: "
            + std::string(err.custom_error_message));
    }

    std::string bi_raw = get_json_rz(_INT_RZ_CMD_BASE_INFO_JSON);
    err = glz::read_json(m_base_info, bi_raw);
    if (err) {
        std::string formatted_err = glz::format_error(err, bi_raw);
        spdlog::error("[Glaze Error BaseInfo]: " + formatted_err);
        throw std::runtime_error(
            "Could not parse base info json. Reason: "
            + std::string(err.custom_error_message));
    }

    std::string symb_raw = get_json_rz(_INT_RZ_CMD_SYMBOL_TABLE_JSON);
    err = glz::read_json(m_symbols, symb_raw);
    if (err) {
        std::string formatted_err = glz::format_error(err, symb_raw);
        spdlog::error("[Glaze Error Symbols]: " + formatted_err);
        throw std::runtime_error(
            "Could not parse symbols json. Reason: "
            + std::string(err.custom_error_message));
    }

    std::string sec_raw = get_json_rz(_INT_RZ_CMD_SECTIONS_JSON);
    err = glz::read_json(m_sections, sec_raw);
    if (err) {
        std::string formatted_err = glz::format_error(err, sec_raw);
        spdlog::error("[Glaze Error Sections]: " + formatted_err);
        throw std::runtime_error(
            "Could not parse sections json. Reason: "
            + std::string(err.custom_error_message));
    }


    return 0;
}

std::span<const uint8_t> AMS::Binary::Raw(uint64_t addr, size_t len) {
    std::vector<uint8_t> buffer(len);
    if (!rz_io_read_at(m_core->io, addr, buffer.data(), len)) {
        return {};
    }

    m_file_raw = buffer;
    return m_file_raw;
}

std::span<const uint8_t> AMS::Binary::Raw() {
    RzIODesc* desc = rz_io_desc_get(m_core->io, m_base_info.core.fd);
    if (!desc) return {};

    ut64 to_read = rz_io_desc_size(desc);
    if (to_read == 0) return {};

    return Raw(0, to_read);
}

const AMS::BaseInfo& AMS::Binary::GetBaseInfo() {
    return m_base_info;
}

std::vector<AMS::ImportData> AMS::Binary::GetImports() {
    return m_imports;
}

std::vector<AMS::StringData> AMS::Binary::GetStrings() {
    return m_strings;
}

std::string AMS::Binary::GetMD5(size_t read_chunks_size) {
    std::ifstream file(m_path, std::ios::binary);
    if (!file) {
        return "Error: Could not open file.";
    }

    MD5 md5;

    std::vector<char> buffer(read_chunks_size);

    while (file.good()) {
        file.read(buffer.data(), read_chunks_size);
        std::streamsize bytes_read = file.gcount();

        if (bytes_read > 0) {
            md5.add(buffer.data(), static_cast<size_t>(bytes_read));
        }
    }
    
    return md5.getHash();
}

std::string AMS::Binary::GetSHA256(size_t read_chunks_size) {
    std::ifstream file(m_path, std::ios::binary);
    if (!file) {
        return "Error: Could not open file.";
    }

    SHA256 sha256;

    std::vector<char> buffer(read_chunks_size);

    while (file.good()) {
        file.read(buffer.data(), read_chunks_size);
        std::streamsize bytes_read = file.gcount();

        if (bytes_read > 0) {
            sha256.add(buffer.data(), static_cast<size_t>(bytes_read));
        }
    }
    
    return sha256.getHash();
}

AMS::ExecFormat AMS::Binary::GetExecutableFormat() {
    return m_base_info.ParseExecFormat();
}

AMS::Arch AMS::Binary::GetArch() {
    return m_base_info.ParseArch();
}

AMS::OsType AMS::Binary::GetTargetOS() {
    return m_base_info.ParseOS();
}

bool AMS::Binary::HasPacker() {

}

bool AMS::Binary::HasProtector() {

}

double AMS::Binary::GetEntropy() {
    auto raw = Raw();
    double entropy = rz_hash_entropy(raw.data(), raw.size());
    return entropy;
}

double AMS::Binary::GetEntropy(const char* section_name) {
    for (auto& sec : m_sections) {
        if (sec.name == section_name) {
            auto raw = Raw(sec.paddr, sec.size);
            double entropy = rz_hash_entropy(raw.data(), raw.size());
            return entropy;
        }
    }
    return 0.0;
}

