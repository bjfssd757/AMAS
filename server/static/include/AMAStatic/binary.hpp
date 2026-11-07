#ifndef AMASTATIC_BINARY_H
#define AMASTATIC_BINARY_H

#include <hash-library/sha256.h>
#include <hash-library/md5.h>
#include <filesystem>
#include <yara/libyara.h>
#include <librz/rz_core.h>
#include <AMAStatic/data.hpp>

#ifdef AMAS_TESTS_ENABLED
#include <doctest/doctest.h>
#endif // AMAS_TESTS_ENABLED

#define _INT_RZ_CMD_IMPORT_TABLE_JSON           "iij"
#define _INT_RZ_CMD_SYMBOL_TABLE_JSON           "isj"
#define _INT_RZ_CMD_STRINGS_JSON                "izj"
#define _INT_RZ_CMD_BINARY_INFO_JSON            "iIj"
#define _INT_RZ_CMD_FUNCTIONS_JSON              "aflj"
#define _INT_RZ_CMD_DISASSEMBLE_CURRENT_JSON    "pdfj"
#define _INT_RZ_CMD_ENTRYPOINT_JSON             "iej"
#define _INT_RZ_CMD_BASE_INFO_JSON              "ij"
#define _INT_RZ_CMD_SECTIONS_JSON               "iSj"

namespace fs = std::filesystem;

namespace AMAStatic {

class Binary {
protected:
    const fs::path& m_path;
    RzCore* m_core = nullptr;
    std::vector<StringData> m_strings;
    std::vector<ImportData> m_imports;
    std::vector<SymbolData> m_symbols;
    std::vector<uint8_t> m_file_raw;
    std::vector<SectionData> m_sections;
    BaseInfo m_base_info;

    inline std::string get_json_rz(const std::string& cmd) {
        char* raw = rz_core_cmd_str(m_core, cmd.c_str());
        if (!raw) return "[]";

        std::string str(raw);
        free(raw);
        return str;
    }

    inline void free_core_rz() {
        if (m_core) rz_core_free(m_core);
        m_core = nullptr;
    }

public:
    Binary(const fs::path& path) : m_path(path) {
        m_core = rz_core_new();
        if (!m_core) throw std::runtime_error("Can't create rizin core");
    }
    ~Binary() { free_core_rz(); }

    int Analyse();
    std::vector<ImportData> GetImports();
    std::vector<StringData> GetStrings();
    // std::vector<ExportData> GetExports();
    std::string GetMD5(size_t read_chunks_size = 4096);
    std::string GetSHA256(size_t read_chunks_size = 4096);
    ExecFormat GetExecutableFormat();
    Arch GetArch();
    OsType GetTargetOS();
    bool HasPacker();
    bool HasProtector();
    double GetEntropy();
    double GetEntropy(const char* section_name);
    const BaseInfo& GetBaseInfo();
    std::span<const uint8_t> Raw();
    std::span<const uint8_t> Raw(uint64_t addr, size_t len);
};

}

#endif // AMASTATIC_H