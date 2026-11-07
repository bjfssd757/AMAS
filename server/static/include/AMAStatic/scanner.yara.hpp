#ifndef AMASTATIC_SCANNER_YARA_H
#define AMASTATIC_SCANNER_YARA_H

#include <AMAStatic/scanner.hpp>
#include <yara.h>
#include <yara/compiler.h>
#include <yara/libyara.h>
#include <yara/rules.h>
#include <yara/types.h>
#include <spdlog/spdlog.h>
#include <filesystem>

namespace fs = std::filesystem;

#ifdef AMAS_TESTS_ENABLED
#include <doctest/doctest.h>
#endif // AMAS_TESTS_ENABLED

namespace AMAStatic {

struct YaraCompilerDeleter { void operator()(YR_COMPILER* c) const { yr_compiler_destroy(c); } };
struct YaraRulesDeleter    { void operator()(YR_RULES* r)    const { yr_rules_destroy(r);    } };

using UniqueCompiler = std::unique_ptr<YR_COMPILER, YaraCompilerDeleter>;
using UniqueRules    = std::unique_ptr<YR_RULES,    YaraRulesDeleter>;

class YaraScanner : public BaseScanner {
private:
    UniqueRules m_rules{nullptr};
    bool m_is_init{false};

    static bool GlobalInit() {
        static bool init = (yr_initialize() == ERROR_SUCCESS);
        return init;
    }

    static int YaraCallback(YR_SCAN_CONTEXT* ctx, int message, void* message_data, void* user_data) {
        if (message != CALLBACK_MSG_RULE_MATCHING) {
            return CALLBACK_CONTINUE;
        }

        auto* res = static_cast<ScanResult*>(user_data);
        auto* rule = static_cast<YR_RULE*>(message_data);

        ScanMatch match;
        match.rule_name = rule->identifier;

        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            if (meta->type == META_TYPE_STRING) {
                match.metadata[meta->identifier] = meta->string;
            } else if (meta->type == META_TYPE_INTEGER) {
                match.metadata[meta->identifier] = std::to_string(meta->integer);
            }
        }

        YR_STRING* string;
        yr_rule_strings_foreach(rule, string) {
            YR_MATCH* yr_match;
            yr_string_matches_foreach(ctx, string, yr_match) {
                match.address = static_cast<uint64_t>(yr_match->base + yr_match->offset);
            }
        }

        res->matches.push_back(std::move(match));
        res->is_triggered = true;

        return CALLBACK_CONTINUE;
    }

public:
    YaraScanner() {
        GlobalInit();
    }
    ~YaraScanner() override {}

    [[nodiscard]] std::string GetName() const noexcept override {
        return "YARA";
    }

    bool Initialize(const std::string& rules_dir_path) override {
        if (!fs::exists(rules_dir_path) || !fs::is_directory(rules_dir_path)) {
            spdlog::error("[YARA] Error: Provided path is not a valid directory: " + rules_dir_path);
            return false;
        }

        YR_COMPILER* compiler_ptr = nullptr;
        if (yr_compiler_create(&compiler_ptr) != ERROR_SUCCESS) {
            spdlog::error("[YARA] Error: Failed to create YARA compiler structure");
            return false;
        }
        UniqueCompiler compiler(compiler_ptr, YaraCompilerDeleter());

        yr_compiler_set_callback(compiler.get(), [](int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) {
            std::string src_file = file_name ? file_name : "unknown_file";
            if (error_level == YARA_ERROR_LEVEL_ERROR) {
                spdlog::error("[YARA Compile ERROR] {}:{}: -> {}", src_file, line_number, message);
            } else {
                spdlog::warn("[YARA Compile WARNING] {}:{}: -> {}", src_file, line_number, message);
            }
        }, nullptr);

        bool has_rules = false;
        int compile_errors = 0;

        for (const auto& entry : fs::recursive_directory_iterator(rules_dir_path)) {
            if (!entry.is_regular_file()) continue;

            auto ext = entry.path().extension().string();
            if (ext == ".yar" || ext == ".yara") {
                std::ifstream file(entry.path());
                if (!file.is_open()) {
                    spdlog::warn("[YARA] Could not open rule file: " + entry.path().string());
                    continue;
                }

                std::string rules_str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                std::string filename_str = entry.path().filename().string();

                if (yr_compiler_add_string(compiler.get(), rules_str.c_str(), filename_str.c_str()) > 0) {
                    spdlog::error("[YARA] Error in file: " + entry.path().string());
                    compile_errors++;
                } else {
                    has_rules = true;
                }
            }
        }

        if (!has_rules) {
            spdlog::error("[YARA] No valid rules found or successfully compiled in directory: " + rules_dir_path);
            return false;
        }

        if (compile_errors > 0) {
            spdlog::warn("[YARA] Directory initialized with warnings/errors. Broken files skipped.");
        }

        YR_RULES* rules_ptr = nullptr;
        if (yr_compiler_get_rules(compiler.get(), &rules_ptr) != ERROR_SUCCESS) {
            spdlog::error("[YARA] Error: Failed to extract compiled rules");
            return false;
        }
        
        m_rules = UniqueRules(rules_ptr, YaraRulesDeleter());
        m_is_init = true;
        
        spdlog::info("[YARA] Successfully initialized scanner with rules from directory: " + rules_dir_path);
        return true;
    }

    [[nodiscard]] ScanResult Scan(std::span<const uint8_t> buffer, const BaseInfo& info) override {
        ScanResult result;
        result.scanner_name = GetName();

        if (!m_is_init || !m_rules) {
            spdlog::error("[YARA] Scanner not rules initialized");
            return result;
        }

        int flags = 0;
        int timeout = 0;

        int scan_res = yr_rules_scan_mem(
            m_rules.get(),
            buffer.data(),
            buffer.size(),
            flags,
            YaraCallback,
            &result,
            timeout
        );

        if (scan_res != ERROR_SUCCESS) {
            spdlog::error("[YARA] Proccess memory scanning error, code: "
                + std::to_string(scan_res));
        }

        return result;
    }
};

}

#endif // AMASTATIC_SCANNER_YARA_H