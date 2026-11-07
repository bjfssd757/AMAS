#include <AMAStatic/scanner.manager.hpp>
#include <AMAStatic/scanner.yara.hpp>
#include <AMAStatic/binary.hpp>
#include <iostream>

namespace AMS = AMAStatic;

extern const std::vector<uint8_t> MOCK_ELF64;

struct YaraEnvironmentFixture {
    fs::path test_file_path;
    fs::path test_rules_dir;

    inline YaraEnvironmentFixture() {
        auto current = fs::current_path();

        test_file_path = current / "test_manager_mock_elf64.bin";
        std::ofstream bin_ofs(test_file_path, std::ios::binary | std::ios::trunc);
        if (bin_ofs) {
            bin_ofs.write(reinterpret_cast<const char*>(MOCK_ELF64.data()), MOCK_ELF64.size());
            bin_ofs.flush();
        }

        test_rules_dir = current / "test_yara_rules_dir";
        fs::create_directories(test_rules_dir);

        std::ofstream rule_ofs(test_rules_dir / "rule1.yara", std::ios::trunc);
        if (rule_ofs) {
            rule_ofs << R"(
                rule DetectElfHeader {
                    strings:
                        $elf_magic = { 7F 45 4C 46 } // \x7FELF
                    condition:
                        any of them
                }
            )";
            rule_ofs.flush();
        }
    }

    inline ~YaraEnvironmentFixture() {
        std::error_code ec;
        fs::remove(test_file_path, ec);
        fs::remove_all(test_rules_dir, ec);
    }
};

TEST_CASE("testing the ScannerManager with YaraScanner") {
    YaraEnvironmentFixture env;

    AMS::ScannerManager sm = AMS::ScannerManager();
    auto yara_ptr = std::make_shared<AMS::YaraScanner>(); 

    yara_ptr->Initialize(env.test_rules_dir.string());
    
    sm.RegisterScanner(yara_ptr);
    CHECK(sm.GetScannersCount() == 1);

    AMS::Binary bin(env.test_file_path);
    REQUIRE(bin.Analyse() == 0);

    auto raw = bin.Raw();
    auto base_info = bin.GetBaseInfo();
    auto report = sm.ExecuteAll(raw, base_info);

    CHECK(report.total_scanners_run == 1);
    CHECK(report.file_path == env.test_file_path.string());

    std::cout << "DURATION: " << report.duration_ms << std::endl;

    CHECK(!report.triggered_results.empty());
    for (auto& res : report.triggered_results) {
        CHECK(res.scanner_name == "YARA");
        CHECK(!res.matches.empty());
        
        for (auto& match : res.matches) {
            CHECK(match.rule_name == "DetectElfHeader");
            std::cout << "MATCHED IN TEST: " << match.rule_name << " at offset " << match.address << std::endl;
        }
    }
}
