#include <AMAStatic/data.hpp>
#include <AMAStatic/binary.hpp>

namespace AMS = AMAStatic;

extern const std::vector<uint8_t> MOCK_ELF64;
extern const char* MOCK_ELF64_MD5;
extern const char* MOCK_ELF64_SHA256;

struct TempBinaryFixture {
    fs::path test_file_path;

    TempBinaryFixture() {
        test_file_path = fs::current_path() / "test_mock_elf64.bin";
        
        std::ofstream ofs(test_file_path, std::ios::binary | std::ios::trunc);
        if (ofs) {
            ofs.write(reinterpret_cast<const char*>(MOCK_ELF64.data()), MOCK_ELF64.size());
            ofs.flush();
        }
    }

    ~TempBinaryFixture() {
        std::error_code ec;
        fs::remove(test_file_path, ec);
    }
};

TEST_CASE("testing GetImports") {
    TempBinaryFixture fixture;
    
    AMS::Binary bin(fixture.test_file_path);
    CHECK(bin.Analyse() == 0);

    auto imports = bin.GetImports();
    CHECK(imports.size() == 5);
}

TEST_CASE("testing GetStrings") {
    TempBinaryFixture fixture;
    
    AMS::Binary bin(fixture.test_file_path);
    CHECK(bin.Analyse() == 0);

    auto strings = bin.GetStrings();
    CHECK(strings.empty());
}

TEST_CASE("testing GetArch") {
    TempBinaryFixture fixture;
    
    AMS::Binary bin(fixture.test_file_path);
    CHECK(bin.Analyse() == 0);

    CHECK(bin.GetArch() == AMS::Arch::X64);
}

TEST_CASE("testing GetTargetOS") {
    TempBinaryFixture fixture;
    
    AMS::Binary bin(fixture.test_file_path);
    CHECK(bin.Analyse() == 0);

    CHECK(bin.GetTargetOS() == AMS::OsType::LINUX);
}

TEST_CASE("testing hashing") {
    TempBinaryFixture fixture;
    
    AMS::Binary bin(fixture.test_file_path);
    CHECK(bin.Analyse() == 0);

    CHECK(bin.GetMD5() == MOCK_ELF64_MD5);
    CHECK(bin.GetSHA256() == MOCK_ELF64_SHA256);
}

TEST_CASE("testing ExecuteableFormat") {
    TempBinaryFixture fixture;
    
    AMS::Binary bin(fixture.test_file_path);
    CHECK(bin.Analyse() == 0);

    CHECK(bin.GetExecutableFormat() == AMS::ExecFormat::ELF64);
}

TEST_CASE("testing GetEntropy") {
    TempBinaryFixture fixture;
    
    AMS::Binary bin(fixture.test_file_path);
    CHECK(bin.Analyse() == 0);

    double entropy = bin.GetEntropy();
    CHECK(entropy >= 0.5); 
    CHECK(entropy <= 4.5);
}