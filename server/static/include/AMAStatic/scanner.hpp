#ifndef AMASTATIC_SCANNER_H
#define AMASTATIC_SCANNER_H

#include <map>
#include <string>
#include <cstdint>
#include <vector>
#include <span>
#include <AMAStatic/data.hpp>

namespace AMAStatic {

struct ScanMatch {
    uint64_t address{};
    std::string rule_name;
    std::map<std::string, std::string> metadata;
};

struct ScanResult {
    bool is_triggered{false};
    std::string scanner_name;
    std::vector<ScanMatch> matches;
};

class BaseScanner {
public:
    virtual ~BaseScanner() = default;

    [[nodiscard]] virtual std::string GetName() const noexcept = 0;
    virtual bool Initialize(const std::string& meta) = 0;
    [[nodiscard]] virtual ScanResult Scan(std::span<const uint8_t> buffer, const BaseInfo& info) = 0;
};

}

#endif // AMASTATIC_SCANNER_H