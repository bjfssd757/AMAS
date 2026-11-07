#ifndef AMASTATIC_SCANNER_MANAGER_H
#define AMASTATIC_SCANNER_MANAGER_H

#include <AMAStatic/scanner.hpp>
#include <chrono>
#include <future>
#include <spdlog/spdlog.h>

#ifdef AMAS_TESTS_ENABLED
#include <doctest/doctest.h>
#endif // AMAS_TESTS_ENABLED

namespace AMAStatic {

struct AnalysisReport {
    std::string file_path;
    size_t total_scanners_run{0};
    std::chrono::milliseconds duration_ms{0};
    std::vector<ScanResult> triggered_results;
};

class ScannerManager {
private:
    std::vector<std::shared_ptr<BaseScanner>> m_scanners;

public:
    ScannerManager() = default;
    ~ScannerManager() = default;

    void RegisterScanner(std::shared_ptr<BaseScanner> scanner) {
        if (scanner) {
            m_scanners.push_back(std::move(scanner));
        }
    }

    [[nodiscard]] size_t GetScannersCount() const noexcept {
        return m_scanners.size();
    }

    [[nodiscard]] AnalysisReport ExecuteAll(std::span<const uint8_t> buffer, const BaseInfo& info) {
        AnalysisReport report;
        report.file_path = info.core.file;
        report.total_scanners_run = m_scanners.size();

        if (m_scanners.empty()) {
            return report;
        }

        auto start_time = std::chrono::high_resolution_clock::now();

        std::vector<std::future<ScanResult>> futures;
        futures.reserve(m_scanners.size());

        for (const auto& scanner : m_scanners) {
            futures.push_back(std::async(std::launch::async, [scanner, buffer, &info]() {
                try {
                    return scanner->Scan(buffer, info);
                } catch (const std::exception& e) {
                    spdlog::error("[ScannerManager] Critical Error in scanner " + scanner->GetName()
                        + ": " + e.what());
                    ScanResult fallback;
                    fallback.scanner_name = scanner->GetName();
                    return fallback;
                }
            }));
        }

        for (auto& fut : futures) {
            ScanResult res = fut.get();
            if (res.is_triggered) {
                report.triggered_results.push_back(std::move(res));
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        report.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        return report;
    }
};

}

#endif // AMASTATIC_SCANNER_MANAGER_H