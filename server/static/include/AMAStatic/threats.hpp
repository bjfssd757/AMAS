#ifndef AMASTATIC_THREATS_H
#define AMASTATIC_THREATS_H

#include <vector>
#include <cmath>

namespace AMAStatic {

enum class Threat : int {
    ImportTableClear                    = 45,
    DangerousImports                    = 30,
    HighCodeEntropy                     = 25,
    SizeMismatch                        = 25,
    ProtectorDetected                   = 20,
    UnpackerDetected                     = 20,
    HighStringsEntropy                  = 15,
    HighFileEntropy                     = 10,
    UnknownCompiler                     = 10,
    UnknownTargetOS                     = 10,
    UnknownLanguage                     = 10,
    UnknownArch                         = 10,
    UnknownTimestamp                    = 10,
    SuspiciousSectionsName              = 15,
    TooFewSections                      = 20,
    CodeSectionHasWRITEAndExecuteFlags  = 35,
    EntryPointInUntypicallySection      = 25
};

class ThreatDatabase {
private:
    std::vector<Threat> threats;

public:
    explicit ThreatDatabase() = default;

    inline void AddThreat(const Threat& threat) {
        this->threats.push_back(threat);
    }

    inline float CalculateThreatScore() {
        if (this->threats.empty()) return 0.0f;

        double multiplier = 1.0;

        for (const Threat& threat : this->threats) {
            double weight = static_cast<double>(threat);

            if (weight > 100.0) weight = 100.0;
            if (weight < 0.0)   weight = 0.0;

            multiplier *= (1.0 - (weight / 100.0));
        }

        float score = static_cast<float>(100.0 * (1.0 - multiplier));

        return std::round(score * 10.0f) / 10.0f;
    }

    inline void Clear() {
        this->threats.clear();
    }
};

}

#endif // AMASTATIC_THREATS_H