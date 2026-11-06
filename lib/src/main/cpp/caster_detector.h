#ifndef CASTER_DETECTOR_H
#define CASTER_DETECTOR_H

#include <string>
#include <vector>

struct RootDetectionResult {
    bool isRooted;
    std::vector<std::string> detectedMethods;
    float confidence;
};

struct EmulatorDetectionResult {
    bool isEmulator;
    std::vector<std::string> detectedMethods;
    float confidence;
};

struct AntiTamperingResult {
    bool isDebuggerAttached;
    bool isHookingDetected;
    std::vector<std::string> detectedMethods;
};

struct MaliciousAppResult {
    bool hasMaliciousApps;
    std::vector<std::string> detectedApps;
    float riskScore;
};

struct FlagSecureResult {
    bool isFlagSecureDisabled;
    std::vector<std::string> detectedMethods;
    float confidence;
};

#endif // CASTER_DETECTOR_H
