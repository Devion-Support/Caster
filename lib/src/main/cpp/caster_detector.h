#ifndef CASTER_DETECTOR_H
#define CASTER_DETECTOR_H

#include <jni.h>
#include <string>
#include <vector>
#include <cstring>
#include "modules/integrity_detector.h"

// Define JNI macros if not already defined
#ifndef JNIEXPORT
#define JNIEXPORT __attribute__ ((visibility ("default")))
#endif

#ifndef JNICALL
#define JNICALL
#endif

// Include the necessary standard JNI macros
#ifdef __cplusplus
extern "C" {
#endif

// Use std::vector for safer and easier string list management.
// These structs will be used internally by the C++ code.

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

// This is a placeholder as the actual check is now in Kotlin.
struct FlagSecureResult {
    bool isFlagSecureDisabled;
    std::vector<std::string> detectedMethods;
    float confidence;
};

// ================================
// JNI Detection Functions
// ================================

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectRoot(
        JNIEnv *env, jobject thiz);

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectEmulator(
        JNIEnv *env, jobject thiz);

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectIntegrity(
        JNIEnv *env, jobject thiz, jstring packageName);

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectAntiTampering(
        JNIEnv *env, jobject thiz);

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectMaliciousApps(
        JNIEnv *env, jobject thiz);

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectFlagSecure(
        JNIEnv *env, jobject thiz);

#ifdef __cplusplus
}
#endif

#endif //CASTER_DETECTOR_H
