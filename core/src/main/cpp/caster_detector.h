#ifndef CASTER_DETECTOR_H
#define CASTER_DETECTOR_H

#include <jni.h>
#include <string>
#include <vector>

extern "C" {

// ================================
// Configuration Structure
// ================================
typedef struct {
    int enableRootDetection;
    int enableEmulatorDetection;
    int enableIntegrityChecks;
    int enableAntiTampering;
    int enableMaliciousAppDetection;
    int enableFlagSecureDetection;
    long detectionTimeoutMs;
} CasterConfig;

// ================================
// Result Structures
// ================================
typedef struct {
    int isRooted;
    char** detectedMethods;
    int methodCount;
    float confidence;
} RootDetectionResult;

typedef struct {
    int isEmulator;
    char** detectedMethods;
    int methodCount;
    float confidence;
} EmulatorDetectionResult;

typedef struct {
    int isTampered;
    char** detectedMethods;
    int methodCount;
} IntegrityDetectionResult;

typedef struct {
    int isDebuggerAttached;
    int isHookingDetected;
    char** detectedMethods;
    int methodCount;
} AntiTamperingResult;

typedef struct {
    int hasMaliciousApps;
    char** detectedApps;
    int appCount;
    float riskScore;
} MaliciousAppResult;

typedef struct {
    int isFlagSecureDisabled;
    char** detectedMethods;
    int methodCount;
    float confidence;
} FlagSecureResult;

// ================================
// Main Detection Function
// ================================
JNIEXPORT void JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_performAllDetection(
        JNIEnv *env, jobject thiz, jobject config, jobject result);

// ================================
// Individual Detection Functions
// ================================

// Root Detection
JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectRoot(
        JNIEnv *env, jobject thiz);

// Emulator Detection
JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectEmulator(
        JNIEnv *env, jobject thiz);

// Integrity Detection
JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectIntegrity(
        JNIEnv *env, jobject thiz, jstring packageName);

// Anti-Tampering Detection
JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectAntiTampering(
        JNIEnv *env, jobject thiz);

// Malicious App Detection
JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectMaliciousApps(
        JNIEnv *env, jobject thiz);

// Flag Secure Detection
JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectFlagSecure(
        JNIEnv *env, jobject thiz);

}

#endif //CASTER_DETECTOR_H