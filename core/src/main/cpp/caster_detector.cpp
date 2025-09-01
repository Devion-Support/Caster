#include "caster_detector.h"
#include "modules/root_detector.h"
#include "modules/emulator_detector.h"
#include "modules/integrity_detector.h"
#include "modules/anti_tampering_detector.h"
#include "modules/malicious_app_detector.h"
#include "modules/flag_secure_detector.h"
#include "modules/helpers.h"
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

// Helper functions are now in modules/helpers.h and modules/helpers.cpp

// ================================
// Root Detection Implementation
// ================================

RootDetectionResult detectRootNative() {
    return detectRoot();
}

// ================================
// Emulator Detection Implementation
// ================================

EmulatorDetectionResult detectEmulatorNative() {
    return detectEmulator();
}

// ================================
// Integrity Detection Implementation
// ================================

IntegrityDetectionResult detectIntegrityNative(const char* packageName) {
    return detectIntegrity(packageName);
}

// ================================
// Anti-Tampering Detection Implementation
// ================================

AntiTamperingResult detectAntiTamperingNative() {
    return detectAntiTampering();
}

// ================================
// Malicious App Detection Implementation
// ================================

MaliciousAppResult detectMaliciousAppsNative() {
    return detectMaliciousApps();
}

// ================================
// Flag Secure Detection Implementation
// ================================

FlagSecureResult detectFlagSecureNative() {
    return detectFlagSecure();
}

// ================================
// JNI Function Implementations
// ================================

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectRoot(
        JNIEnv *env, jobject thiz) {
    
    RootDetectionResult result = detectRootNative();
    
    // Create the RootDetectionResult object
    jclass resultClass = env->FindClass("io/github/yoganataa/caster/core/detection/CasterNativeDetector$RootDetectionResult");
    if (!resultClass) return NULL;
    
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(Z[Ljava/lang/String;Ljava/util/List;F)V");
    if (!constructor) return NULL;
    
    // Create empty threats list (for simplicity in this example)
    jclass listClass = env->FindClass("java/util/ArrayList");
    jmethodID listConstructor = env->GetMethodID(listClass, "<init>", "()V");
    jobject threatsList = env->NewObject(listClass, listConstructor);
    
    // Create detected methods array
    jobjectArray methodsArray = env->NewObjectArray(result.methodCount, env->FindClass("java/lang/String"), NULL);
    
    jobject resultObject = env->NewObject(resultClass, constructor, 
                                        (jboolean)result.isRooted, 
                                        methodsArray, 
                                        threatsList, 
                                        (jfloat)result.confidence);
    
    return resultObject;
}

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectEmulator(
        JNIEnv *env, jobject thiz) {
    
    EmulatorDetectionResult result = detectEmulatorNative();
    
    // Create the EmulatorResult object
    jclass resultClass = env->FindClass("io/github/yoganataa/caster/core/detection/CasterNativeDetector$EmulatorResult");
    if (!resultClass) return NULL;
    
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(Z[Ljava/lang/String;Ljava/util/List;F)V");
    if (!constructor) return NULL;
    
    // Create empty threats list (for simplicity in this example)
    jclass listClass = env->FindClass("java/util/ArrayList");
    jmethodID listConstructor = env->GetMethodID(listClass, "<init>", "()V");
    jobject threatsList = env->NewObject(listClass, listConstructor);
    
    // Create detected methods array
    jobjectArray methodsArray = env->NewObjectArray(result.methodCount, env->FindClass("java/lang/String"), NULL);
    
    jobject resultObject = env->NewObject(resultClass, constructor, 
                                        (jboolean)result.isEmulator, 
                                        methodsArray, 
                                        threatsList, 
                                        (jfloat)result.confidence);
    
    return resultObject;
}

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectIntegrity(
        JNIEnv *env, jobject thiz, jstring packageName) {
    
    const char* pkgName = env->GetStringUTFChars(packageName, NULL);
    IntegrityDetectionResult result = detectIntegrityNative(pkgName);
    env->ReleaseStringUTFChars(packageName, pkgName);
    
    // Create the IntegrityResult object
    jclass resultClass = env->FindClass("io/github/yoganataa/caster/core/detection/CasterNativeDetector$IntegrityResult");
    if (!resultClass) return NULL;
    
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZLjava/util/List;[Ljava/lang/String;)V");
    if (!constructor) return NULL;
    
    // Create empty threats list (for simplicity in this example)
    jclass listClass = env->FindClass("java/util/ArrayList");
    jmethodID listConstructor = env->GetMethodID(listClass, "<init>", "()V");
    jobject threatsList = env->NewObject(listClass, listConstructor);
    
    // Create detected methods array
    jobjectArray methodsArray = env->NewObjectArray(result.methodCount, env->FindClass("java/lang/String"), NULL);
    
    jobject resultObject = env->NewObject(resultClass, constructor, 
                                        (jboolean)result.isTampered, 
                                        threatsList, 
                                        methodsArray);
    
    return resultObject;
}

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectAntiTampering(
        JNIEnv *env, jobject thiz) {
    
    AntiTamperingResult result = detectAntiTamperingNative();
    
    // Create the AntiTamperingResult object
    jclass resultClass = env->FindClass("io/github/yoganataa/caster/core/detection/CasterNativeDetector$AntiTamperingResult");
    if (!resultClass) return NULL;
    
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZZLjava/util/List;[Ljava/lang/String;)V");
    if (!constructor) return NULL;
    
    // Create empty threats list (for simplicity in this example)
    jclass listClass = env->FindClass("java/util/ArrayList");
    jmethodID listConstructor = env->GetMethodID(listClass, "<init>", "()V");
    jobject threatsList = env->NewObject(listClass, listConstructor);
    
    // Create detected methods array
    jobjectArray methodsArray = env->NewObjectArray(result.methodCount, env->FindClass("java/lang/String"), NULL);
    
    jobject resultObject = env->NewObject(resultClass, constructor, 
                                        (jboolean)result.isDebuggerAttached,
                                        (jboolean)result.isHookingDetected,
                                        threatsList, 
                                        methodsArray);
    
    return resultObject;
}

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectMaliciousApps(
        JNIEnv *env, jobject thiz) {
    
    MaliciousAppResult result = detectMaliciousAppsNative();
    
    // Create the MaliciousAppResult object
    jclass resultClass = env->FindClass("io/github/yoganataa/caster/core/detection/CasterNativeDetector$MaliciousAppResult");
    if (!resultClass) return NULL;
    
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZLjava/util/List;[Ljava/lang/String;F)V");
    if (!constructor) return NULL;
    
    // Create empty detected apps list (for simplicity in this example)
    jclass listClass = env->FindClass("java/util/ArrayList");
    jmethodID listConstructor = env->GetMethodID(listClass, "<init>", "()V");
    jobject appsList = env->NewObject(listClass, listConstructor);
    
    // Create detected methods array
    jobjectArray methodsArray = env->NewObjectArray(result.appCount, env->FindClass("java/lang/String"), NULL);
    
    jobject resultObject = env->NewObject(resultClass, constructor, 
                                        (jboolean)result.hasMaliciousApps,
                                        appsList,
                                        methodsArray,
                                        (jfloat)result.riskScore);
    
    return resultObject;
}

JNIEXPORT jobject JNICALL
Java_io_github_yoganataa_caster_core_detection_CasterNativeDetector_detectFlagSecure(
        JNIEnv *env, jobject thiz) {
    
    FlagSecureResult result = detectFlagSecureNative();
    
    // Create the FlagSecureResult object
    jclass resultClass = env->FindClass("io/github/yoganataa/caster/core/detection/CasterNativeDetector$FlagSecureResult");
    if (!resultClass) return NULL;
    
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(Z[Ljava/lang/String;Ljava/util/List;F)V");
    if (!constructor) return NULL;
    
    // Create empty threats list (for simplicity in this example)
    jclass listClass = env->FindClass("java/util/ArrayList");
    jmethodID listConstructor = env->GetMethodID(listClass, "<init>", "()V");
    jobject threatsList = env->NewObject(listClass, listConstructor);
    
    // Create detected methods array
    jobjectArray methodsArray = env->NewObjectArray(result.methodCount, env->FindClass("java/lang/String"), NULL);
    
    jobject resultObject = env->NewObject(resultClass, constructor, 
                                        (jboolean)result.isFlagSecureDisabled,
                                        methodsArray,
                                        threatsList,
                                        (jfloat)result.confidence);
    
    return resultObject;
}