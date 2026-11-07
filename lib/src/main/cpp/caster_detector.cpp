#include <android/log.h>
#include <string>
#include <vector>
#include <cstring>
#include <jni.h>
#include "caster_detector.h"
#include "modules/root_detector.h"
#include "modules/emulator_detector.h"
#include "modules/integrity_detector.h"
#include "modules/anti_tampering_detector.h"
#include "modules/malicious_app_detector.h"
#include "modules/flag_secure_detector.h"

// Helper function to convert a C++ vector of strings to a Java List of strings
jobject convertVectorToJavaList(JNIEnv *env, const std::vector<std::string>& vec) {
    jclass listClass = env->FindClass("java/util/ArrayList");
    if (!listClass) return nullptr;
    jmethodID listConstructor = env->GetMethodID(listClass, "<init>", "()V");
    if (!listConstructor) return nullptr;
    jobject listObj = env->NewObject(listClass, listConstructor);
    if (!listObj) return nullptr;

    jmethodID addMethod = env->GetMethodID(listClass, "add", "(Ljava/lang/Object;)Z");
    if (!addMethod) return nullptr;

    for (const auto& s : vec) {
        jstring javaString = env->NewStringUTF(s.c_str());
        env->CallBooleanMethod(listObj, addMethod, javaString);
        env->DeleteLocalRef(javaString);
    }
    return listObj;
}

extern "C" {

jobject
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectRoot(
        JNIEnv *env, jobject thiz) {
    RootDetectionResult result = detectRoot();

    jclass resultClass = env->FindClass("io/github/yoganataa/caster/detection/RootDetectionResult");
    if (!resultClass) return nullptr;
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZLjava/util/List;F)V");
    if (!constructor) return nullptr;

    jobject methodsList = convertVectorToJavaList(env, result.detectedMethods);

    return env->NewObject(resultClass, constructor,
                          (jboolean)result.isRooted,
                          methodsList,
                          (jfloat)result.confidence);
}

jobject
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectEmulator(
        JNIEnv *env, jobject thiz) {
    EmulatorDetectionResult result = detectEmulator();

    jclass resultClass = env->FindClass("io/github/yoganataa/caster/detection/EmulatorResult");
    if (!resultClass) return nullptr;
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZLjava/util/List;F)V");
    if (!constructor) return nullptr;

    jobject methodsList = convertVectorToJavaList(env, result.detectedMethods);

    return env->NewObject(resultClass, constructor,
                          (jboolean)result.isEmulator,
                          methodsList,
                          (jfloat)result.confidence);
}

jobject
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectIntegrity(
        JNIEnv *env, jobject thiz, jstring packageName) {
    const char* packageNameStr = env->GetStringUTFChars(packageName, nullptr);
    if (!packageNameStr) return nullptr;
    
    IntegrityDetectionResult result = detectIntegrity(packageNameStr);
    
    env->ReleaseStringUTFChars(packageName, packageNameStr);

    jclass resultClass = env->FindClass("io/github/yoganataa/caster/detection/IntegrityResult");
    if (!resultClass) return nullptr;
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZLjava/util/List;)V");
    if (!constructor) return nullptr;

    jobject methodsList = convertVectorToJavaList(env, result.detectedMethods);

    return env->NewObject(resultClass, constructor,
                          (jboolean)result.isTampered,
                          methodsList);
}

jobject
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectAntiTampering(
        JNIEnv *env, jobject thiz) {
    AntiTamperingResult result = detectAntiTampering();

    jclass resultClass = env->FindClass("io/github/yoganataa/caster/detection/AntiTamperingResult");
    if (!resultClass) return nullptr;
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZZLjava/util/List;)V");
    if (!constructor) return nullptr;

    jobject methodsList = convertVectorToJavaList(env, result.detectedMethods);

    return env->NewObject(resultClass, constructor,
                          (jboolean)result.isDebuggerAttached,
                          (jboolean)result.isHookingDetected,
                          methodsList);
}

jobject
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectMaliciousApps(
        JNIEnv *env, jobject thiz) {
    MaliciousAppResult result = detectMaliciousApps();

    jclass resultClass = env->FindClass("io/github/yoganataa/caster/detection/MaliciousAppResult");
    if (!resultClass) return nullptr;
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZLjava/util/List;F)V");
    if (!constructor) return nullptr;

    jobject appsList = convertVectorToJavaList(env, result.detectedApps);

    return env->NewObject(resultClass, constructor,
                          (jboolean)result.hasMaliciousApps,
                          appsList,
                          (jfloat)result.riskScore);
}

jobject
Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectFlagSecure(
        JNIEnv *env, jobject thiz) {
    FlagSecureResult result = detectFlagSecure();

    jclass resultClass = env->FindClass("io/github/yoganataa/caster/detection/FlagSecureResult");
    if (!resultClass) return nullptr;
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(ZLjava/util/List;F)V");
    if (!constructor) return nullptr;

    jobject methodsList = convertVectorToJavaList(env, result.detectedMethods);

    return env->NewObject(resultClass, constructor,
                          (jboolean)result.isFlagSecureDisabled,
                          methodsList,
                          (jfloat)result.confidence);
}

jobject nativePerformAllDetection(JNIEnv* env, jobject thiz, jstring packageName) {
    jobject root = Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectRoot(env, thiz);
    jobject emulator = Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectEmulator(env, thiz);
    jobject integrity = Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectIntegrity(env, thiz, packageName);
    jobject tampering = Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectAntiTampering(env, thiz);
    jobject malicious = Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectMaliciousApps(env, thiz);
    jobject flagSecure = Java_io_github_yoganataa_caster_detection_CasterNativeDetector_detectFlagSecure(env, thiz);

    if (root == nullptr || emulator == nullptr || integrity == nullptr ||
        tampering == nullptr || malicious == nullptr || flagSecure == nullptr) {
        return nullptr;
    }

    jclass resultClass = env->FindClass("io/github/yoganataa/caster/detection/CasterDetectionResult");
    if (resultClass == nullptr) return nullptr;

    jmethodID constructor = env->GetMethodID(
        resultClass,
        "<init>",
        "(Lio/github/yoganataa/caster/detection/RootDetectionResult;"
        "Lio/github/yoganataa/caster/detection/EmulatorResult;"
        "Lio/github/yoganataa/caster/detection/IntegrityResult;"
        "Lio/github/yoganataa/caster/detection/AntiTamperingResult;"
        "Lio/github/yoganataa/caster/detection/MaliciousAppResult;"
        "Lio/github/yoganataa/caster/detection/FlagSecureResult;)V"
    );
    if (constructor == nullptr) return nullptr;

    return env->NewObject(
        resultClass,
        constructor,
        root,
        emulator,
        integrity,
        tampering,
        malicious,
        flagSecure
    );
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass detectorClass = env->FindClass(
        "io/github/yoganataa/caster/detection/CasterNativeDetector"
    );
    if (detectorClass == nullptr) return JNI_ERR;

    static const JNINativeMethod methods[] = {
        {
            "nativePerformAllDetection",
            "(Ljava/lang/String;)Lio/github/yoganataa/caster/detection/CasterDetectionResult;",
            reinterpret_cast<void*>(nativePerformAllDetection)
        }
    };

    return env->RegisterNatives(
        detectorClass,
        methods,
        sizeof(methods) / sizeof(methods[0])
    ) == JNI_OK ? JNI_VERSION_1_6 : JNI_ERR;
}

} // extern "C"