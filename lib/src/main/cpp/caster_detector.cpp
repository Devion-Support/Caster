#include "caster_detector.h"

#include <jni.h>

#include <string>
#include <vector>

#include "modules/anti_tampering_detector.h"
#include "modules/emulator_detector.h"
#include "modules/flag_secure_detector.h"
#include "modules/integrity_detector.h"
#include "modules/malicious_app_detector.h"
#include "modules/root_detector.h"

namespace {

jobject toJavaStringList(JNIEnv* env, const std::vector<std::string>& values) {
    const jclass listClass = env->FindClass("java/util/ArrayList");
    if (listClass == nullptr) {
        return nullptr;
    }

    const jmethodID constructor = env->GetMethodID(listClass, "<init>", "()V");
    const jmethodID add = env->GetMethodID(
        listClass,
        "add",
        "(Ljava/lang/Object;)Z"
    );

    if (constructor == nullptr || add == nullptr) {
        return nullptr;
    }

    jobject list = env->NewObject(listClass, constructor);
    if (list == nullptr) {
        return nullptr;
    }

    for (const auto& value : values) {
        jstring item = env->NewStringUTF(value.c_str());
        if (item == nullptr) {
            return nullptr;
        }

        env->CallBooleanMethod(list, add, item);
        env->DeleteLocalRef(item);

        if (env->ExceptionCheck()) {
            return nullptr;
        }
    }

    return list;
}

jobject newRootResult(JNIEnv* env, const RootDetectionResult& result) {
    const jclass clazz = env->FindClass(
        "io/github/yoganataa/caster/detection/RootDetectionResult"
    );
    if (clazz == nullptr) {
        return nullptr;
    }

    const jmethodID constructor = env->GetMethodID(
        clazz,
        "<init>",
        "(ZLjava/util/List;F)V"
    );
    if (constructor == nullptr) {
        return nullptr;
    }

    return env->NewObject(
        clazz,
        constructor,
        static_cast<jboolean>(result.isRooted),
        toJavaStringList(env, result.detectedMethods),
        static_cast<jfloat>(result.confidence)
    );
}

jobject newEmulatorResult(JNIEnv* env, const EmulatorDetectionResult& result) {
    const jclass clazz = env->FindClass(
        "io/github/yoganataa/caster/detection/EmulatorResult"
    );
    if (clazz == nullptr) {
        return nullptr;
    }

    const jmethodID constructor = env->GetMethodID(
        clazz,
        "<init>",
        "(ZLjava/util/List;F)V"
    );
    if (constructor == nullptr) {
        return nullptr;
    }

    return env->NewObject(
        clazz,
        constructor,
        static_cast<jboolean>(result.isEmulator),
        toJavaStringList(env, result.detectedMethods),
        static_cast<jfloat>(result.confidence)
    );
}

jobject newIntegrityResult(JNIEnv* env, const IntegrityDetectionResult& result) {
    const jclass clazz = env->FindClass(
        "io/github/yoganataa/caster/detection/IntegrityResult"
    );
    if (clazz == nullptr) {
        return nullptr;
    }

    const jmethodID constructor = env->GetMethodID(
        clazz,
        "<init>",
        "(ZLjava/util/List;)V"
    );
    if (constructor == nullptr) {
        return nullptr;
    }

    return env->NewObject(
        clazz,
        constructor,
        static_cast<jboolean>(result.isTampered),
        toJavaStringList(env, result.detectedMethods)
    );
}

jobject newAntiTamperingResult(JNIEnv* env, const AntiTamperingResult& result) {
    const jclass clazz = env->FindClass(
        "io/github/yoganataa/caster/detection/AntiTamperingResult"
    );
    if (clazz == nullptr) {
        return nullptr;
    }

    const jmethodID constructor = env->GetMethodID(
        clazz,
        "<init>",
        "(ZZLjava/util/List;)V"
    );
    if (constructor == nullptr) {
        return nullptr;
    }

    return env->NewObject(
        clazz,
        constructor,
        static_cast<jboolean>(result.isDebuggerAttached),
        static_cast<jboolean>(result.isHookingDetected),
        toJavaStringList(env, result.detectedMethods)
    );
}

jobject newMaliciousAppResult(JNIEnv* env, const MaliciousAppResult& result) {
    const jclass clazz = env->FindClass(
        "io/github/yoganataa/caster/detection/MaliciousAppResult"
    );
    if (clazz == nullptr) {
        return nullptr;
    }

    const jmethodID constructor = env->GetMethodID(
        clazz,
        "<init>",
        "(ZLjava/util/List;F)V"
    );
    if (constructor == nullptr) {
        return nullptr;
    }

    return env->NewObject(
        clazz,
        constructor,
        static_cast<jboolean>(result.hasMaliciousApps),
        toJavaStringList(env, result.detectedApps),
        static_cast<jfloat>(result.riskScore)
    );
}

jobject newFlagSecureResult(JNIEnv* env, const FlagSecureResult& result) {
    const jclass clazz = env->FindClass(
        "io/github/yoganataa/caster/detection/FlagSecureResult"
    );
    if (clazz == nullptr) {
        return nullptr;
    }

    const jmethodID constructor = env->GetMethodID(
        clazz,
        "<init>",
        "(ZLjava/util/List;F)V"
    );
    if (constructor == nullptr) {
        return nullptr;
    }

    return env->NewObject(
        clazz,
        constructor,
        static_cast<jboolean>(result.isFlagSecureDisabled),
        toJavaStringList(env, result.detectedMethods),
        static_cast<jfloat>(result.confidence)
    );
}

jobject nativePerformAllDetection(
    JNIEnv* env,
    jobject,
    jstring packageName
) {
    if (packageName == nullptr) {
        return nullptr;
    }

    const char* packageNameChars = env->GetStringUTFChars(packageName, nullptr);
    if (packageNameChars == nullptr) {
        return nullptr;
    }

    const RootDetectionResult root = detectRoot();
    const EmulatorDetectionResult emulator = detectEmulator();
    const IntegrityDetectionResult integrity = detectIntegrity(packageNameChars);
    const AntiTamperingResult tampering = detectAntiTampering();
    const MaliciousAppResult maliciousApps = detectMaliciousApps();
    const FlagSecureResult flagSecure = detectFlagSecure();

    env->ReleaseStringUTFChars(packageName, packageNameChars);

    jobject rootResult = newRootResult(env, root);
    jobject emulatorResult = newEmulatorResult(env, emulator);
    jobject integrityResult = newIntegrityResult(env, integrity);
    jobject tamperingResult = newAntiTamperingResult(env, tampering);
    jobject maliciousAppResult = newMaliciousAppResult(env, maliciousApps);
    jobject flagSecureResult = newFlagSecureResult(env, flagSecure);

    if (rootResult == nullptr || emulatorResult == nullptr || integrityResult == nullptr ||
        tamperingResult == nullptr || maliciousAppResult == nullptr ||
        flagSecureResult == nullptr) {
        return nullptr;
    }

    const jclass resultClass = env->FindClass(
        "io/github/yoganataa/caster/detection/CasterDetectionResult"
    );
    if (resultClass == nullptr) {
        return nullptr;
    }

    const jmethodID constructor = env->GetMethodID(
        resultClass,
        "<init>",
        "(Lio/github/yoganataa/caster/detection/RootDetectionResult;"
        "Lio/github/yoganataa/caster/detection/EmulatorResult;"
        "Lio/github/yoganataa/caster/detection/IntegrityResult;"
        "Lio/github/yoganataa/caster/detection/AntiTamperingResult;"
        "Lio/github/yoganataa/caster/detection/MaliciousAppResult;"
        "Lio/github/yoganataa/caster/detection/FlagSecureResult;)V"
    );
    if (constructor == nullptr) {
        return nullptr;
    }

    return env->NewObject(
        resultClass,
        constructor,
        rootResult,
        emulatorResult,
        integrityResult,
        tamperingResult,
        maliciousAppResult,
        flagSecureResult
    );
}

}  // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    const jclass detectorClass = env->FindClass(
        "io/github/yoganataa/caster/detection/CasterNativeDetector"
    );
    if (detectorClass == nullptr) {
        return JNI_ERR;
    }

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
    ) == JNI_OK
        ? JNI_VERSION_1_6
        : JNI_ERR;
}
