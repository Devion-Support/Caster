#include "integrity_detector.h"
#include "helpers.h"
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

// Helper functions are now in modules/helpers.h

// ================================
// Integrity Detection Implementation
// ================================

int checkSignatureIntegrity(const char* packageName) {
    // This would typically check APK signature
    // For now, we'll just return a placeholder
    return 0;
}

int checkApkModification(const char* packageName) {
    // This would check for APK modification
    // For now, we'll just return a placeholder
    return 0;
}

int checkDebuggableFlag(const char* packageName) {
    char command[512];
    snprintf(command, sizeof(command), "dumpsys package %s | grep -c debuggable=true", packageName);
    
    FILE *fp = popen(command, "r");
    if (!fp) return 0;
    
    char result[16];
    if (fgets(result, sizeof(result), fp) != NULL) {
        int debuggable = atoi(result);
        pclose(fp);
        return debuggable;
    }
    
    pclose(fp);
    return 0;
}

IntegrityDetectionResult detectIntegrity(const char* packageName) {
    IntegrityDetectionResult result = {0, NULL, 0};
    
    int signatureTampered = checkSignatureIntegrity(packageName);
    int apkModified = checkApkModification(packageName);
    int debuggableFlag = checkDebuggableFlag(packageName);
    
    int tamperDetected = signatureTampered || apkModified || debuggableFlag;
    
    result.isTampered = tamperDetected;
    
    return result;
}