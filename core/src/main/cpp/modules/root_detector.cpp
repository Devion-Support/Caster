#include "root_detector.h"
#include "helpers.h"
#include "../toolChecker.h"
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

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

// Helper functions are now in modules/helpers.h

// ================================
// Root Detection Implementation
// ================================

int checkForRootBinaries(const char* paths[], int pathCount) {
    int foundCount = 0;
    
    for (int i = 0; i < pathCount; i++) {
        if (fileExists(paths[i]) && isFileExecutable(paths[i])) {
            foundCount++;
        }
    }
    
    return foundCount;
}

int checkForMagiskArtifacts() {
    const char* magiskPaths[] = {
        "/sbin/.magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
        "/data/adb/magisk"
    };
    
    int magiskPathCount = sizeof(magiskPaths) / sizeof(magiskPaths[0]);
    int foundCount = 0;
    
    for (int i = 0; i < magiskPathCount; i++) {
        if (fileExists(magiskPaths[i])) {
            foundCount++;
        }
    }
    
    return foundCount;
}

int checkForMagiskUDS() {
    FILE *fh = fopen("/proc/net/unix", "r");
    if (!fh) {
        LOGE("Failed to open /proc/net/unix: %s", strerror(errno));
        return 0;
    }
    
    char line[1024];
    while (fgets(line, sizeof(line), fh)) {
        // Check for abstract Unix domain sockets (starting with '@') and a specific length pattern
        if (strstr(line, "@") != NULL && strlen(strstr(line, "@")) > 32) {
            // Ensure it's not a file-backed or path-based socket
            if (strstr(line, "/") == NULL && strstr(line, ".") == NULL) {
                fclose(fh);
                return 1;
            }
        }
    }
    fclose(fh);
    return 0;
}

int checkForSuperSUArtifacts() {
    const char* superSUPaths[] = {
        "/system/app/SuperSU",
        "/system/app/SuperSU.apk",
        "/system/app/supersu",
        "/system/app/supersu.apk"
    };
    
    int pathCount = sizeof(superSUPaths) / sizeof(superSUPaths[0]);
    int foundCount = 0;
    
    for (int i = 0; i < pathCount; i++) {
        if (fileExists(superSUPaths[i])) {
            foundCount++;
        }
    }
    
    return foundCount;
}

int checkForKernelSUArtifacts() {
    const char* kernelSUPaths[] = {
        "/system/bin/ksu",
        "/system/xbin/ksu",
        "/sbin/ksu",
        "/data/adb/ksu"
    };
    
    int pathCount = sizeof(kernelSUPaths) / sizeof(kernelSUPaths[0]);
    int foundCount = 0;
    
    for (int i = 0; i < pathCount; i++) {
        if (fileExists(kernelSUPaths[i])) {
            foundCount++;
        }
    }
    
    return foundCount;
}

RootDetectionResult detectRoot() {
    RootDetectionResult result = {0, NULL, 0, 0.0f};
    
    // Common SU binary paths
    const char* suPaths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/data/local/bin/su",
        "/data/local/xbin/su"
    };
    
    int pathCount = sizeof(suPaths) / sizeof(suPaths[0]);
    int rootBinaryCount = checkForRootBinaries(suPaths, pathCount);
    int magiskArtifactCount = checkForMagiskArtifacts();
    int magiskUDSFound = checkForMagiskUDS();
    int superSUArtifactCount = checkForSuperSUArtifacts();
    int kernelSUArtifactCount = checkForKernelSUArtifacts();
    
    int totalDetections = rootBinaryCount + magiskArtifactCount + magiskUDSFound + 
                         superSUArtifactCount + kernelSUArtifactCount;
    
    result.isRooted = (totalDetections > 0);
    result.confidence = (totalDetections > 0) ? (totalDetections > 3 ? 1.0f : 0.7f) : 0.0f;
    
    return result;
}