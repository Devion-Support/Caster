#include "emulator_detector.h"
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
// Emulator Detection Implementation
// ================================

int checkEmulatorProperties() {
    int emulatorScore = 0;
    
    // Check build properties
    char* fingerprint = getSystemProperty("ro.build.fingerprint");
    char* model = getSystemProperty("ro.product.model");
    char* manufacturer = getSystemProperty("ro.product.manufacturer");
    char* brand = getSystemProperty("ro.product.brand");
    char* device = getSystemProperty("ro.product.device");
    char* hardware = getSystemProperty("ro.hardware");
    
    // Check for emulator fingerprints
    if (fingerprint) {
        if (strstr(fingerprint, "generic") || strstr(fingerprint, "unknown")) {
            emulatorScore += 20;
        }
        free(fingerprint);
    }
    
    // Check model
    if (model) {
        if (strstr(model, "sdk") || strstr(model, "emulator") || strstr(model, "generic")) {
            emulatorScore += 15;
        }
        free(model);
    }
    
    // Check manufacturer
    if (manufacturer) {
        if (strstr(manufacturer, "genymotion") || strstr(manufacturer, "unknown")) {
            emulatorScore += 10;
        }
        free(manufacturer);
    }
    
    // Check brand
    if (brand) {
        if (strstr(brand, "generic") || strstr(brand, "android")) {
            emulatorScore += 10;
        }
        free(brand);
    }
    
    // Check device
    if (device) {
        if (strstr(device, "generic") || strstr(device, "emulator")) {
            emulatorScore += 15;
        }
        free(device);
    }
    
    // Check hardware
    if (hardware) {
        if (strstr(hardware, "goldfish") || strstr(hardware, "ranchu")) {
            emulatorScore += 20;
        }
        free(hardware);
    }
    
    return emulatorScore;
}

int checkEmulatorFiles() {
    const char* emulatorFiles[] = {
        "/system/bin/qemu-props",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so"
    };
    
    int fileCount = sizeof(emulatorFiles) / sizeof(emulatorFiles[0]);
    int foundCount = 0;
    
    for (int i = 0; i < fileCount; i++) {
        if (fileExists(emulatorFiles[i])) {
            foundCount++;
        }
    }
    
    return foundCount * 10; // Each file is worth 10 points
}

int checkEmulatorHardware() {
    char* hardware = getSystemProperty("ro.hardware");
    int score = 0;
    
    if (hardware) {
        if (strstr(hardware, "goldfish") || strstr(hardware, "ranchu")) {
            score = 30;
        }
        free(hardware);
    }
    
    return score;
}

int checkEmulatorSensors() {
    // This would check for emulator-specific sensor characteristics
    // For now, we'll return a placeholder value
    return 0;
}

EmulatorDetectionResult detectEmulator() {
    EmulatorDetectionResult result = {0, NULL, 0, 0.0f};
    
    int propertyScore = checkEmulatorProperties();
    int fileScore = checkEmulatorFiles();
    int hardwareScore = checkEmulatorHardware();
    int sensorScore = checkEmulatorSensors();
    
    int totalScore = propertyScore + fileScore + hardwareScore + sensorScore;
    
    result.isEmulator = (totalScore > 30);
    result.confidence = (totalScore > 100) ? 1.0f : (totalScore / 100.0f);
    
    return result;
}