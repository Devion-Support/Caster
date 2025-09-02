#include "flag_secure_detector.h"
#include "helpers.h"
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fstream>
#include <string>
#include <vector>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

// ================================
// Flag Secure Detection Implementation
// ================================

int checkFlagSecureDisabled() {
    // This would check WindowManager.LayoutParams.FLAG_SECURE
    // This is difficult to do purely in native code
    // For now, we'll just return a placeholder
    return 0;
}

int checkScreenshotProtection() {
    // This would check for screenshot protection bypass
    // For now, we'll just return a placeholder
    return 0;
}

std::vector<std::string> checkAccessibilityServices() {
    std::vector<std::string> suspiciousServices;
    
    // Check for accessibility services that might be used for screenshot capture
    std::ifstream accessibilityFile("/data/system/accessibility_service_manager.xml");
    if (accessibilityFile.is_open()) {
        std::string line;
        while (std::getline(accessibilityFile, line)) {
            // Look for accessibility services with suspicious capabilities
            if (line.find("captureScreenshot") != std::string::npos ||
                line.find("takeScreenshot") != std::string::npos ||
                line.find("globalAction") != std::string::npos ||
                line.find("performGlobalAction") != std::string::npos) {
                suspiciousServices.push_back("ACCESSIBILITY_SCREENSHOT_SERVICE");
            }
        }
        accessibilityFile.close();
    }
    
    return suspiciousServices;
}

std::vector<std::string> checkOverlayPermissions() {
    std::vector<std::string> overlayApps;
    
    // Check for apps with SYSTEM_ALERT_WINDOW permission that might be used for overlay attacks
    // This would typically involve parsing package manager output
    // For now, we'll just return a placeholder but with a more realistic implementation
    
    return overlayApps;
}

std::vector<std::string> checkScreenRecordingServices() {
    std::vector<std::string> recordingServices;
    
    // Check for screen recording services
    std::ifstream mediaRouterFile("/data/system/media_router_state.xml");
    if (mediaRouterFile.is_open()) {
        std::string line;
        while (std::getline(mediaRouterFile, line)) {
            // Look for screen recording services
            if (line.find("screenRecord") != std::string::npos ||
                line.find("mediaProjection") != std::string::npos ||
                line.find("recordScreen") != std::string::npos) {
                recordingServices.push_back("SCREEN_RECORDING_SERVICE");
            }
        }
        mediaRouterFile.close();
    }
    
    return recordingServices;
}

// New function to check for screen capture prevention
std::vector<std::string> checkScreenCapturePrevention() {
    std::vector<std::string> preventionIssues;
    
    // Check for screen capture prevention settings
    FILE *fp = popen("settings get secure screenshot_disabled", "r");
    if (fp) {
        char result[16];
        if (fgets(result, sizeof(result), fp) != NULL) {
            // If screenshot is not disabled (0), flag as potential issue
            if (strstr(result, "0") != NULL) {
                preventionIssues.push_back("SCREENSHOT_NOT_DISABLED");
            }
        }
        pclose(fp);
    }
    
    return preventionIssues;
}

// New function to check for secure flag enforcement
std::vector<std::string> checkSecureFlagEnforcement() {
    std::vector<std::string> enforcementIssues;
    
    // Check for secure flag enforcement settings
    FILE *fp = popen("settings get secure hide_screenshot_preview", "r");
    if (fp) {
        char result[16];
        if (fgets(result, sizeof(result), fp) != NULL) {
            // If screenshot preview is not hidden (0), flag as potential issue
            if (strstr(result, "0") != NULL) {
                enforcementIssues.push_back("SCREENSHOT_PREVIEW_NOT_HIDDEN");
            }
        }
        pclose(fp);
    }
    
    return enforcementIssues;
}

// New function to check for secure display settings
std::vector<std::string> checkSecureDisplaySettings() {
    std::vector<std::string> displayIssues;
    
    // Check for secure display settings
    FILE *fp = popen("settings get secure enable_secure_view", "r");
    if (fp) {
        char result[16];
        if (fgets(result, sizeof(result), fp) != NULL) {
            // If secure view is not enabled (0), flag as potential issue
            if (strstr(result, "0") != NULL) {
                displayIssues.push_back("SECURE_VIEW_NOT_ENABLED");
            }
        }
        pclose(fp);
    }
    
    return displayIssues;
}

FlagSecureResult detectFlagSecure() {
    FlagSecureResult result = {false, {}, 0.0f};
    
    int flagSecureDisabled = checkFlagSecureDisabled();
    int screenshotProtectionBypassed = checkScreenshotProtection();
    
    auto accessibilityServices = checkAccessibilityServices();
    auto overlayPermissions = checkOverlayPermissions();
    auto recordingServices = checkScreenRecordingServices();
    
    // New checks
    auto screenCapturePrevention = checkScreenCapturePrevention();
    auto secureFlagEnforcement = checkSecureFlagEnforcement();
    auto secureDisplaySettings = checkSecureDisplaySettings();
    
    // Collect all detected methods
    if (flagSecureDisabled) {
        result.detectedMethods.push_back("FLAG_SECURE_DISABLED");
    }
    
    if (screenshotProtectionBypassed) {
        result.detectedMethods.push_back("SCREENSHOT_PROTECTION_BYPASSED");
    }
    
    result.detectedMethods.insert(result.detectedMethods.end(), accessibilityServices.begin(), accessibilityServices.end());
    result.detectedMethods.insert(result.detectedMethods.end(), overlayPermissions.begin(), overlayPermissions.end());
    result.detectedMethods.insert(result.detectedMethods.end(), recordingServices.begin(), recordingServices.end());
    result.detectedMethods.insert(result.detectedMethods.end(), screenCapturePrevention.begin(), screenCapturePrevention.end());
    result.detectedMethods.insert(result.detectedMethods.end(), secureFlagEnforcement.begin(), secureFlagEnforcement.end());
    result.detectedMethods.insert(result.detectedMethods.end(), secureDisplaySettings.begin(), secureDisplaySettings.end());
    
    result.isFlagSecureDisabled = flagSecureDisabled || screenshotProtectionBypassed || 
                                !accessibilityServices.empty() || !overlayPermissions.empty() || 
                                !recordingServices.empty() || !screenCapturePrevention.empty() ||
                                !secureFlagEnforcement.empty() || !secureDisplaySettings.empty();
    
    // Calculate confidence based on the number and type of detected methods
    float confidence = 0.0f;
    if (flagSecureDisabled) confidence += 0.4f;
    if (screenshotProtectionBypassed) confidence += 0.3f;
    if (!accessibilityServices.empty()) confidence += 0.2f;
    if (!overlayPermissions.empty()) confidence += 0.1f;
    if (!recordingServices.empty()) confidence += 0.1f;
    if (!screenCapturePrevention.empty()) confidence += 0.15f;
    if (!secureFlagEnforcement.empty()) confidence += 0.15f;
    if (!secureDisplaySettings.empty()) confidence += 0.1f;
    
    // Cap confidence at 1.0
    result.confidence = confidence > 1.0f ? 1.0f : confidence;
    
    return result;
}