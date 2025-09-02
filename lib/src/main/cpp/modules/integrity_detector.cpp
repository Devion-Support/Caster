// Standard C library headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

// Standard C++ library headers
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

// Android specific headers
#include <android/log.h>

// Project headers
#include "integrity_detector.h"
#include "helpers.h"
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#include <vector>

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
    // In a real implementation, this would compare the current signature with expected signature
    return 0;
}

int checkApkModification(const char* packageName) {
    // This would check for APK modification
    // For now, we'll just return a placeholder
    // In a real implementation, this would compute and compare checksums
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

std::vector<std::string> checkInstallerIntegrity(const char* packageName) {
    std::vector<std::string> found;
    
    char command[512];
    snprintf(command, sizeof(command), "dumpsys package %s | grep -E 'installerPackageName|installerUid'", packageName);
    
    FILE *fp = popen(command, "r");
    if (!fp) return found;
    
    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        // Check for suspicious installers
        if (strstr(line, "com.android.vending") == NULL &&  // Google Play Store
            strstr(line, "com.amazon.venezia") == NULL &&   // Amazon Appstore
            strstr(line, "com.sec.android.app.samsungapps") == NULL &&  // Samsung Galaxy Store
            strstr(line, "com.huawei.appmarket") == NULL &&  // Huawei AppGallery
            strstr(line, "com.xiaomi.market") == NULL &&     // Xiaomi Mi Store
            strstr(line, "com.oppo.market") == NULL &&       // OPPO App Market
            strstr(line, "com.vivo.appstore") == NULL &&     // vivo App Store
            strstr(line, "com.oneplus.appstore") == NULL &&  // OnePlus App Store
            strstr(line, "com.lenovo.leos.appstore") == NULL) { // Lenovo App Store
            // If not from a known app store, flag as suspicious
            found.push_back("SUSPICIOUS_INSTALLER:" + std::string(line));
        }
    }
    
    pclose(fp);
    return found;
}

std::vector<std::string> checkPackageVerification(const char* packageName) {
    std::vector<std::string> found;
    
    // Check if package verifier is disabled
    FILE *fp = popen("settings get package_verifier_enable", "r");
    if (fp) {
        char result[16];
        if (fgets(result, sizeof(result), fp) != NULL) {
            // If package verifier is disabled (0), flag as suspicious
            if (strstr(result, "0") != NULL) {
                found.push_back("PACKAGE_VERIFIER_DISABLED");
            }
        }
        pclose(fp);
    }
    
    return found;
}

std::vector<std::string> checkAppSigning(const char* packageName) {
    std::vector<std::string> found;
    
    char command[512];
    snprintf(command, sizeof(command), "dumpsys package %s | grep -A 10 'signatures:'", packageName);
    
    FILE *fp = popen(command, "r");
    if (!fp) return found;
    
    char line[512];
    bool foundSignatures = false;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "signatures:") != NULL) {
            foundSignatures = true;
        } else if (foundSignatures && strlen(line) > 10) {
            // Look for suspicious signature patterns
            if (strstr(line, "test-keys") != NULL) {
                found.push_back("TEST_KEYS_IN_SIGNATURE");
            }
            // Check for debug certificates
            if (strstr(line, "CN=Android Debug") != NULL) {
                found.push_back("DEBUG_CERTIFICATE");
            }
        }
    }
    
    pclose(fp);
    return found;
}

std::vector<std::string> checkRuntimeIntegrity() {
    std::vector<std::string> found;
    
    // Check for common runtime modifications
    const char* suspiciousPaths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su",
        "/data/local/bin/su", "/data/local/xbin/su", "/system/bin/failsafe/su",
        "/system/bin/sudo", "/system/xbin/sudo", "/system/bin/su-backup",
        "/system/xbin/su-backup", "/system/etc/security/otacerts.zip"
    };
    
    for (const char* path : suspiciousPaths) {
        if (access(path, F_OK) == 0) {
            found.push_back("RUNTIME_MODIFICATION:" + std::string(path));
        }
    }
    
    return found;
}

// New function to check for SELinux status
std::vector<std::string> checkSELinuxStatus() {
    std::vector<std::string> found;
    
    char* selinuxStatus = getSystemProperty("ro.build.selinux");
    if (selinuxStatus) {
        if (strcmp(selinuxStatus, "0") == 0) {
            found.push_back("SELINUX_DISABLED");
        }
        free(selinuxStatus);
    }
    
    return found;
}

// New function to check for system partition integrity
std::vector<std::string> checkSystemPartitionIntegrity() {
    std::vector<std::string> found;
    
    // Check if system partition is mounted as read-write
    FILE *mountsFile = fopen("/proc/mounts", "r");
    if (mountsFile) {
        char line[1024];
        while (fgets(line, sizeof(line), mountsFile)) {
            if (strstr(line, "/system") != NULL) {
                // Check if it's mounted as read-write
                if (strstr(line, "rw,") != NULL || strstr(line, "rw ") != NULL) {
                    found.push_back("SYSTEM_PARTITION_RW");
                }
            }
        }
        fclose(mountsFile);
    }
    
    return found;
}

// New function to check for bootloader status
std::vector<std::string> checkBootloaderStatus() {
    std::vector<std::string> found;
    
    char* bootloaderStatus = getSystemProperty("ro.boot.flash.locked");
    if (bootloaderStatus) {
        if (strcmp(bootloaderStatus, "0") == 0) {
            found.push_back("BOOTLOADER_UNLOCKED");
        }
        free(bootloaderStatus);
    }
    
    char* verifiedBootState = getSystemProperty("ro.boot.verifiedbootstate");
    if (verifiedBootState) {
        if (strcmp(verifiedBootState, "orange") == 0 || strcmp(verifiedBootState, "yellow") == 0) {
            found.push_back("VERIFIED_BOOT_COMPROMISED:" + std::string(verifiedBootState));
        }
        free(verifiedBootState);
    }
    
    return found;
}

IntegrityDetectionResult detectIntegrity(const char* packageName) {
    IntegrityDetectionResult result;
    result.isTampered = false;
    result.detectedMethods.clear();
    
    int signatureTampered = checkSignatureIntegrity(packageName);
    int apkModified = checkApkModification(packageName);
    int debuggableFlag = checkDebuggableFlag(packageName);
    
    auto installerIssues = checkInstallerIntegrity(packageName);
    auto packageVerificationIssues = checkPackageVerification(packageName);
    auto signingIssues = checkAppSigning(packageName);
    auto runtimeIssues = checkRuntimeIntegrity();
    
    // New checks
    auto selinuxIssues = checkSELinuxStatus();
    auto systemPartitionIssues = checkSystemPartitionIntegrity();
    auto bootloaderIssues = checkBootloaderStatus();
    
    // Collect all detected methods
    if (signatureTampered) {
        result.detectedMethods.push_back("SIGNATURE_TAMPERED");
    }
    
    if (apkModified) {
        result.detectedMethods.push_back("APK_MODIFIED");
    }
    
    if (debuggableFlag) {
        result.detectedMethods.push_back("DEBUGGABLE_FLAG_SET");
    }
    
    result.detectedMethods.insert(result.detectedMethods.end(), installerIssues.begin(), installerIssues.end());
    result.detectedMethods.insert(result.detectedMethods.end(), packageVerificationIssues.begin(), packageVerificationIssues.end());
    result.detectedMethods.insert(result.detectedMethods.end(), signingIssues.begin(), signingIssues.end());
    result.detectedMethods.insert(result.detectedMethods.end(), runtimeIssues.begin(), runtimeIssues.end());
    result.detectedMethods.insert(result.detectedMethods.end(), selinuxIssues.begin(), selinuxIssues.end());
    result.detectedMethods.insert(result.detectedMethods.end(), systemPartitionIssues.begin(), systemPartitionIssues.end());
    result.detectedMethods.insert(result.detectedMethods.end(), bootloaderIssues.begin(), bootloaderIssues.end());
    
    int tamperDetected = signatureTampered || apkModified || debuggableFlag || 
                        !installerIssues.empty() || !packageVerificationIssues.empty() ||
                        !signingIssues.empty() || !runtimeIssues.empty() ||
                        !selinuxIssues.empty() || !systemPartitionIssues.empty() ||
                        !bootloaderIssues.empty();
    
    result.isTampered = tamperDetected;
    
    return result;
}