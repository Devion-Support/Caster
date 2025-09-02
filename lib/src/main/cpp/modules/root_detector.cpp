#include "root_detector.h"
#include "helpers.h"
#include <android/log.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fstream>
#include <sstream>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

std::vector<std::string> checkForRootBinaries() {
    std::vector<std::string> found;
    const char* suPaths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
        "/data/local/bin/su", "/data/local/xbin/su", "/system/sbin/su",
        "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
        "/system/app/Superuser.apk", "/system/app/SuperUser.apk",
        "/system/app/superuser.apk", "/system/app/Superuser.odex",
        "/system/app/SuperUser.odex", "/system/app/superuser.odex",
        "/system/bin/failsafe/su", "/system/bin/sudo", "/system/bin/su-backup",
        "/system/xbin/sudo", "/system/xbin/su-backup", "/system/etc/security/otacerts.zip"
    };
    for (const char* path : suPaths) {
        if (fileExists(path) && isFileExecutable(path)) {
            found.push_back("BINARY:" + std::string(path));
        }
    }
    return found;
}

std::vector<std::string> checkForMagiskArtifacts() {
    std::vector<std::string> found;
    const char* magiskPaths[] = {
        "/sbin/.magisk", "/cache/.disable_magisk", "/dev/.magisk.unblock", 
        "/data/adb/magisk", "/data/adb/magisk.img", "/data/adb/magisk.db",
        "/data/adb/magisk_simple", "/data/adb/modules", "/data/adb/modules_update",
        "/data/adb/post-fs-data.d", "/data/adb/service.d", "/data/adb/bin",
        "/dev/.magisk_random", "/cache/magisk.log", "/data/adb/magisk/util_functions.sh",
        "/sbin/magisk", "/sbin/magiskhide", "/sbin/magiskpolicy", "/sbin/magiskinit",
        "/dev/magisk_device", "/dev/magisk", "/dev/magiskhide", "/dev/magiskpolicy",
        "/sbin/magisk_patched", "/data/magisk", "/cache/magisk"
    };
    for (const char* path : magiskPaths) {
        if (fileExists(path)) {
            found.push_back("MAGISK_ARTIFACT:" + std::string(path));
        }
    }
    return found;
}

std::vector<std::string> checkForMagiskUDS() {
    std::vector<std::string> found;
    FILE *fh = fopen("/proc/net/unix", "r");
    if (!fh) {
        LOGE("Failed to open /proc/net/unix: %s", strerror(errno));
        return found;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fh)) {
        // More precise detection of Magisk UDS
        if (strstr(line, "@") != NULL) {
            // Check for common Magisk UDS names
            if (strstr(line, "magisk") != NULL || 
                strstr(line, "MGIS") != NULL || 
                strstr(line, "MGIT") != NULL ||
                (strlen(strstr(line, "@")) > 32)) {  // Long random names
                found.push_back("MAGISK_UDS_DETECTED");
                break; // Found it, no need to continue
            }
        }
    }
    fclose(fh);
    return found;
}

std::vector<std::string> checkForSuperSUArtifacts() {
    std::vector<std::string> found;
    const char* superSUPaths[] = {
        "/system/app/SuperSU.apk", "/system/app/supersu.apk",
        "/system/app/SuperSU/SuperSU.apk", "/system/app/SuperSU/", 
        "/system/etc/init.d/99SuperSUDaemon", "/system/etc/.installed_su_daemon",
        "/system/bin/.ext/.su", "/system/xbin/daemonsu", "/system/xbin/sugote",
        "/system/xbin/sugote-mksh", "/system/xbin/supolicy", "/system/lib/libsupol.so",
        "/system/lib64/libsupol.so", "/system/etc/install-recovery.sh",
        "/system/bin/supolicy", "/system/bin/sukernel", "/system/bin/sukernel_daemon",
        "/system/bin/supersu", "/system/xbin/supersu", "/system/app/SuperUser/SuperUser.apk"
    };
    for (const char* path : superSUPaths) {
        if (fileExists(path)) {
            found.push_back("SUPERSU_ARTIFACT:" + std::string(path));
        }
    }
    return found;
}

std::vector<std::string> checkForKernelSUArtifacts() {
    std::vector<std::string> found;
    const char* kernelSUPaths[] = {
        "/system/bin/ksu", "/system/xbin/ksu", "/sbin/ksu", "/data/adb/ksu",
        "/data/adb/ksud", "/data/adb/ksu.log", "/data/adb/ksu_version",
        "/system/bin/kernelsu", "/system/xbin/kernelsu", "/sbin/kernelsu",
        "/dev/kernelsu", "/dev/ksu", "/data/adb/modules/ksu", "/data/adb/ksud_tmp"
    };
    for (const char* path : kernelSUPaths) {
        if (fileExists(path)) {
            found.push_back("KERNELSU_ARTIFACT:" + std::string(path));
        }
    }
    
    // Check for KernelSU in /proc/modules
    std::ifstream modulesFile("/proc/modules");
    if (modulesFile.is_open()) {
        std::string line;
        while (std::getline(modulesFile, line)) {
            if (line.find("kernelsu") != std::string::npos) {
                found.push_back("KERNELSU_MODULE_LOADED");
                break;
            }
        }
        modulesFile.close();
    }
    
    return found;
}

std::vector<std::string> checkForAdditionalRootIndicators() {
    std::vector<std::string> found;
    
    // Check for test keys in build properties
    std::ifstream buildProp("/system/build.prop");
    if (buildProp.is_open()) {
        std::string line;
        while (std::getline(buildProp, line)) {
            if (line.find("ro.build.tags=test-keys") != std::string::npos) {
                found.push_back("TEST_KEYS_DETECTED");
            }
            // Check for common rooted device properties
            if (line.find("ro.secure=0") != std::string::npos) {
                found.push_back("RO_SECURE_DISABLED");
            }
            if (line.find("ro.debuggable=1") != std::string::npos) {
                found.push_back("RO_DEBUGGABLE_ENABLED");
            }
        }
        buildProp.close();
    }
    
    // Check for dangerous permissions in packages.xml
    if (fileExists("/data/system/packages.xml")) {
        std::ifstream packagesFile("/data/system/packages.xml");
        if (packagesFile.is_open()) {
            std::string content((std::istreambuf_iterator<char>(packagesFile)),
                               std::istreambuf_iterator<char>());
            if (content.find("package-verifier-enable=0") != std::string::npos ||
                content.find("verifier_verify_adb_enable=0") != std::string::npos) {
                found.push_back("PACKAGE_VERIFIER_DISABLED");
            }
            packagesFile.close();
        }
    }
    
    // Check for common root-related system properties
    const char* rootProps[] = {
        "ro.build.selinux=0",
        "ro.boot.flash.locked=0",
        "ro.boot.verifiedbootstate=orange",
        "ro.boot.veritymode=disabled"
    };
    
    for (const char* prop : rootProps) {
        char* propValue = getSystemProperty(prop);
        if (propValue) {
            std::string propStr = std::string(prop);
            size_t eqPos = propStr.find("=");
            if (eqPos != std::string::npos) {
                std::string expectedValue = propStr.substr(eqPos + 1);
                if (strstr(propValue, expectedValue.c_str())) {
                    found.push_back("ROOT_PROP:" + propStr);
                }
            }
            free(propValue);
        }
    }
    
    return found;
}

std::vector<std::string> checkForRootCloaking() {
    std::vector<std::string> found;
    
    // Check if common root cloaking apps are installed
    const char* cloakingApps[] = {
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
        "de.robv.android.xposed.installer", "com.saurik.substrate",
        "com.topjohnwu.magisk", "io.github.huskydg.magisk",
        "com.aefyr.sai", "com.lbe.security.lesel", "org.lsposed.manager"
    };
    
    for (const char* app : cloakingApps) {
        std::string path = "/data/data/" + std::string(app);
        if (fileExists(path.c_str())) {
            found.push_back("ROOT_CLOAKING_APP:" + std::string(app));
        }
    }
    
    return found;
}

// New function to check for root cloaking techniques
std::vector<std::string> checkForRootCloakingTechniques() {
    std::vector<std::string> found;
    
    // Check if common root cloaking techniques are in use
    // This involves checking for hooking of system functions
    FILE *mapsFile = fopen("/proc/self/maps", "r");
    if (mapsFile) {
        char line[1024];
        while (fgets(line, sizeof(line), mapsFile)) {
            // Look for libraries commonly used in root cloaking
            if (strstr(line, "libriru.so") != NULL ||
                strstr(line, "liblsposed.so") != NULL ||
                strstr(line, "libxposed.so") != NULL ||
                strstr(line, "libsubstrate.so") != NULL) {
                found.push_back("ROOT_CLOAKING_LIB:" + std::string(line));
            }
        }
        fclose(mapsFile);
    }
    
    return found;
}

// New function to check for root hiding techniques
std::vector<std::string> checkForRootHidingTechniques() {
    std::vector<std::string> found;
    
    // Check for common root hiding techniques
    const char* hidingPaths[] = {
        "/sbin/.magisk/mirror/system/bin/su",
        "/sbin/.magisk/mirror/system/xbin/su",
        "/dev/.ksu/mirror/system/bin/su",
        "/dev/.ksu/mirror/system/xbin/su"
    };
    
    for (const char* path : hidingPaths) {
        if (fileExists(path)) {
            found.push_back("ROOT_HIDING_ARTIFACT:" + std::string(path));
        }
    }
    
    return found;
}

RootDetectionResult detectRoot() {
    RootDetectionResult result = {false, {}, 0.0f};

    auto binaries = checkForRootBinaries();
    result.detectedMethods.insert(result.detectedMethods.end(), binaries.begin(), binaries.end());

    auto magiskFiles = checkForMagiskArtifacts();
    result.detectedMethods.insert(result.detectedMethods.end(), magiskFiles.begin(), magiskFiles.end());

    auto magiskUDS = checkForMagiskUDS();
    result.detectedMethods.insert(result.detectedMethods.end(), magiskUDS.begin(), magiskUDS.end());

    auto superSU = checkForSuperSUArtifacts();
    result.detectedMethods.insert(result.detectedMethods.end(), superSU.begin(), superSU.end());

    auto kernelSU = checkForKernelSUArtifacts();
    result.detectedMethods.insert(result.detectedMethods.end(), kernelSU.begin(), kernelSU.end());

    auto additionalIndicators = checkForAdditionalRootIndicators();
    result.detectedMethods.insert(result.detectedMethods.end(), additionalIndicators.begin(), additionalIndicators.end());

    auto cloakingApps = checkForRootCloaking();
    result.detectedMethods.insert(result.detectedMethods.end(), cloakingApps.begin(), cloakingApps.end());

    // New checks
    auto cloakingTechniques = checkForRootCloakingTechniques();
    result.detectedMethods.insert(result.detectedMethods.end(), cloakingTechniques.begin(), cloakingTechniques.end());

    auto hidingTechniques = checkForRootHidingTechniques();
    result.detectedMethods.insert(result.detectedMethods.end(), hidingTechniques.begin(), hidingTechniques.end());

    if (!result.detectedMethods.empty()) {
        result.isRooted = true;
        // More sophisticated confidence score calculation
        float confidence = 0.0f;
        int highConfidenceIndicators = 0;
        int mediumConfidenceIndicators = 0;
        int lowConfidenceIndicators = 0;
        
        for (const auto& method : result.detectedMethods) {
            if (method.find("BINARY:") != std::string::npos || 
                method.find("MAGISK_ARTIFACT:") != std::string::npos ||
                method.find("MAGISK_UDS_DETECTED") != std::string::npos ||
                method.find("TEST_KEYS_DETECTED") != std::string::npos ||
                method.find("RO_SECURE_DISABLED") != std::string::npos ||
                method.find("RO_DEBUGGABLE_ENABLED") != std::string::npos) {
                highConfidenceIndicators++;
            } else if (method.find("SUPERSU_ARTIFACT:") != std::string::npos ||
                       method.find("KERNELSU_ARTIFACT:") != std::string::npos ||
                       method.find("KERNELSU_MODULE_LOADED") != std::string::npos ||
                       method.find("ROOT_PROP:") != std::string::npos) {
                mediumConfidenceIndicators++;
            } else {
                lowConfidenceIndicators++;
            }
        }
        
        // Calculate confidence based on the types of indicators found
        confidence += highConfidenceIndicators * 0.35f;
        confidence += mediumConfidenceIndicators * 0.25f;
        confidence += lowConfidenceIndicators * 0.1f;
        
        // Cap confidence at 1.0
        result.confidence = confidence > 1.0f ? 1.0f : confidence;
    }

    return result;
}