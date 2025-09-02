#include "emulator_detector.h"
#include "helpers.h"
#include <android/log.h>
#include <string>
#include <vector>
#include <stdlib.h>
#include <string.h>
#include <fstream>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

void checkProperty(const char* propName, const char* suspiciousValue, std::vector<std::string>& found) {
    char* propValue = getSystemProperty(propName);
    if (propValue) {
        if (strstr(propValue, suspiciousValue)) {
            found.push_back("PROP:" + std::string(propName) + "=" + std::string(propValue));
        }
        free(propValue);
    }
}

std::vector<std::string> checkEmulatorProperties() {
    std::vector<std::string> found;
    
    // Extended list of emulator properties
    checkProperty("ro.hardware", "goldfish", found);
    checkProperty("ro.hardware", "ranchu", found);
    checkProperty("ro.hardware", "vbox", found);
    checkProperty("ro.hardware", "nox", found);
    checkProperty("ro.product.model", "sdk", found);
    checkProperty("ro.product.model", "emulator", found);
    checkProperty("ro.product.model", "Android SDK", found);
    checkProperty("ro.product.device", "generic", found);
    checkProperty("ro.product.device", "generic_x86", found);
    checkProperty("ro.product.device", "vbox", found);
    checkProperty("ro.product.device", "nox", found);
    checkProperty("ro.product.brand", "generic", found);
    checkProperty("ro.product.manufacturer", "Genymotion", found);
    checkProperty("ro.product.manufacturer", "unknown", found);
    checkProperty("ro.build.fingerprint", "generic", found);
    checkProperty("ro.build.fingerprint", "vbox", found);
    checkProperty("ro.build.host", "android", found);
    checkProperty("ro.build.host", "localhost", found);
    checkProperty("ro.build.user", "android", found);
    checkProperty("ro.build.user", "jenkins", found);
    checkProperty("ro.build.tags", "test-keys", found);
    checkProperty("ro.kernel.qemu", "1", found);
    checkProperty("ro.boot.hardware", "ranchu", found);
    checkProperty("ro.boot.hardware", "goldfish", found);
    checkProperty("ro.boot.qemu", "1", found);
    checkProperty("ro.boot.qemu.gles", "1", found);
    checkProperty("ro.com.android.dataroaming", "true", found);
    checkProperty("ro.ril.haxxored", "1", found);
    checkProperty("ro.telephony.call_ring.multiple", "0", found);
    checkProperty("ro.telephony.call_ring.delay", "0", found);
    checkProperty("ro.kernel.android.checkjni", "1", found);
    checkProperty("ro.kernel.checkjni", "1", found);
    checkProperty("ro.monkey", "1", found);
    
    return found;
}

std::vector<std::string> checkEmulatorFiles() {
    std::vector<std::string> found;
    
    // Extended list of emulator files
    const char* emulatorFiles[] = {
        "/system/bin/qemu-props",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/system/lib/libc_malloc_debug_qemu.so.1",
        "/system/lib/libc_malloc_debug_qemu.so.2",
        "/system/lib/libc_malloc_debug_qemu.so.3",
        "/system/lib/libc_malloc_debug_qemu.so.4",
        "/system/lib/libc_malloc_debug_qemu.so.5",
        "/system/lib/libc_malloc_debug_qemu.so.6",
        "/system/lib/libc_malloc_debug_qemu.so.7",
        "/system/lib/libc_malloc_debug_qemu.so.8",
        "/system/lib/libc_malloc_debug_qemu.so.9",
        "/system/lib/libc_malloc_debug_qemu.so.10",
        "/system/bin/qemud",
        "/system/bin/nox-prop",
        "/system/bin/noxd",
        "/system/bin/noxscreen",
        "/system/bin/noxplayer",
        "/system/bin/nox",
        "/system/bin/bluestacks",
        "/system/bin/andy",
        "/system/bin/andyx",
        "/system/bin/memu",
        "/system/bin/memud",
        "/system/bin/ldoplayer",
        "/system/bin/droid4x",
        "/system/bin/droid4x-prop",
        "/system/bin/koplayer",
        "/system/bin/leidian",
        "/system/bin/yunvm",
        "/system/bin/tiantian",
        "/system/bin/windroye",
        "/system/bin/nomachine",
        "/system/bin/remix",
        "/system/bin/remixd",
        "/system/bin/vphone",
        "/system/bin/vphone-prop",
        "/system/bin/vbox",
        "/system/bin/vboxd",
        "/system/bin/vbox_prop",
        "/system/bin/vboxd_prop",
        "/system/bin/vbox_sf",
        "/system/bin/vbox_sf_prop",
        "/system/bin/vboxguest",
        "/system/bin/vboxguest_prop",
        "/system/bin/vboxservice",
        "/system/bin/vboxservice_prop",
        "/system/bin/vboxvideo",
        "/system/bin/vboxvideo_prop",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/system/bin/androVM-prop",
        "/system/bin/microvirt-prop",
        "/system/bin/rtmixer",
        "/system/bin/rtmixer.sh",
        "/system/bin/rtmixer_daemon",
        "/system/bin/rtmixer_service",
        "/system/bin/rtmixer_manager",
        "/system/bin/rtmixer_controller",
        "/system/bin/rtmixer_helper",
        "/system/bin/rtmixer_driver",
        "/system/bin/rtmixer_kernel"
    };
    
    for (const char* path : emulatorFiles) {
        if (fileExists(path)) {
            found.push_back("FILE:" + std::string(path));
        }
    }
    return found;
}

std::vector<std::string> checkEmulatorDrivers() {
    std::vector<std::string> found;
    
    // Check for emulator-specific drivers in /proc/tty/drivers
    std::ifstream driversFile("/proc/tty/drivers");
    if (driversFile.is_open()) {
        std::string line;
        while (std::getline(driversFile, line)) {
            if (line.find("goldfish") != std::string::npos ||
                line.find("qemu") != std::string::npos ||
                line.find("vbox") != std::string::npos ||
                line.find("nox") != std::string::npos ||
                line.find("bluestacks") != std::string::npos ||
                line.find("andy") != std::string::npos ||
                line.find("memu") != std::string::npos ||
                line.find("ldoplayer") != std::string::npos ||
                line.find("droid4x") != std::string::npos ||
                line.find("koplayer") != std::string::npos ||
                line.find("leidian") != std::string::npos ||
                line.find("yunvm") != std::string::npos ||
                line.find("tiantian") != std::string::npos ||
                line.find("windroye") != std::string::npos ||
                line.find("nomachine") != std::string::npos ||
                line.find("remix") != std::string::npos ||
                line.find("vphone") != std::string::npos ||
                line.find("microvirt") != std::string::npos ||
                line.find("rtmixer") != std::string::npos) {
                found.push_back("DRIVER:" + line);
            }
        }
        driversFile.close();
    }
    
    return found;
}

std::vector<std::string> checkEmulatorCpuInfo() {
    std::vector<std::string> found;
    
    // Check for emulator-specific CPU info
    std::ifstream cpuInfo("/proc/cpuinfo");
    if (cpuInfo.is_open()) {
        std::string line;
        while (std::getline(cpuInfo, line)) {
            if (line.find("Intel") != std::string::npos ||
                line.find("AMD") != std::string::npos ||
                line.find("QEMU") != std::string::npos ||
                line.find("Virtual CPU") != std::string::npos ||
                line.find("KVM") != std::string::npos ||
                line.find("VMware") != std::string::npos ||
                line.find("VirtualBox") != std::string::npos ||
                line.find("Parallels") != std::string::npos ||
                line.find("Hyper-V") != std::string::npos ||
                line.find("Xen") != std::string::npos ||
                line.find("Bochs") != std::string::npos ||
                line.find("Bhyve") != std::string::npos ||
                line.find("HVM domU") != std::string::npos) {
                found.push_back("CPU_INFO:" + line);
            }
        }
        cpuInfo.close();
    }
    
    return found;
}

// New function to check for emulator-specific network interfaces
std::vector<std::string> checkEmulatorNetworkInterfaces() {
    std::vector<std::string> found;
    
    // Check for emulator-specific network interfaces
    std::ifstream netDev("/proc/net/dev");
    if (netDev.is_open()) {
        std::string line;
        while (std::getline(netDev, line)) {
            if (line.find("eth0:") != std::string::npos ||
                line.find("wlan0:") != std::string::npos ||
                line.find("rmnet0:") != std::string::npos ||
                line.find("usb0:") != std::string::npos ||
                line.find("ppp0:") != std::string::npos ||
                line.find("tun0:") != std::string::npos ||
                line.find("tap0:") != std::string::npos) {
                // Check for suspicious MAC addresses
                std::ifstream arpTable("/proc/net/arp");
                if (arpTable.is_open()) {
                    std::string arpLine;
                    while (std::getline(arpTable, arpLine)) {
                        if (arpLine.find("00:00:00:00:00:00") != std::string::npos ||
                            arpLine.find("02:00:00:00:00:00") != std::string::npos ||
                            arpLine.find("52:54:00:") != std::string::npos ||
                            arpLine.find("08:00:27:") != std::string::npos ||
                            arpLine.find("00:50:56:") != std::string::npos ||
                            arpLine.find("00:0c:29:") != std::string::npos ||
                            arpLine.find("00:1c:14:") != std::string::npos ||
                            arpLine.find("00:05:69:") != std::string::npos ||
                            arpLine.find("00:16:3e:") != std::string::npos) {
                            found.push_back("SUSPICIOUS_MAC_ADDRESS");
                        }
                    }
                    arpTable.close();
                }
            }
        }
        netDev.close();
    }
    
    return found;
}

EmulatorDetectionResult detectEmulator() {
    EmulatorDetectionResult result = {false, {}, 0.0f};

    auto properties = checkEmulatorProperties();
    result.detectedMethods.insert(result.detectedMethods.end(), properties.begin(), properties.end());

    auto files = checkEmulatorFiles();
    result.detectedMethods.insert(result.detectedMethods.end(), files.begin(), files.end());

    auto drivers = checkEmulatorDrivers();
    result.detectedMethods.insert(result.detectedMethods.end(), drivers.begin(), drivers.end());

    auto cpuInfo = checkEmulatorCpuInfo();
    result.detectedMethods.insert(result.detectedMethods.end(), cpuInfo.begin(), cpuInfo.end());

    // New checks
    auto networkInterfaces = checkEmulatorNetworkInterfaces();
    result.detectedMethods.insert(result.detectedMethods.end(), networkInterfaces.begin(), networkInterfaces.end());

    if (!result.detectedMethods.empty()) {
        result.isEmulator = true;
        
        // More sophisticated confidence calculation
        float confidence = 0.0f;
        int highConfidenceIndicators = 0;
        int mediumConfidenceIndicators = 0;
        int lowConfidenceIndicators = 0;
        
        for (const auto& method : result.detectedMethods) {
            if (method.find("PROP:ro.kernel.qemu=1") != std::string::npos ||
                method.find("FILE:/dev/qemu_pipe") != std::string::npos ||
                method.find("PROP:ro.hardware=goldfish") != std::string::npos ||
                method.find("PROP:ro.hardware=ranchu") != std::string::npos ||
                method.find("SUSPICIOUS_MAC_ADDRESS") != std::string::npos) {
                highConfidenceIndicators++;
            } else if (method.find("CPU_INFO:") != std::string::npos ||
                       method.find("DRIVER:") != std::string::npos ||
                       method.find("PROP:") != std::string::npos ||
                       method.find("VIRTUAL_SENSOR:") != std::string::npos) {
                mediumConfidenceIndicators++;
            } else {
                lowConfidenceIndicators++;
            }
        }
        
        // Calculate confidence based on the types of indicators found
        confidence += highConfidenceIndicators * 0.4f;
        confidence += mediumConfidenceIndicators * 0.25f;
        confidence += lowConfidenceIndicators * 0.1f;
        
        // Cap confidence at 1.0
        result.confidence = confidence > 1.0f ? 1.0f : confidence;
    }

    return result;
}