#include "anti_tampering_detector.h"
#include "helpers.h"
#include <android/log.h>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <fstream>
#include <sstream>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

#define FRIDA_PORT 27042

bool checkForTracerPid() {
    FILE *statusFile = fopen("/proc/self/status", "r");
    if (!statusFile) {
        LOGE("Failed to open /proc/self/status: %s", strerror(errno));
        return false;
    }
    char line[512];
    while (fgets(line, sizeof(line), statusFile)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracerPid = atoi(line + 10);
            fclose(statusFile);
            if (tracerPid != 0) {
                LOGD("[ANTI-DEBUG] Debugger detected! TracerPid: %d", tracerPid);
                return true;
            }
            return false;
        }
    }
    fclose(statusFile);
    return false;
}

std::vector<std::string> checkForHookingFrameworks() {
    std::vector<std::string> found;
    FILE *mapsFile = fopen("/proc/self/maps", "r");
    if (!mapsFile) {
        LOGE("Failed to open /proc/self/maps: %s", strerror(errno));
        return found;
    }
    char line[1024];
    const char* suspiciousStrings[] = {
        "frida", "xposed", "substrate", "cydia", "libhook", "libinject", "libsandhook", 
        "edxposed", "lsposed", "riru", "magisk", "kernelsu", "sauron", "shadowhook",
        "libdobby", "libwhale", "libele7en", "libhooker", "libpdd", "libxsigner"
    };
    while (fgets(line, sizeof(line), mapsFile)) {
        for (const char* suspect : suspiciousStrings) {
            if (strstr(line, suspect) != NULL) {
                found.push_back("HOOK_LIB:" + std::string(suspect));
            }
        }
    }
    fclose(mapsFile);
    return found;
}

std::vector<std::string> checkForFridaArtifacts() {
    std::vector<std::string> found;
    const char* fridaPaths[] = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida-agent-32.so",
        "/data/local/tmp/frida-agent-64.so",
        "/sdcard/frida-server",
        "/data/data/com.android.tools.fd",
        "/data/data/com.fr0z3n.betterinjector",
        "/sbin/frida-server",
        "/system/bin/frida-server",
        "/system/xbin/frida-server",
        "/dev/socket/frida",
        "/dev/socket/frida64",
        "/data/user_de/0/com.android.tools.fd",
        "/data/user_de/0/com.fr0z3n.betterinjector"
    };
    
    for (const char* path : fridaPaths) {
        if (access(path, F_OK) == 0) {
            found.push_back("FRIDA_ARTIFACT:" + std::string(path));
        }
    }
    
    return found;
}

bool checkForFridaPort() {
    struct sockaddr_in serverAddr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return false;

    // Set socket timeout to avoid hanging
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(FRIDA_PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    bool detected = (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0);
    close(sockfd);
    return detected;
}

bool checkForDebuggingArtifacts() {
    // Check for common emulator/debugging artifacts
    const char* debugPaths[] = {
        "/sys/class/kgsl/kgsl-3d0/devfreq/governor",
        "/sys/devices/virtual/kgsl/kgsl/page_alloc",
        "/sys/module/kgsl/parameters/vmalloc_start",
        "/dev/qemu_pipe",
        "/dev/socket/qemu_pipe",
        "/system/bin/qemu-props",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd"
    };
    
    for (const char* path : debugPaths) {
        if (access(path, F_OK) == 0) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> checkForReverseEngineeringTools() {
    std::vector<std::string> found;
    
    // Check for common reverse engineering tools in /proc/net/unix
    FILE *unixFile = fopen("/proc/net/unix", "r");
    if (unixFile) {
        char line[1024];
        const char* reTools[] = {
            "gdb", "gdbserver", "strace", "ltrace", "ptrace", "radare2", "frida", "xposed"
        };
        
        while (fgets(line, sizeof(line), unixFile)) {
            for (const char* tool : reTools) {
                if (strstr(line, tool) != NULL) {
                    found.push_back("RE_TOOL:" + std::string(tool));
                }
            }
        }
        fclose(unixFile);
    }
    
    return found;
}

bool checkForTimingAnomalies() {
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    // Perform a simple computation
    volatile long result = 0;
    for (int i = 0; i < 1000000; i++) {
        result += i;
    }
    
    gettimeofday(&end, NULL);
    
    // Calculate elapsed time in microseconds
    long elapsed = (end.tv_sec - start.tv_sec) * 1000000L + (end.tv_usec - start.tv_usec);
    
    // Normal execution should take much less than 100ms (100000 microseconds)
    // If it takes significantly longer, it might indicate instrumentation
    if (elapsed > 100000) {  // 100ms threshold
        LOGD("[ANTI-TAMPER] Timing anomaly detected: %ld microseconds", elapsed);
        return true;
    }
    
    return false;
}

// New function to check for memory tampering
bool checkForMemoryTampering() {
    // Check if memory is being manipulated by comparing checksums
    // This is a simplified example - in practice, you would check critical memory regions
    char buffer[1024];
    memset(buffer, 0xAA, sizeof(buffer));
    
    // Simple checksum
    unsigned long checksum = 0;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        checksum += (unsigned char)buffer[i];
    }
    
    // Simulate some time passing
    usleep(1000); // 1ms
    
    // Check if buffer was modified
    unsigned long newChecksum = 0;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        newChecksum += (unsigned char)buffer[i];
    }
    
    return checksum != newChecksum;
}

// New function to check for code injection
std::vector<std::string> checkForCodeInjection() {
    std::vector<std::string> found;
    
    // Check /proc/self/maps for unexpected memory mappings
    FILE *mapsFile = fopen("/proc/self/maps", "r");
    if (mapsFile) {
        char line[1024];
        while (fgets(line, sizeof(line), mapsFile)) {
            // Look for executable memory mappings that don't belong to our app
            if (strstr(line, "r-xp") != NULL) {
                // Skip known legitimate mappings
                if (strstr(line, "libc.so") == NULL &&
                    strstr(line, "libm.so") == NULL &&
                    strstr(line, "libdl.so") == NULL &&
                    strstr(line, "liblog.so") == NULL &&
                    strstr(line, "libz.so") == NULL &&
                    strstr(line, "libandroid.so") == NULL &&
                    strstr(line, "libjavacore.so") == NULL &&
                    strstr(line, "libopenjdk.so") == NULL &&
                    strstr(line, "libart.so") == NULL &&
                    strstr(line, "libnativehelper.so") == NULL &&
                    strstr(line, "libutils.so") == NULL &&
                    strstr(line, "libcutils.so") == NULL &&
                    strstr(line, "libbinder.so") == NULL &&
                    strstr(line, "libgui.so") == NULL &&
                    strstr(line, "libui.so") == NULL &&
                    strstr(line, "libEGL.so") == NULL &&
                    strstr(line, "libGLESv2.so") == NULL &&
                    strstr(line, "libhardware.so") == NULL &&
                    strstr(line, "libhardware_legacy.so") == NULL &&
                    strstr(line, "libcamera_client.so") == NULL &&
                    strstr(line, "libstagefright.so") == NULL &&
                    strstr(line, "libmedia.so") == NULL &&
                    strstr(line, "libcrypto.so") == NULL &&
                    strstr(line, "libssl.so") == NULL &&
                    strstr(line, "libsqlite.so") == NULL &&
                    strstr(line, "libicuuc.so") == NULL &&
                    strstr(line, "libicui18n.so") == NULL &&
                    strstr(line, "libexpat.so") == NULL &&
                    strstr(line, "libpng.so") == NULL &&
                    strstr(line, "libjpeg.so") == NULL &&
                    strstr(line, "libskia.so") == NULL &&
                    strstr(line, "libvorbisidec.so") == NULL &&
                    strstr(line, "libsonivox.so") == NULL &&
                    strstr(line, "libaudioutils.so") == NULL &&
                    strstr(line, "libpdfium.so") == NULL &&
                    strstr(line, "libharfbuzz_ng.so") == NULL &&
                    strstr(line, "libminikin.so") == NULL &&
                    strstr(line, "libmemtrack.so") == NULL &&
                    strstr(line, "libRScpp.so") == NULL &&
                    strstr(line, "libRSDriver.so") == NULL &&
                    strstr(line, "libRS.so") == NULL &&
                    strstr(line, "libbacktrace.so") == NULL &&
                    strstr(line, "libunwind.so") == NULL &&
                    strstr(line, "liblzma.so") == NULL &&
                    strstr(line, "libunwind-ptrace.so") == NULL &&
                    strstr(line, "libbase.so") == NULL &&
                    strstr(line, "libc++.so") == NULL &&
                    strstr(line, "libprocessgroup.so") == NULL &&
                    strstr(line, "libnetd_client.so") == NULL &&
                    strstr(line, "libselinux.so") == NULL &&
                    strstr(line, "libadbconnection.so") == NULL &&
                    strstr(line, "libcpu_features.so") == NULL &&
                    strstr(line, "libvndksupport.so") == NULL &&
                    strstr(line, "libhidlbase.so") == NULL &&
                    strstr(line, "libhidltransport.so") == NULL &&
                    strstr(line, "libhwbinder.so") == NULL &&
                    strstr(line, "libfmq.so") == NULL &&
                    strstr(line, "libusbhost.so") == NULL &&
                    strstr(line, "libziparchive.so") == NULL &&
                    strstr(line, "libpackagelistparser.so") == NULL &&
                    strstr(line, "libext4_utils.so") == NULL &&
                    strstr(line, "libsquashfs_utils.so") == NULL &&
                    strstr(line, "libcrypto_utils.so") == NULL &&
                    strstr(line, "libfec.so") == NULL &&
                    strstr(line, "libjsoncpp.so") == NULL &&
                    strstr(line, "libpcre2.so") == NULL &&
                    strstr(line, "libtinyxml2.so") == NULL &&
                    strstr(line, "libbrotli.so") == NULL &&
                    strstr(line, "libpng.so") == NULL &&
                    strstr(line, "libjpeg.so") == NULL &&
                    strstr(line, "libpiex.so") == NULL &&
                    strstr(line, "libheif.so") == NULL &&
                    strstr(line, "libyuv.so") == NULL &&
                    strstr(line, "libcodec2.so") == NULL &&
                    strstr(line, "libmedia_codeclist.so") == NULL &&
                    strstr(line, "libmedia_omx.so") == NULL &&
                    strstr(line, "libmediaextractor.so") == NULL &&
                    strstr(line, "libnativewindow.so") == NULL &&
                    strstr(line, "libsync.so") == NULL &&
                    strstr(line, "libvulkan.so") == NULL &&
                    strstr(line, "libneuralnetworks.so") == NULL &&
                    strstr(line, "libtextclassifier.so") == NULL &&
                    strstr(line, "libtextclassifier_hash.so") == NULL &&
                    strstr(line, "libtextclassifier_nnapi.so") == NULL &&
                    strstr(line, "libtextclassifier_support.so") == NULL &&
                    strstr(line, "libtextclassifier_utils.so") == NULL &&
                    strstr(line, "libtextclassifier_utils_jni.so") == NULL &&
                    strstr(line, "libtextclassifier_utils_native.so") == NULL) {
                    // This might be suspicious
                    found.push_back("SUSPICIOUS_MEMORY_MAPPING");
                }
            }
        }
        fclose(mapsFile);
    }
    
    return found;
}

// New function to check for emulator-specific artifacts
std::vector<std::string> checkForEmulatorArtifacts() {
    std::vector<std::string> found;
    
    // Check for common emulator artifacts
    const char* emulatorPaths[] = {
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
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
        "/system/lib/libc_malloc_debug_qemu.so.10"
    };
    
    for (const char* path : emulatorPaths) {
        if (access(path, F_OK) == 0) {
            found.push_back("EMULATOR_ARTIFACT:" + std::string(path));
        }
    }
    
    return found;
}

AntiTamperingResult detectAntiTampering() {
    AntiTamperingResult result = {false, false, {}};

    // Check for debugger attachment
    result.isDebuggerAttached = checkForTracerPid();
    if (result.isDebuggerAttached) {
        result.detectedMethods.push_back("TRACER_PID");
    }

    // Check for hooking frameworks
    auto hookedLibs = checkForHookingFrameworks();
    if (!hookedLibs.empty()) {
        result.isHookingDetected = true;
        result.detectedMethods.insert(result.detectedMethods.end(), hookedLibs.begin(), hookedLibs.end());
    }

    // Check for Frida artifacts
    auto fridaArtifacts = checkForFridaArtifacts();
    if (!fridaArtifacts.empty()) {
        result.isHookingDetected = true;
        result.detectedMethods.insert(result.detectedMethods.end(), fridaArtifacts.begin(), fridaArtifacts.end());
    }

    // Check for Frida port
    if (checkForFridaPort()) {
        result.isHookingDetected = true;
        result.detectedMethods.push_back("FRIDA_PORT_OPEN");
    }

    // Check for debugging artifacts
    if (checkForDebuggingArtifacts()) {
        result.isHookingDetected = true;
        result.detectedMethods.push_back("DEBUGGING_ARTIFACTS");
    }

    // Check for reverse engineering tools
    auto reTools = checkForReverseEngineeringTools();
    if (!reTools.empty()) {
        result.isHookingDetected = true;
        result.detectedMethods.insert(result.detectedMethods.end(), reTools.begin(), reTools.end());
    }

    // Check for timing anomalies
    if (checkForTimingAnomalies()) {
        result.isHookingDetected = true;
        result.detectedMethods.push_back("TIMING_ANOMALY");
    }

    // New checks
    // Check for memory tampering
    if (checkForMemoryTampering()) {
        result.isHookingDetected = true;
        result.detectedMethods.push_back("MEMORY_TAMPERING");
    }

    // Check for code injection
    auto codeInjection = checkForCodeInjection();
    if (!codeInjection.empty()) {
        result.isHookingDetected = true;
        result.detectedMethods.insert(result.detectedMethods.end(), codeInjection.begin(), codeInjection.end());
    }

    // Check for emulator artifacts
    auto emulatorArtifacts = checkForEmulatorArtifacts();
    if (!emulatorArtifacts.empty()) {
        result.isHookingDetected = true;
        result.detectedMethods.insert(result.detectedMethods.end(), emulatorArtifacts.begin(), emulatorArtifacts.end());
    }

    return result;
}