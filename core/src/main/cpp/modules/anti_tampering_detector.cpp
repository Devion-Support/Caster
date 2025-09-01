#include "anti_tampering_detector.h"
#include "helpers.h"
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

#define FRIDA_PORT 27042

// ================================
// Anti-Tampering Detection Implementation
// ================================

int checkForTracerPid() {
    FILE *statusFile = fopen("/proc/self/status", "r");
    if (!statusFile) {
        LOGE("Failed to open /proc/self/status: %s", strerror(errno));
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), statusFile)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracerPid = atoi(line + 10);
            fclose(statusFile);
            if (tracerPid != 0) {
                LOGD("[ANTI-DEBUG] Debugger detected! TracerPid: %d", tracerPid);
                return 1;
            }
            return 0;
        }
    }
    fclose(statusFile);
    return 0;
}

int checkForHookingFrameworks() {
    FILE *mapsFile = fopen("/proc/self/maps", "r");
    if (!mapsFile) {
        LOGE("Failed to open /proc/self/maps: %s", strerror(errno));
        return 0;
    }

    char line[1024];
    const char* suspiciousStrings[] = {
        "frida", "xposed", "substrate", "cydia", "libhook", "libinject", "libsandhook"
    };
    int numSuspicious = sizeof(suspiciousStrings) / sizeof(suspiciousStrings[0]);

    while (fgets(line, sizeof(line), mapsFile)) {
        for (int i = 0; i < numSuspicious; i++) {
            if (strstr(line, suspiciousStrings[i]) != NULL) {
                LOGD("[ANTI-HOOK] Suspicious library detected: %s", suspiciousStrings[i]);
                fclose(mapsFile);
                return 1;
            }
        }
    }

    fclose(mapsFile);
    return 0;
}

int checkForFridaPort() {
    struct sockaddr_in serverAddr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOGE("Failed to create socket: %s", strerror(errno));
        return 0;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(FRIDA_PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int result = 0;
    // Attempt connection; if successful, it means Frida is active.
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
        LOGD("[ANTI-FRIDA] Successfully connected to Frida server port %d!", FRIDA_PORT);
        result = 1;
    } else {
        LOGD("[ANTI-FRIDA] Failed to connect to Frida server port %d: %s", FRIDA_PORT, strerror(errno));
    }

    close(sockfd);
    return result;
}

int checkForDebuggingArtifacts() {
    // Check for common debugging artifacts
    const char* debugFiles[] = {
        "/data/local/tmp/frida-agent.so",
        "/data/local/tmp/re.frida.server",
        "/dev/socket/frida"
    };
    
    int fileCount = sizeof(debugFiles) / sizeof(debugFiles[0]);
    for (int i = 0; i < fileCount; i++) {
        if (access(debugFiles[i], F_OK) == 0) {
            return 1;
        }
    }
    
    return 0;
}

AntiTamperingResult detectAntiTampering() {
    AntiTamperingResult result = {0, 0, NULL, 0};
    
    result.isDebuggerAttached = checkForTracerPid();
    result.isHookingDetected = checkForHookingFrameworks() || checkForFridaPort() || checkForDebuggingArtifacts();
    
    return result;
}