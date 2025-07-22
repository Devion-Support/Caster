#include "toolChecker.h"
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // For access()
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

#define LOG_TAG "CasterNative"
#define LOGD(...)  if (DEBUG) __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

#define BUFSIZE 1024
#define MAX_LINE_LENGTH 512
#define FRIDA_PORT 27042 // Use constant for Frida default port

static int DEBUG = 1;

// ================================
// Helper Functions
// ================================

/**
 * @brief Checks if a file exists at the given path.
 *
 * Uses `access()` for a lightweight file existence check.
 *
 * @param fname The path to the file.
 * @return 1 if the file exists, 0 otherwise.
 */
int exists(const char *fname) {
    if (access(fname, F_OK) == 0) {
        LOGD("LOOKING FOR BINARY: %s PRESENT!!!", fname);
        return 1;
    }
    return 0;
}

/**
 * @brief Checks the TracerPid value in /proc/self/status.
 *
 * A non-zero TracerPid indicates that the process is being debugged.
 *
 * @return 1 if a debugger is detected (TracerPid > 0), 0 otherwise.
 */
int checkTracerPid() {
    FILE *statusFile = fopen("/proc/self/status", "r");
    if (!statusFile) {
        LOGE("Failed to open /proc/self/status: %s", strerror(errno));
        return 0;
    }

    char line[MAX_LINE_LENGTH];
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

/**
 * @brief Checks for the presence of hooking frameworks by inspecting /proc/self/maps.
 *
 * This function reads the process's memory maps and looks for signatures of known
 * hooking frameworks (e.g., Frida, Xposed, Substrate).
 *
 * @return 1 if a hooking framework is detected, 0 otherwise.
 */
int checkForHookingInMaps() {
    FILE *mapsFile = fopen("/proc/self/maps", "r");
    if (!mapsFile) {
        LOGE("Failed to open /proc/self/maps: %s", strerror(errno));
        return 0;
    }

    char line[BUFSIZE];
    // Recommendation: Obfuscate this array for maximum security
    const char* suspiciousStrings[] = {
            "frida", "xposed", "substrate", "cydia",
            "libhook", "libinject", "libsandhook"
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

/**
 * @brief Checks if a Frida server is running by attempting a TCP connection to localhost:27042.
 *
 * Port 27042 is the default port used by the Frida server.
 *
 * @return 1 if a Frida server is detected, 0 otherwise.
 */
int checkFridaServer() {
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

// ================================
// JNI Function Implementations
// ================================

extern "C" {

/**
 * @brief JNI implementation for setting debug log messages.
 * @see Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_setLogDebugMessages
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_setLogDebugMessages(
        JNIEnv *env, jobject thiz, jboolean debug) {
    DEBUG = (debug == JNI_TRUE) ? 1 : 0;
    return 0;
}

/**
 * @brief JNI implementation for checking Magisk Unix Domain Socket.
 * @see Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForMagiskUDS
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForMagiskUDS(
        JNIEnv *env, jobject thiz) {
    FILE *fh = fopen("/proc/net/unix", "r");
    if (!fh) {
        LOGE("Failed to open /proc/net/unix: %s", strerror(errno));
        return 0;
    }
    char line[BUFSIZE];
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

/**
 * @brief JNI implementation for checking root binaries in specified paths.
 * @see Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForRoot
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForRoot(
        JNIEnv *env, jobject thiz, jobjectArray pathsArray) {
    int binariesFound = 0;
    int stringCount = env->GetArrayLength(pathsArray);

    for (int i = 0; i < stringCount; i++) {
        jstring string = (jstring) env->GetObjectArrayElement(pathsArray, i);
        const char *pathString = env->GetStringUTFChars(string, 0);
        if (exists(pathString)) {
            binariesFound++;
        }
        env->ReleaseStringUTFChars(string, pathString);
    }
    return binariesFound > 0 ? 1 : 0;
}

/**
 * @brief JNI implementation for checking TracerPid.
 * @see Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForTracerPid
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForTracerPid(
        JNIEnv *env, jobject thiz) {
    return checkTracerPid();
}

/**
 * @brief JNI implementation for checking hooking frameworks.
 * @see Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForHookingFrameworks
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForHookingFrameworks(
        JNIEnv *env, jobject thiz) {
    return checkForHookingInMaps();
}

/**
 * @brief JNI implementation for checking Frida server port.
 * @see Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForFridaPort
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForFridaPort(
        JNIEnv *env, jobject thiz) {
    return checkFridaServer();
}

} // End of extern "C"