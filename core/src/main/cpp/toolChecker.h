#include <jni.h>

#ifndef CASTER_TOOLCHECKER_H
#define CASTER_TOOLCHECKER_H

extern "C" {

// ================================
// Root Detection Functions
// ================================

/**
 * @brief Sets the debug logging mode for native functions.
 *
 * This function controls whether native debug messages are printed to logcat.
 *
 * @param env JNI environment pointer.
 * @param thiz The jobject representing the calling Java instance.
 * @param debug A boolean indicating whether to enable (true) or disable (false) debug logging.
 * @return An integer indicating success (e.g., 0) or failure.
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_setLogDebugMessages(
        JNIEnv *env, jobject thiz, jboolean debug);

/**
 * @brief Checks for the presence of Magisk via its Unix Domain Socket.
 *
 * This is a common method to detect Magisk root solution.
 *
 * @param env JNI environment pointer.
 * @param thiz The jobject representing the calling Java instance.
 * @return 1 if Magisk UDS is detected, 0 otherwise.
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForMagiskUDS(
        JNIEnv *env, jobject thiz);

/**
 * @brief Checks for the existence of common root binaries in specified paths.
 *
 * This function iterates through an array of paths and checks if 'su' or other root binaries exist.
 *
 * @param env JNI environment pointer.
 * @param thiz The jobject representing the calling Java instance.
 * @param pathsArray A jobjectArray containing strings of paths to check.
 * @return 1 if a root binary is found, 0 otherwise.
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForRoot(
        JNIEnv *env, jobject thiz, jobjectArray pathsArray);

// ================================
// Anti-Tampering Detection Functions
// ================================

/**
 * @brief Checks for TracerPid in /proc/self/status to detect debugger attachment.
 *
 * A non-zero TracerPid indicates that the process is being debugged.
 *
 * @param env JNI environment pointer.
 * @param thiz The jobject representing the calling Java instance.
 * @return 1 if debugging is detected (TracerPid > 0), 0 otherwise.
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForTracerPid(
        JNIEnv *env, jobject thiz);

/**
 * @brief Checks for the presence of hooking frameworks by inspecting /proc/self/maps.
 *
 * This function looks for signatures of known hooking frameworks like Frida, Xposed, etc.,
 * within the process's memory maps.
 *
 * @param env JNI environment pointer.
 * @param thiz The jobject representing the calling Java instance.
 * @return 1 if a hooking framework is detected, 0 otherwise.
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForHookingFrameworks(
        JNIEnv *env, jobject thiz);

/**
 * @brief Checks if a Frida server is running by attempting a TCP connection to localhost:27042.
 *
 * Port 27042 is the default port used by the Frida server.
 *
 * @param env JNI environment pointer.
 * @param thiz The jobject representing the calling Java instance.
 * @return 1 if a Frida server is detected, 0 otherwise.
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForFridaPort(
        JNIEnv *env, jobject thiz);

}

#endif //CASTER_TOOLCHECKER_H