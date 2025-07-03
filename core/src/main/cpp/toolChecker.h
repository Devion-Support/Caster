#include <jni.h>

#ifndef CASTER_TOOLCHECKER_H
#define CASTER_TOOLCHECKER_H

extern "C" {

// ================================
// Fungsi Root Detection (Existing)
// ================================

/*
 * Fungsi untuk mengatur mode debug logging
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_setLogDebugMessages(
        JNIEnv *env, jobject thiz, jboolean debug);

/*
 * Fungsi untuk mendeteksi Magisk melalui Unix Domain Socket
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForMagiskUDS(
        JNIEnv *env, jobject thiz);

/*
 * Fungsi untuk memeriksa keberadaan binary root di path tertentu
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForRoot(
        JNIEnv *env, jobject thiz, jobjectArray pathsArray);

// ================================
// Fungsi Anti-Tampering Detection (New)
// ================================

/*
 * Fungsi untuk memeriksa TracerPid di /proc/self/status
 * Mendeteksi apakah aplikasi sedang di-debug
 *
 * @return 1 jika terdeteksi debugging (TracerPid > 0), 0 jika tidak
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForTracerPid(
        JNIEnv *env, jobject thiz);

/*
 * Fungsi untuk memeriksa keberadaan framework hooking
 * Memeriksa /proc/self/maps untuk signature Frida, Xposed, dll
 *
 * @return 1 jika terdeteksi framework hooking, 0 jika tidak
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForHookingFrameworks(
        JNIEnv *env, jobject thiz);

/*
 * Fungsi untuk memeriksa apakah Frida server sedang berjalan
 * Mencoba koneksi TCP ke localhost:27042 (default Frida port)
 *
 * @return 1 jika Frida server terdeteksi, 0 jika tidak
 */
JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_tampering_AntiTamperingDetector_checkForFridaPort(
        JNIEnv *env, jobject thiz);

}

#endif //CASTER_TOOLCHECKER_H