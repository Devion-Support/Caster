#include <jni.h>

#ifndef CASTER_TOOLCHECKER_H
#define CASTER_TOOLCHECKER_H

extern "C" {

/*
 * PERBAIKAN: Nama fungsi diubah dari:
 * Java_com_kimchangyoun_rootbeerFresh_RootBeerNative_...
 * menjadi:
 * Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_...
 * agar cocok dengan struktur paket dan nama kelas Kotlin Anda.
 */

JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_setLogDebugMessages(
        JNIEnv *env, jobject thiz, jboolean debug);

JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForMagiskUDS(
        JNIEnv *env, jobject thiz);

JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForRoot(
        JNIEnv *env, jobject thiz, jobjectArray pathsArray);

}

#endif //CASTER_TOOLCHECKER_H