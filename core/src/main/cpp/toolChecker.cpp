#include "toolChecker.h" // Pastikan header di-include terlebih dahulu
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>


#define LOG_TAG "CasterNative"
#define LOGD(...)  if (DEBUG) __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

#define BUFSIZE 1024

static int DEBUG = 1;

int exists(const char *fname) {
    FILE *file;
    if ((file = fopen(fname, "r"))) {
        LOGD("LOOKING FOR BINARY: %s PRESENT!!!", fname);
        fclose(file);
        return 1;
    }
    LOGD("LOOKING FOR BINARY: %s Absent :(", fname);
    return 0;
}

// PERBAIKAN: Bungkus semua definisi fungsi JNI dalam blok extern "C"
// Ini akan menghilangkan peringatan linkage dari IDE.
extern "C" {

JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_setLogDebugMessages(
        JNIEnv *env, jobject thiz, jboolean debug) {
    DEBUG = (debug == JNI_TRUE) ? 1 : 0;
    return 0;
}

JNIEXPORT jint JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_NativeRootDetector_checkForMagiskUDS(
        JNIEnv *env, jobject thiz) {
    FILE *fh = fopen("/proc/net/unix", "r");
    if (!fh) {
        return 0;
    }

    char line[BUFSIZE];
    while (fgets(line, sizeof(line), fh)) {
        if (strstr(line, "@") != NULL && strlen(strstr(line, "@")) > 32) {
            if (strstr(line, "/") == NULL && strstr(line, ".") == NULL) {
                LOGD("[Detect Magisk UnixDomainSocket] %s", line);
                fclose(fh);
                return 1;
            }
        }
    }

    fclose(fh);
    return 0;
}

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

} // Akhir dari blok extern "C"
