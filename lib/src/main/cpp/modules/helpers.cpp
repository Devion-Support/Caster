#include "helpers.h"
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

#define LOG_TAG "CasterNative"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

/**
 * @brief Checks if a file exists at the given path.
 */
int fileExists(const char *fname) {
    if (access(fname, F_OK) == 0) {
        LOGD("File exists: %s", fname);
        return 1;
    }
    return 0;
}

/**
 * @brief Checks if a file is readable.
 */
int isFileReadable(const char *fname) {
    if (access(fname, R_OK) == 0) {
        return 1;
    }
    return 0;
}

/**
 * @brief Checks if a file is executable.
 */
int isFileExecutable(const char *fname) {
    if (access(fname, X_OK) == 0) {
        return 1;
    }
    return 0;
}

/**
 * @brief Reads content of a file.
 */
char* readFile(const char *fname) {
    FILE *file = fopen(fname, "r");
    if (!file) return NULL;
    
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *content = (char*)malloc(length + 1);
    if (content) {
        fread(content, 1, length, file);
        content[length] = '\0';
    }
    fclose(file);
    return content;
}

/**
 * @brief Gets system property value.
 */
char* getSystemProperty(const char *property) {
    char command[256];
    snprintf(command, sizeof(command), "getprop %s", property);
    
    FILE *fp = popen(command, "r");
    if (!fp) return NULL;
    
    char *result = (char*)malloc(256);
    if (fgets(result, 256, fp) != NULL) {
        // Remove newline if present
        char *newline = strchr(result, '\n');
        if (newline) *newline = '\0';
        pclose(fp);
        return result;
    }
    
    pclose(fp);
    free(result);
    return NULL;
}