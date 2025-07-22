#include <jni.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <cstdio>
#include <memory>

// Function to execute a shell command and return its output
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        return "popen() failed!";
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_yoganataa_caster_core_detection_root_detectors_LsDataDetector_executeLsDataCommand(
        JNIEnv* env,
        jobject /* this */) {
    std::string command = "ls /sdcard/Android/data$'\\u200b'";
    std::string output = exec(command.c_str());
    return env->NewStringUTF(output.c_str());
}