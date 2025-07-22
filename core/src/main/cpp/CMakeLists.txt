cmake_minimum_required(VERSION 3.4.1)
project(CasterNative)

# Add security flags to protect against stack smashing attacks
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-all -fvisibility=hidden")

# Define our native library, named 'toolChecker'
# This name will be called in System.loadLibrary("toolChecker")
add_library(toolChecker SHARED
        toolChecker.cpp
        ls_data_detector.cpp)

# Link with NDK's built-in log and android libraries
# -Wl,--strip-all: Strips all symbols from the generated binary for obfuscation
target_link_libraries(toolChecker
        android
        log
        -Wl,--strip-all)