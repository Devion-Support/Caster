cmake_minimum_required(VERSION 3.4.1)
project(CasterNative)

# Find the Android NDK
if(NOT DEFINED ANDROID_NDK)
    # Try to find a default NDK location
    if(DEFINED ENV{ANDROID_NDK_HOME})
        set(ANDROID_NDK $ENV{ANDROID_NDK_HOME})
    elseif(DEFINED ENV{ANDROID_NDK})
        set(ANDROID_NDK $ENV{ANDROID_NDK})
    else()
        # Fallback to a common NDK location relative to the CMAKE_BINARY_DIR
        set(ANDROID_NDK "${CMAKE_BINARY_DIR}/../../../../ndk")
    endif()
endif()

message(STATUS "Using Android NDK: ${ANDROID_NDK}")

# Compiler flags - Remove redundant flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -fvisibility=hidden -fPIE -fPIC -O2 -DNDEBUG -D_FORTIFY_SOURCE=2 -fno-exceptions -fsanitize=cfi -flto -fstack-clash-protection")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-all -fvisibility=hidden -fPIE -fPIC -O2 -DNDEBUG -D_FORTIFY_SOURCE=2 -fno-exceptions -fsanitize=cfi -flto -fstack-clash-protection")

# Linker flags - Only keep essential security flags
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -Wl,--strip-all -Wl,--no-undefined -Wl,--gc-sections -Wl,-z,noexecstack")

# Position independent executable
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pie")

# Define macros to ensure JNI compatibility
add_definitions(-DJNI_VERSION_1_1=0x00010001)
add_definitions(-DJNI_VERSION_1_2=0x00010002)
add_definitions(-DJNI_VERSION_1_4=0x00010004)
add_definitions(-DJNI_VERSION_1_6=0x00010006)

# Define our new unified detection library
add_library(caster_detector SHARED
        caster_detector.cpp
        modules/root_detector.cpp
        modules/emulator_detector.cpp
        modules/integrity_detector.cpp
        modules/anti_tampering_detector.cpp
        modules/malicious_app_detector.cpp
        modules/flag_secure_detector.cpp
        modules/helpers.cpp)

# Add include directories for JNI headers
find_library(log-lib log)
find_library(android-lib android)

# Simplified JNI includes
include_directories(
    ${ANDROID_NDK}/sources/android/native_app_glue
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link with NDK's built-in log and android libraries
# Additional security flags for linker
target_link_libraries(caster_detector
        android
        log)
