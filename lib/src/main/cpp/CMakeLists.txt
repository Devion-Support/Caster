cmake_minimum_required(VERSION 3.22.1)
project(CasterNative LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(caster_detector SHARED
    caster_detector.cpp
    modules/root_detector.cpp
    modules/emulator_detector.cpp
    modules/integrity_detector.cpp
    modules/anti_tampering_detector.cpp
    modules/malicious_app_detector.cpp
    modules/flag_secure_detector.cpp
    modules/helpers.cpp
)

target_include_directories(caster_detector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(caster_detector PRIVATE
    -O2
    -fstack-protector-strong
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -D_FORTIFY_SOURCE=2
)

target_link_options(caster_detector PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    -Wl,--gc-sections
    -Wl,--no-undefined
    -Wl,--strip-all
)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(caster_detector
    ${android-lib}
    ${log-lib}
)
