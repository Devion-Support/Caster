cmake_minimum_required(VERSION 3.4.1)

# Menambahkan flag keamanan untuk melindungi dari serangan stack smashing
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-all")

# Mendefinisikan library native kita, bernama 'toolChecker'
# Nama ini yang akan dipanggil di System.loadLibrary("toolChecker")
add_library(toolChecker SHARED
        toolChecker.cpp)

# Menautkan dengan library log dan android bawaan NDK
target_link_libraries(toolChecker
        android
        log)