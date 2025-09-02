# Caster Native Implementation

This directory contains the native C++ implementation of the Caster security detection library.

## Files

- [caster_detector.h](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/caster_detector.h) - Header file with function declarations
- [caster_detector.cpp](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/caster_detector.cpp) - Main implementation that coordinates all detection modules
- [CMakeLists.txt](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/CMakeLists.txt) - CMake build configuration

## Modules Directory

The [modules](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/) directory contains modular implementations of each detection type:

- [root_detector.h](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/root_detector.h) / [root_detector.cpp](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/root_detector.cpp) - Root detection implementation
- [emulator_detector.h](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/emulator_detector.h) / [emulator_detector.cpp](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/emulator_detector.cpp) - Emulator detection implementation
- [integrity_detector.h](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/integrity_detector.h) / [integrity_detector.cpp](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/integrity_detector.cpp) - Integrity checks implementation
- [anti_tampering_detector.h](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/anti_tampering_detector.h) / [anti_tampering_detector.cpp](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/anti_tampering_detector.cpp) - Anti-tampering implementation
- [malicious_app_detector.h](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/malicious_app_detector.h) / [malicious_app_detector.cpp](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/malicious_app_detector.cpp) - Malicious app detection implementation
- [flag_secure_detector.h](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/flag_secure_detector.h) / [flag_secure_detector.cpp](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/flag_secure_detector.cpp) - Flag secure detection implementation
- [helpers.h](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/helpers.h) / [helpers.cpp](file:///c:/Users/arbiy/StudioProjects/Caster/core/src/main/cpp/modules/helpers.cpp) - Helper functions used across modules

## Building

The native code is built automatically as part of the Android build process when you run:

```
./gradlew build
```

## Security Features

The native implementation provides several security advantages:

1. **Harder to Reverse Engineer**: Native code is more difficult to decompile than Java/Kotlin
2. **Better Performance**: C++ executes faster for computationally intensive detection tasks
3. **Anti-Tampering**: Native code is harder to hook or modify at runtime
4. **Obfuscation**: Compiler-level obfuscation provides additional protection

## Detection Modules

The native implementation includes:

- Root detection (checking for su binaries, Magisk files, etc.)
- Emulator detection (checking build properties, system files, etc.)
- Integrity checks (verifying application signatures)
- Anti-tampering (debugger detection, hooking framework detection)
- Malicious app detection (scanning for known malicious packages)
- Flag secure detection (checking WindowManager security flags)

## Usage

Caster automatically uses the native implementation by default. All detection logic has been moved to C++ for enhanced security. Simply use the regular [Caster](../../../src/main/java/io/github/yoganataa/caster/Caster.kt) class:

```kotlin
val caster = Caster.Builder(context)
    .enableRootDetection(true)
    .enableEmulatorDetection(true)
    .build()

// For asynchronous analysis (recommended)
lifecycleScope.launch {
    val result = caster.analyze(activity)
}

// Or for synchronous analysis
val result = caster.analyze(activity)
```

The Caster library will automatically use the native C++ implementation for all detection logic, providing better security against reverse engineering and tampering.
