# Core Concepts

Understanding how Caster works is essential for effectively using its security features. This section explains the fundamental concepts and architecture of the library.

## Architecture Overview

Caster follows a modular architecture with a clear separation between the Kotlin API layer and the native C++ implementation layer:

```txt
┌─────────────────────────────────────────────┐
│              Application Layer              │
│  (Your Android App using Caster library)    │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│              Kotlin API Layer               │
│  - Caster.kt (Main entry point)             │
│  - CasterConfig.kt (Configuration)          │
│  - Models (Data classes)                    │
│  - Utilities                                │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│           Native Interface Layer            │
│  - CasterNativeDetector.kt (JNI bridge)     │
│  - CasterDetectionModels.kt (Data models)   │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│            Native C++ Implementation        │
│  - root_detector.cpp                        │
│  - emulator_detector.cpp                    │
│  - integrity_detector.cpp                   │
│  - anti_tampering_detector.cpp              │
│  - malicious_app_detector.cpp               │
│  - flag_secure_detector.cpp                 │
│  - helpers.cpp (Utility functions)          │
└─────────────────────────────────────────────┘
```

## Main Components

### Caster Class

The [Caster](../../lib/src/main/java/io/github/yoganataa/caster/Caster.kt) class is the main entry point for the library. It provides:

- Singleton access to the security analysis functionality
- Configuration management through [CasterConfig](../../lib/src/main/java/io/github/yoganataa/caster/CasterConfig.kt)
- Result aggregation and processing
- Security reporting capabilities

### CasterConfig

[CasterConfig](../../lib/src/main/java/io/github/yoganataa/caster/CasterConfig.kt) allows you to customize various aspects of Caster's behavior:

- Enable/disable specific detection modules
- Configure logging and remote reporting
- Set detection timeouts
- Customize malicious app lists

### Native Implementation

All core detection logic is implemented in native C++ code for enhanced security:

- Protection against reverse engineering
- Improved performance for intensive operations
- Access to low-level system information
- Harder to tamper with than pure Java/Kotlin code

### Security Analysis Results

The security analysis produces a [CasterResult](../../lib/src/main/java/io/github/yoganataa/caster/models/CasterResult.kt) object containing:

- Individual results for each detection module
- Overall security status and threat level
- Detailed threat information and recommendations
- Security reports in various formats

## Detection Modules

Caster includes several specialized detection modules:

### Root Detection

Checks for signs of rooted devices including:

- Root binaries and applications
- Magisk, SuperSU, and KernelSU artifacts
- System property modifications
- Test keys and debug flags

### Emulator Detection

Identifies when the app is running in an emulator:

- System property analysis
- Emulator-specific file paths
- Hardware and sensor characteristics
- Network interface information

### Anti-Tampering

Protects against debugging and hooking attempts:

- Debugger attachment detection
- Hooking framework identification (Frida, Xposed)
- Memory tampering detection
- Timing-based anomaly detection

### Integrity Checks

Verifies application and system integrity:

- APK signature verification
- Installer source validation
- System partition status
- SELinux enforcement

### Malicious App Detection

Scans for known malicious applications:

- Package name matching against threat database
- Suspicious permission combinations
- Accessibility service abuse
- Device administrator apps

### Flag Secure Detection

Checks for screenshot and screen recording protection:

- WindowManager flag verification
- Accessibility service detection
- Overlay permission analysis
- Screen recording service identification

## Security Model

Caster uses a multi-layered security approach:

1. **Confidence Scoring**: Each detection module calculates a confidence score
2. **Threat Level Classification**: Overall threat level based on individual results
3. **Risk-Based Response**: Different actions based on threat severity
4. **Detailed Reporting**: Comprehensive security reports for analysis

## Performance Considerations

Caster is designed to be lightweight and efficient:

- Native implementation for performance-critical operations
- Configurable parallel execution
- Reasonable timeout settings
- Minimal impact on app performance

## Privacy and Data Handling

Caster prioritizes user privacy:

- All analysis performed locally on the device
- Minimal data collection
- No personal information transmitted
- Configurable remote logging with encryption

## Next Steps

- Learn about [Security Features](../security-features/README.md)
- Explore [Configuration Options](../configuration/README.md)
- Understand the [Native Implementation](../native-implementation/README.md)
