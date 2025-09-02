# Caster

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-android-green.svg)](https://developer.android.com/)
[![API](https://img.shields.io/badge/API-27%2B-brightgreen.svg?style=flat)](https://android-arsenal.com/api?level=27)

A comprehensive Android security library designed to provide robust device security analysis and threat detection.

## Features

- **Root Detection**: Advanced detection of rooted devices including Magisk, SuperSU, and KernelSU
- **Emulator Detection**: Comprehensive detection of Android emulators and virtualized environments
- **Anti-Tampering**: Protection against debugging, hooking frameworks (Frida/Xposed), and code injection
- **Integrity Checks**: Verification of application signatures, APK integrity, and system partition status
- **Malicious App Detection**: Scanning for known malicious applications and suspicious behaviors
- **Flag Secure Detection**: Protection against screen recording and screenshot bypasses
- **Native Implementation**: Core security logic implemented in C++ for enhanced protection
- **Modular Design**: Easy integration as a separate library module
- **Privacy Protection**: Minimal data collection with local processing

## Enhanced Security Features

Caster implements state-of-the-art security detection capabilities:

### Root Detection

- Extended binary checks for su, magisk, supersu, and kernelsu
- Magisk artifact and Unix Domain Socket detection
- Root cloaking and hiding technique detection
- Sophisticated confidence scoring system

### Emulator Detection

- Comprehensive system property analysis
- Extended emulator file and driver detection
- CPU information and sensor analysis
- Network interface and system service detection

### Anti-Tampering

- Advanced debugger and hooking framework detection
- Frida artifact and port detection
- Reverse engineering tool identification
- Memory tampering and code injection detection

### Integrity Checks

- APK signature and modification verification
- Installer and package verification
- Runtime and system partition integrity checks
- Bootloader and SELinux status verification

### Malicious App Detection

- Extended malware database with updated threat intelligence
- Suspicious permission and behavior analysis
- Vulnerable app identification
- Risk scoring system for threat assessment

### Flag Secure Detection

- Comprehensive screen protection analysis
- Accessibility service and overlay permission detection
- Screen recording service identification
- Enhanced confidence scoring

## Installation

To use the Caster library in your Android project, add the following dependency to your app module's `build.gradle.kts` file:

```kotlin
dependencies {
    implementation("io.github.yoganataa.caster:caster:1.0.0")
}
```

Make sure your project's `settings.gradle.kts` includes the Maven Local repository:

```kotlin
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        mavenLocal() // Add this line
    }
}
```

## Usage

### Initialize Caster

Initialize Caster in your Application class:

```kotlin
import android.app.Application
import io.github.yoganataa.caster.Caster
import io.github.yoganataa.caster.logging.LogLevel

class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Configure Caster using the Builder pattern
        Caster.Builder(this)
            .setLogLevel(if (BuildConfig.DEBUG) LogLevel.DEBUG else LogLevel.WARN)
            .enableRootDetection(true)
            .enableEmulatorDetection(true)
            .enableIntegrityChecks(true)
            .enableAntiTampering(true)
            .build()
    }
}
```

### Perform Security Analysis

Use Caster in your Activity to perform security analysis:

```kotlin
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import io.github.yoganataa.caster.Caster
import io.github.yoganataa.caster.models.CasterResult
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Get the singleton instance of Caster
        val caster = Caster.getInstance()
        
        // Perform security analysis
        lifecycleScope.launch {
            try {
                val result: CasterResult = caster.analyze(this@MainActivity)
                
                // Process the results
                if (result.isSecure) {
                    // Device is secure
                    handleSecureDevice(result)
                } else {
                    // Handle security threats
                    handleSecurityThreats(result)
                }
            } catch (e: Exception) {
                // Handle analysis error
                handleAnalysisError(e)
            }
        }
    }
}
```

## Documentation

For comprehensive documentation, please visit our [GitBook documentation](docs/README.md):

- [Getting Started](docs/getting-started/README.md)
- [Core Concepts](docs/core-concepts/README.md)
- [API Reference](docs/api/README.md)
- [Security Features](docs/security-features/README.md)
- [Native Implementation](docs/native-implementation/README.md)
- [Configuration](docs/configuration/README.md)
- [Best Practices](docs/best-practices/README.md)
- [Contributing](docs/contributing/README.md)

## Security Hardening

Caster implements multiple security hardening measures:

- **ProGuard Obfuscation**: Advanced code obfuscation
- **Native Code Protection**: Enhanced security flags for C++ compilation
- **Symbol Stripping**: Complete removal of debug symbols
- **Control Flow Integrity**: Protection against control flow hijacking
- **Stack Protection**: Enhanced stack overflow protection
- **Position Independent Code**: PIE compilation for all native code

## Privacy Protection

Caster implements privacy protection measures:

- **Data Minimization**: Only collects necessary security information
- **No Personal Data**: Does not collect personal or sensitive user data
- **Local Processing**: All analysis is performed locally on the device
- **Secure Communication**: Encrypted transmission for remote logging

## Building from Source

To build Caster from source:

1. Clone the repository:

   ```bash
   git clone https://github.com/yoganataa/caster.git
   ```

2. Open the project in Android Studio

3. Sync the project with Gradle files

4. Build the project:

   ```bash
   ./gradlew build
   ```

5. Publish to local Maven repository:

   ```bash
   ./gradlew publishToMavenLocal
   ```

## Testing

Run unit tests:

```bash
./gradlew test
```

Run instrumentation tests:

```bash
./gradlew connectedAndroidTest
```

Generate code coverage reports:

```bash
./gradlew jacocoTestReport
```

## Contributing

We welcome contributions to Caster! Please read our [Contributing Guide](docs/contributing/README.md) and [Code of Conduct](docs/contributing/code-of-conduct.md) before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](docs/license/README.md) file for details.

## Support

If you encounter any issues or have questions about Caster, please [open an issue](https://github.com/yoganataa/caster/issues) on GitHub.
