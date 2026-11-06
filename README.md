# Caster

## Description

Caster is a comprehensive Android security library designed to provide robust device security analysis and threat detection. The library offers enhanced security features implemented in native C++ code for maximum protection against reverse engineering and tampering.

## Features

- **Core Functionality**: Provides reusable components commonly needed in Android app development
- **Modular Design**: Built as a separate module for easy integration
- **Lightweight**: Optimized for performance and minimal app size impact
- **Native Implementation**: Enhanced security detection logic moved to native C++ code
- **Comprehensive Security Detection**: Complete security analysis including root, emulator, anti-tampering, and malicious app detection

## Enhanced Security Features

Caster now includes state-of-the-art security detection capabilities:

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

For detailed information about the enhanced security features, see [ENHANCED_SECURITY.md](docs/ENHANCED_SECURITY.md).

## Installation

To use the Caster library in your Android project, add the following dependency to your app module's `build.gradle.kts` file:

```kotlin
dependencies {
    implementation(project(":caster"))
}
```

Make sure your `settings.gradle.kts` includes the `:caster` module:

```kotlin
include(':app', ':caster')
```

## Usage

After publishing the library locally (e.g., by running `./gradlew publishToMavenLocal` in the Caster project), you can use it in other Android projects on your machine.

### Standard Usage

1. **Add Maven Local Repository** to your project's `settings.gradle.kts` file:

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

2. **Add Dependency** to your app module (`app/build.gradle.kts` or other relevant module):

    ```kotlin
    dependencies {
        implementation("io.github.yoganataa.caster:caster:1.0.0")
    }
    ```

3. **Code Example**:

    ```kotlin
    import io.github.yoganataa.caster.Caster
    
    class MyActivity : AppCompatActivity() {
        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            setContentView(R.layout.activity_main)
            
            // Initialize Caster in your Application class
            // Caster.Builder(this)
            //     .enableRootDetection(true)
            //     .build()
            
            // Use Caster for security analysis
            // val caster = Caster.getInstance()
            // lifecycleScope.launch {
            //     val result = caster.analyze(this@MyActivity)
            //     // Process analysis results
            // }
        }
    }
    ```

### Enhanced Security Usage (Recommended)

For maximum security, Caster uses native implementation by default, moving all detection logic to C++ code:

```kotlin
import io.github.yoganataa.caster.Caster

class MyActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Initialize Caster with enhanced security configuration
        Caster.Builder(this)
            .enableRootDetection(true)
            .enableEmulatorDetection(true)
            .enableIntegrityChecks(true)
            .enableAntiTampering(true)
            .enableMaliciousAppDetection(true)
            .enableFlagSecureDetection(true)
            .build()
        
        // Use Caster for security analysis
        val caster = Caster.getInstance()
        // For asynchronous analysis (recommended)
        lifecycleScope.launch {
            val result = caster.analyze(this@MyActivity)
            // Process analysis results
            if (result.isSecure) {
                // Device is secure
            } else {
                // Handle security threats
                val threatLevel = result.threatLevel
                val summary = result.generateSummary()
            }
        }
    }
}

```

## Comprehensive Security Detection

Caster now provides comprehensive security detection:

### Root Detection
- Binary checks for root executables in multiple locations
- Detection of Magisk, SuperSU, and KernelSU artifacts
- Confidence-based scoring system

### Emulator Detection
- System property analysis
- Emulator-specific file detection
- Driver and CPU information analysis

### Anti-Tampering
- Debugger and hooking framework detection
- Frida and reverse engineering tool detection
- Timing anomaly analysis

### Application Integrity
- Installer verification
- Package verification
- Signature analysis

### Malicious App Detection
- Known malware scanning
- Suspicious behavior detection
- Risk-based scoring

### Flag Secure Detection
- Accessibility service detection
- Overlay permission analysis
- Screen recording service identification

For more information about the enhanced security implementation, see [ENHANCED_SECURITY.md](docs/ENHANCED_SECURITY.md).

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

## Contribution

Contributions are welcome! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<!-- Android modernization CI validation -->
