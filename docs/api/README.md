# API Reference

This document provides detailed information about Caster's public API. For usage examples, see the [Getting Started](../getting-started/README.md) guide.

## Core Classes

### Caster

The main entry point for the Caster library.

#### Builder

The configuration builder for Caster.

```kotlin
class Builder(context: Context)
```

**Methods:**

- `build(): Caster` - Builds and initializes the Caster instance
- `setLogLevel(logLevel: LogLevel): Builder` - Sets the minimum log level
- `setLogEndpoint(endpoint: String?): Builder` - Sets the remote logging endpoint
- `setCustomHeaders(headers: Map<String, String>): Builder` - Sets custom HTTP headers
- `setCustomMaliciousApps(apps: Set<String>): Builder` - Sets custom malicious app list
- `setDetectionTimeoutMs(timeout: Long): Builder` - Sets detection timeout in milliseconds
- `enableRootDetection(enabled: Boolean): Builder` - Enables/disables root detection
- `enableEmulatorDetection(enabled: Boolean): Builder` - Enables/disables emulator detection
- `enableFlagSecureDetection(enabled: Boolean): Builder` - Enables/disables flag secure detection
- `enableMaliciousAppDetection(enabled: Boolean): Builder` - Enables/disables malicious app detection
- `enableNativeChecks(enabled: Boolean): Builder` - Enables/disables native checks
- `enableIntegrityChecks(enabled: Boolean): Builder` - Enables/disables integrity checks
- `enableAntiTampering(enabled: Boolean): Builder` - Enables/disables anti-tampering
- `enableLsDataDetection(enabled: Boolean): Builder` - Enables/disables LS data detection
- `enableParallelDetection(enabled: Boolean): Builder` - Enables/disables parallel detection
- `includeDeviceInfo(include: Boolean): Builder` - Includes/excludes device info in reports
- `includeAppInfo(include: Boolean): Builder` - Includes/excludes app info in reports

#### Instance Methods

```kotlin
companion object {
    fun getInstance(): Caster
}
```

- `analyze(activity: Activity): CasterResult` - Performs comprehensive security analysis

### CasterConfig

Configuration class for Caster.

**Properties:**

- `logEndpoint: String?` - Remote logging endpoint
- `minLogLevel: LogLevel` - Minimum log level
- `customMaliciousApps: Set<String>` - Custom malicious app list
- `enableRootDetection: Boolean` - Root detection enabled
- `enableEmulatorDetection: Boolean` - Emulator detection enabled
- `enableFlagSecureDetection: Boolean` - Flag secure detection enabled
- `enableMaliciousAppDetection: Boolean` - Malicious app detection enabled
- `enableNativeChecks: Boolean` - Native checks enabled
- `enableIntegrityChecks: Boolean` - Integrity checks enabled
- `enableAntiTampering: Boolean` - Anti-tampering enabled
- `enableLsDataDetection: Boolean` - LS data detection enabled
- `detectionTimeoutMs: Long` - Detection timeout in milliseconds
- `enableParallelDetection: Boolean` - Parallel detection enabled
- `customHeaders: Map<String, String>` - Custom HTTP headers
- `includeDeviceInfo: Boolean` - Include device info in reports
- `includeAppInfo: Boolean` - Include app info in reports

### CasterResult

Results from security analysis.

**Properties:**

- `rootResult: RootResult` - Root detection results
- `emulatorResult: EmulatorResult` - Emulator detection results
- `flagSecureResult: FlagSecureResult` - Flag secure detection results
- `maliciousAppsResult: MaliciousAppsResult` - Malicious app detection results
- `integrityResult: IntegrityResult` - Integrity check results
- `tamperingResult: TamperingResult` - Anti-tampering results
- `securityReport: SecurityReport` - Detailed security report
- `analysisTimeMs: Long` - Analysis duration in milliseconds
- `timestamp: Long` - Timestamp of analysis
- `isSecure: Boolean` - Overall security status
- `threatLevel: ThreatLevel` - Overall threat level
- `totalIssuesDetected: Int` - Total security issues detected
- `threatSummary: List<String>` - Summary of detected threats

**Methods:**

- `generateSummary(): String` - Generates detailed security summary
- `toJson(): String` - Generates JSON representation
- `generateSummaryReport(): String` - Generates summary report

## Result Classes

### RootResult

Root detection results.

**Properties:**

- `isRooted: Boolean` - Device is rooted
- `detectedMethods: List<String>` - Detection methods used
- `confidence: Float` - Confidence level (0.0 - 1.0)

### EmulatorResult

Emulator detection results.

**Properties:**

- `isEmulator: Boolean` - Running in emulator
- `detectedMethods: List<String>` - Detection methods used
- `confidence: Float` - Confidence level (0.0 - 1.0)

### FlagSecureResult

Flag secure detection results.

**Properties:**

- `isFlagSecureDisabled: Boolean` - Flag secure is disabled
- `detectionMethods: List<String>` - Detection methods used
- `confidence: Float` - Confidence level (0.0 - 1.0)

### MaliciousAppsResult

Malicious app detection results.

**Properties:**

- `hasMaliciousApps: Boolean` - Malicious apps detected
- `detectedApps: List<MaliciousAppInfo>` - Detected malicious apps
- `riskScore: Float` - Overall risk score (0.0 - 1.0)

### MaliciousAppInfo

Information about a detected malicious app.

**Properties:**

- `packageName: String` - App package name
- `appName: String` - App name
- `category: String` - App category
- `riskLevel: String` - Risk level

### IntegrityResult

Integrity check results.

**Properties:**

- `isTampered: Boolean` - App is tampered
- `threats: List<String>` - Detected threats

### TamperingResult

Anti-tampering results.

**Properties:**

- `isDebuggerAttached: Boolean` - Debugger is attached
- `isHookingDetected: Boolean` - Hooking is detected
- `isFridaServerRunning: Boolean` - Frida server is running
- `detectedMethods: List<String>` - Detection methods used

## Enumerations

### ThreatLevel

Overall threat level classification.

**Values:**

- `NONE` - No threats detected
- `LOW` - Low-level threats
- `MEDIUM` - Medium-level threats
- `HIGH` - High-level threats
- `CRITICAL` - Critical threats

### LogLevel

Logging level for security events.

**Values:**

- `DEBUG` - Debug level
- `INFO` - Info level
- `WARN` - Warning level
- `ERROR` - Error level

## Utility Classes

### SecurityReport

Detailed security report containing all analysis information.

**Properties:**

- `timestamp: Long` - Report timestamp
- `appPackage: String` - Application package name
- `deviceInfo: DeviceInfo` - Device information
- `securityStatus: SecurityStatus` - Overall security status
- `detectedThreats: List<ThreatInfo>` - Detected threats
- `analysisTimeMs: Long` - Analysis duration

### DeviceInfo

Information about the device.

**Properties:**

- `model: String` - Device model
- `manufacturer: String` - Device manufacturer
- `androidVersion: String` - Android version
- `apiLevel: Int` - API level
- `kernelVersion: String?` - Kernel version
- `buildFingerprint: String?` - Build fingerprint
- `securityPatch: String?` - Security patch level
- `bootloaderStatus: String?` - Bootloader status

### SecurityStatus

Overall security status.

**Properties:**

- `riskLevel: RiskLevel` - Risk level
- `overallConfidence: Float` - Overall confidence
- `isRooted: Boolean` - Device is rooted
- `isEmulator: Boolean` - Running in emulator
- `flagSecureDisabled: Boolean` - Flag secure disabled
- `maliciousAppsDetected: Boolean` - Malicious apps detected
- `isTampered: Boolean` - App is tampered
- `isDebuggerAttached: Boolean` - Debugger attached
- `isHookingDetected: Boolean` - Hooking detected

## Exception Classes

### SecurityException

Base exception for security-related errors.

### TimeoutException

Exception thrown when detection times out.

## Next Steps

- Review [Configuration Options](../configuration/README.md)
- Learn about [Best Practices](../best-practices/README.md)
- Explore [Security Features](../security-features/README.md)
