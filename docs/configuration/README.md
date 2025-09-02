# Configuration

Caster provides extensive configuration options through the [CasterConfig](../../lib/src/main/java/io/github/yoganataa/caster/CasterConfig.kt) class. This allows you to customize the library's behavior to meet your specific security requirements.

## Basic Configuration

The simplest way to configure Caster is using the Builder pattern:

```kotlin
Caster.Builder(context)
    .enableRootDetection(true)
    .enableEmulatorDetection(true)
    .enableIntegrityChecks(true)
    .build()
```

## Configuration Options

### Logging Configuration

Control how Caster logs security events:

```kotlin
Caster.Builder(context)
    .setLogLevel(LogLevel.DEBUG)  // Set minimum log level
    .setLogEndpoint("https://your-server.com/api/security-logs")  // Remote logging endpoint
    .setCustomHeaders(mapOf("Authorization" to "Bearer token"))  // Custom HTTP headers
    .build()
```

### Detection Module Configuration

Enable or disable specific detection modules:

```kotlin
Caster.Builder(context)
    .enableRootDetection(true)              // Root detection
    .enableEmulatorDetection(true)          // Emulator detection
    .enableFlagSecureDetection(true)        // Flag secure detection
    .enableMaliciousAppDetection(true)      // Malicious app detection
    .enableIntegrityChecks(true)            // Integrity checks
    .enableAntiTampering(true)              // Anti-tampering protection
    .enableLsDataDetection(false)           // LS Data detection (experimental)
    .build()
```

### Performance Configuration

Adjust performance-related settings:

```kotlin
Caster.Builder(context)
    .setDetectionTimeoutMs(5000L)           // Detection timeout (milliseconds)
    .enableParallelDetection(true)          // Enable parallel detection
    .build()
```

### Customization Options

Customize detection behavior:

```kotlin
Caster.Builder(context)
    .setCustomMaliciousApps(setOf("com.example.malicious"))  // Custom malicious app list
    .build()
```

### Data Collection Configuration

Control what information is included in security reports:

```kotlin
Caster.Builder(context)
    .includeDeviceInfo(true)                // Include device information
    .includeAppInfo(true)                   // Include application information
    .build()
```

## Detailed Configuration Parameters

### logEndpoint

- **Type**: `String?`
- **Default**: `null`
- **Description**: Optional URL endpoint for sending security logs. If null, logs are not sent remotely.

### minLogLevel

- **Type**: [LogLevel](../../lib/src/main/java/io/github/yoganataa/caster/logging/LogLevel.kt)
- **Default**: `LogLevel.INFO`
- **Description**: The minimum LogLevel for messages to be logged. Messages below this level will be ignored.

### customMaliciousApps

- **Type**: `Set<String>`
- **Default**: `emptySet()`
- **Description**: A set of package names that should be considered malicious, in addition to built-in lists.

### enableRootDetection

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, Caster will perform checks to detect if the device is rooted.

### enableEmulatorDetection

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, Caster will perform checks to detect if the application is running on an emulator.

### enableFlagSecureDetection

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, Caster will attempt to detect bypasses of `WindowManager.LayoutParams.FLAG_SECURE`.

### enableMaliciousAppDetection

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, Caster will scan for known malicious or suspicious applications installed on the device.

### enableNativeChecks

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, Caster will utilize native (JNI) checks for certain detections (e.g., anti-tampering).

### enableIntegrityChecks

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, Caster will verify the application's signature and DEX checksum for tampering.

### enableAntiTampering

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, Caster will perform checks for debugging, hooking frameworks (like Frida/Xposed), and other tampering attempts.

### enableLsDataDetection

- **Type**: `Boolean`
- **Default**: `false`
- **Description**: If true, Caster will perform additional security checks including device attestation, network security, and privacy protection.

### detectionTimeoutMs

- **Type**: `Long`
- **Default**: `5000L`
- **Description**: The maximum time (in milliseconds) allowed for certain detection processes to complete.

### enableParallelDetection

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, multiple detection processes will run concurrently using coroutines.

### customHeaders

- **Type**: `Map<String, String>`
- **Default**: `emptyMap()`
- **Description**: Custom HTTP headers to include when sending logs to the `logEndpoint`.

### includeDeviceInfo

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, device information will be included in the security reports.

### includeAppInfo

- **Type**: `Boolean`
- **Default**: `true`
- **Description**: If true, application information will be included in the security reports.

## Recommended Configurations

### High Security Configuration

For applications requiring maximum security:

```kotlin
Caster.Builder(context)
    .setLogLevel(LogLevel.DEBUG)
    .setDetectionTimeoutMs(10000L)
    .enableRootDetection(true)
    .enableEmulatorDetection(true)
    .enableFlagSecureDetection(true)
    .enableMaliciousAppDetection(true)
    .enableNativeChecks(true)
    .enableIntegrityChecks(true)
    .enableAntiTampering(true)
    .enableLsDataDetection(true)
    .enableParallelDetection(true)
    .includeDeviceInfo(true)
    .includeAppInfo(true)
    .build()
```

### Performance-Oriented Configuration

For applications where performance is critical:

```kotlin
Caster.Builder(context)
    .setLogLevel(LogLevel.WARN)
    .setDetectionTimeoutMs(3000L)
    .enableRootDetection(true)
    .enableEmulatorDetection(true)
    .enableFlagSecureDetection(false)  // Disable for better performance
    .enableMaliciousAppDetection(true)
    .enableNativeChecks(true)
    .enableIntegrityChecks(true)
    .enableAntiTampering(false)  // Disable for better performance
    .enableLsDataDetection(false)
    .enableParallelDetection(false)  // Sequential execution
    .includeDeviceInfo(false)  // Reduce data collection
    .includeAppInfo(true)
    .build()
```

### Balanced Configuration

For most applications:

```kotlin
Caster.Builder(context)
    .setLogLevel(LogLevel.INFO)
    .setDetectionTimeoutMs(5000L)
    .enableRootDetection(true)
    .enableEmulatorDetection(true)
    .enableFlagSecureDetection(true)
    .enableMaliciousAppDetection(true)
    .enableNativeChecks(true)
    .enableIntegrityChecks(true)
    .enableAntiTampering(true)
    .enableLsDataDetection(false)
    .enableParallelDetection(true)
    .includeDeviceInfo(true)
    .includeAppInfo(true)
    .build()
```

## Dynamic Configuration

You can modify configuration at runtime by creating a new Caster instance with different settings:

```kotlin
// Initial configuration
Caster.Builder(context)
    .enableRootDetection(true)
    .build()

// Later, reconfigure with different settings
Caster.Builder(context)
    .enableRootDetection(false)  // Disable root detection
    .enableEmulatorDetection(true)
    .build()
```

## Configuration Validation

Caster performs validation on configuration parameters:

```kotlin
// This will throw an IllegalArgumentException
Caster.Builder(context)
    .setDetectionTimeoutMs(-1L)  // Invalid: negative timeout
    .build()
```

## Next Steps

- Learn about [Best Practices](../best-practices/README.md)
- Explore [Security Features](../security-features/README.md)
- Review [API Reference](../api/README.md)
