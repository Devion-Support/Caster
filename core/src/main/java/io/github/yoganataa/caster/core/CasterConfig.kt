package io.github.yoganataa.caster.core

import io.github.yoganataa.caster.core.logging.LogLevel

/**
 * Configuration class for the Caster security analysis library.
 *
 * This data class allows customization of various aspects of the Caster library's behavior,
 * including logging, enabling/disabling specific detections, and setting timeouts.
 *
 * @property logEndpoint Optional URL endpoint for sending security logs. If null, logs are not sent remotely.
 * @property minLogLevel The minimum [LogLevel] for messages to be logged. Messages below this level will be ignored.
 * @property customMaliciousApps A set of package names that should be considered malicious, in addition to built-in lists.
 * @property enableRootDetection If true, Caster will perform checks to detect if the device is rooted. Defaults to true.
 * @property enableEmulatorDetection If true, Caster will perform checks to detect if the application is running on an emulator. Defaults to true.
 * @property enableFlagSecureDetection If true, Caster will attempt to detect bypasses of `WindowManager.LayoutParams.FLAG_SECURE`. Defaults to true.
 * @property enableMaliciousAppDetection If true, Caster will scan for known malicious or suspicious applications installed on the device. Defaults to true.
 * @property enableNativeChecks If true, Caster will utilize native (JNI) checks for certain detections (e.g., anti-tampering). Defaults to true.
 * @property enableIntegrityChecks If true, Caster will verify the application's signature and DEX checksum for tampering. Defaults to true.
 * @property enableAntiTampering If true, Caster will perform checks for debugging, hooking frameworks (like Frida/Xposed), and other tampering attempts. Defaults to true.
 * @property detectionTimeoutMs The maximum time (in milliseconds) allowed for certain detection processes to complete. Defaults to 5000ms.
 * @property enableParallelDetection If true, multiple detection processes will run concurrently using coroutines. Defaults to true.
 * @property customHeaders Custom HTTP headers to include when sending logs to the `logEndpoint`. Defaults to an empty map.
 * @property includeDeviceInfo If true, device information will be included in the security reports. Defaults to true.
 * @property includeAppInfo If true, application information will be included in the security reports. Defaults to true.
 */
data class CasterConfig(
    val logEndpoint: String? = null,
    val minLogLevel: LogLevel = LogLevel.INFO,
    val customMaliciousApps: Set<String> = emptySet(),
    val enableRootDetection: Boolean = true,
    val enableEmulatorDetection: Boolean = true,
    val enableFlagSecureDetection: Boolean = true,
    val enableMaliciousAppDetection: Boolean = true,
    val enableNativeChecks: Boolean = true,
    val enableIntegrityChecks: Boolean = true,
    val enableAntiTampering: Boolean = true,
    val enableLsDataDetection: Boolean = false,
    val detectionTimeoutMs: Long = 5000L,
    val enableParallelDetection: Boolean = true,
    val customHeaders: Map<String, String> = emptyMap(),
    val includeDeviceInfo: Boolean = true,
    val includeAppInfo: Boolean = true
) {
    init {
        // Ensure that the detection timeout is a positive value to prevent infinite waits or invalid configurations.
        require(detectionTimeoutMs > 0) { "Detection timeout must be positive" }
    }
}