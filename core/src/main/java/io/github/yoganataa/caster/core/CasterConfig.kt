package io.github.yoganataa.caster.core

import io.github.yoganataa.caster.core.logging.LogLevel

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
    val detectionTimeoutMs: Long = 5000L,
    val enableParallelDetection: Boolean = true,
    val customHeaders: Map<String, String> = emptyMap(),
    val includeDeviceInfo: Boolean = true,
    val includeAppInfo: Boolean = true
) {
    init {
        require(detectionTimeoutMs > 0) { "Detection timeout must be positive" }
    }
}