package io.github.yoganataa.caster.core.logging

import com.google.gson.annotations.SerializedName

data class SecurityReport(
    @SerializedName("timestamp") val timestamp: Long = System.currentTimeMillis(),
    @SerializedName("device_info") val deviceInfo: DeviceInfo,
    @SerializedName("security_status") val securityStatus: SecurityStatus,
    @SerializedName("detected_threats") val detectedThreats: List<ThreatInfo> = emptyList(),
    @SerializedName("app_package") val appPackage: String
)

data class DeviceInfo(
    @SerializedName("model") val model: String,
    @SerializedName("manufacturer") val manufacturer: String,
    @SerializedName("android_version") val androidVersion: String,
    @SerializedName("api_level") val apiLevel: Int,
    @SerializedName("kernel_version") val kernelVersion: String?
)

data class SecurityStatus(
    @SerializedName("is_rooted") val isRooted: Boolean,
    @SerializedName("is_emulator") val isEmulator: Boolean,
    @SerializedName("flag_secure_disabled") val flagSecureDisabled: Boolean,
    @SerializedName("malicious_apps_detected") val maliciousAppsDetected: Boolean,
    @SerializedName("risk_level") val riskLevel: RiskLevel
)

data class ThreatInfo(
    @SerializedName("type") val type: ThreatType,
    @SerializedName("description") val description: String,
    @SerializedName("severity") val severity: String,
    @SerializedName("details") val details: Map<String, Any> = emptyMap()
)

enum class ThreatType {
    ROOT_ACCESS,
    EMULATOR,
    FLAG_SECURE_BYPASS,
    MALICIOUS_APP,
    SUSPICIOUS_ENVIRONMENT
}

enum class RiskLevel {
    LOW, MEDIUM, HIGH, CRITICAL
}