package io.github.yoganataa.caster.logging

import com.google.gson.annotations.SerializedName

data class SecurityReport(
    @SerializedName("timestamp") val timestamp: Long = System.currentTimeMillis(),
    @SerializedName("device_info") val deviceInfo: DeviceInfo,
    @SerializedName("security_status") val securityStatus: SecurityStatus,
    @SerializedName("detected_threats") val detectedThreats: List<ThreatInfo> = emptyList(),
    @SerializedName("app_package") val appPackage: String,
    @SerializedName("analysis_summary") val analysisSummary: AnalysisSummary? = null
)

data class DeviceInfo(
    @SerializedName("model") val model: String,
    @SerializedName("manufacturer") val manufacturer: String,
    @SerializedName("android_version") val androidVersion: String,
    @SerializedName("api_level") val apiLevel: Int,
    @SerializedName("kernel_version") val kernelVersion: String?,
    @SerializedName("build_fingerprint") val buildFingerprint: String? = null,
    @SerializedName("security_patch") val securityPatch: String? = null,
    @SerializedName("bootloader_status") val bootloaderStatus: String? = null
)

data class SecurityStatus(
    @SerializedName("is_rooted") val isRooted: Boolean,
    @SerializedName("is_emulator") val isEmulator: Boolean,
    @SerializedName("flag_secure_disabled") val flagSecureDisabled: Boolean,
    @SerializedName("malicious_apps_detected") val maliciousAppsDetected: Boolean,
    @SerializedName("is_tampered") val isTampered: Boolean,
    @SerializedName("is_debugger_attached") val isDebuggerAttached: Boolean,
    @SerializedName("is_hooking_detected") val isHookingDetected: Boolean,
    @SerializedName("is_screenshot_possible") val isScreenshotPossible: Boolean,
    @SerializedName("risk_level") val riskLevel: RiskLevel,
    @SerializedName("overall_confidence") val overallConfidence: Float = 0.0f
)

data class ThreatInfo(
    @SerializedName("type") val type: ThreatType,
    @SerializedName("description") val description: String,
    @SerializedName("severity") val severity: ThreatSeverity,
    @SerializedName("confidence") val confidence: Float = 0.0f,
    @SerializedName("detection_methods") val detectionMethods: List<String> = emptyList(),
    @SerializedName("details") val details: Map<String, Any> = emptyMap(),
    @SerializedName("recommendations") val recommendations: List<String> = emptyList()
)

data class AnalysisSummary(
    @SerializedName("total_threats") val totalThreats: Int,
    @SerializedName("critical_threats") val criticalThreats: Int,
    @SerializedName("high_threats") val highThreats: Int,
    @SerializedName("medium_threats") val mediumThreats: Int,
    @SerializedName("low_threats") val lowThreats: Int,
    @SerializedName("analysis_duration_ms") val analysisDurationMs: Long,
    @SerializedName("security_score") val securityScore: Float,
    @SerializedName("recommendations") val recommendations: List<String> = emptyList()
)

enum class ThreatType {
    ROOT_ACCESS,
    EMULATOR,
    FLAG_SECURE_BYPASS,
    MALICIOUS_APP,
    TAMPERING,
    DEBUGGING,
    HOOKING,
    INTEGRITY_VIOLATION,
    SUSPICIOUS_ENVIRONMENT,
    CONFIGURATION_ERROR,
    RUNTIME_ERROR
}

enum class ThreatSeverity {
    LOW, MEDIUM, HIGH, CRITICAL
}

enum class RiskLevel {
    NONE, LOW, MEDIUM, HIGH, CRITICAL
}