package io.github.yoganataa.caster.models

import io.github.yoganataa.caster.logging.SecurityReport
import io.github.yoganataa.caster.utils.SecurityReportGenerator
import java.util.Date

// Kelas-kelas ini berfungsi sebagai lapisan abstraksi antara 'core' dan 'app'.
// Aplikasi Anda hanya perlu tahu tentang model-model ini.

data class RootResult(
    val isRooted: Boolean,
    val detectedMethods: List<String>,
    val confidence: Float
)

data class EmulatorResult(
    val isEmulator: Boolean,
    val detectedMethods: List<String>,
    val confidence: Float
)

data class FlagSecureResult(
    val isFlagSecureDisabled: Boolean,
    val detectionMethods: List<String>,
    val confidence: Float
)

data class MaliciousAppInfo(
    val packageName: String,
    val appName: String,
    val category: String,
    val riskLevel: String
)

data class MaliciousAppsResult(
    val hasMaliciousApps: Boolean,
    val detectedApps: List<MaliciousAppInfo>,
    val riskScore: Float
)

data class IntegrityResult(
    val isTampered: Boolean,
    val threats: List<String>,
)

data class TamperingResult(
    val isDebuggerAttached: Boolean,
    val isHookingDetected: Boolean,
    val isFridaServerRunning: Boolean,
    val detectedMethods: List<String>
)

/**
 * Hasil komprehensif yang berisi semua hasil deteksi keamanan.
 * Ini adalah objek utama yang akan Anda terima setelah pemindaian.
 */
data class CasterResult(
    val rootResult: RootResult,
    val emulatorResult: EmulatorResult,
    val flagSecureResult: FlagSecureResult,
    val maliciousAppsResult: MaliciousAppsResult,
    val integrityResult: IntegrityResult,
    val tamperingResult: TamperingResult,
    val securityReport: SecurityReport,
    val analysisTimeMs: Long = 0L
) {
    val timestamp: Long = securityReport.timestamp

    val isSecure: Boolean
        get() = !rootResult.isRooted &&
                !emulatorResult.isEmulator &&
                !flagSecureResult.isFlagSecureDisabled &&
                !maliciousAppsResult.hasMaliciousApps &&
                !integrityResult.isTampered &&
                !tamperingResult.isDebuggerAttached &&
                !tamperingResult.isHookingDetected &&
                !tamperingResult.isFridaServerRunning

    val threatLevel: ThreatLevel
        get() = when {
            rootResult.confidence >= 0.9f || maliciousAppsResult.riskScore >= 0.9f -> ThreatLevel.CRITICAL
            rootResult.isRooted || maliciousAppsResult.hasMaliciousApps -> ThreatLevel.HIGH
            emulatorResult.isEmulator && emulatorResult.confidence > 0.7f -> ThreatLevel.HIGH
            flagSecureResult.isFlagSecureDisabled -> ThreatLevel.MEDIUM
            emulatorResult.isEmulator -> ThreatLevel.MEDIUM
            rootResult.detectedMethods.isNotEmpty() || emulatorResult.detectedMethods.isNotEmpty() -> ThreatLevel.LOW
            else -> ThreatLevel.NONE
        }

    val totalIssuesDetected: Int
        get() = listOf(
            rootResult.isRooted,
            emulatorResult.isEmulator,
            flagSecureResult.isFlagSecureDisabled,
            maliciousAppsResult.hasMaliciousApps,
            integrityResult.isTampered,
            tamperingResult.isDebuggerAttached,
            tamperingResult.isHookingDetected,
            tamperingResult.isFridaServerRunning
        ).count { it }

    val threatSummary: List<String>
        get() = buildList {
            if (rootResult.isRooted) {
                add("Device is rooted (confidence: ${String.format("%.1f", rootResult.confidence * 100)}%)")
            }
            if (emulatorResult.isEmulator) {
                add("Running in emulator (confidence: ${String.format("%.1f", emulatorResult.confidence * 100)}%)")
            }
            if (flagSecureResult.isFlagSecureDisabled) {
                add("Screen recording/screenshots are possible")
            }
            if (maliciousAppsResult.hasMaliciousApps) {
                add("${maliciousAppsResult.detectedApps.size} malicious app(s) detected")
            }
            if (integrityResult.isTampered)
                add("Application integrity compromised: ${integrityResult.threats.joinToString()}")
            if (tamperingResult.isDebuggerAttached)
                add("A debugger is attached to the application")
            if (tamperingResult.isHookingDetected || tamperingResult.isFridaServerRunning) {
                add("Hooking/Tampering tool (Frida/Xposed) detected")
            }
        }

    /**
     * Generates a comprehensive security analysis summary.
     */
    fun generateSummary(): String {
        return SecurityReportGenerator.generateDetailedReport(securityReport)
    }

    /**
     * Generates a JSON representation of the security analysis.
     */
    fun toJson(): String {
        return SecurityReportGenerator.generateJsonReport(securityReport)
    }

    /**
     * Generates a summary report for quick overview.
     */
    fun generateSummaryReport(): String {
        return SecurityReportGenerator.generateSummaryReport(securityReport)
    }
}

enum class ThreatLevel {
    NONE, LOW, MEDIUM, HIGH, CRITICAL
}