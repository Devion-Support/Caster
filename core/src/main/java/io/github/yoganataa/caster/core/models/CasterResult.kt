package io.github.yoganataa.caster.core.models

import io.github.yoganataa.caster.core.logging.SecurityReport
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

    fun generateSummary(): String {
        return buildString {
            appendLine("=== Caster Security Analysis Summary ===")
            appendLine("Timestamp: ${Date(timestamp)}")
            appendLine("Analysis Time: ${analysisTimeMs}ms")
            appendLine("Overall Status: ${if (isSecure) "SECURE" else "THREATS DETECTED"}")
            appendLine("Issues Found: $totalIssuesDetected")
            appendLine()

            if (threatSummary.isNotEmpty()) {
                appendLine("Detected Threats:")
                threatSummary.forEach { threat ->
                    appendLine(" • $threat")
                }
                appendLine()
            }

            appendLine("Root Detection:")
            appendLine("  Status: ${if (rootResult.isRooted) "ROOTED" else "NOT ROOTED"}")
            appendLine("  Confidence: ${String.format("%.1f", rootResult.confidence * 100)}%")
            appendLine("  Methods: ${rootResult.detectedMethods.joinToString(", ").ifEmpty { "N/A" }}")
            appendLine()

            appendLine("Emulator Detection:")
            appendLine("  Status: ${if (emulatorResult.isEmulator) "EMULATOR" else "REAL DEVICE"}")
            appendLine("  Confidence: ${String.format("%.1f", emulatorResult.confidence * 100)}%")
            appendLine("  Methods: ${emulatorResult.detectedMethods.joinToString(", ").ifEmpty { "N/A" }}")
            appendLine()

            appendLine("Screen Protection:")
            appendLine("  Status: ${if (flagSecureResult.isFlagSecureDisabled) "VULNERABLE (Bypassed)" else "PROTECTED"}")
            appendLine()

            appendLine("Malicious Apps:")
            appendLine("  Status: ${if (maliciousAppsResult.hasMaliciousApps) "${maliciousAppsResult.detectedApps.size} DETECTED" else "NONE DETECTED"}")
            appendLine()

            appendLine("Application Integrity:")
            appendLine("  Status: ${if (integrityResult.isTampered) "COMPROMISED" else "OK"}")
            if (integrityResult.isTampered) {
                appendLine("  Reasons: ${integrityResult.threats.joinToString(", ")}")
            }
            appendLine()

            appendLine("Anti-Tampering:")
            appendLine("  Debugger Attached: ${if (tamperingResult.isDebuggerAttached) "YES" else "NO"}")
            appendLine("  Hooking Detected: ${if (tamperingResult.isHookingDetected) "YES" else "NO"}")
            appendLine("  Frida Server Running: ${if (tamperingResult.isFridaServerRunning) "YES" else "NO"}")
            if (tamperingResult.isHookingDetected || tamperingResult.isFridaServerRunning) {
                appendLine("  Methods: ${tamperingResult.detectedMethods.joinToString(", ")}")
            }
            appendLine("==========================================")
        }
    }
}

enum class ThreatLevel {
    NONE, LOW, MEDIUM, HIGH, CRITICAL
}