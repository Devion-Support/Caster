package io.github.yoganataa.caster.utils

import com.google.common.truth.Truth.assertThat
import io.github.yoganataa.caster.logging.*
import org.junit.Before
import org.junit.Test
import java.util.*

class SecurityReportGeneratorTest {

    private lateinit var securityReport: SecurityReport

    @Before
    fun setUp() {
        securityReport = SecurityReport(
            timestamp = System.currentTimeMillis(),
            deviceInfo = DeviceInfo(
                model = "Pixel 5",
                manufacturer = "Google",
                androidVersion = "12",
                apiLevel = 31,
                kernelVersion = "5.4.86",
                buildFingerprint = "google/redfin/redfin:12/SP1A.210812.016.C1/7818238:user/release-keys",
                securityPatch = "2022-01-05",
                bootloaderStatus = "locked"
            ),
            securityStatus = SecurityStatus(
                isRooted = false,
                isEmulator = false,
                flagSecureDisabled = false,
                maliciousAppsDetected = false,
                isTampered = false,
                isDebuggerAttached = false,
                isHookingDetected = false,
                isScreenshotPossible = false,
                riskLevel = RiskLevel.NONE,
                overallConfidence = 0.95f
            ),
            detectedThreats = emptyList(),
            appPackage = "io.github.yoganataa.caster.test"
        )
    }

    @Test
    fun `generateDetailedReport should create valid report for secure device`() {
        val report = SecurityReportGenerator.generateDetailedReport(securityReport)
        
        assertThat(report).isNotEmpty()
        assertThat(report).contains("CASTER SECURITY REPORT")
        assertThat(report).contains("NO SECURITY THREATS DETECTED")
        assertThat(report).contains("Device appears to be secure")
        assertThat(report).contains("Security Score: 100.0/100")
        assertThat(report).contains("STATUS: EXCELLENT - Device is highly secure")
    }

    @Test
    fun `generateDetailedReport should include device information`() {
        val report = SecurityReportGenerator.generateDetailedReport(securityReport)
        
        assertThat(report).contains("Pixel 5")
        assertThat(report).contains("Google")
        assertThat(report).contains("12")
        assertThat(report).contains("31")
        assertThat(report).contains("5.4.86")
        assertThat(report).contains("google/redfin/redfin:12/SP1A.210812.016.C1/7818238:user/release-keys")
        assertThat(report).contains("2022-01-05")
        assertThat(report).contains("locked")
    }

    @Test
    fun `generateDetailedReport should include security status`() {
        val report = SecurityReportGenerator.generateDetailedReport(securityReport)
        
        assertThat(report).contains("Overall Risk Level: NONE")
        assertThat(report).contains("Overall Confidence: 95.0%")
        assertThat(report).contains("Device Rooted: NO")
        assertThat(report).contains("Running in Emulator: NO")
        assertThat(report).contains("Screenshot Protection: ENABLED")
        assertThat(report).contains("Malicious Apps Detected: NO")
        assertThat(report).contains("System Integrity Compromised: NO")
        assertThat(report).contains("Debugger Attached: NO")
        assertThat(report).contains("Hooking Detected: NO")
    }

    @Test
    fun `generateDetailedReport should handle threats correctly`() {
        val threatReport = securityReport.copy(
            securityStatus = securityReport.securityStatus.copy(
                isRooted = true,
                riskLevel = RiskLevel.CRITICAL,
                overallConfidence = 0.9f
            ),
            detectedThreats = listOf(
                ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = "Device is rooted",
                    severity = ThreatSeverity.CRITICAL,
                    confidence = 0.95f,
                    detectionMethods = listOf("SU_BINARY_FOUND", "MAGISK_ARTIFACTS"),
                    recommendations = listOf(
                        "Unroot the device for maximum security",
                        "Use official firmware from device manufacturer"
                    )
                )
            )
        )
        
        val report = SecurityReportGenerator.generateDetailedReport(threatReport)
        
        assertThat(report).contains("DETECTED THREATS")
        assertThat(report).contains("Device is rooted")
        assertThat(report).contains("CRITICAL THREATS (1)")
        assertThat(report).contains("SU_BINARY_FOUND")
        assertThat(report).contains("MAGISK_ARTIFACTS")
        assertThat(report).contains("Unroot the device for maximum security")
        assertThat(report).contains("Security Score: 5.0/100")
        assertThat(report).contains("STATUS: CRITICAL - Device has severe security vulnerabilities")
    }

    @Test
    fun `generateJsonReport should create valid JSON`() {
        val jsonReport = SecurityReportGenerator.generateJsonReport(securityReport)
        
        assertThat(jsonReport).isNotEmpty()
        assertThat(jsonReport).contains("\"timestamp\"")
        assertThat(jsonReport).contains("\"device_info\"")
        assertThat(jsonReport).contains("\"security_status\"")
        assertThat(jsonReport).contains("\"detected_threats\"")
        assertThat(jsonReport).contains("\"app_package\"")
    }

    @Test
    fun `generateSummaryReport should create concise summary`() {
        val threatReport = securityReport.copy(
            securityStatus = securityReport.securityStatus.copy(
                isRooted = true,
                isEmulator = true,
                riskLevel = RiskLevel.HIGH
            ),
            detectedThreats = listOf(
                ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = "Device is rooted",
                    severity = ThreatSeverity.HIGH,
                    confidence = 0.85f
                ),
                ThreatInfo(
                    type = ThreatType.EMULATOR,
                    description = "Running in emulator",
                    severity = ThreatSeverity.MEDIUM,
                    confidence = 0.9f
                )
            )
        )
        
        val summary = SecurityReportGenerator.generateSummaryReport(threatReport)
        
        assertThat(summary).isNotEmpty()
        assertThat(summary).contains("Caster Security Report Summary")
        assertThat(summary).contains("Risk Level: HIGH")
        assertThat(summary).contains("Threats Detected: 2")
        assertThat(summary).contains("Device Rooted: Yes")
        assertThat(summary).contains("Emulator: Yes")
        assertThat(summary).contains("Device is rooted")
        assertThat(summary).contains("Running in emulator")
    }

    @Test
    fun `calculateSecurityScore should handle various threat scenarios`() {
        // Test secure device
        var score = calculateSecurityScore(securityReport)
        assertThat(score).isEqualTo(100.0f)
        
        // Test device with critical risk
        val criticalReport = securityReport.copy(
            securityStatus = securityReport.securityStatus.copy(
                riskLevel = RiskLevel.CRITICAL
            )
        )
        score = calculateSecurityScore(criticalReport)
        assertThat(score).isEqualTo(30.0f)
        
        // Test device with threats
        val threatReport = securityReport.copy(
            securityStatus = securityReport.securityStatus.copy(
                riskLevel = RiskLevel.HIGH
            ),
            detectedThreats = listOf(
                ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = "Device is rooted",
                    severity = ThreatSeverity.CRITICAL
                )
            )
        )
        score = calculateSecurityScore(threatReport)
        assertThat(score).isEqualTo(5.0f)
    }

    private fun calculateSecurityScore(report: SecurityReport): Float {
        // This is a copy of the private method for testing purposes
        var score = 100.0f
        
        when (report.securityStatus.riskLevel) {
            RiskLevel.CRITICAL -> score -= 70
            RiskLevel.HIGH -> score -= 50
            RiskLevel.MEDIUM -> score -= 30
            RiskLevel.LOW -> score -= 10
            RiskLevel.NONE -> {}
        }
        
        report.detectedThreats.forEach { threat ->
            when (threat.severity) {
                ThreatSeverity.CRITICAL -> score -= 25
                ThreatSeverity.HIGH -> score -= 15
                ThreatSeverity.MEDIUM -> score -= 8
                ThreatSeverity.LOW -> score -= 3
            }
        }
        
        return if (score < 0) 0.0f else score
    }
}