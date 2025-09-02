package io.github.yoganataa.caster.models

import com.google.common.truth.Truth.assertThat
import io.github.yoganataa.caster.logging.*
import org.junit.Before
import org.junit.Test
import java.util.*

class CasterResultTest {

    private lateinit var securityReport: SecurityReport
    private lateinit var rootResult: RootResult
    private lateinit var emulatorResult: EmulatorResult
    private lateinit var flagSecureResult: FlagSecureResult
    private lateinit var maliciousAppsResult: MaliciousAppsResult
    private lateinit var integrityResult: IntegrityResult
    private lateinit var tamperingResult: TamperingResult

    @Before
    fun setUp() {
        securityReport = SecurityReport(
            timestamp = System.currentTimeMillis(),
            deviceInfo = DeviceInfo(
                model = "Test Device",
                manufacturer = "Test Manufacturer",
                androidVersion = "10",
                apiLevel = 29,
                kernelVersion = "4.14.117"
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
                riskLevel = RiskLevel.LOW
            ),
            detectedThreats = emptyList(),
            appPackage = "io.github.yoganataa.caster.test"
        )

        rootResult = RootResult(
            isRooted = false,
            detectedMethods = emptyList(),
            confidence = 0.0f
        )

        emulatorResult = EmulatorResult(
            isEmulator = false,
            detectedMethods = emptyList(),
            confidence = 0.0f
        )

        flagSecureResult = FlagSecureResult(
            isFlagSecureDisabled = false,
            detectionMethods = emptyList(),
            confidence = 0.0f
        )

        maliciousAppsResult = MaliciousAppsResult(
            hasMaliciousApps = false,
            detectedApps = emptyList(),
            riskScore = 0.0f
        )

        integrityResult = IntegrityResult(
            isTampered = false,
            threats = emptyList()
        )

        tamperingResult = TamperingResult(
            isDebuggerAttached = false,
            isHookingDetected = false,
            isFridaServerRunning = false,
            detectedMethods = emptyList()
        )
    }

    @Test
    fun `CasterResult should be created correctly`() {
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result).isNotNull()
        assertThat(result.rootResult).isEqualTo(rootResult)
        assertThat(result.emulatorResult).isEqualTo(emulatorResult)
        assertThat(result.flagSecureResult).isEqualTo(flagSecureResult)
        assertThat(result.maliciousAppsResult).isEqualTo(maliciousAppsResult)
        assertThat(result.integrityResult).isEqualTo(integrityResult)
        assertThat(result.tamperingResult).isEqualTo(tamperingResult)
        assertThat(result.securityReport).isEqualTo(securityReport)
    }

    @Test
    fun `isSecure should return true when no threats detected`() {
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.isSecure).isTrue()
    }

    @Test
    fun `isSecure should return false when threats detected`() {
        val rootedResult = rootResult.copy(isRooted = true)
        
        val result = CasterResult(
            rootResult = rootedResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.isSecure).isFalse()
    }

    @Test
    fun `threatLevel should be NONE when no threats detected`() {
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.threatLevel).isEqualTo(ThreatLevel.NONE)
    }

    @Test
    fun `threatLevel should be CRITICAL when high confidence root detected`() {
        val highConfidenceRoot = rootResult.copy(
            isRooted = true,
            confidence = 0.95f
        )
        
        val result = CasterResult(
            rootResult = highConfidenceRoot,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.threatLevel).isEqualTo(ThreatLevel.CRITICAL)
    }

    @Test
    fun `threatLevel should be HIGH when rooted`() {
        val rootedResult = rootResult.copy(
            isRooted = true,
            confidence = 0.7f
        )
        
        val result = CasterResult(
            rootResult = rootedResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.threatLevel).isEqualTo(ThreatLevel.HIGH)
    }

    @Test
    fun `threatLevel should be MEDIUM when flag secure disabled`() {
        val disabledFlagSecure = flagSecureResult.copy(isFlagSecureDisabled = true)
        
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = disabledFlagSecure,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.threatLevel).isEqualTo(ThreatLevel.MEDIUM)
    }

    @Test
    fun `totalIssuesDetected should count all detected issues`() {
        val rootedResult = rootResult.copy(isRooted = true)
        val emulatorDetected = emulatorResult.copy(isEmulator = true)
        val flagSecureDisabled = flagSecureResult.copy(isFlagSecureDisabled = true)
        val maliciousAppsDetected = maliciousAppsResult.copy(hasMaliciousApps = true)
        val integrityCompromised = integrityResult.copy(isTampered = true)
        val tamperingDetected = tamperingResult.copy(isDebuggerAttached = true)
        
        val result = CasterResult(
            rootResult = rootedResult,
            emulatorResult = emulatorDetected,
            flagSecureResult = flagSecureDisabled,
            maliciousAppsResult = maliciousAppsDetected,
            integrityResult = integrityCompromised,
            tamperingResult = tamperingDetected,
            securityReport = securityReport
        )

        // Should count all 6 issues
        assertThat(result.totalIssuesDetected).isEqualTo(6)
    }

    @Test
    fun `threatSummary should list all detected threats`() {
        val rootedResult = rootResult.copy(
            isRooted = true,
            confidence = 0.85f,
            detectedMethods = listOf("SU_BINARY_FOUND")
        )
        val emulatorDetected = emulatorResult.copy(
            isEmulator = true,
            confidence = 0.9f,
            detectedMethods = listOf("EMULATOR_PROPERTIES")
        )
        val flagSecureDisabled = flagSecureResult.copy(
            isFlagSecureDisabled = true,
            detectionMethods = listOf("FLAG_SECURE_NOT_SET")
        )
        
        val result = CasterResult(
            rootResult = rootedResult,
            emulatorResult = emulatorDetected,
            flagSecureResult = flagSecureDisabled,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        val summary = result.threatSummary
        assertThat(summary).hasSize(3)
        assertThat(summary).contains("Device is rooted (confidence: 85.0%)")
        assertThat(summary).contains("Running in emulator (confidence: 90.0%)")
        assertThat(summary).contains("Screen recording/screenshots are possible")
    }

    @Test
    fun `generateSummary should create detailed report`() {
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport,
            analysisTimeMs = 150
        )

        val summary = result.generateSummary()
        assertThat(summary).isNotEmpty()
        assertThat(summary).contains("Caster Security Analysis Summary")
        assertThat(summary).contains("Timestamp: ${Date(result.timestamp)}")
        assertThat(summary).contains("Analysis Time: 150ms")
        assertThat(summary).contains("Overall Status: SECURE")
        assertThat(summary).contains("Issues Found: 0")
        assertThat(summary).contains("Root Detection:")
        assertThat(summary).contains("Emulator Detection:")
        assertThat(summary).contains("Screen Protection:")
        assertThat(summary).contains("Malicious Apps:")
        assertThat(summary).contains("Application Integrity:")
        assertThat(summary).contains("Anti-Tampering:")
    }

    // New tests for enhanced security features
    
    @Test
    fun `threatLevel should be CRITICAL when multiple high-risk threats detected`() {
        val rootedResult = rootResult.copy(
            isRooted = true,
            confidence = 0.95f
        )
        val maliciousAppsDetected = maliciousAppsResult.copy(
            hasMaliciousApps = true,
            riskScore = 0.9f
        )
        val tamperingDetected = tamperingResult.copy(
            isDebuggerAttached = true,
            isHookingDetected = true
        )
        
        val result = CasterResult(
            rootResult = rootedResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsDetected,
            integrityResult = integrityResult,
            tamperingResult = tamperingDetected,
            securityReport = securityReport
        )

        assertThat(result.threatLevel).isEqualTo(ThreatLevel.CRITICAL)
    }
    
    @Test
    fun `threatLevel should be HIGH when emulator with high confidence detected`() {
        val emulatorDetected = emulatorResult.copy(
            isEmulator = true,
            confidence = 0.85f
        )
        
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorDetected,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.threatLevel).isEqualTo(ThreatLevel.HIGH)
    }
    
    @Test
    fun `threatLevel should be MEDIUM when integrity compromised`() {
        val integrityCompromised = integrityResult.copy(
            isTampered = true,
            threats = listOf("SYSTEM_PARTITION_RW", "BOOTLOADER_UNLOCKED")
        )
        
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityCompromised,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.threatLevel).isEqualTo(ThreatLevel.MEDIUM)
    }
    
    @Test
    fun `threatLevel should be LOW when low confidence threats detected`() {
        val lowConfidenceRoot = rootResult.copy(
            isRooted = true,
            confidence = 0.3f
        )
        
        val result = CasterResult(
            rootResult = lowConfidenceRoot,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        assertThat(result.threatLevel).isEqualTo(ThreatLevel.LOW)
    }
    
    @Test
    fun `totalIssuesDetected should handle complex threat scenarios`() {
        val rootedResult = rootResult.copy(
            isRooted = true,
            detectedMethods = listOf("SU_BINARY_FOUND", "MAGISK_ARTIFACTS")
        )
        val emulatorDetected = emulatorResult.copy(
            isEmulator = true,
            detectedMethods = listOf("EMULATOR_PROPERTIES", "VIRTUAL_CPU")
        )
        val flagSecureDisabled = flagSecureResult.copy(
            isFlagSecureDisabled = true,
            detectionMethods = listOf("FLAG_SECURE_NOT_SET", "SCREENSHOT_ENABLED")
        )
        val maliciousAppsDetected = maliciousAppsResult.copy(
            hasMaliciousApps = true,
            detectedApps = listOf(
                MaliciousAppInfo("com.malicious.app1", "Malicious App 1", "Spyware", "High"),
                MaliciousAppInfo("com.malicious.app2", "Malicious App 2", "Ransomware", "Critical")
            ),
            riskScore = 0.7f
        )
        val integrityCompromised = integrityResult.copy(
            isTampered = true,
            threats = listOf("SYSTEM_PARTITION_RW", "BOOTLOADER_UNLOCKED", "SELINUX_DISABLED")
        )
        val tamperingDetected = tamperingResult.copy(
            isDebuggerAttached = true,
            isHookingDetected = true,
            detectedMethods = listOf("DEBUGGER_ATTACHED", "HOOKING_FRAMEWORKS")
        )
        
        val result = CasterResult(
            rootResult = rootedResult,
            emulatorResult = emulatorDetected,
            flagSecureResult = flagSecureDisabled,
            maliciousAppsResult = maliciousAppsDetected,
            integrityResult = integrityCompromised,
            tamperingResult = tamperingDetected,
            securityReport = securityReport
        )

        // Should count all issues
        assertThat(result.totalIssuesDetected).isEqualTo(6)
    }
    
    @Test
    fun `threatSummary should provide detailed information for complex scenarios`() {
        val rootedResult = rootResult.copy(
            isRooted = true,
            confidence = 0.9f,
            detectedMethods = listOf("SU_BINARY_FOUND", "MAGISK_ARTIFACTS")
        )
        val emulatorDetected = emulatorResult.copy(
            isEmulator = true,
            confidence = 0.85f,
            detectedMethods = listOf("EMULATOR_PROPERTIES", "VIRTUAL_CPU")
        )
        val maliciousAppsDetected = maliciousAppsResult.copy(
            hasMaliciousApps = true,
            detectedApps = listOf(
                MaliciousAppInfo("com.malicious.app1", "Malicious App 1", "Spyware", "High")
            ),
            riskScore = 0.8f
        )
        
        val result = CasterResult(
            rootResult = rootedResult,
            emulatorResult = emulatorDetected,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsDetected,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )

        val summary = result.threatSummary
        assertThat(summary).hasSize(3)
        assertThat(summary).contains("Device is rooted (confidence: 90.0%)")
        assertThat(summary).contains("Running in emulator (confidence: 85.0%)")
        assertThat(summary).contains("Malicious apps detected (risk score: 80.0%)")
    }
    
    @Test
    fun `generateSummary should include enhanced security information`() {
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport,
            analysisTimeMs = 200
        )

        val summary = result.generateSummary()
        assertThat(summary).isNotEmpty()
        // Check for enhanced security information
        assertThat(summary).contains("Security Analysis Complete")
        assertThat(summary).contains("No critical security threats detected")
        assertThat(summary).contains("Device appears to be secure")
    }
    
    @Test
    fun `CasterResult should handle timestamp correctly`() {
        val currentTime = System.currentTimeMillis()
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport
        )
        
        // Timestamp should be recent
        assertThat(result.timestamp).isAtLeast(currentTime - 1000) // Within 1 second
        assertThat(result.timestamp).isAtMost(currentTime + 1000) // Within 1 second
    }
    
    @Test
    fun `CasterResult should handle analysis time correctly`() {
        val result = CasterResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            flagSecureResult = flagSecureResult,
            maliciousAppsResult = maliciousAppsResult,
            integrityResult = integrityResult,
            tamperingResult = tamperingResult,
            securityReport = securityReport,
            analysisTimeMs = 300
        )
        
        assertThat(result.analysisTimeMs).isEqualTo(300)
    }
}