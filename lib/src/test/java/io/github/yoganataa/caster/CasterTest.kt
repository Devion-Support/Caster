package io.github.yoganataa.caster

import android.app.Activity
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import io.github.yoganataa.caster.logging.LogLevel
import io.github.yoganataa.caster.models.CasterResult
import io.github.yoganataa.caster.models.ThreatLevel
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.annotation.Config

@RunWith(AndroidJUnit4::class)
@Config(sdk = [28])
class CasterTest {

    private lateinit var context: Context
    private lateinit var activity: Activity

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        activity = Robolectric.buildActivity(Activity::class.java).get()
        
        // Initialize Caster instance for testing
        Caster.Builder(context)
            .setLogLevel(LogLevel.DEBUG)
            .enableRootDetection(true)
            .enableEmulatorDetection(true)
            .enableIntegrityChecks(true)
            .enableAntiTampering(true)
            .enableMaliciousAppDetection(true)
            .enableFlagSecureDetection(true)
            .build()
    }

    @After
    fun tearDown() {
        // Clean up the singleton instance
        resetCasterInstance()
    }

    @Test
    fun `getInstance should return singleton instance`() {
        val instance1 = Caster.getInstance()
        val instance2 = Caster.getInstance()
        
        assertThat(instance1).isNotNull()
        assertThat(instance2).isNotNull()
        assertThat(instance1).isSameInstanceAs(instance2)
    }

    @Test
    fun `analyze should return valid CasterResult`() {
        val caster = Caster.getInstance()
        val result = caster.analyze(activity)
        
        // Verify that we get a valid result object
        assertThat(result).isNotNull()
        assertThat(result.timestamp).isGreaterThan(0)
        assertThat(result.analysisTimeMs).isAtLeast(0)
        
        // Verify all detection results are present
        assertThat(result.rootResult).isNotNull()
        assertThat(result.emulatorResult).isNotNull()
        assertThat(result.flagSecureResult).isNotNull()
        assertThat(result.maliciousAppsResult).isNotNull()
        assertThat(result.integrityResult).isNotNull()
        assertThat(result.tamperingResult).isNotNull()
        assertThat(result.securityReport).isNotNull()
    }

    @Test
    fun `CasterResult should calculate isSecure correctly`() {
        val caster = Caster.getInstance()
        val result = caster.analyze(activity)
        
        // On a normal device, all security checks should pass
        // So isSecure should be true
        assertThat(result.isSecure).isTrue()
    }

    @Test
    fun `CasterResult should calculate threatLevel correctly`() {
        val caster = Caster.getInstance()
        val result = caster.analyze(activity)
        
        // On a normal device, threat level should be NONE or LOW
        assertThat(result.threatLevel).isAnyOf(ThreatLevel.NONE, ThreatLevel.LOW)
    }

    @Test
    fun `CasterResult should calculate totalIssuesDetected correctly`() {
        val caster = Caster.getInstance()
        val result = caster.analyze(activity)
        
        // On a normal device, there should be no issues detected
        assertThat(result.totalIssuesDetected).isEqualTo(0)
    }

    @Test
    fun `CasterResult should generate summary correctly`() {
        val caster = Caster.getInstance()
        val result = caster.analyze(activity)
        val summary = result.generateSummary()
        
        // Verify that summary is generated and contains expected content
        assertThat(summary).isNotEmpty()
        assertThat(summary).contains("Caster Security Analysis Summary")
        assertThat(summary).contains("Overall Status")
        assertThat(summary).contains("Root Detection")
        assertThat(summary).contains("Emulator Detection")
    }

    @Test
    fun `Builder should configure Caster correctly`() {
        // Test with different configuration
        Caster.Builder(context)
            .setLogLevel(LogLevel.ERROR)
            .enableRootDetection(false)
            .enableEmulatorDetection(false)
            .build()
        
        val caster = Caster.getInstance()
        // Note: We can't directly test the configuration values as they're private
        // But we can verify the instance is created successfully
        assertThat(caster).isNotNull()
    }

    @Test(expected = IllegalStateException::class)
    fun `getInstance should throw exception when not initialized`() {
        // Reset the instance first
        resetCasterInstance()
        
        // This should throw an IllegalStateException
        Caster.getInstance()
    }

    // Helper method to reset the singleton instance for testing
    private fun resetCasterInstance() {
        try {
            val field = Caster::class.java.getDeclaredField("instance")
            field.isAccessible = true
            field.set(null, null)
        } catch (e: Exception) {
            // Ignore exceptions during reset
        }
    }

    // New comprehensive tests for enhanced security features
    
    @Test
    fun `Caster should handle all security detection types`() {
        val caster = Caster.getInstance()
        val result = caster.analyze(activity)
        
        // Verify all security detection types are working
        assertThat(result.rootResult).isNotNull()
        assertThat(result.emulatorResult).isNotNull()
        assertThat(result.flagSecureResult).isNotNull()
        assertThat(result.maliciousAppsResult).isNotNull()
        assertThat(result.integrityResult).isNotNull()
        assertThat(result.tamperingResult).isNotNull()
        
        // On a normal device, all should indicate no threats
        assertThat(result.rootResult.isRooted).isFalse()
        assertThat(result.emulatorResult.isEmulator).isFalse()
        assertThat(result.flagSecureResult.isFlagSecureDisabled).isFalse()
        assertThat(result.maliciousAppsResult.hasMaliciousApps).isFalse()
        assertThat(result.integrityResult.isTampered).isFalse()
        assertThat(result.tamperingResult.isDebuggerAttached).isFalse()
        assertThat(result.tamperingResult.isHookingDetected).isFalse()
    }
    
    @Test
    fun `Caster should generate comprehensive security report`() {
        val caster = Caster.getInstance()
        val result = caster.analyze(activity)
        val securityReport = result.securityReport
        
        // Verify security report structure
        assertThat(securityReport).isNotNull()
        assertThat(securityReport.timestamp).isGreaterThan(0)
        assertThat(securityReport.deviceInfo).isNotNull()
        assertThat(securityReport.securityStatus).isNotNull()
        assertThat(securityReport.appPackage).isNotEmpty()
        
        // Verify security status
        val securityStatus = securityReport.securityStatus
        assertThat(securityStatus.isRooted).isFalse()
        assertThat(securityStatus.isEmulator).isFalse()
        assertThat(securityStatus.flagSecureDisabled).isFalse()
        assertThat(securityStatus.maliciousAppsDetected).isFalse()
        assertThat(securityStatus.isTampered).isFalse()
        assertThat(securityStatus.isDebuggerAttached).isFalse()
    }
    
    @Test
    fun `Caster should handle different configuration options`() {
        // Test various configuration combinations
        val configs = listOf(
            CasterConfig(enableRootDetection = true),
            CasterConfig(enableEmulatorDetection = true),
            CasterConfig(enableIntegrityChecks = true),
            CasterConfig(enableAntiTampering = true),
            CasterConfig(enableMaliciousAppDetection = true),
            CasterConfig(enableFlagSecureDetection = true)
        )
        
        configs.forEach { config ->
            // Create a new Caster instance with specific config
            Caster.Builder(context)
                .enableRootDetection(config.enableRootDetection)
                .enableEmulatorDetection(config.enableEmulatorDetection)
                .enableIntegrityChecks(config.enableIntegrityChecks)
                .enableAntiTampering(config.enableAntiTampering)
                .enableMaliciousAppDetection(config.enableMaliciousAppDetection)
                .enableFlagSecureDetection(config.enableFlagSecureDetection)
                .build()
            
            val caster = Caster.getInstance()
            val result = caster.analyze(activity)
            
            // All results should be valid
            assertThat(result).isNotNull()
            assertThat(result.rootResult).isNotNull()
            assertThat(result.emulatorResult).isNotNull()
            assertThat(result.flagSecureResult).isNotNull()
            assertThat(result.maliciousAppsResult).isNotNull()
            assertThat(result.integrityResult).isNotNull()
            assertThat(result.tamperingResult).isNotNull()
        }
    }
    
    @Test
    fun `Caster should provide detailed threat analysis`() {
        val caster = Caster.getInstance()
        val result = caster.analyze(activity)
        
        // Verify detailed threat analysis components
        assertThat(result.rootResult.confidence).isAtLeast(0f)
        assertThat(result.rootResult.confidence).isAtMost(1f)
        assertThat(result.rootResult.detectedMethods).isInstanceOf(List::class.java)
        
        assertThat(result.emulatorResult.confidence).isAtLeast(0f)
        assertThat(result.emulatorResult.confidence).isAtMost(1f)
        assertThat(result.emulatorResult.detectedMethods).isInstanceOf(List::class.java)
        
        assertThat(result.maliciousAppsResult.riskScore).isAtLeast(0f)
        assertThat(result.maliciousAppsResult.riskScore).isAtMost(1f)
        assertThat(result.maliciousAppsResult.detectedApps).isInstanceOf(List::class.java)
        
        assertThat(result.tamperingResult.detectedMethods).isInstanceOf(List::class.java)
    }
    
    @Test
    fun `Caster should handle performance constraints`() {
        val caster = Caster.getInstance()
        
        // Measure analysis time
        val startTime = System.currentTimeMillis()
        val result = caster.analyze(activity)
        val endTime = System.currentTimeMillis()
        val analysisTime = endTime - startTime
        
        // Analysis should complete in a reasonable time
        assertThat(analysisTime).isAtMost(5000) // 5 seconds maximum
        
        // Result should include analysis time
        assertThat(result.analysisTimeMs).isAtLeast(0)
        assertThat(result.analysisTimeMs).isAtMost(5000)
    }
    
    @Test
    fun `Caster should generate consistent results`() {
        val caster = Caster.getInstance()
        val results = mutableListOf<CasterResult>()
        
        // Run analysis multiple times
        repeat(3) {
            val result = caster.analyze(activity)
            results.add(result)
        }
        
        // All results should be consistent on a normal device
        for (i in 1 until results.size) {
            assertThat(results[i].isSecure).isEqualTo(results[0].isSecure)
            assertThat(results[i].threatLevel).isEqualTo(results[0].threatLevel)
            assertThat(results[i].totalIssuesDetected).isEqualTo(results[0].totalIssuesDetected)
        }
    }
    
    @Test
    fun `Caster should handle edge cases in security analysis`() {
        val caster = Caster.getInstance()
        
        // Test with different activity states
        val normalActivity = Robolectric.buildActivity(Activity::class.java).create().get()
        val resumedActivity = Robolectric.buildActivity(Activity::class.java).create().start().resume().get()
        
        val normalResult = caster.analyze(normalActivity)
        val resumedResult = caster.analyze(resumedActivity)
        
        // Both results should be valid
        assertThat(normalResult).isNotNull()
        assertThat(resumedResult).isNotNull()
        
        // Results should be consistent
        assertThat(normalResult.isSecure).isEqualTo(resumedResult.isSecure)
        assertThat(normalResult.threatLevel).isEqualTo(resumedResult.threatLevel)
    }
}