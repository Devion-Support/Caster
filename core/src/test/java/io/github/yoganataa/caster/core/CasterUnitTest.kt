package io.github.yoganataa.caster.core

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import io.github.yoganataa.caster.core.detection.app.MaliciousAppDetector
import io.github.yoganataa.caster.core.detection.environment.EmulatorDetector
import io.github.yoganataa.caster.core.detection.integrity.IntegrityDetector
import io.github.yoganataa.caster.core.detection.root.RootDetector
import io.github.yoganataa.caster.core.detection.security.FlagSecureDetector
import io.github.yoganataa.caster.core.detection.tampering.AntiTamperingDetector
import io.github.yoganataa.caster.core.logging.RiskLevel
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito.anyString
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowBuild
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import io.github.yoganataa.caster.core.detection.app.MaliciousAppDetector.MaliciousAppResult as MaliciousResult
import io.github.yoganataa.caster.core.detection.environment.EmulatorResult
import io.github.yoganataa.caster.core.detection.integrity.IntegrityDetector.Result as IntegrityResult
import io.github.yoganataa.caster.core.detection.root.RootDetectionResult as RootResult
import io.github.yoganataa.caster.core.detection.security.FlagSecureDetector.FlagSecureResult
import io.github.yoganataa.caster.core.detection.tampering.AntiTamperingDetector.Result as TamperingResult

@ExperimentalCoroutinesApi
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [Build.VERSION_CODES.P])
class CasterUnitTest {

    @Mock
    lateinit var mockActivity: Activity

    @Mock
    lateinit var mockContext: Context

    @Mock
    lateinit var mockPackageManager: PackageManager

    @Mock
    lateinit var mockRootDetector: RootDetector

    @Mock
    lateinit var mockEmulatorDetector: EmulatorDetector

    @Mock
    lateinit var mockFlagSecureDetector: FlagSecureDetector

    @Mock
    lateinit var mockIntegrityDetector: IntegrityDetector

    @Mock
    lateinit var mockAntiTamperingDetector: AntiTamperingDetector

    @Mock
    lateinit var mockMaliciousAppDetector: MaliciousAppDetector

    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        mockkStatic(Log::class)
        mockkStatic(System::class)

        `when`(mockActivity.applicationContext).thenReturn(mockContext)
        `when`(mockContext.packageName).thenReturn("io.github.yoganataa.caster.test")
        `when`(mockContext.packageManager).thenReturn(mockPackageManager)

        ShadowBuild.setModel("CasterTest-Model")
        ShadowBuild.setManufacturer("CasterTest-Manu")
        `when`(System.loadLibrary(anyString())).thenAnswer { }
    }

    @After
    fun tearDown() {
        unmockkStatic(Log::class)
        unmockkStatic(System::class)
    }

    private fun createCaster(config: CasterConfig = CasterConfig()): Caster {
        return Caster(
            config = config,
            rootDetectorFactory = { mockRootDetector },
            emulatorDetectorFactory = { mockEmulatorDetector },
            flagSecureDetectorFactory = { mockFlagSecureDetector },
            maliciousAppDetectorFactory = { _, _, _ -> mockMaliciousAppDetector },
            integrityDetectorFactory = { mockIntegrityDetector },
            antiTamperingDetectorFactory = { mockAntiTamperingDetector }
        )
    }

    @Test
    fun `analyze returns clean result when no threats are detected`() = runTest {
        // Given
        `when`(mockRootDetector.detect()).thenReturn(
            RootResult(isRooted = false, emptyList(), emptyList(), 0f)
        )
        `when`(mockEmulatorDetector.detect()).thenReturn(
            EmulatorResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockFlagSecureDetector.detectFlagSecureBypass()).thenReturn(
            FlagSecureResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockIntegrityDetector.detect()).thenReturn(
            IntegrityResult(false, emptyList(), emptyList())
        )
        `when`(mockAntiTamperingDetector.detect()).thenReturn(
            TamperingResult(false, false, emptyList(), emptyList())
        )
        `when`(mockMaliciousAppDetector.detectMaliciousApps()).thenReturn(
            MaliciousResult(false, emptyList(), emptyList(), 0f)
        )

        val caster = createCaster()

        // When
        val result = caster.analyze(mockActivity)

        // Then
        assertFalse(result.rootResult.isRooted)
        assertFalse(result.emulatorResult.isEmulator)
        assertFalse(result.maliciousAppsResult.hasMaliciousApps)
        assertTrue(result.securityReport.detectedThreats.isEmpty())
        assertEquals(RiskLevel.LOW, result.securityReport.securityStatus.riskLevel)
    }

    @Test
    fun `analyze reports root threat correctly`() = runTest {
        // Given
        val threat = ThreatInfo(ThreatType.ROOT_ACCESS, "Root found", "CRITICAL")
        `when`(mockRootDetector.detect()).thenReturn(
            RootResult(true, listOf("TestRootMethod"), listOf(threat), 1.0f)
        )
        `when`(mockEmulatorDetector.detect()).thenReturn(
            EmulatorResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockFlagSecureDetector.detectFlagSecureBypass()).thenReturn(
            FlagSecureResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockIntegrityDetector.detect()).thenReturn(
            IntegrityResult(false, emptyList(), emptyList())
        )
        `when`(mockAntiTamperingDetector.detect()).thenReturn(
            TamperingResult(false, false, emptyList(), emptyList())
        )
        `when`(mockMaliciousAppDetector.detectMaliciousApps()).thenReturn(
            MaliciousResult(false, emptyList(), emptyList(), 0f)
        )

        val caster = createCaster()

        // When
        val result = caster.analyze(mockActivity)

        // Then
        assertTrue(result.rootResult.isRooted)
        assertEquals(1, result.securityReport.detectedThreats.size)
        assertEquals(threat, result.securityReport.detectedThreats.first())
        assertEquals(RiskLevel.CRITICAL, result.securityReport.securityStatus.riskLevel)
    }

    @Test
    fun `analyze reports emulator threat correctly`() = runTest {
        // Given
        val threat = ThreatInfo(ThreatType.EMULATOR, "Emulator found", "HIGH")
        `when`(mockRootDetector.detect()).thenReturn(
            RootResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockEmulatorDetector.detect()).thenReturn(
            EmulatorResult(true, listOf("TestEmulatorMethod"), listOf(threat), 1.0f)
        )
        `when`(mockFlagSecureDetector.detectFlagSecureBypass()).thenReturn(
            FlagSecureResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockIntegrityDetector.detect()).thenReturn(
            IntegrityResult(false, emptyList(), emptyList())
        )
        `when`(mockAntiTamperingDetector.detect()).thenReturn(
            TamperingResult(false, false, emptyList(), emptyList())
        )
        `when`(mockMaliciousAppDetector.detectMaliciousApps()).thenReturn(
            MaliciousResult(false, emptyList(), emptyList(), 0f)
        )

        val caster = createCaster()

        // When
        val result = caster.analyze(mockActivity)

        // Then
        assertTrue(result.emulatorResult.isEmulator)
        assertEquals(1, result.securityReport.detectedThreats.size)
        assertEquals(threat, result.securityReport.detectedThreats.first())
        assertEquals(RiskLevel.HIGH, result.securityReport.securityStatus.riskLevel)
    }

    @Test
    fun `riskLevel is highest of all detected threats`() = runTest {
        // Given
        val rootThreat = ThreatInfo(ThreatType.ROOT_ACCESS, "Root found", "MEDIUM")
        `when`(mockRootDetector.detect()).thenReturn(
            RootResult(true, listOf("TestRootMethod"), listOf(rootThreat), 1.0f)
        )

        val emulatorThreat = ThreatInfo(ThreatType.EMULATOR, "Emulator found", "HIGH")
        `when`(mockEmulatorDetector.detect()).thenReturn(
            EmulatorResult(true, listOf("TestEmulatorMethod"), listOf(emulatorThreat), 1.0f)
        )
        `when`(mockFlagSecureDetector.detectFlagSecureBypass()).thenReturn(
            FlagSecureResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockIntegrityDetector.detect()).thenReturn(
            IntegrityResult(false, emptyList(), emptyList())
        )
        `when`(mockAntiTamperingDetector.detect()).thenReturn(
            TamperingResult(false, false, emptyList(), emptyList())
        )
        `when`(mockMaliciousAppDetector.detectMaliciousApps()).thenReturn(
            MaliciousResult(false, emptyList(), emptyList(), 0f)
        )

        val caster = createCaster()

        // When
        val result = caster.analyze(mockActivity)

        // Then
        assertEquals(2, result.securityReport.detectedThreats.size)
        assertEquals(
            RiskLevel.HIGH,
            result.securityReport.securityStatus.riskLevel,
            "Risk level should be the highest of all threats"
        )
    }

    @Test
    fun `disabled root detector is not executed`() = runTest {
        // Given
        val config = CasterConfig(enableRootDetection = false)
        val caster = createCaster(config)

        // Stub all detectors, even the disabled one, as a safeguard against unexpected calls.
        `when`(mockRootDetector.detect()).thenReturn(
            RootResult(true, listOf("ShouldNotBeCalled"), emptyList(), 1f)
        )
        `when`(mockEmulatorDetector.detect()).thenReturn(
            EmulatorResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockFlagSecureDetector.detectFlagSecureBypass()).thenReturn(
            FlagSecureResult(false, emptyList(), emptyList(), 0f)
        )
        `when`(mockIntegrityDetector.detect()).thenReturn(
            IntegrityResult(false, emptyList(), emptyList())
        )
        `when`(mockAntiTamperingDetector.detect()).thenReturn(
            TamperingResult(false, false, emptyList(), emptyList())
        )
        `when`(mockMaliciousAppDetector.detectMaliciousApps()).thenReturn(
            MaliciousResult(false, emptyList(), emptyList(), 0f)
        )

        // When
        val result = caster.analyze(mockActivity)

        // Then
        // The main verification: ensure the disabled detector's detect method was never called.
        verify(mockRootDetector, never()).detect()

        // Also verify the final result is clean for the disabled detector.
        assertFalse(
            result.rootResult.isRooted,
            "Root result should be clean when detector is disabled"
        )
    }
}
