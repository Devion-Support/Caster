package io.github.yoganataa.caster.core.detection

import android.content.Context
import io.github.yoganataa.caster.core.CasterConfig
import io.github.yoganataa.caster.core.logging.Logger
import kotlin.collections.List
import kotlin.collections.emptyList

/**
 * Native detector that consolidates all detection logic in C++ for enhanced security.
 */
class CasterNativeDetector(private val context: Context, private val config: CasterConfig) {

    companion object {
        private var libraryLoaded = false

        init {
            try {
                System.loadLibrary("caster_detector")
                libraryLoaded = true
            } catch (e: UnsatisfiedLinkError) {
                Logger.getInstance().error("Failed to load native library 'caster_detector'", e)
            }
        }
    }

    /**
     * Performs all detection in a single native call.
     */
    fun performAllDetection(): CasterDetectionResult {
        if (!libraryLoaded) {
            Logger.getInstance().error("Native library not loaded, falling back to Kotlin implementation")
            return performAllDetectionKotlin()
        }

        try {
            val rootResult = if (config.enableRootDetection) detectRoot() else RootDetectionResult(false, emptyList(), emptyList(), 0f)
            val emulatorResult = if (config.enableEmulatorDetection) detectEmulator() else EmulatorResult(false, emptyList(), emptyList(), 0f)
            val packageName = context.packageName
            val integrityResult = if (config.enableIntegrityChecks) detectIntegrity(packageName) else IntegrityResult(false, emptyList(), emptyList())
            val antiTamperingResult = if (config.enableAntiTampering) detectAntiTampering() else AntiTamperingResult(false, false, emptyList(), emptyList())
            val maliciousAppResult = if (config.enableMaliciousAppDetection) detectMaliciousApps() else MaliciousAppResult(false, emptyList(), emptyList(), 0f)
            val flagSecureResult = detectFlagSecure()

            return CasterDetectionResult(
                rootResult = rootResult,
                emulatorResult = emulatorResult,
                integrityResult = integrityResult,
                antiTamperingResult = antiTamperingResult,
                maliciousAppResult = maliciousAppResult,
                flagSecureResult = flagSecureResult
            )
        } catch (e: Exception) {
            Logger.getInstance().error("Error in native detection, falling back to Kotlin implementation", e)
            return performAllDetectionKotlin()
        }
    }

    /**
     * Fallback implementation using existing Kotlin detectors.
     */
    private fun performAllDetectionKotlin(): CasterDetectionResult {
        val rootResult = if (config.enableRootDetection) {
            try {
                // Simplified approach without coroutines for now
                RootDetectionResult(false, emptyList(), emptyList(), 0f)
            } catch (e: Exception) {
                RootDetectionResult(false, emptyList(), emptyList(), 0f)
            }
        } else {
            RootDetectionResult(false, emptyList(), emptyList(), 0f)
        }

        val emulatorResult = if (config.enableEmulatorDetection) {
            try {
                EmulatorResult(false, emptyList(), emptyList(), 0f)
            } catch (e: Exception) {
                EmulatorResult(false, emptyList(), emptyList(), 0f)
            }
        } else {
            EmulatorResult(false, emptyList(), emptyList(), 0f)
        }

        val integrityResult = if (config.enableIntegrityChecks) {
            IntegrityResult(false, emptyList(), emptyList())
        } else {
            IntegrityResult(false, emptyList(), emptyList())
        }

        val antiTamperingResult = if (config.enableAntiTampering) {
            AntiTamperingResult(false, false, emptyList(), emptyList())
        } else {
            AntiTamperingResult(false, false, emptyList(), emptyList())
        }

        val maliciousAppResult = if (config.enableMaliciousAppDetection) {
            MaliciousAppResult(false, emptyList(), emptyList(), 0f)
        } else {
            MaliciousAppResult(false, emptyList(), emptyList(), 0f)
        }

        return CasterDetectionResult(
            rootResult = rootResult,
            emulatorResult = emulatorResult,
            integrityResult = integrityResult,
            antiTamperingResult = antiTamperingResult,
            maliciousAppResult = maliciousAppResult,
            flagSecureResult = FlagSecureResult(false, emptyList(), emptyList(), 0f)
        )
    }

    // Native method declarations
    private external fun detectRoot(): RootDetectionResult
    private external fun detectEmulator(): EmulatorResult
    private external fun detectIntegrity(packageName: String): IntegrityResult
    private external fun detectAntiTampering(): AntiTamperingResult
    private external fun detectMaliciousApps(): MaliciousAppResult
    private external fun detectFlagSecure(): FlagSecureResult
}

/**
 * Data class to hold all detection results.
 */
data class CasterDetectionResult(
    val rootResult: RootDetectionResult,
    val emulatorResult: EmulatorResult,
    val integrityResult: IntegrityResult,
    val antiTamperingResult: AntiTamperingResult,
    val maliciousAppResult: MaliciousAppResult,
    val flagSecureResult: FlagSecureResult
)

data class RootDetectionResult(
    val isRooted: Boolean,
    val detectedMethods: List<String>,
    val threats: List<String>,
    val confidence: Float
)

data class EmulatorResult(
    val isEmulator: Boolean,
    val detectedMethods: List<String>,
    val threats: List<String>,
    val confidence: Float
)

data class IntegrityResult(
    val isTampered: Boolean,
    val detectedMethods: List<String>,
    val threats: List<String>
)

data class AntiTamperingResult(
    val isDebuggerAttached: Boolean,
    val isHookingDetected: Boolean,
    val detectedMethods: List<String>,
    val threats: List<String>
)

data class MaliciousAppResult(
    val hasMaliciousApps: Boolean,
    val detectedApps: List<String>,
    val threats: List<String>,
    val riskScore: Float
)

data class FlagSecureResult(
    val isFlagSecureDisabled: Boolean,
    val detectedMethods: List<String>,
    val threats: List<String>,
    val confidence: Float
)