package io.github.yoganataa.caster.detection

import android.content.Context
import io.github.yoganataa.caster.CasterConfig
import io.github.yoganataa.caster.logging.Logger
import java.util.Collections

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
            Logger.getInstance().error("Native library not loaded, falling back to default implementation")
            return createDefaultResult()
        }

        try {
            val rootResult = if (config.enableRootDetection) detectRoot() else createDefaultRootResult()
            val emulatorResult = if (config.enableEmulatorDetection) detectEmulator() else createDefaultEmulatorResult()
            val packageName = context.packageName
            val integrityResult = if (config.enableIntegrityChecks) detectIntegrity(packageName) else createDefaultIntegrityResult()
            val antiTamperingResult = if (config.enableAntiTampering) detectAntiTampering() else createDefaultAntiTamperingResult()
            val maliciousAppResult = if (config.enableMaliciousAppDetection) detectMaliciousApps() else createDefaultMaliciousAppResult()
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
            Logger.getInstance().error("Error in native detection, falling back to default implementation", e)
            return createDefaultResult()
        }
    }

    /**
     * Create default result when native detection is not available.
     */
    private fun createDefaultResult(): CasterDetectionResult {
        return CasterDetectionResult(
            rootResult = createDefaultRootResult(),
            emulatorResult = createDefaultEmulatorResult(),
            integrityResult = createDefaultIntegrityResult(),
            antiTamperingResult = createDefaultAntiTamperingResult(),
            maliciousAppResult = createDefaultMaliciousAppResult(),
            flagSecureResult = createDefaultFlagSecureResult()
        )
    }

    private fun createDefaultRootResult(): RootDetectionResult {
        return RootDetectionResult(false, Collections.emptyList(), 0f)
    }

    private fun createDefaultEmulatorResult(): EmulatorResult {
        return EmulatorResult(false, Collections.emptyList(), 0f)
    }

    private fun createDefaultIntegrityResult(): IntegrityResult {
        return IntegrityResult(false, Collections.emptyList())
    }

    private fun createDefaultAntiTamperingResult(): AntiTamperingResult {
        return AntiTamperingResult(false, false, Collections.emptyList())
    }

    private fun createDefaultMaliciousAppResult(): MaliciousAppResult {
        return MaliciousAppResult(false, Collections.emptyList(), 0f)
    }

    private fun createDefaultFlagSecureResult(): FlagSecureResult {
        return FlagSecureResult(false, Collections.emptyList(), 0f)
    }

    // Native method declarations with full package name in JNI function signatures
    private external fun detectRoot(): RootDetectionResult
    private external fun detectEmulator(): EmulatorResult
    private external fun detectIntegrity(packageName: String): IntegrityResult
    private external fun detectAntiTampering(): AntiTamperingResult
    private external fun detectMaliciousApps(): MaliciousAppResult
    private external fun detectFlagSecure(): FlagSecureResult
}