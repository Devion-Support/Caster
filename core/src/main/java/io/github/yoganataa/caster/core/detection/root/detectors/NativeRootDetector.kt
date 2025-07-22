package io.github.yoganataa.caster.core.detection.root.detectors

import android.content.Context
import io.github.yoganataa.caster.core.detection.root.RootDetectionResult
import io.github.yoganataa.caster.core.detection.root.RootDetectorInterface
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import org.lsposed.lsparanoid.Obfuscate

/**
 * Detector for native root detection methods.
 *
 * This class leverages native code (JNI) to perform checks that are harder to bypass
 * from user-space, such as checking for `su` binaries and Magisk Unix Domain Socket.
 *
 * @param context The application context.
 */
@Obfuscate
class NativeRootDetector(private val context: Context) : RootDetectorInterface {
    private val logger = Logger.getInstance()

    companion object {
        private var libraryLoaded = false
        // Common paths for 'su' and 'busybox' binaries.
        private val suPaths = arrayOf(
            "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su"
        )

        init {
            try {
                // Load the native 'toolChecker' library as defined in CMakeLists.txt.
                System.loadLibrary("toolChecker")
                libraryLoaded = true
            } catch (e: UnsatisfiedLinkError) {
                Logger.getInstance().error("Failed to load native library 'toolChecker'", e)
            }
        }
    }

    // Native function declarations corresponding to the custom toolChecker.cpp.
    private external fun checkForRoot(paths: Array<String>): Int
    private external fun checkForMagiskUDS(): Int
    private external fun setLogDebugMessages(enable: Boolean): Int

    /**
     * Performs native root detection checks.
     *
     * This method checks for:
     * - The presence of `su` binaries in common paths.
     * - The existence of Magisk Unix Domain Socket.
     *
     * @return A [RootDetectionResult] indicating whether root is detected via native methods.
     */
    override suspend fun detect(): RootDetectionResult {
        if (!libraryLoaded) {
            logger.warn("Native library not loaded, skipping native root detection.")
            return RootDetectionResult(false, emptyList(), emptyList(), 0f)
        }

        val detectedMethods = mutableListOf<String>()
        val threats = mutableListOf<ThreatInfo>()

        try {
            // Enable logging from C++ if needed.
            setLogDebugMessages(true)

            // 1. Check for 'su' binaries using predefined paths.
            if (checkForRoot(suPaths) == 1) {
                val sign = "Native check found 'su' binary in common paths"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = sign,
                    severity = "HIGH"
                ))
            }

            // 2. Check for Magisk Unix Domain Socket.
            if (checkForMagiskUDS() == 1) {
                val sign = "Native check detected Magisk Unix Domain Socket"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = sign,
                    severity = "CRITICAL",
                    details = mapOf("method" to "MagiskUDS")
                ))
            }

        } catch (e: Exception) {
            logger.error("Error during native root detection", e)
        }

        val confidence = calculateConfidence(detectedMethods.size)
        return RootDetectionResult(
            isRooted = detectedMethods.isNotEmpty(),
            detectedMethods = detectedMethods,
            threats = threats,
            confidence = confidence
        )
    }

    /**
     * Calculates the confidence score based on the number of native root detection methods triggered.
     *
     * @param detectionCount The number of native detection methods that returned true.
     * @return A float value (0.0 to 1.0) representing the confidence score.
     */
    private fun calculateConfidence(detectionCount: Int): Float {
        // Confidence score adjusted for the new detection methods.
        return when (detectionCount) {
            0 -> 0f
            1 -> 0.7f // One detected method is already quite strong.
            else -> 1.0f // More than one is very convincing.
        }
    }
}