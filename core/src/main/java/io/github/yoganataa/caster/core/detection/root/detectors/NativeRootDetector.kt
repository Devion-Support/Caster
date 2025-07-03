package io.github.yoganataa.caster.core.detection.root.detectors

import android.content.Context
import io.github.yoganataa.caster.core.detection.root.RootDetectionResult
import io.github.yoganataa.caster.core.detection.root.RootDetectorInterface
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import org.lsposed.lsparanoid.Obfuscate

/**
 * PERBAIKAN: Kelas ini di-refactor untuk menggunakan fungsi native dari referensi 'RootBeerFresh'.
 */
@Obfuscate
class NativeRootDetector(private val context: Context) : RootDetectorInterface {
    private val logger = Logger.getInstance()

    companion object {
        private var libraryLoaded = false
        // Daftar path yang umum digunakan untuk biner 'su' dan 'busybox'
        private val suPaths = arrayOf(
            "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su"
        )

        init {
            try {
                // Memuat library native 'toolChecker' sesuai CMakeLists.txt
                System.loadLibrary("toolChecker")
                libraryLoaded = true
            } catch (e: UnsatisfiedLinkError) {
                Logger.getInstance().error("Failed to load native library 'toolChecker'", e)
            }
        }
    }

    // Deklarasi fungsi native yang sesuai dengan toolChecker.cpp yang sudah disesuaikan
    private external fun checkForRoot(paths: Array<String>): Int
    private external fun checkForMagiskUDS(): Int
    private external fun setLogDebugMessages(enable: Boolean): Int

    override suspend fun detect(): RootDetectionResult {
        if (!libraryLoaded) {
            logger.warn("Native library not loaded, skipping native root detection.")
            return RootDetectionResult(false, emptyList(), emptyList(), 0f)
        }

        val detectedMethods = mutableListOf<String>()
        val threats = mutableListOf<ThreatInfo>()

        try {
            // Mengaktifkan log dari C++ jika perlu
            setLogDebugMessages(true)

            // 1. Memeriksa biner 'su' menggunakan path yang sudah ditentukan
            if (checkForRoot(suPaths) == 1) {
                val sign = "Native check found 'su' binary in common paths"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = sign,
                    severity = "HIGH"
                ))
            }

            // 2. Memeriksa Magisk Unix Domain Socket
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

    private fun calculateConfidence(detectionCount: Int): Float {
        // Skor confidence disesuaikan dengan metode deteksi yang baru
        return when (detectionCount) {
            0 -> 0f
            1 -> 0.7f // Satu metode terdeteksi sudah cukup kuat
            else -> 1.0f // Lebih dari satu sangat meyakinkan
        }
    }
}