package io.github.yoganataa.caster.core.detection.root

import android.content.Context
import io.github.yoganataa.caster.core.detection.root.detectors.*
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

/**
 * Interface yang harus diimplementasikan oleh semua kelas detektor root.
 * Dipindahkan ke top-level agar bisa diakses dari file lain.
 */
interface RootDetectorInterface {
    suspend fun detect(): RootDetectionResult
}

/**
 * Data class untuk hasil deteksi root.
 * Dipindahkan ke top-level agar bisa diakses dari file lain.
 */
data class RootDetectionResult(
    val isRooted: Boolean,
    val detectedMethods: List<String>,
    val threats: List<ThreatInfo>,
    val confidence: Float
)

/**
 * Kelas utama yang mengorkestrasi semua detektor root.
 */
class RootDetector(private val context: Context) {
    private val logger = Logger.getInstance()

    // Sekarang semua kelas detektor akan cocok dengan tipe RootDetectorInterface
    private val detectors: List<RootDetectorInterface> = listOf(
        MagiskDetector(context),
        SuperSUDetector(context),
        KernelSUDetector(context),
        NativeRootDetector(context)
    )

    suspend fun detect(): RootDetectionResult = coroutineScope {
        logger.info("Starting comprehensive root detection")

        val results = detectors.map { detector ->
            async {
                try {
                    detector.detect()
                } catch (e: Exception) {
                    logger.error("Error in ${detector.javaClass.simpleName}", e)
                    // Membuat hasil default jika ada error pada salah satu detektor
                    RootDetectionResult(false, emptyList(), emptyList(), 0f)
                }
            }
        }.awaitAll()

        val allDetectedMethods = results.flatMap { it.detectedMethods }.distinct()
        val allThreats = results.flatMap { it.threats }
        val isRooted = results.any { it.isRooted }

        // Menghitung rata-rata confidence hanya dari detektor yang memberikan hasil positif
        val positiveConfidenceScores = results.filter { it.confidence > 0 }.map { it.confidence }
        val averageConfidence = if (positiveConfidenceScores.isNotEmpty()) {
            positiveConfidenceScores.average().toFloat()
        } else {
            0f
        }

        logger.info("Root detection complete. Rooted: $isRooted, Methods: ${allDetectedMethods.size}, Confidence: $averageConfidence")

        RootDetectionResult(
            isRooted = isRooted,
            detectedMethods = allDetectedMethods,
            threats = allThreats,
            confidence = averageConfidence
        )
    }
}