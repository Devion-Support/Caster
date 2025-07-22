package io.github.yoganataa.caster.core.detection.root

import android.content.Context
import io.github.yoganataa.caster.core.detection.root.detectors.*
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

/**
 * Interface that all root detector classes must implement.
 */
interface RootDetectorInterface {
    /**
     * Performs the root detection and returns the result.
     * @return A [RootDetectionResult] indicating whether root is detected and by which methods.
     */
    suspend fun detect(): RootDetectionResult
}

/**
 * Data class representing the result of a root detection.
 *
 * @property isRooted True if root is detected, false otherwise.
 * @property detectedMethods A list of strings indicating the specific methods or signs that led to the detection.
 * @property threats A list of [ThreatInfo] objects, providing detailed threat information.
 * @property confidence A float value (0.0 to 1.0) indicating the confidence level of the detection.
 */
data class RootDetectionResult(
    val isRooted: Boolean,
    val detectedMethods: List<String>,
    val threats: List<ThreatInfo>,
    val confidence: Float
)

/**
 * Main class that orchestrates all root detectors.
 *
 * This class runs multiple root detection checks (e.g., Magisk, SuperSU, KernelSU, Native checks)
 * and aggregates their results to provide a comprehensive root detection outcome.
 *
 * @param context The application context.
 */
class RootDetector(private val context: Context) {
    private val logger = Logger.getInstance()

    // All detector classes now conform to the RootDetectorInterface type
    private val detectors: List<RootDetectorInterface> = listOf(
        MagiskDetector(context),
        SuperSUDetector(context),
        KernelSUDetector(context),
        NativeRootDetector(context)
    )

    /**
     * Performs a comprehensive root detection by running all configured detectors.
     *
     * This method executes each detector in parallel and aggregates their results.
     * The overall `isRooted` status is true if any detector reports root.
     * The confidence score is an average of positive confidence scores from individual detectors.
     *
     * @return A [RootDetectionResult] summarizing the root detection outcome.
     */
    suspend fun detect(): RootDetectionResult = coroutineScope {
        logger.info("Starting comprehensive root detection")

        val results = detectors.map { detector ->
            async {
                try {
                    detector.detect()
                } catch (e: Exception) {
                    logger.error("Error in ${detector.javaClass.simpleName}", e)
                    // Create a default result if there's an error in one of the detectors
                    RootDetectionResult(false, emptyList(), emptyList(), 0f)
                }
            }
        }.awaitAll()

        val allDetectedMethods = results.flatMap { it.detectedMethods }.distinct()
        val allThreats = results.flatMap { it.threats }
        val isRooted = results.any { it.isRooted }

        // Calculate average confidence only from detectors that provided a positive result
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