package io.github.yoganataa.caster.detection

import android.content.Context
import io.github.yoganataa.caster.CasterConfig
import io.github.yoganataa.caster.logging.Logger

/**
 * Kotlin boundary for the native detection engine.
 *
 * JNI is intentionally limited to one synchronous call. Scheduling stays in Kotlin
 * so callers never have to manage native threads or callbacks.
 */
class CasterNativeDetector(
    private val context: Context,
    private val config: CasterConfig
) {

    companion object {
        private var libraryLoaded = false

        init {
            try {
                System.loadLibrary("caster_detector")
                libraryLoaded = true
            } catch (error: UnsatisfiedLinkError) {
                Logger.getInstance().error("Failed to load native library caster_detector", error)
            }
        }
    }

    fun performAllDetection(): CasterDetectionResult {
        if (!libraryLoaded) {
            Logger.getInstance().error("Native library is unavailable; returning safe defaults")
            return defaultResult()
        }

        return try {
            nativePerformAllDetection(context.packageName)
        } catch (error: Throwable) {
            Logger.getInstance().error("Native security scan failed; returning safe defaults", error)
            defaultResult()
        }
    }

    private fun defaultResult(): CasterDetectionResult = CasterDetectionResult(
        rootResult = RootDetectionResult(false, emptyList(), 0f),
        emulatorResult = EmulatorResult(false, emptyList(), 0f),
        integrityResult = IntegrityResult(false, emptyList()),
        antiTamperingResult = AntiTamperingResult(false, false, emptyList()),
        maliciousAppResult = MaliciousAppResult(false, emptyList(), 0f),
        flagSecureResult = FlagSecureResult(false, emptyList(), 0f)
    )

    private external fun nativePerformAllDetection(packageName: String): CasterDetectionResult
}