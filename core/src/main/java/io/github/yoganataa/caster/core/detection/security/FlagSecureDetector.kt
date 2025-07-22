package io.github.yoganataa.caster.core.detection.security

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.view.View
import android.view.WindowManager
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.lsposed.hiddenapibypass.HiddenApiBypass
import org.lsposed.lsparanoid.Obfuscate
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

/**
 * Detector for identifying bypasses of `WindowManager.LayoutParams.FLAG_SECURE`.
 *
 * This class attempts to detect if screen content protected by `FLAG_SECURE` can be captured
 * or bypassed using various techniques, including hidden API calls and virtual display creation.
 *
 * @param activity The current [Activity] context, required for accessing window and display services.
 */
@Obfuscate
class FlagSecureDetector(
    private val activity: Activity
) {

    private val logger = Logger.getInstance()

    companion object {
        private const val DETECTION_TIMEOUT_MS = 3000L
        private const val VIRTUAL_DISPLAY_SIZE = 10

        init {
            // Attempt to set Hidden API exemptions for Android P and above.
            // This is necessary for some detection methods that rely on internal APIs.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                kotlin.runCatching {
                    HiddenApiBypass.setHiddenApiExemptions("")
                }.onFailure {
                    Logger.getInstance().error("Failed to set Hidden API exemptions", it)
                }
            }
        }
    }

    /**
     * Represents the result of the FLAG_SECURE bypass detection.
     *
     * @property isFlagSecureDisabled True if a FLAG_SECURE bypass is detected, false otherwise.
     * @property detectionMethods A list of strings indicating the specific methods or signs that led to the detection.
     * @property threats A list of [ThreatInfo] objects, providing detailed threat information.
     * @property confidence A float value (0.0 to 1.0) indicating the confidence level of the detection.
     */
    data class FlagSecureResult(
        val isFlagSecureDisabled: Boolean,
        val detectionMethods: List<String>,
        val threats: List<ThreatInfo>,
        val confidence: Float
    )

    /**
     * Performs detection for `FLAG_SECURE` bypasses.
     *
     * This method attempts to capture the screen content using hidden APIs and virtual displays.
     * If successful, it indicates a potential bypass of `FLAG_SECURE`.
     *
     * @return A [FlagSecureResult] object indicating whether a bypass was detected.
     */
    suspend fun detectFlagSecureBypass(): FlagSecureResult = withContext(Dispatchers.Main) {
        val detectedMethods = mutableListOf<String>()
        val threats = mutableListOf<ThreatInfo>()

        logger.debug("Starting advanced FLAG_SECURE bypass detection...")

        // Attempt detection using hidden APIs (e.g., SurfaceControl.captureLayers)
        if (detectWithHiddenAPIs()) {
            val sign = "Hidden API Surface Capture"
            detectedMethods.add(sign)
            threats.add(ThreatInfo(
                type = ThreatType.FLAG_SECURE_BYPASS,
                severity = "CRITICAL",
                description = "Surface layer capture bypassed FLAG_SECURE",
                details = mapOf("method" to "ScreenCapture/SurfaceControl.captureLayers")
            ))
        }

        // If no bypass detected yet, attempt detection using virtual display creation
        if (detectedMethods.isEmpty() && detectWithVirtualDisplay()) {
            val sign = "Virtual Display Capture"
            detectedMethods.add(sign)
            threats.add(ThreatInfo(
                type = ThreatType.FLAG_SECURE_BYPASS,
                severity = "CRITICAL",
                description = "Virtual display successfully captured secure content",
                details = mapOf("method" to "DisplayManager.createVirtualDisplay")
            ))
        }

        val isBypassed = detectedMethods.isNotEmpty()
        val confidence = if (isBypassed) 1.0f else 0.0f

        if (isBypassed) {
            logger.warn("FLAG_SECURE bypass detected with confidence: $confidence")
        }

        FlagSecureResult(
            isFlagSecureDisabled = isBypassed,
            detectionMethods = detectedMethods.distinct(),
            threats = threats,
            confidence = confidence
        )
    }

    /**
     * Attempts to detect FLAG_SECURE bypass using hidden Android APIs.
     *
     * This method leverages reflection and `HiddenApiBypass` to call internal system methods
     * that might allow capturing protected screen content.
     *
     * @return True if the hidden API capture is successful, false otherwise.
     */
    @SuppressLint("PrivateApi")
    private fun detectWithHiddenAPIs(): Boolean {
        return try {
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> {
                    val viewRootImpl = HiddenApiBypass.invoke(activity.window.decorView::class.java, activity.window.decorView, "getViewRootImpl")
                    val surfaceControl = HiddenApiBypass.invoke(viewRootImpl::class.java, viewRootImpl, "getSurfaceControl")
                    val builderClass = Class.forName("android.window.ScreenCapture\$LayerCaptureArgs\$Builder")
                    val builderConstructor = builderClass.getConstructor(Class.forName("android.view.SurfaceControl"))
                    val builder = builderConstructor.newInstance(surfaceControl)
                    builderClass.getMethod("setUid", Long::class.javaPrimitiveType).invoke(builder, Process.myUid().toLong())
                    val captureArgs = builderClass.getMethod("build").invoke(builder)
                    val screenCaptureClass = Class.forName("android.window.ScreenCapture")
                    val buffer = HiddenApiBypass.invoke(screenCaptureClass, null, "captureLayers", captureArgs)
                    buffer != null
                }
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
                    val viewRootImpl = HiddenApiBypass.invoke(activity.window.decorView::class.java, activity.window.decorView, "getViewRootImpl")
                    val surfaceControl = HiddenApiBypass.invoke(viewRootImpl::class.java, viewRootImpl, "getSurfaceControl")
                    val builderClass = Class.forName("android.view.SurfaceControl\$LayerCaptureArgs\$Builder")
                    val builderConstructor = builderClass.getConstructor(Class.forName("android.view.SurfaceControl"))
                    val builder = builderConstructor.newInstance(surfaceControl)
                    builderClass.getMethod("setUid", Long::class.javaPrimitiveType).invoke(builder, Process.myUid().toLong())
                    val captureArgs = builderClass.getMethod("build").invoke(builder)
                    val surfaceControlClass = Class.forName("android.view.SurfaceControl")
                    val buffer = HiddenApiBypass.invoke(surfaceControlClass, null, "captureLayers", captureArgs)
                    buffer != null
                }
                else -> false
            }
        } catch (e: Exception) {
            if (e !is InvocationTargetException) {
                logger.error("Hidden API detection error", e)
            }
            false
        }
    }

    /**
     * Attempts to detect FLAG_SECURE bypass by creating a virtual display and capturing its content.
     *
     * If a virtual display can successfully capture content from a secure window, it indicates
     * a potential bypass.
     *
     * @return True if the virtual display capture is successful, false otherwise.
     */
    @SuppressLint("WrongConstant")
    private suspend fun detectWithVirtualDisplay(): Boolean = suspendCancellableCoroutine { continuation ->
        // Using AtomicBoolean to prevent race conditions.
        // This ensures `continuation.resume` is called only once, either by the listener or by the timeout,
        // whichever comes first, preventing crashes.
        val continuationResumed = AtomicBoolean(false)

        val handler = Handler(Looper.getMainLooper())
        var virtualDisplay: VirtualDisplay? = null
        var imageReader: ImageReader? = null
        var windowManager: WindowManager? = null
        var testView: View? = null
        val displayManager = activity.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager

        val cleanupAndResume: (Boolean) -> Unit = { result ->
            if (continuationResumed.compareAndSet(false, true)) {
                handler.removeCallbacksAndMessages(null)
                kotlin.runCatching { testView?.let { windowManager?.removeViewImmediate(it) } }
                kotlin.runCatching { virtualDisplay?.release() }
                kotlin.runCatching { imageReader?.close() }
                logger.debug("Virtual Display resources cleaned up, resuming with: $result")
                if (continuation.isActive) {
                    continuation.resume(result)
                }
            }
        }

        val timeoutRunnable = Runnable {
            logger.debug("Virtual Display test timed out.")
            cleanupAndResume(false)
        }

        try {
            imageReader = ImageReader.newInstance(VIRTUAL_DISPLAY_SIZE, VIRTUAL_DISPLAY_SIZE, PixelFormat.RGBA_8888, 1)
            val reader = imageReader!!

            reader.setOnImageAvailableListener({ imgReader ->
                imgReader.acquireLatestImage()?.use { image ->
                    val bitmap = Bitmap.createBitmap(VIRTUAL_DISPLAY_SIZE, VIRTUAL_DISPLAY_SIZE, Bitmap.Config.ARGB_8888)
                    bitmap.copyPixelsFromBuffer(image.planes[0].buffer)
                    if (bitmap.getPixel(0, 0) == Color.RED) {
                        logger.warn("Virtual Display captured FLAG_SECURE content - bypass detected!")
                        cleanupAndResume(true)
                    }
                }
            }, handler)

            virtualDisplay = displayManager.createVirtualDisplay("CasterVD", VIRTUAL_DISPLAY_SIZE, VIRTUAL_DISPLAY_SIZE, 1, reader.surface, 0)
            val vdContext = activity.createDisplayContext(virtualDisplay!!.display)
            windowManager = vdContext.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            testView = View(vdContext).apply { setBackgroundColor(Color.RED) }
            val layoutParams = WindowManager.LayoutParams(VIRTUAL_DISPLAY_SIZE, VIRTUAL_DISPLAY_SIZE, WindowManager.LayoutParams.TYPE_PRIVATE_PRESENTATION, WindowManager.LayoutParams.FLAG_SECURE, PixelFormat.RGBA_8888)
            windowManager.addView(testView, layoutParams)
            handler.postDelayed(timeoutRunnable, DETECTION_TIMEOUT_MS)
        } catch (e: Exception) {
            logger.error("Virtual display detection setup failed", e)
            cleanupAndResume(false)
        }
        continuation.invokeOnCancellation { cleanupAndResume(false) }
    }
}