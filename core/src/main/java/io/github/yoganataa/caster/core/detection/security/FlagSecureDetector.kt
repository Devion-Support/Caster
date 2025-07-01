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
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

class FlagSecureDetector(
    private val activity: Activity
) {

    private val logger = Logger.getInstance()

    companion object {
        private const val DETECTION_TIMEOUT_MS = 3000L
        private const val VIRTUAL_DISPLAY_SIZE = 10

        init {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                kotlin.runCatching {
                    HiddenApiBypass.setHiddenApiExemptions("")
                }.onFailure {
                    Logger.getInstance().error("Failed to set Hidden API exemptions", it)
                }
            }
        }
    }

    data class FlagSecureResult(
        val isFlagSecureDisabled: Boolean,
        val detectionMethods: List<String>,
        val threats: List<ThreatInfo>,
        val confidence: Float
    )

    suspend fun detectFlagSecureBypass(): FlagSecureResult = withContext(Dispatchers.Main) {
        val detectedMethods = mutableListOf<String>()
        val threats = mutableListOf<ThreatInfo>()

        logger.debug("Starting advanced FLAG_SECURE bypass detection...")

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

    @SuppressLint("WrongConstant")
    private suspend fun detectWithVirtualDisplay(): Boolean = suspendCancellableCoroutine { continuation ->
        // =================================================================
        // PERBAIKAN: Menggunakan AtomicBoolean untuk mencegah race condition.
        // PENJELASAN: Ini memastikan `continuation.resume` hanya dipanggil
        // satu kali, baik oleh listener maupun oleh timeout, mana saja
        // yang lebih dulu, sehingga mencegah crash.
        // =================================================================
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