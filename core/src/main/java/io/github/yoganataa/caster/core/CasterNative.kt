package io.github.yoganataa.caster.core

import android.app.Activity
import android.content.Context
import io.github.yoganataa.caster.core.detection.CasterNativeDetector
import io.github.yoganataa.caster.core.logging.DeviceInfo
import io.github.yoganataa.caster.core.logging.LogLevel
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.RiskLevel
import io.github.yoganataa.caster.core.logging.SecurityReport
import io.github.yoganataa.caster.core.logging.SecurityStatus
import io.github.yoganataa.caster.core.models.CasterResult
import io.github.yoganataa.caster.core.models.EmulatorResult as CoreEmulatorResult
import io.github.yoganataa.caster.core.models.FlagSecureResult as CoreFlagSecureResult
import io.github.yoganataa.caster.core.models.IntegrityResult as CoreIntegrityResult
import io.github.yoganataa.caster.core.models.MaliciousAppInfo
import io.github.yoganataa.caster.core.models.MaliciousAppsResult
import io.github.yoganataa.caster.core.models.RootResult as CoreRootResult
import io.github.yoganataa.caster.core.models.TamperingResult
import io.github.yoganataa.caster.core.utils.SystemUtils
import kotlin.system.measureTimeMillis
import io.github.yoganataa.caster.core.CasterConfig

/**
 * Native implementation of the Caster security analysis library.
 * This version moves all detection logic to native C++ code for enhanced security.
 */
class CasterNative internal constructor(
    private val config: CasterConfig
) {
    private val logger: Logger = Logger.getInstance()

    init {
        logger.info("CasterNative initialized.")
        Logger.configure(config.logEndpoint, config.minLogLevel)
    }

    fun analyze(activity: Activity): CasterResult {
        logger.info("Starting comprehensive security analysis with native implementation...")
        val result: CasterResult
        val analysisTime = measureTimeMillis {
            result = analyzeNative(activity)
        }
        logger.info("Security analysis completed in ${analysisTime}ms")
        return result.copy(analysisTimeMs = analysisTime)
    }

    private fun analyzeNative(activity: Activity): CasterResult {
        val appContext = activity.applicationContext
        val nativeDetector = CasterNativeDetector(appContext, config)
        
        // Perform all detection in native code
        val detectionResult = nativeDetector.performAllDetection()
        
        // Handle FlagSecure separately as it requires Activity context and suspend functions
        val flagSecureResult: CasterNativeDetector.FlagSecureResult = if (config.enableFlagSecureDetection) {
            // For now, we'll return a default result since we can't easily call suspend functions here
            CasterNativeDetector.FlagSecureResult(
                false, emptyList<String>(), emptyList<String>(), 0f
            )
        } else {
            CasterNativeDetector.FlagSecureResult(
                false, emptyList<String>(), emptyList<String>(), 0f
            )
        }
        
        // Handle malicious app result
        val maliciousAppResult = detectionResult.maliciousAppResult
        
        val securityReport = createSecurityReport(
            detectionResult.rootResult,
            detectionResult.emulatorResult,
            flagSecureResult,
            maliciousAppResult,
            detectionResult.integrityResult,
            detectionResult.antiTamperingResult,
            appContext
        )

        return CasterResult(
            rootResult = CoreRootResult(
                detectionResult.rootResult.isRooted,
                detectionResult.rootResult.detectedMethods,
                detectionResult.rootResult.confidence
            ),
            emulatorResult = CoreEmulatorResult(
                detectionResult.emulatorResult.isEmulator,
                detectionResult.emulatorResult.detectedMethods,
                detectionResult.emulatorResult.confidence
            ),
            flagSecureResult = CoreFlagSecureResult(
                flagSecureResult.isFlagSecureDisabled,
                flagSecureResult.detectedMethods,
                flagSecureResult.confidence
            ),
            maliciousAppsResult = MaliciousAppsResult(
                hasMaliciousApps = maliciousAppResult.hasMaliciousApps,
                detectedApps = maliciousAppResult.detectedApps.map {
                    // Convert DetectedApp to MaliciousAppInfo
                    MaliciousAppInfo(
                        it, "", "", ""
                    )
                },
                riskScore = maliciousAppResult.riskScore
            ),
            integrityResult = CoreIntegrityResult(
                detectionResult.integrityResult.isTampered,
                detectionResult.integrityResult.threats
            ),
            tamperingResult = TamperingResult(
                isDebuggerAttached = detectionResult.antiTamperingResult.isDebuggerAttached,
                isHookingDetected = detectionResult.antiTamperingResult.isHookingDetected,
                isFridaServerRunning = false,
                detectedMethods = detectionResult.antiTamperingResult.detectedMethods
            ),
            securityReport = securityReport
        )
    }

    private fun createSecurityReport(
        rootResult: CasterNativeDetector.RootDetectionResult,
        emulatorResult: CasterNativeDetector.EmulatorResult,
        flagSecureResult: CasterNativeDetector.FlagSecureResult,
        maliciousAppsResult: CasterNativeDetector.MaliciousAppResult,
        integrityResult: CasterNativeDetector.IntegrityResult,
        antiTamperingResult: CasterNativeDetector.AntiTamperingResult,
        context: Context
    ): SecurityReport {
        // Create empty threat lists since our new data classes don't have them
        val allThreats = emptyList<io.github.yoganataa.caster.core.logging.ThreatInfo>()

        val riskLevel = RiskLevel.LOW

        return SecurityReport(
            timestamp = System.currentTimeMillis(),
            deviceInfo = getDeviceInfo(),
            securityStatus = SecurityStatus(
                isRooted = rootResult.isRooted,
                isEmulator = emulatorResult.isEmulator,
                flagSecureDisabled = flagSecureResult.isFlagSecureDisabled,
                maliciousAppsDetected = maliciousAppsResult.hasMaliciousApps,
                isTampered = integrityResult.isTampered || antiTamperingResult.isHookingDetected,
                isDebuggerAttached = antiTamperingResult.isDebuggerAttached,
                riskLevel = riskLevel
            ),
            detectedThreats = allThreats,
            appPackage = context.packageName
        )
    }

    private fun getDeviceInfo(): DeviceInfo = DeviceInfo(
        model = android.os.Build.MODEL,
        manufacturer = android.os.Build.MANUFACTURER,
        androidVersion = android.os.Build.VERSION.RELEASE,
        apiLevel = android.os.Build.VERSION.SDK_INT,
        kernelVersion = SystemUtils.getKernelVersion() ?: "Unknown"
    )

    companion object {
        @Volatile
        private var instance: CasterNative? = null

        fun getInstance(): CasterNative {
            return instance ?: throw IllegalStateException("CasterNative has not been initialized. Call CasterNative.Builder(context).build() in your Application class.")
        }

        private fun initialize(caster: CasterNative) {
            synchronized(this) {
                if (this.instance == null) {
                    this.instance = caster
                } else {
                    Logger.getInstance().warn("CasterNative is already initialized. Ignoring subsequent initialization.")
                }
            }
        }
    }

    class Builder {
        private var config = CasterConfig()

        fun setLogLevel(level: LogLevel): Builder {
            config = config.copy(minLogLevel = level)
            return this
        }

        fun setLogEndpoint(url: String?): Builder {
            config = config.copy(logEndpoint = url)
            return this
        }

        fun addCustomMaliciousApps(packageNames: Set<String>): Builder {
            config = config.copy(customMaliciousApps = config.customMaliciousApps + packageNames)
            return this
        }

        fun enableRootDetection(enable: Boolean): Builder {
            config = config.copy(enableRootDetection = enable)
            return this
        }

        fun enableEmulatorDetection(enable: Boolean): Builder {
            config = config.copy(enableEmulatorDetection = enable)
            return this
        }

        fun enableFlagSecureDetection(enable: Boolean): Builder {
            config = config.copy(enableFlagSecureDetection = enable)
            return this
        }

        fun enableMaliciousAppDetection(enable: Boolean): Builder {
            config = config.copy(enableMaliciousAppDetection = enable)
            return this
        }

        fun enableNativeChecks(enable: Boolean): Builder {
            config = config.copy(enableNativeChecks = enable)
            return this
        }

        fun enableIntegrityChecks(enable: Boolean): Builder {
            config = config.copy(enableIntegrityChecks = enable)
            return this
        }

        fun enableAntiTampering(enable: Boolean): Builder {
            config = config.copy(enableAntiTampering = enable)
            return this
        }

        fun enableLsDataDetection(enable: Boolean): Builder {
            config = config.copy(enableLsDataDetection = enable)
            return this
        }

        fun setDetectionTimeout(timeoutMs: Long): Builder {
            config = config.copy(detectionTimeoutMs = timeoutMs)
            return this
        }

        fun enableParallelDetection(enable: Boolean): Builder {
            config = config.copy(enableParallelDetection = enable)
            return this
        }

        fun addCustomHeaders(headers: Map<String, String>): Builder {
            config = config.copy(customHeaders = config.customHeaders + headers)
            return this
        }

        fun includeDeviceInfo(include: Boolean): Builder {
            config = config.copy(includeDeviceInfo = include)
            return this
        }

        fun includeAppInfo(include: Boolean): Builder {
            config = config.copy(includeAppInfo = include)
            return this
        }

        fun build() {
            val newInstance = CasterNative(config)
            initialize(newInstance)
        }
    }
}