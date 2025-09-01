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
import kotlin.collections.emptyList

class Caster internal constructor(
    private val config: CasterConfig
) {
    private val logger: Logger = Logger.getInstance()

    init {
        logger.info("Caster initialized.")
        Logger.configure(config.logEndpoint, config.minLogLevel)
    }

    suspend fun analyze(activity: Activity): CasterResult {
        logger.info("Starting comprehensive security analysis...")
        val result: CasterResult
        val analysisTime = measureTimeMillis {
            result = if (config.enableParallelDetection) {
                analyzeParallel(activity)
            } else {
                analyzeSequential(activity)
            }
        }
        logger.info("Security analysis completed in ${analysisTime}ms")
        return result.copy(analysisTimeMs = analysisTime)
    }

    private suspend fun analyzeParallel(activity: Activity): CasterResult = coroutineScope {
        // Use native implementation instead of parallel detection
        analyzeSequential(activity)
    }

    private suspend fun analyzeSequential(activity: Activity): CasterResult {
        // Use native implementation instead of sequential detection
        val appContext = activity.applicationContext
        val nativeDetector = CasterNativeDetector(appContext, config)
        val detectionResult = nativeDetector.performAllDetection()
        
        // Handle FlagSecure separately as it requires Activity context
        val flagSecureResult: CasterNativeDetector.FlagSecureResult = if (config.enableFlagSecureDetection) {
            try {
                // We'll implement a simple check here for now
                CasterNativeDetector.FlagSecureResult(
                    false, emptyList<String>(), emptyList<String>(), 0f
                )
            } catch (e: Exception) {
                CasterNativeDetector.FlagSecureResult(
                    false, emptyList<String>(), emptyList<String>(), 0f
                )
            }
        } else {
            CasterNativeDetector.FlagSecureResult(
                false, emptyList<String>(), emptyList<String>(), 0f
            )
        }
        
        return createFinalResult(
            detectionResult.rootResult,
            detectionResult.emulatorResult,
            flagSecureResult,
            detectionResult.maliciousAppResult,
            detectionResult.integrityResult,
            detectionResult.antiTamperingResult,
            appContext
        )
    }

    private fun createFinalResult(
        coreRootResult: CasterNativeDetector.RootDetectionResult,
        coreEmulatorResult: CasterNativeDetector.EmulatorResult,
        coreFlagSecureResult: CasterNativeDetector.FlagSecureResult,
        coreMaliciousAppResult: CasterNativeDetector.MaliciousAppResult,
        coreIntegrityResult: CasterNativeDetector.IntegrityResult,
        coreTamperingResult: CasterNativeDetector.AntiTamperingResult,
        context: Context
    ): CasterResult {
        val securityReport = createSecurityReport(
            coreRootResult,
            coreEmulatorResult,
            coreFlagSecureResult,
            coreMaliciousAppResult,
            coreIntegrityResult,
            coreTamperingResult,
            context
        )

        return CasterResult(
            rootResult = CoreRootResult(
                coreRootResult.isRooted, 
                coreRootResult.detectedMethods, 
                coreRootResult.confidence
            ),
            emulatorResult = CoreEmulatorResult(
                coreEmulatorResult.isEmulator, 
                coreEmulatorResult.detectedMethods, 
                coreEmulatorResult.confidence
            ),
            flagSecureResult = CoreFlagSecureResult(
                coreFlagSecureResult.isFlagSecureDisabled, 
                coreFlagSecureResult.detectedMethods, 
                coreFlagSecureResult.confidence
            ),
            maliciousAppsResult = MaliciousAppsResult(
                hasMaliciousApps = coreMaliciousAppResult.hasMaliciousApps,
                detectedApps = coreMaliciousAppResult.detectedApps.map {
                    MaliciousAppInfo(it, "", "", "")
                },
                riskScore = coreMaliciousAppResult.riskScore
            ),
            integrityResult = CoreIntegrityResult(
                coreIntegrityResult.isTampered, 
                coreIntegrityResult.threats
            ),
            tamperingResult = TamperingResult(
                isDebuggerAttached = coreTamperingResult.isDebuggerAttached,
                isHookingDetected = coreTamperingResult.isHookingDetected,
                isFridaServerRunning = false,
                detectedMethods = coreTamperingResult.detectedMethods
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
        tamperingResult: CasterNativeDetector.AntiTamperingResult,
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
                isTampered = integrityResult.isTampered || tamperingResult.isHookingDetected,
                isDebuggerAttached = tamperingResult.isDebuggerAttached,
                riskLevel = riskLevel
            ),
            detectedThreats = allThreats,
            appPackage = context.packageName
        )
    }

    private fun createDefaultCoreRootResult() = CasterNativeDetector.RootDetectionResult(false, emptyList(), emptyList(), 0f)
    private fun createDefaultCoreEmulatorResult() = CasterNativeDetector.EmulatorResult(false, emptyList(), emptyList(), 0f)
    private fun createDefaultCoreFlagSecureResult() = CasterNativeDetector.FlagSecureResult(false, emptyList(), emptyList(), 0f)
    private fun createDefaultCoreMaliciousAppResult() = CasterNativeDetector.MaliciousAppResult(false, emptyList(), emptyList(), 0f)
    private fun createDefaultCoreIntegrityResult() = CasterNativeDetector.IntegrityResult(false, emptyList(), emptyList())
    private fun createDefaultCoreTamperingResult() = CasterNativeDetector.AntiTamperingResult(false, false, emptyList(), emptyList())

    private fun getDeviceInfo(): DeviceInfo = DeviceInfo(
        model = android.os.Build.MODEL,
        manufacturer = android.os.Build.MANUFACTURER,
        androidVersion = android.os.Build.VERSION.RELEASE,
        apiLevel = android.os.Build.VERSION.SDK_INT,
        kernelVersion = SystemUtils.getKernelVersion()
    )

    companion object {
        @Volatile
        private var instance: Caster? = null

        fun getInstance(): Caster {
            return instance ?: throw IllegalStateException("Caster has not been initialized. Call Caster.Builder(context).build() in your Application class.")
        }

        private fun initialize(caster: Caster) {
            synchronized(this) {
                if (this.instance == null) {
                    this.instance = caster
                } else {
                    Logger.getInstance().warn("Caster is already initialized. Ignoring subsequent initialization.")
                }
            }
        }
    }

    class Builder(private val context: Context) {
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
            val newInstance = Caster(config)
            initialize(newInstance)
        }
    }
}