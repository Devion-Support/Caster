package io.github.yoganataa.caster.core

import android.app.Activity
import android.content.Context
import io.github.yoganataa.caster.core.detection.app.MaliciousAppDetector
import io.github.yoganataa.caster.core.detection.environment.EmulatorDetector
import io.github.yoganataa.caster.core.detection.integrity.IntegrityDetector
import io.github.yoganataa.caster.core.detection.root.RootDetector
import io.github.yoganataa.caster.core.detection.root.detectors.LsDataDetector
import io.github.yoganataa.caster.core.detection.security.FlagSecureDetector
import io.github.yoganataa.caster.core.detection.tampering.AntiTamperingDetector
import io.github.yoganataa.caster.core.logging.DeviceInfo
import io.github.yoganataa.caster.core.logging.LogLevel
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.RiskLevel
import io.github.yoganataa.caster.core.logging.SecurityReport
import io.github.yoganataa.caster.core.logging.SecurityStatus
import io.github.yoganataa.caster.core.models.CasterResult
import io.github.yoganataa.caster.core.models.EmulatorResult
import io.github.yoganataa.caster.core.models.FlagSecureResult
import io.github.yoganataa.caster.core.models.IntegrityResult
import io.github.yoganataa.caster.core.models.MaliciousAppInfo
import io.github.yoganataa.caster.core.models.MaliciousAppsResult
import io.github.yoganataa.caster.core.models.RootResult
import io.github.yoganataa.caster.core.models.TamperingResult
import io.github.yoganataa.caster.core.utils.SystemUtils
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlin.system.measureTimeMillis
import io.github.yoganataa.caster.core.detection.app.MaliciousAppDetector.MaliciousAppResult as CoreMaliciousAppResult
import io.github.yoganataa.caster.core.detection.environment.EmulatorResult as CoreEmulatorResult
import io.github.yoganataa.caster.core.detection.integrity.IntegrityDetector.Result as CoreIntegrityResult
import io.github.yoganataa.caster.core.detection.root.RootDetectionResult as CoreRootResult
import io.github.yoganataa.caster.core.detection.security.FlagSecureDetector.FlagSecureResult as CoreFlagSecureResult
import io.github.yoganataa.caster.core.detection.tampering.AntiTamperingDetector.Result as CoreTamperingResult

class Caster internal constructor(
    private val config: CasterConfig,
    private val rootDetectorFactory: (Context) -> RootDetector = { RootDetector(it) },
    private val emulatorDetectorFactory: (Context) -> EmulatorDetector = { EmulatorDetector(it) },
    private val flagSecureDetectorFactory: (Activity) -> FlagSecureDetector = { FlagSecureDetector(it) },
    private val maliciousAppDetectorFactory: (Context, CasterConfig, (Context) -> LsDataDetector) -> MaliciousAppDetector = { context, config, lsDataDetectorFactory -> MaliciousAppDetector(context, config, lsDataDetectorFactory) },
    private val integrityDetectorFactory: (Context) -> IntegrityDetector = { IntegrityDetector(it) },
    private val antiTamperingDetectorFactory: () -> AntiTamperingDetector = { AntiTamperingDetector() }
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
        val appContext = activity.applicationContext
        val rootDetector = if (config.enableRootDetection) rootDetectorFactory(appContext) else null
        val emulatorDetector = if (config.enableEmulatorDetection) emulatorDetectorFactory(appContext) else null
        val flagSecureDetector = if (config.enableFlagSecureDetection) flagSecureDetectorFactory(activity) else null
        val maliciousAppDetector = if (config.enableMaliciousAppDetection) maliciousAppDetectorFactory(appContext, config, { LsDataDetector(it) }) else null
        val integrityDetector = if (config.enableIntegrityChecks) integrityDetectorFactory(appContext) else null
        val antiTamperingDetector = if (config.enableAntiTampering) antiTamperingDetectorFactory() else null

        val rootJob = async { rootDetector?.detect() ?: createDefaultCoreRootResult() }
        val emulatorJob = async { emulatorDetector?.detect() ?: createDefaultCoreEmulatorResult() }
        val flagSecureJob = async { flagSecureDetector?.detectFlagSecureBypass() ?: createDefaultCoreFlagSecureResult() }
        val maliciousAppJob = async { maliciousAppDetector?.detectMaliciousApps() ?: createDefaultCoreMaliciousAppResult() }
        val integrityJob = async { integrityDetector?.detect() ?: createDefaultCoreIntegrityResult() }
        val tamperingJob = async { antiTamperingDetector?.detect() ?: createDefaultCoreTamperingResult() }

        createFinalResult(
            rootJob.await(),
            emulatorJob.await(),
            flagSecureJob.await(),
            maliciousAppJob.await(),
            integrityJob.await(),
            tamperingJob.await(),
            appContext
        )
    }

    private suspend fun analyzeSequential(activity: Activity): CasterResult {
        val appContext = activity.applicationContext
        val rootDetector = if (config.enableRootDetection) rootDetectorFactory(appContext) else null
        val emulatorDetector = if (config.enableEmulatorDetection) emulatorDetectorFactory(appContext) else null
        val flagSecureDetector = if (config.enableFlagSecureDetection) flagSecureDetectorFactory(activity) else null
        val maliciousAppDetector = if (config.enableMaliciousAppDetection) maliciousAppDetectorFactory(appContext, config, { LsDataDetector(it) }) else null
        val integrityDetector = if (config.enableIntegrityChecks) integrityDetectorFactory(appContext) else null
        val antiTamperingDetector = if (config.enableAntiTampering) antiTamperingDetectorFactory() else null

        val rootResult = rootDetector?.detect() ?: createDefaultCoreRootResult()
        val emulatorResult = emulatorDetector?.detect() ?: createDefaultCoreEmulatorResult()
        val flagSecureResult = flagSecureDetector?.detectFlagSecureBypass() ?: createDefaultCoreFlagSecureResult()
        val maliciousAppsResult = maliciousAppDetector?.detectMaliciousApps() ?: createDefaultCoreMaliciousAppResult()
        val integrityResult = integrityDetector?.detect() ?: createDefaultCoreIntegrityResult()
        val tamperingResult = antiTamperingDetector?.detect() ?: createDefaultCoreTamperingResult()

        return createFinalResult(rootResult, emulatorResult, flagSecureResult, maliciousAppsResult, integrityResult, tamperingResult, appContext)
    }

    private fun createFinalResult(
        coreRootResult: CoreRootResult,
        coreEmulatorResult: CoreEmulatorResult,
        coreFlagSecureResult: CoreFlagSecureResult,
        coreMaliciousAppResult: CoreMaliciousAppResult,
        coreIntegrityResult: CoreIntegrityResult,
        coreTamperingResult: CoreTamperingResult,
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
            rootResult = RootResult(coreRootResult.isRooted, coreRootResult.detectedMethods, coreRootResult.confidence),
            emulatorResult = EmulatorResult(coreEmulatorResult.isEmulator, coreEmulatorResult.detectedMethods, coreEmulatorResult.confidence),
            flagSecureResult = FlagSecureResult(coreFlagSecureResult.isFlagSecureDisabled, coreFlagSecureResult.detectionMethods, coreFlagSecureResult.confidence),
            maliciousAppsResult = MaliciousAppsResult(
                hasMaliciousApps = coreMaliciousAppResult.hasMaliciousApps,
                detectedApps = coreMaliciousAppResult.detectedApps.map {
                    MaliciousAppInfo(it.packageName, it.appName, it.category, it.riskLevel)
                },
                riskScore = coreMaliciousAppResult.riskScore
            ),
            integrityResult = IntegrityResult(coreIntegrityResult.isTampered, coreIntegrityResult.detectedMethods),
            tamperingResult = TamperingResult(
                isDebuggerAttached = coreTamperingResult.isDebuggerAttached,
                isHookingDetected = coreTamperingResult.isHookingDetected,
                isFridaServerRunning = coreTamperingResult.detectedMethods.any { it.contains("Frida", true) },
                detectedMethods = coreTamperingResult.detectedMethods
            ),
            securityReport = securityReport
        )
    }

    private fun createSecurityReport(
        rootResult: CoreRootResult,
        emulatorResult: CoreEmulatorResult,
        flagSecureResult: CoreFlagSecureResult,
        maliciousAppsResult: CoreMaliciousAppResult,
        integrityResult: CoreIntegrityResult,
        tamperingResult: CoreTamperingResult,
        context: Context
    ): SecurityReport {
        val allThreats = rootResult.threats +
                emulatorResult.threats +
                flagSecureResult.threats +
                maliciousAppsResult.threats +
                integrityResult.threats +
                tamperingResult.threats

        val riskLevel = allThreats.fold(RiskLevel.LOW) { currentMax, threat ->
            val threatRisk = when (threat.severity.uppercase()) {
                "CRITICAL" -> RiskLevel.CRITICAL
                "HIGH" -> RiskLevel.HIGH
                "MEDIUM" -> RiskLevel.MEDIUM
                else -> RiskLevel.LOW
            }
            if (threatRisk.ordinal > currentMax.ordinal) threatRisk else currentMax
        }

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

    private fun createDefaultCoreRootResult() = CoreRootResult(false, emptyList(), emptyList(), 0f)
    private fun createDefaultCoreEmulatorResult() = CoreEmulatorResult(false, emptyList(), emptyList(), 0f)
    private fun createDefaultCoreFlagSecureResult() = CoreFlagSecureResult(false, emptyList(), emptyList(), 0f)
    private fun createDefaultCoreMaliciousAppResult() = CoreMaliciousAppResult(false, emptyList(), emptyList(), 0f)
    private fun createDefaultCoreIntegrityResult() = CoreIntegrityResult(false, emptyList(), emptyList())
    private fun createDefaultCoreTamperingResult() = CoreTamperingResult(false, false, emptyList(), emptyList())

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