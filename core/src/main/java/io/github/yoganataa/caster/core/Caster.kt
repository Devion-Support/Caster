package io.github.yoganataa.caster.core

import android.app.Activity
import android.content.Context
import io.github.yoganataa.caster.core.detection.app.MaliciousAppDetector
import io.github.yoganataa.caster.core.detection.environment.EmulatorDetector
import io.github.yoganataa.caster.core.detection.root.RootDetector
import io.github.yoganataa.caster.core.detection.security.FlagSecureDetector
import io.github.yoganataa.caster.core.logging.*
import io.github.yoganataa.caster.core.models.*
import io.github.yoganataa.caster.core.utils.SystemUtils
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlin.system.measureTimeMillis
import io.github.yoganataa.caster.core.detection.app.MaliciousAppDetector.MaliciousAppResult as CoreMaliciousAppResult
import io.github.yoganataa.caster.core.detection.environment.EmulatorResult as CoreEmulatorResult
import io.github.yoganataa.caster.core.detection.root.RootDetectionResult as CoreRootResult
import io.github.yoganataa.caster.core.detection.security.FlagSecureDetector.FlagSecureResult as CoreFlagSecureResult

class Caster(
    // =================================================================
    // PERBAIKAN: Constructor tidak lagi menyimpan context.
    // PENJELASAN: Ini membuat Caster lebih fleksibel dan mencegah
    // potensi kebocoran memory jika context yang disimpan adalah
    // Activity Context.
    // =================================================================
    private val config: CasterConfig = CasterConfig()
) {
    private val logger: Logger = Logger.getInstance()

    init {
        logger.info("Caster initialized.")
        // Konfigurasi logger dipindahkan ke sini agar konsisten.
        Logger.configure(config.logEndpoint, config.minLogLevel)
    }

    // =================================================================
    // PERBAIKAN: Metode `analyze` sekarang wajib menerima `Activity`.
    // PENJELASAN: Ini adalah perbaikan paling penting. Memaksa pemanggil
    // untuk menyediakan Activity Context memastikan FlagSecureDetector
    // dapat bekerja dengan benar.
    // =================================================================
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

        // PENJELASAN: Detektor sekarang diinisialisasi di sini, bukan dengan `lazy`,
        // menggunakan context yang sesuai (`activity` atau `appContext`).
        val rootDetector = if (config.enableRootDetection) RootDetector(appContext) else null
        val emulatorDetector = if (config.enableEmulatorDetection) EmulatorDetector(appContext) else null
        val flagSecureDetector = if (config.enableFlagSecureDetection) FlagSecureDetector(activity) else null
        val maliciousAppDetector = if (config.enableMaliciousAppDetection) MaliciousAppDetector(appContext).apply {
            addCustomMaliciousApps(config.customMaliciousApps)
        } else null

        val rootJob = async { rootDetector?.detect() ?: createDefaultCoreRootResult() }
        val emulatorJob = async { emulatorDetector?.detect() ?: createDefaultCoreEmulatorResult() }
        val flagSecureJob = async { flagSecureDetector?.detectFlagSecureBypass() ?: createDefaultCoreFlagSecureResult() }
        val maliciousAppJob = async { maliciousAppDetector?.detectMaliciousApps() ?: createDefaultCoreMaliciousAppResult() }

        createFinalResult(
            rootJob.await(),
            emulatorJob.await(),
            flagSecureJob.await(),
            maliciousAppJob.await(),
            appContext
        )
    }

    private suspend fun analyzeSequential(activity: Activity): CasterResult {
        val appContext = activity.applicationContext

        val rootDetector = if (config.enableRootDetection) RootDetector(appContext) else null
        val emulatorDetector = if (config.enableEmulatorDetection) EmulatorDetector(appContext) else null
        val flagSecureDetector = if (config.enableFlagSecureDetection) FlagSecureDetector(activity) else null
        val maliciousAppDetector = if (config.enableMaliciousAppDetection) MaliciousAppDetector(appContext).apply {
            addCustomMaliciousApps(config.customMaliciousApps)
        } else null

        val rootResult = rootDetector?.detect() ?: createDefaultCoreRootResult()
        val emulatorResult = emulatorDetector?.detect() ?: createDefaultCoreEmulatorResult()
        val flagSecureResult = flagSecureDetector?.detectFlagSecureBypass() ?: createDefaultCoreFlagSecureResult()
        val maliciousAppsResult = maliciousAppDetector?.detectMaliciousApps() ?: createDefaultCoreMaliciousAppResult()

        return createFinalResult(rootResult, emulatorResult, flagSecureResult, maliciousAppsResult, appContext)
    }

    private fun createFinalResult(
        coreRootResult: CoreRootResult,
        coreEmulatorResult: CoreEmulatorResult,
        coreFlagSecureResult: CoreFlagSecureResult,
        coreMaliciousAppResult: CoreMaliciousAppResult,
        context: Context
    ): CasterResult {
        val securityReport = createSecurityReport(coreRootResult, coreEmulatorResult, coreFlagSecureResult, coreMaliciousAppResult, context)

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
            securityReport = securityReport
        )
    }

    private fun createSecurityReport(
        rootResult: CoreRootResult,
        emulatorResult: CoreEmulatorResult,
        flagSecureResult: CoreFlagSecureResult,
        maliciousAppsResult: CoreMaliciousAppResult,
        context: Context
    ): SecurityReport {
        val allThreats = rootResult.threats + emulatorResult.threats + flagSecureResult.threats + maliciousAppsResult.threats
        val riskLevel = allThreats.map {
            when (it.severity.uppercase()) {
                "CRITICAL" -> RiskLevel.CRITICAL
                "HIGH" -> RiskLevel.HIGH
                "MEDIUM" -> RiskLevel.MEDIUM
                else -> RiskLevel.LOW
            }
        }.maxOrNull() ?: RiskLevel.LOW

        return SecurityReport(
            timestamp = System.currentTimeMillis(),
            deviceInfo = getDeviceInfo(),
            securityStatus = SecurityStatus(
                isRooted = rootResult.isRooted,
                isEmulator = emulatorResult.isEmulator,
                flagSecureDisabled = flagSecureResult.isFlagSecureDisabled,
                maliciousAppsDetected = maliciousAppsResult.hasMaliciousApps,
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

    private fun getDeviceInfo(): DeviceInfo = DeviceInfo(
        model = android.os.Build.MODEL,
        manufacturer = android.os.Build.MANUFACTURER,
        androidVersion = android.os.Build.VERSION.RELEASE,
        apiLevel = android.os.Build.VERSION.SDK_INT,
        kernelVersion = SystemUtils.getKernelVersion()
    )
}