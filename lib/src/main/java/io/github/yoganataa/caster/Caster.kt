package io.github.yoganataa.caster

import android.app.Activity
import android.content.Context
import android.view.WindowManager
import io.github.yoganataa.caster.detection.AntiTamperingResult
import io.github.yoganataa.caster.detection.CasterNativeDetector
import io.github.yoganataa.caster.detection.EmulatorResult
import io.github.yoganataa.caster.detection.FlagSecureResult
import io.github.yoganataa.caster.detection.IntegrityResult
import io.github.yoganataa.caster.detection.MaliciousAppResult
import io.github.yoganataa.caster.detection.RootDetectionResult
import io.github.yoganataa.caster.logging.DeviceInfo
import io.github.yoganataa.caster.logging.LogLevel
import io.github.yoganataa.caster.logging.Logger
import io.github.yoganataa.caster.logging.RiskLevel
import io.github.yoganataa.caster.logging.SecurityReport
import io.github.yoganataa.caster.logging.SecurityStatus
import io.github.yoganataa.caster.models.CasterResult
import io.github.yoganataa.caster.models.EmulatorResult as CoreEmulatorResult
import io.github.yoganataa.caster.models.FlagSecureResult as CoreFlagSecureResult
import io.github.yoganataa.caster.models.IntegrityResult as CoreIntegrityResult
import io.github.yoganataa.caster.models.MaliciousAppInfo
import io.github.yoganataa.caster.models.MaliciousAppsResult
import io.github.yoganataa.caster.models.RootResult as CoreRootResult
import io.github.yoganataa.caster.models.TamperingResult
import io.github.yoganataa.caster.protection.SecurityMonitor
import io.github.yoganataa.caster.utils.SystemUtils
import io.github.yoganataa.caster.network.SecureHttpClient
import io.github.yoganataa.caster.attestation.DeviceAttestation
import io.github.yoganataa.caster.security.SecureKeyStore
import io.github.yoganataa.caster.network.NetworkSecurityManager
import io.github.yoganataa.caster.privacy.PrivacyProtectionManager
import java.util.Collections
import kotlin.system.measureTimeMillis

class Caster internal constructor(
    private val config: CasterConfig
) {
    private val logger: Logger = Logger.getInstance()
    private val securityMonitor: SecurityMonitor = SecurityMonitor.getInstance(ContextHolder.getAppContext())
    private val secureHttpClient: SecureHttpClient? = if (config.logEndpoint != null) SecureHttpClient(config) else null

    init {
        logger.info("Caster initialized.")
        Logger.configure(config.logEndpoint, config.minLogLevel)
        securityMonitor.initialize(config)
    }

    fun analyze(activity: Activity): CasterResult {
        logger.info("Starting comprehensive security analysis...")
        val result: CasterResult
        val analysisTime = measureTimeMillis {
            result = analyzeSequential(activity)
        }
        logger.info("Security analysis completed in ${analysisTime}ms")
        
        // Send security report if endpoint is configured
        if (config.logEndpoint != null && secureHttpClient != null) {
            try {
                val reportJson = io.github.yoganataa.caster.utils.SecurityReportGenerator.generateJsonReport(result.securityReport)
                secureHttpClient.sendSecurityReport(reportJson)
            } catch (e: Exception) {
                logger.error("Failed to send security report", e)
            }
        }
        
        return result.copy(analysisTimeMs = analysisTime)
    }

    private fun analyzeSequential(activity: Activity): CasterResult {
        // Start security monitoring if enabled
        if (config.enableAntiTampering) {
            securityMonitor.startMonitoring()
        }
        
        val appContext = activity.applicationContext
        val nativeDetector = CasterNativeDetector(appContext, config)
        val detectionResult = nativeDetector.performAllDetection()

        // Handle FlagSecure separately as it requires Activity context
        val flagSecureResult: FlagSecureResult = if (config.enableFlagSecureDetection) {
            val windowFlags = activity.window.attributes.flags
            val isFlagSecureDisabled = (windowFlags and WindowManager.LayoutParams.FLAG_SECURE) == 0
            val methods = if (isFlagSecureDisabled) listOf("WINDOW_FLAGS_CHECK") else emptyList()
            FlagSecureResult(
                isFlagSecureDisabled = isFlagSecureDisabled,
                detectedMethods = methods,
                confidence = if (isFlagSecureDisabled) 1.0f else 0.0f
            )
        } else {
            // Return a default "not disabled" result if the check is disabled
            FlagSecureResult(false, emptyList(), 0f)
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
        coreRootResult: RootDetectionResult,
        coreEmulatorResult: EmulatorResult,
        coreFlagSecureResult: FlagSecureResult,
        coreMaliciousAppResult: MaliciousAppResult,
        coreIntegrityResult: IntegrityResult,
        coreTamperingResult: AntiTamperingResult,
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
                isRooted = coreRootResult.isRooted,
                detectedMethods = coreRootResult.detectedMethods,
                confidence = coreRootResult.confidence
            ),
            emulatorResult = CoreEmulatorResult(
                isEmulator = coreEmulatorResult.isEmulator,
                detectedMethods = coreEmulatorResult.detectedMethods,
                confidence = coreEmulatorResult.confidence
            ),
            flagSecureResult = CoreFlagSecureResult(
                isFlagSecureDisabled = coreFlagSecureResult.isFlagSecureDisabled,
                detectionMethods = coreFlagSecureResult.detectedMethods,
                confidence = coreFlagSecureResult.confidence
            ),
            maliciousAppsResult = MaliciousAppsResult(
                hasMaliciousApps = coreMaliciousAppResult.hasMaliciousApps,
                detectedApps = coreMaliciousAppResult.detectedApps.map {
                    MaliciousAppInfo(it, "", "", "")
                },
                riskScore = coreMaliciousAppResult.riskScore
            ),
            integrityResult = CoreIntegrityResult(
                isTampered = coreIntegrityResult.isTampered,
                threats = coreIntegrityResult.detectedMethods
            ),
            tamperingResult = TamperingResult(
                isDebuggerAttached = coreTamperingResult.isDebuggerAttached,
                isHookingDetected = coreTamperingResult.isHookingDetected,
                isFridaServerRunning = false, // Placeholder, can be improved later
                detectedMethods = coreTamperingResult.detectedMethods
            ),
            securityReport = securityReport
        )
    }

    private fun createSecurityReport(
        rootResult: RootDetectionResult,
        emulatorResult: EmulatorResult,
        flagSecureResult: FlagSecureResult,
        maliciousAppsResult: MaliciousAppResult,
        integrityResult: IntegrityResult,
        tamperingResult: AntiTamperingResult,
        context: Context
    ): SecurityReport {
        val threats = mutableListOf<io.github.yoganataa.caster.logging.ThreatInfo>()
        
        // Add root threats
        if (rootResult.isRooted) {
            threats.add(
                io.github.yoganataa.caster.logging.ThreatInfo(
                    type = io.github.yoganataa.caster.logging.ThreatType.ROOT_ACCESS,
                    description = "Device is rooted",
                    severity = if (rootResult.confidence > 0.8) 
                        io.github.yoganataa.caster.logging.ThreatSeverity.CRITICAL 
                    else if (rootResult.confidence > 0.5) 
                        io.github.yoganataa.caster.logging.ThreatSeverity.HIGH
                    else 
                        io.github.yoganataa.caster.logging.ThreatSeverity.MEDIUM,
                    confidence = rootResult.confidence,
                    detectionMethods = rootResult.detectedMethods,
                    recommendations = listOf(
                        "Unroot the device for maximum security",
                        "Use official firmware from device manufacturer",
                        "Avoid installing apps from unknown sources"
                    )
                )
            )
        }
        
        // Add emulator threats
        if (emulatorResult.isEmulator) {
            threats.add(
                io.github.yoganataa.caster.logging.ThreatInfo(
                    type = io.github.yoganataa.caster.logging.ThreatType.EMULATOR,
                    description = "Running in emulator",
                    severity = if (emulatorResult.confidence > 0.8) 
                        io.github.yoganataa.caster.logging.ThreatSeverity.HIGH
                    else 
                        io.github.yoganataa.caster.logging.ThreatSeverity.MEDIUM,
                    confidence = emulatorResult.confidence,
                    detectionMethods = emulatorResult.detectedMethods,
                    recommendations = listOf(
                        "Use a physical device for sensitive operations",
                        "Emulators are not recommended for production use"
                    )
                )
            )
        }
        
        // Add flag secure threats
        if (flagSecureResult.isFlagSecureDisabled) {
            threats.add(
                io.github.yoganataa.caster.logging.ThreatInfo(
                    type = io.github.yoganataa.caster.logging.ThreatType.FLAG_SECURE_BYPASS,
                    description = "Screen recording/screenshots are possible",
                    severity = io.github.yoganataa.caster.logging.ThreatSeverity.MEDIUM,
                    confidence = flagSecureResult.confidence,
                    detectionMethods = flagSecureResult.detectedMethods,
                    recommendations = listOf(
                        "Enable FLAG_SECURE in your application",
                        "Review screen protection settings",
                        "Monitor for unauthorized screen capture"
                    )
                )
            )
        }
        
        // Add malicious app threats
        if (maliciousAppsResult.hasMaliciousApps) {
            threats.add(
                io.github.yoganataa.caster.logging.ThreatInfo(
                    type = io.github.yoganataa.caster.logging.ThreatType.MALICIOUS_APP,
                    description = "Malicious apps detected",
                    severity = if (maliciousAppsResult.riskScore > 0.7) 
                        io.github.yoganataa.caster.logging.ThreatSeverity.CRITICAL
                    else if (maliciousAppsResult.riskScore > 0.4) 
                        io.github.yoganataa.caster.logging.ThreatSeverity.HIGH
                    else 
                        io.github.yoganataa.caster.logging.ThreatSeverity.MEDIUM,
                    confidence = maliciousAppsResult.riskScore,
                    detectionMethods = maliciousAppsResult.detectedApps,
                    recommendations = listOf(
                        "Uninstall detected malicious apps",
                        "Scan device with antivirus software",
                        "Review app permissions regularly"
                    )
                )
            )
        }
        
        // Add integrity threats
        if (integrityResult.isTampered) {
            threats.add(
                io.github.yoganataa.caster.logging.ThreatInfo(
                    type = io.github.yoganataa.caster.logging.ThreatType.INTEGRITY_VIOLATION,
                    description = "Application or system integrity compromised",
                    severity = io.github.yoganataa.caster.logging.ThreatSeverity.HIGH,
                    confidence = 0.8f, // Default confidence for integrity issues
                    detectionMethods = integrityResult.detectedMethods,
                    recommendations = listOf(
                        "Verify application signature",
                        "Check system partition integrity",
                        "Review bootloader status",
                        "Update to official firmware"
                    )
                )
            )
        }
        
        // Add tampering threats
        if (tamperingResult.isDebuggerAttached || tamperingResult.isHookingDetected) {
            threats.add(
                io.github.yoganataa.caster.logging.ThreatInfo(
                    type = io.github.yoganataa.caster.logging.ThreatType.TAMPERING,
                    description = "Anti-tampering mechanisms detected suspicious activity",
                    severity = if (tamperingResult.isDebuggerAttached) 
                        io.github.yoganataa.caster.logging.ThreatSeverity.CRITICAL
                    else 
                        io.github.yoganataa.caster.logging.ThreatSeverity.HIGH,
                    confidence = 0.9f, // High confidence for tampering detection
                    detectionMethods = tamperingResult.detectedMethods,
                    recommendations = listOf(
                        "Disable debugging features",
                        "Remove hooking frameworks",
                        "Use obfuscated builds",
                        "Implement additional runtime protection"
                    )
                )
            )
        }
        
        // Perform additional security checks if enabled
        if (config.enableLsDataDetection) {
            performAdditionalSecurityChecks(context, threats)
        }
        
        // Calculate overall risk level
        val riskLevel = when {
            rootResult.isRooted && rootResult.confidence > 0.8 -> io.github.yoganataa.caster.logging.RiskLevel.CRITICAL
            maliciousAppsResult.hasMaliciousApps && maliciousAppsResult.riskScore > 0.7 -> io.github.yoganataa.caster.logging.RiskLevel.CRITICAL
            tamperingResult.isDebuggerAttached -> io.github.yoganataa.caster.logging.RiskLevel.CRITICAL
            rootResult.isRooted || maliciousAppsResult.hasMaliciousApps -> io.github.yoganataa.caster.logging.RiskLevel.HIGH
            integrityResult.isTampered || tamperingResult.isHookingDetected -> io.github.yoganataa.caster.logging.RiskLevel.MEDIUM
            emulatorResult.isEmulator || flagSecureResult.isFlagSecureDisabled -> io.github.yoganataa.caster.logging.RiskLevel.LOW
            else -> io.github.yoganataa.caster.logging.RiskLevel.NONE
        }
        
        // Calculate overall confidence
        val confidences = listOf(
            rootResult.confidence,
            emulatorResult.confidence,
            flagSecureResult.confidence,
            maliciousAppsResult.riskScore
        )
        val overallConfidence = if (confidences.isNotEmpty()) {
            confidences.average().toFloat()
        } else {
            0.0f
        }
        
        return SecurityReport(
            timestamp = System.currentTimeMillis(),
            deviceInfo = getDeviceInfo(),
            securityStatus = io.github.yoganataa.caster.logging.SecurityStatus(
                isRooted = rootResult.isRooted,
                isEmulator = emulatorResult.isEmulator,
                flagSecureDisabled = flagSecureResult.isFlagSecureDisabled,
                maliciousAppsDetected = maliciousAppsResult.hasMaliciousApps,
                isTampered = integrityResult.isTampered || tamperingResult.isHookingDetected,
                isDebuggerAttached = tamperingResult.isDebuggerAttached,
                isHookingDetected = tamperingResult.isHookingDetected,
                isScreenshotPossible = flagSecureResult.isFlagSecureDisabled,
                riskLevel = riskLevel,
                overallConfidence = overallConfidence
            ),
            detectedThreats = threats,
            appPackage = context.packageName
        )
    }
    
    /**
     * Performs additional security checks if enabled in configuration.
     */
    private fun performAdditionalSecurityChecks(context: Context, threats: MutableList<io.github.yoganataa.caster.logging.ThreatInfo>) {
        try {
            // Device attestation
            val deviceAttestation = DeviceAttestation(context)
            val attestationResult = deviceAttestation.performAttestation()
            
            if (!attestationResult.isTrustedDevice) {
                threats.add(
                    io.github.yoganataa.caster.logging.ThreatInfo(
                        type = io.github.yoganataa.caster.logging.ThreatType.SUSPICIOUS_ENVIRONMENT,
                        description = "Device attestation failed",
                        severity = io.github.yoganataa.caster.logging.ThreatSeverity.HIGH,
                        confidence = 0.8f,
                        detectionMethods = listOf("DEVICE_ATTESTATION"),
                        recommendations = listOf(
                            "Verify device integrity",
                            "Check bootloader status",
                            "Ensure system is not tampered"
                        )
                    )
                )
            }
            
            // Network security
            val networkSecurityManager = NetworkSecurityManager(context)
            val networkResult = networkSecurityManager.performNetworkSecurityCheck()
            
            if (!networkResult.isNetworkSecure) {
                threats.add(
                    io.github.yoganataa.caster.logging.ThreatInfo(
                        type = io.github.yoganataa.caster.logging.ThreatType.SUSPICIOUS_ENVIRONMENT,
                        description = "Network security issues detected",
                        severity = io.github.yoganataa.caster.logging.ThreatSeverity.MEDIUM,
                        confidence = 0.7f,
                        detectionMethods = listOf("NETWORK_SECURITY_CHECK"),
                        recommendations = listOf(
                            "Use secure connections only",
                            "Avoid public Wi-Fi for sensitive operations",
                            "Check for VPN/proxy usage"
                        )
                    )
                )
            }
            
            // Privacy protection
            val privacyManager = PrivacyProtectionManager(context)
            val privacyResult = privacyManager.performPrivacyCheck()
            
            if (!privacyResult.isPrivacyProtected) {
                threats.add(
                    io.github.yoganataa.caster.logging.ThreatInfo(
                        type = io.github.yoganataa.caster.logging.ThreatType.CONFIGURATION_ERROR,
                        description = "Privacy protection issues detected",
                        severity = io.github.yoganataa.caster.logging.ThreatSeverity.MEDIUM,
                        confidence = 0.6f,
                        detectionMethods = listOf("PRIVACY_PROTECTION_CHECK"),
                        recommendations = listOf(
                            "Review app permissions",
                            "Check data storage security",
                            "Verify analytics/tracking compliance"
                        )
                    )
                )
            }
        } catch (e: Exception) {
            logger.error("Error performing additional security checks", e)
        }
    }

    private fun getDeviceInfo(): io.github.yoganataa.caster.logging.DeviceInfo = io.github.yoganataa.caster.logging.DeviceInfo(
        model = android.os.Build.MODEL,
        manufacturer = android.os.Build.MANUFACTURER,
        androidVersion = android.os.Build.VERSION.RELEASE,
        apiLevel = android.os.Build.VERSION.SDK_INT,
        kernelVersion = SystemUtils.getKernelVersion(),
        buildFingerprint = android.os.Build.FINGERPRINT,
        securityPatch = android.os.Build.VERSION.SECURITY_PATCH,
        bootloaderStatus = try {
            // This might not work on all devices due to permissions
            @Suppress("DEPRECATION")
            android.os.Build.BOOTLOADER
        } catch (e: Exception) {
            "unknown"
        }
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
            // Initialize the context holder for security monitor access
            ContextHolder.init(context)
            
            val newInstance = Caster(config)
            initialize(newInstance)
        }
    }
}

// Helper class to hold application context for security monitor
object ContextHolder {
    private var appContext: Context? = null
    
    fun init(context: Context) {
        appContext = context.applicationContext
    }
    
    fun getAppContext(): Context {
        return appContext ?: throw IllegalStateException("Context not initialized")
    }
}