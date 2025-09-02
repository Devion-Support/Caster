package io.github.yoganataa.caster.integrity

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import io.github.yoganataa.caster.logging.Logger
import java.io.File
import java.security.MessageDigest
import java.util.*

/**
 * Enhanced code integrity checker to verify application integrity.
 */
class CodeIntegrityChecker private constructor(private val context: Context) {
    
    private val logger = Logger.getInstance()
    
    companion object {
        @Volatile
        private var INSTANCE: CodeIntegrityChecker? = null
        
        fun getInstance(context: Context): CodeIntegrityChecker {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: CodeIntegrityChecker(context.applicationContext).also { INSTANCE = it }
            }
        }
    }
    
    /**
     * Performs a comprehensive integrity check of the application.
     */
    fun performIntegrityCheck(): IntegrityCheckResult {
        logger.info("Performing comprehensive integrity check")
        
        val result = IntegrityCheckResult()
        
        try {
            // Check application signature
            val signatureCheck = checkApplicationSignature()
            result.checks.add(signatureCheck)
            
            // Check APK integrity
            val apkCheck = checkApkIntegrity()
            result.checks.add(apkCheck)
            
            // Check for debugging
            val debugCheck = checkForDebugging()
            result.checks.add(debugCheck)
            
            // Check for emulator
            val emulatorCheck = checkForEmulator()
            result.checks.add(emulatorCheck)
            
            // Check for root
            val rootCheck = checkForRoot()
            result.checks.add(rootCheck)
            
            // Check for tampering
            val tamperCheck = checkForTampering()
            result.checks.add(tamperCheck)
            
            // Determine overall integrity status
            result.isIntegrityCompromised = result.checks.any { it.isCompromised }
            result.confidence = calculateIntegrityConfidence(result.checks)
            
            logger.info("Integrity check completed. Compromised: ${result.isIntegrityCompromised}, Confidence: ${result.confidence}")
        } catch (e: Exception) {
            logger.error("Error during integrity check", e)
            result.isIntegrityCompromised = true
            result.confidence = 1.0f
            result.checks.add(IntegrityCheck(
                type = IntegrityCheckType.RUNTIME_ERROR,
                name = "Runtime Error",
                isCompromised = true,
                confidence = 1.0f,
                details = mapOf("error" to e.message.toString())
            ))
        }
        
        return result
    }
    
    /**
     * Checks the application signature for validity.
     */
    private fun checkApplicationSignature(): IntegrityCheck {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }
            
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }
            
            if (signatures.isNullOrEmpty()) {
                IntegrityCheck(
                    type = IntegrityCheckType.SIGNATURE,
                    name = "Signature Check",
                    isCompromised = true,
                    confidence = 0.9f,
                    details = mapOf("issue" to "No signatures found")
                )
            } else {
                // In a real implementation, you would compare against expected signatures
                // For now, we'll assume valid if signatures exist
                IntegrityCheck(
                    type = IntegrityCheckType.SIGNATURE,
                    name = "Signature Check",
                    isCompromised = false,
                    confidence = 0.8f,
                    details = mapOf("signatures" to signatures.size.toString())
                )
            }
        } catch (e: Exception) {
            logger.error("Error checking application signature", e)
            IntegrityCheck(
                type = IntegrityCheckType.SIGNATURE,
                name = "Signature Check",
                isCompromised = true,
                confidence = 0.9f,
                details = mapOf("error" to e.message.toString())
            )
        }
    }
    
    /**
     * Checks the APK file integrity using checksums.
     */
    private fun checkApkIntegrity(): IntegrityCheck {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            val apkPath = packageInfo.applicationInfo?.sourceDir
            val apkFile = File(apkPath)
            
            if (!apkFile.exists()) {
                return IntegrityCheck(
                    type = IntegrityCheckType.APK_INTEGRITY,
                    name = "APK Integrity Check",
                    isCompromised = true,
                    confidence = 0.9f,
                    details = mapOf("issue" to "APK file not found")
                )
            }
            
            // Calculate SHA-256 hash of the APK
            val apkHash = calculateFileHash(apkFile, "SHA-256")
            
            // In a real implementation, you would compare against expected hash
            // For now, we'll just verify the hash was calculated
            val isCompromised = apkHash.isNullOrEmpty()
            
            IntegrityCheck(
                type = IntegrityCheckType.APK_INTEGRITY,
                name = "APK Integrity Check",
                isCompromised = isCompromised,
                confidence = if (isCompromised) 0.9f else 0.7f,
                details = mapOf("apk_hash" to (apkHash ?: "unknown"))
            )
        } catch (e: Exception) {
            logger.error("Error checking APK integrity", e)
            IntegrityCheck(
                type = IntegrityCheckType.APK_INTEGRITY,
                name = "APK Integrity Check",
                isCompromised = true,
                confidence = 0.9f,
                details = mapOf("error" to e.message.toString())
            )
        }
    }
    
    /**
     * Checks for debugging artifacts.
     */
    private fun checkForDebugging(): IntegrityCheck {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            
            // Check if app is debuggable
            val isDebuggable = (packageInfo.applicationInfo?.flags ?: 0 and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
            
            // Check for common debugging artifacts
            val debugArtifacts = listOf(
                "/data/local/tmp",
                "/data/data/${context.packageName}/shared_prefs/debug.xml"
            )
            
            val hasDebugArtifacts = debugArtifacts.any { File(it).exists() }
            
            val isCompromised = isDebuggable || hasDebugArtifacts
            
            IntegrityCheck(
                type = IntegrityCheckType.DEBUGGING,
                name = "Debugging Check",
                isCompromised = isCompromised,
                confidence = 0.8f,
                details = mapOf(
                    "debuggable" to isDebuggable.toString(),
                    "debug_artifacts" to hasDebugArtifacts.toString()
                )
            )
        } catch (e: Exception) {
            logger.error("Error checking for debugging", e)
            IntegrityCheck(
                type = IntegrityCheckType.DEBUGGING,
                name = "Debugging Check",
                isCompromised = true,
                confidence = 0.7f,
                details = mapOf("error" to e.message.toString())
            )
        }
    }
    
    /**
     * Checks if running in an emulator.
     */
    private fun checkForEmulator(): IntegrityCheck {
        return try {
            val isEmulator = (
                Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
                "google_sdk".equals(Build.PRODUCT)
            )
            
            IntegrityCheck(
                type = IntegrityCheckType.EMULATOR,
                name = "Emulator Check",
                isCompromised = isEmulator,
                confidence = 0.9f,
                details = mapOf(
                    "is_emulator" to isEmulator.toString(),
                    "model" to Build.MODEL,
                    "manufacturer" to Build.MANUFACTURER,
                    "fingerprint" to Build.FINGERPRINT
                )
            )
        } catch (e: Exception) {
            logger.error("Error checking for emulator", e)
            IntegrityCheck(
                type = IntegrityCheckType.EMULATOR,
                name = "Emulator Check",
                isCompromised = true,
                confidence = 0.6f,
                details = mapOf("error" to e.message.toString())
            )
        }
    }
    
    /**
     * Checks for root access.
     */
    private fun checkForRoot(): IntegrityCheck {
        return try {
            // Check for common root binaries
            val rootBins = arrayOf("/system/bin/su", "/system/xbin/su", "/sbin/su")
            val hasRootBins = rootBins.any { File(it).exists() }
            
            // Check for test keys
            val hasTestKeys = Build.TAGS?.contains("test-keys") == true
            
            // Check for root apps
            val rootApps = listOf(
                "com.noshufou.android.su",
                "com.noshufou.android.su.elite",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.thirdparty.superuser",
                "com.topjohnwu.magisk"
            )
            
            val hasRootApps = rootApps.any { isPackageInstalled(it) }
            
            val isCompromised = hasRootBins || hasTestKeys || hasRootApps
            
            IntegrityCheck(
                type = IntegrityCheckType.ROOT,
                name = "Root Check",
                isCompromised = isCompromised,
                confidence = 0.85f,
                details = mapOf(
                    "has_root_bins" to hasRootBins.toString(),
                    "has_test_keys" to hasTestKeys.toString(),
                    "has_root_apps" to hasRootApps.toString()
                )
            )
        } catch (e: Exception) {
            logger.error("Error checking for root", e)
            IntegrityCheck(
                type = IntegrityCheckType.ROOT,
                name = "Root Check",
                isCompromised = true,
                confidence = 0.7f,
                details = mapOf("error" to e.message.toString())
            )
        }
    }
    
    /**
     * Checks for signs of tampering.
     */
    private fun checkForTampering(): IntegrityCheck {
        return try {
            // Check for common tampering indicators
            val tamperingIndicators = listOf(
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/data/local/tmp/frida-server",
                "/data/local/tmp/frida-agent-32.so",
                "/data/local/tmp/frida-agent-64.so"
            )
            
            val hasTamperingIndicators = tamperingIndicators.any { File(it).exists() }
            
            // Check /proc/self/maps for hooking frameworks
            val hasHookingFrameworks = try {
                val mapsFile = File("/proc/self/maps")
                if (mapsFile.exists()) {
                    mapsFile.readLines().any { line ->
                        line.contains("frida", ignoreCase = true) ||
                        line.contains("xposed", ignoreCase = true) ||
                        line.contains("substrate", ignoreCase = true)
                    }
                } else {
                    false
                }
            } catch (e: Exception) {
                logger.error("Error checking for hooking frameworks", e)
                false
            }
            
            val isCompromised = hasTamperingIndicators || hasHookingFrameworks
            
            IntegrityCheck(
                type = IntegrityCheckType.TAMPERING,
                name = "Tampering Check",
                isCompromised = isCompromised,
                confidence = 0.9f,
                details = mapOf(
                    "has_tampering_indicators" to hasTamperingIndicators.toString(),
                    "has_hooking_frameworks" to hasHookingFrameworks.toString()
                )
            )
        } catch (e: Exception) {
            logger.error("Error checking for tampering", e)
            IntegrityCheck(
                type = IntegrityCheckType.TAMPERING,
                name = "Tampering Check",
                isCompromised = true,
                confidence = 0.7f,
                details = mapOf("error" to e.message.toString())
            )
        }
    }
    
    /**
     * Calculates the hash of a file.
     */
    private fun calculateFileHash(file: File, algorithm: String): String? {
        return try {
            val digest = MessageDigest.getInstance(algorithm)
            file.inputStream().use { inputStream ->
                val buffer = ByteArray(8192)
                var bytesCount: Int
                while (inputStream.read(buffer).also { bytesCount = it } != -1) {
                    digest.update(buffer, 0, bytesCount)
                }
            }
            val bytes = digest.digest()
            bytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            logger.error("Error calculating file hash", e)
            null
        }
    }
    
    /**
     * Checks if a package is installed.
     */
    private fun isPackageInstalled(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }
    
    /**
     * Calculates the overall confidence in the integrity check results.
     */
    private fun calculateIntegrityConfidence(checks: List<IntegrityCheck>): Float {
        if (checks.isEmpty()) return 0.0f
        
        val totalConfidence = checks.sumOf { it.confidence.toDouble() }
        return (totalConfidence / checks.size).toFloat()
    }
    
    /**
     * Cleans up resources.
     */
    fun cleanup() {
        INSTANCE = null
    }
}

/**
 * Data class representing the result of an integrity check.
 */
data class IntegrityCheckResult(
    var isIntegrityCompromised: Boolean = false,
    var confidence: Float = 0.0f,
    val checks: MutableList<IntegrityCheck> = mutableListOf()
)

/**
 * Data class representing a single integrity check.
 */
data class IntegrityCheck(
    val type: IntegrityCheckType,
    val name: String,
    val isCompromised: Boolean,
    val confidence: Float,
    val details: Map<String, String> = emptyMap()
)

/**
 * Enum representing different types of integrity checks.
 */
enum class IntegrityCheckType {
    SIGNATURE,
    APK_INTEGRITY,
    DEBUGGING,
    EMULATOR,
    ROOT,
    TAMPERING,
    RUNTIME_ERROR
}