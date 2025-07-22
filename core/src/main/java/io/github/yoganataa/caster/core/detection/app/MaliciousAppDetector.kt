package io.github.yoganataa.caster.core.detection.app

import io.github.yoganataa.caster.core.CasterConfig
import io.github.yoganataa.caster.core.detection.root.detectors.LsDataDetector
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import org.lsposed.lsparanoid.Obfuscate

/**
 * Detects malicious applications based on known lists, name heuristics,
 * and excessive permission usage.
 *
 * IMPORTANT: To function on Android 11 (API 30) and above, applications using
 * this library MUST declare the `<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />`
 * permission in their AndroidManifest.xml.
 */

@Obfuscate
class MaliciousAppDetector(private val context: Context, private val config: CasterConfig, private val lsDataDetectorFactory: (Context) -> LsDataDetector = { LsDataDetector(it) }) {

    private val logger = Logger.getInstance()
    private val customMaliciousApps = mutableSetOf<String>()

    // List of known root management applications.
    private val rootManagementApps = setOf(
        "eu.chainfire.supersu", "com.noshufou.android.su", "com.thirdparty.superuser", "com.yellowes.su",
        "com.topjohnwu.magisk", "com.kingroot.kinguser", "com.kingo.root", "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global", "com.alephzain.framaroot", "moe.shizuku.privileged.api",
        "com.rifsxd.ksunext", "me.weishu.kernelsu", "bin.mt.plus", "com.mixplorer",
        "com.speedsoftware.rootexplorer", "com.lonelycatgames.Xplore", "pl.solidexplorer2",
        "com.ghostsq.commander", "com.ghisler.android.TotalCommander", "nextapp.fx.filemanager",
        "com.amaze.filemanager", "com.cxwey.android", "com.bmax.apatch", "io.github.huskydg.magisk",
        "io.github.kitsune.mask"
    )

    // List of known security bypass and virtualization tools.
    private val securityBypassTools = setOf(
        "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager", "org.lsposed.manager",
        "top.canyie.dreamland.manager", "com.github.riru", "com.ceco.gm2.gravitybox",
        "com.github.skipifzero.flag_secure_camera", "com.yaerin.flag_secure_bypass",
        "io.github.a13e300.disable_flag_secure", "com.finity.virtual", "com.lbe.parallel.intl",
        "com.dimonvideo.luckypatch", "com.android.vending.billing.InAppBillingService.COIN",
        "re.frida.server", "io.github.varuhs2002.disable_flag_secure","com.chelpus.lackypatcher",
        "ru.chelpus.lpinst", "gg.android.bt", "com.draco.hidemyapplist"
    )

    // List of known debugging and analysis tools.
    private val debuggingTools = setOf(
        "com.android.insecurebankv2", "jakhar.aseem.diva", "com.htbridge.pivaa", "com.android.dvci",
        "com.scottyab.rootbeer.sample", "jackpal.androidterm", "com.termux", "org.connectbot",
        "app.greyshirts.sslcapture", "org.jtb.alogcat", "org.gstress.logcatextreme"
    )

    // List of known emulator bypass tools.
    private val emulatorBypassTools = setOf(
        "com.android.development_settings", "com.android.development", "com.android.gallery3d.dev"
    )

    // List of known malware family package names.
    private val knownMalwareFamilies = setOf(
        "com.android.systemui.evil", "com.system.update.malware", "android.process.malicious",
        "com.droiddream", "com.geinimi", "com.adups.fota", "com.cerberusapp", "com.spynote",
        "com.anubis", "com.joker.billing", "com.android.billing.fake"
    )

    private val allKnownThreats = rootManagementApps + securityBypassTools + debuggingTools + emulatorBypassTools + knownMalwareFamilies

    /**
     * Represents the result of the malicious application detection.
     *
     * @property hasMaliciousApps True if any malicious applications were detected, false otherwise.
     * @property detectedApps A list of [DetectedApp] instances, detailing each detected malicious application.
     * @property threats A list of [ThreatInfo] objects, providing detailed threat information.
     * @property riskScore A float value representing the overall risk score based on detected malicious apps.
     */
    data class MaliciousAppResult(
        val hasMaliciousApps: Boolean,
        val detectedApps: List<DetectedApp>,
        val threats: List<ThreatInfo>,
        val riskScore: Float
    )

    /**
     * Represents a single detected malicious application.
     *
     * @property packageName The package name of the detected application.
     * @property appName The human-readable name of the detected application.
     * @property category The category of the detected application (e.g., "Root Management").
     * @property riskLevel The risk level associated with this application (e.g., "CRITICAL", "HIGH").
     * @property isSystemApp True if the detected application is a system app, false otherwise.
     */
    data class DetectedApp(
        val packageName: String,
        val appName: String,
        val category: String,
        val riskLevel: String,
        val isSystemApp: Boolean
    )

    /**
     * Adds custom malicious application package names to the detection list.
     *
     * These package names will be checked in addition to the built-in known threat lists.
     * Blank package names will be ignored.
     *
     * @param packageNames A collection of package names to add to the custom malicious app list.
     */
    fun addCustomMaliciousApps(packageNames: Collection<String>) {
        customMaliciousApps.addAll(packageNames.filter { it.isNotBlank() })
    }

    /**
     * Detects malicious applications installed on the device.
     *
     * This method scans through installed packages and identifies applications based on:
     * 1. Matching known malicious package names.
     * 2. Heuristic detection using suspicious keywords in package names.
     * 3. Excessive usage of dangerous permissions.
     *
     * @return A [MaliciousAppResult] containing information about detected malicious applications, if any.
     */
    suspend fun detectMaliciousApps(): MaliciousAppResult {
        logger.info("Starting optimized malicious app detection...")

        val installedPackagesInfo = getInstalledPackagesWithInfo(context)
        val installedPackageNamesFromPm = installedPackagesInfo.map { it.packageName }.toSet()

        val allPackageNamesToScan = mutableSetOf<String>()
        allPackageNamesToScan.addAll(installedPackageNamesFromPm)

        if (config.enableLsDataDetection) {
            val lsDataPackages = lsDataDetectorFactory(context).getPackagesFromLsData()
            allPackageNamesToScan.addAll(lsDataPackages)
        }

        val detectedApps = mutableListOf<DetectedApp>()
        val threats = mutableListOf<ThreatInfo>()
        val detectedPackageNames = mutableSetOf<String>()

        val threatsToScan = allKnownThreats + customMaliciousApps
        val suspiciousKeywords = listOf(
            "hack", "crack", "cheat", "mod", "fake", "clone",
            "stealer", "spy", "monitor", "keylog", "backdoor"
        )
        val dangerousPermissions = setOf(
            "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.CALL_PHONE",
            "android.permission.RECORD_AUDIO", "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.WRITE_EXTERNAL_STORAGE"
        )

        // Iterate through all unique package names collected
        for (packageName in allPackageNamesToScan) {
            if (packageName in detectedPackageNames) continue // Skip if already processed

            // Try to get ApplicationInfo for the package. This will only work for packages
            // found by PackageManager, not necessarily for those from ls /sdcard/Android/data
            val appInfo: ApplicationInfo? = try {
                context.packageManager.getApplicationInfo(packageName, 0)
            } catch (e: PackageManager.NameNotFoundException) {
                null // App not found by PackageManager, likely from ls /sdcard/Android/data
            }

            var detectedCategory: String? = null
            var detectionDetail: Map<String, Any> = emptyMap()
            var isSystemApp = false
            var appName = packageName // Default to package name if app name cannot be retrieved

            appInfo?.let { info ->
                isSystemApp = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                appName = getAppName(info)
            }

            // Check 1: Known threat list
            if (packageName in threatsToScan) {
                detectedCategory = categorizeApp(packageName)
                detectionDetail = mapOf("reason" to "Matched known threat list")
            }
            // Check 2: Suspicious keywords (only if not already categorized)
            else if (detectedCategory == null) {
                val foundKeyword = suspiciousKeywords.find { packageName.lowercase().contains(it) }
                if (foundKeyword != null) {
                    detectedCategory = "Heuristic Detection"
                    detectionDetail = mapOf("reason" to "Keyword match", "keyword" to foundKeyword)
                }
            }

            // Check 3: Dangerous permissions (only for non-system apps found by PackageManager)
            if (detectedCategory == null && appInfo != null && !isSystemApp) {
                val pkgInfo = installedPackagesInfo.find { it.packageName == packageName }
                pkgInfo?.let {
                    val requestedPermissions = it.requestedPermissions?.toSet() ?: emptySet()
                    if (requestedPermissions.intersect(dangerousPermissions).size >= 5) {
                        detectedCategory = "Excessive Permissions"
                        detectionDetail = mapOf("reason" to "High number of dangerous permissions", "count" to requestedPermissions.size)
                    }
                }
            }

            if (detectedCategory != null) {
                val riskLevel = getRiskLevel(detectedCategory)
                detectedApps.add(
                    DetectedApp(
                        packageName = packageName,
                        appName = appName,
                        category = detectedCategory,
                        riskLevel = riskLevel,
                        isSystemApp = isSystemApp
                    )
                )
                threats.add(
                    ThreatInfo(
                        type = ThreatType.MALICIOUS_APP,
                        description = "Suspicious application detected: $detectedCategory",
                        severity = riskLevel,
                        details = mapOf("package" to packageName) + detectionDetail
                    )
                )
                detectedPackageNames.add(packageName)
            }
        }

        val riskScore = calculateRiskScore(detectedApps)
        logger.info("Malicious app detection complete. Found: ${detectedApps.size} apps, Risk: $riskScore")

        return MaliciousAppResult(detectedApps.isNotEmpty(), detectedApps, threats, riskScore)
    }

    /**
     * Retrieves a list of all installed packages with their associated permissions.
     *
     * @param context The application context.
     * @return A list of [PackageInfo] objects for all installed packages.
     */
    private fun getInstalledPackagesWithInfo(context: Context): List<PackageInfo> {
        return try {
            context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            logger.error("Failed to get installed packages with info", e)
            emptyList()
        }
    }

    /**
     * Retrieves the human-readable application name for a given [ApplicationInfo] object.
     *
     * @param appInfo The [ApplicationInfo] object for which to retrieve the name.
     * @return The application name as a String.
     */
    private fun getAppName(appInfo: ApplicationInfo): String {
        return context.packageManager.getApplicationLabel(appInfo).toString()
    }

    /**
     * Categorizes a given package name into a specific threat category.
     *
     * @param packageName The package name to categorize.
     * @return A String representing the category (e.g., "Root Management / File Explorer").
     */
    private fun categorizeApp(packageName: String): String {
        return when {
            rootManagementApps.contains(packageName) -> "Root Management / File Explorer"
            securityBypassTools.contains(packageName) -> "Security Bypass / Virtualization"
            debuggingTools.contains(packageName) -> "Debugging & Analysis Tool"
            emulatorBypassTools.contains(packageName) -> "Emulator Bypass Tool"
            knownMalwareFamilies.contains(packageName) -> "Known Malware Family"
            else -> "Suspicious App (Custom List)"
        }
    }

    /**
     * Determines the risk level (e.g., CRITICAL, HIGH, MEDIUM, LOW) for a given application category.
     *
     * @param category The category of the detected application.
     * @return A String representing the risk level.
     */
    internal fun getRiskLevel(category: String): String {
        return when (category) {
            "Known Malware Family" -> "CRITICAL"
            "Security Bypass / Virtualization" -> "HIGH"
            "Root Management / File Explorer" -> "HIGH"
            "Heuristic Detection" -> "MEDIUM"
            "Debugging & Analysis Tool" -> "MEDIUM"
            "Excessive Permissions" -> "LOW"
            "Emulator Bypass Tool" -> "LOW"
            else -> "LOW"
        }
    }

    /**
     * Calculates an overall risk score based on the list of detected malicious applications.
     *
     * The score is determined by the highest risk level among the detected apps.
     * CRITICAL = 1.0, HIGH = 0.8, MEDIUM = 0.5, LOW = 0.2.
     *
     * @param detectedApps A list of [DetectedApp] instances.
     * @return A float representing the calculated risk score (0.0 to 1.0).
     */
    internal fun calculateRiskScore(detectedApps: List<DetectedApp>): Float {
        if (detectedApps.isEmpty()) return 0f
        val riskWeights = mapOf("CRITICAL" to 1.0f, "HIGH" to 0.8f, "MEDIUM" to 0.5f, "LOW" to 0.2f)
        val maxRisk = detectedApps.maxOfOrNull { riskWeights[it.riskLevel]?.toDouble() ?: 0.0 } ?: 0.0
        return maxRisk.toFloat()
    }
}