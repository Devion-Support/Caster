package io.github.yoganataa.caster.core.detection.app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType

/**
 * Mendeteksi aplikasi berbahaya berdasarkan daftar yang diketahui, heuristik nama,
 * dan penggunaan izin yang berlebihan.
 *
 * PENTING: Untuk berfungsi di Android 11 (API 30) ke atas, aplikasi yang menggunakan
 * pustaka ini WAJIB mendeklarasikan izin <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
 * di AndroidManifest.xml-nya.
 */
class MaliciousAppDetector(private val context: Context) {

    private val logger = Logger.getInstance()
    private val customMaliciousApps = mutableSetOf<String>()

    // PENYESUAIAN: Daftar paket aplikasi telah diperbarui sesuai permintaan Anda.
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

    private val securityBypassTools = setOf(
        "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager", "org.lsposed.manager",
        "top.canyie.dreamland.manager", "com.github.riru", "com.ceco.gm2.gravitybox",
        "com.github.skipifzero.flag_secure_camera", "com.yaerin.flag_secure_bypass",
        "io.github.a13e300.disable_flag_secure", "com.finity.virtual", "com.lbe.parallel.intl",
        "com.dimonvideo.luckypatch", "com.android.vending.billing.InAppBillingService.COIN",
        "re.frida.server", "io.github.varuhs2002.disable_flag_secure","com.chelpus.lackypatcher",
        "ru.chelpus.lpinst", "gg.android.bt"
    )

    private val debuggingTools = setOf(
        "com.android.insecurebankv2", "jakhar.aseem.diva", "com.htbridge.pivaa", "com.android.dvci",
        "com.scottyab.rootbeer.sample", "jackpal.androidterm", "com.termux", "org.connectbot",
        "app.greyshirts.sslcapture", "org.jtb.alogcat", "org.gstress.logcatextreme"
    )

    private val emulatorBypassTools = setOf(
        "com.android.development_settings", "com.android.development", "com.android.gallery3d.dev"
    )

    private val knownMalwareFamilies = setOf(
        "com.android.systemui.evil", "com.system.update.malware", "android.process.malicious",
        "com.droiddream", "com.geinimi", "com.adups.fota", "com.cerberusapp", "com.spynote",
        "com.anubis", "com.joker.billing", "com.android.billing.fake"
    )

    private val allKnownThreats = rootManagementApps + securityBypassTools + debuggingTools + emulatorBypassTools + knownMalwareFamilies

    data class MaliciousAppResult(
        val hasMaliciousApps: Boolean,
        val detectedApps: List<DetectedApp>,
        val threats: List<ThreatInfo>,
        val riskScore: Float
    )

    data class DetectedApp(
        val packageName: String,
        val appName: String,
        val category: String,
        val riskLevel: String,
        val isSystemApp: Boolean
    )

    fun addCustomMaliciousApps(packageNames: Collection<String>) {
        customMaliciousApps.addAll(packageNames.filter { it.isNotBlank() })
    }

    suspend fun detectMaliciousApps(): MaliciousAppResult {
        logger.info("Starting optimized malicious app detection...")

        val installedPackagesInfo = getInstalledPackagesWithInfo(context)
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

        for (pkgInfo in installedPackagesInfo) {
            // PERBAIKAN: Menggunakan `pkgInfo.applicationInfo?.let { ... }` untuk menangani null-safety.
            // PENJELASAN: Seluruh logika deteksi untuk satu aplikasi hanya akan berjalan
            // jika `applicationInfo` tidak null. Ini menyelesaikan kedua error yang Anda laporkan.
            pkgInfo.applicationInfo?.let { appInfo ->
                val packageName = appInfo.packageName
                if (packageName in detectedPackageNames) return@let // Lanjutkan ke aplikasi berikutnya jika sudah terdeteksi

                var detectedCategory: String? = null
                var detectionDetail: Map<String, Any> = emptyMap()

                // Cek 1: Daftar ancaman yang diketahui
                if (packageName in threatsToScan) {
                    detectedCategory = categorizeApp(packageName)
                    detectionDetail = mapOf("reason" to "Matched known threat list")
                }
                // Cek 2: Kata kunci mencurigakan
                else {
                    val foundKeyword = suspiciousKeywords.find { packageName.lowercase().contains(it) }
                    if (foundKeyword != null) {
                        detectedCategory = "Heuristic Detection"
                        detectionDetail = mapOf("reason" to "Keyword match", "keyword" to foundKeyword)
                    }
                }

                // Cek 3: Izin berbahaya
                if (detectedCategory == null && (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) == 0) {
                    val requestedPermissions = pkgInfo.requestedPermissions?.toSet() ?: emptySet()
                    if (requestedPermissions.intersect(dangerousPermissions).size >= 5) {
                        detectedCategory = "Excessive Permissions"
                        detectionDetail = mapOf("reason" to "High number of dangerous permissions", "count" to requestedPermissions.size)
                    }
                }

                if (detectedCategory != null) {
                    val riskLevel = getRiskLevel(detectedCategory)
                    detectedApps.add(
                        DetectedApp(
                            packageName = packageName,
                            appName = getAppName(appInfo),
                            category = detectedCategory,
                            riskLevel = riskLevel,
                            isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
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
        }

        val riskScore = calculateRiskScore(detectedApps)
        logger.info("Malicious app detection complete. Found: ${detectedApps.size} apps, Risk: $riskScore")

        return MaliciousAppResult(detectedApps.isNotEmpty(), detectedApps, threats, riskScore)
    }

    private fun getInstalledPackagesWithInfo(context: Context): List<PackageInfo> {
        return try {
            context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            logger.error("Failed to get installed packages with info", e)
            emptyList()
        }
    }

    private fun getAppName(appInfo: ApplicationInfo): String {
        return context.packageManager.getApplicationLabel(appInfo).toString()
    }

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

    private fun getRiskLevel(category: String): String {
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

    private fun calculateRiskScore(detectedApps: List<DetectedApp>): Float {
        if (detectedApps.isEmpty()) return 0f
        val riskWeights = mapOf("CRITICAL" to 1.0f, "HIGH" to 0.8f, "MEDIUM" to 0.5f, "LOW" to 0.2f)
        val maxRisk = detectedApps.maxOfOrNull { riskWeights[it.riskLevel]?.toDouble() ?: 0.0 } ?: 0.0
        return maxRisk.toFloat()
    }
}