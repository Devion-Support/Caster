package io.github.yoganataa.caster.core.detection.environment

import android.content.Context
import android.os.Build
import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import io.github.yoganataa.caster.core.utils.FileUtils
import io.github.yoganataa.caster.core.utils.SystemUtils

/**
 * PERBAIKAN: Struktur data class disesuaikan agar konsisten dengan seluruh proyek.
 * - 'detectedSigns' diubah menjadi 'detectedMethods' untuk konsistensi.
 * - 'threats' ditambahkan untuk laporan keamanan yang detail.
 */
data class EmulatorResult(
    val isEmulator: Boolean,
    val detectedMethods: List<String>,
    val threats: List<ThreatInfo>,
    val confidence: Float
)

/**
 * Detector for identifying Android emulator environments, mempertahankan logika skor yang kompleks.
 */
class EmulatorDetector(private val context: Context) {

    companion object {
        // Build property indicators
        private val EMULATOR_BUILD_FINGERPRINTS = listOf(
            "generic", "unknown", "test-keys", "generic_x86", "generic_x86_64"
        )

        private val EMULATOR_MODELS = listOf(
            "sdk", "google_sdk", "android sdk built for x86", "android sdk built for x86_64",
            "sdk_gphone_x86", "sdk_gphone_x86_64", "emulator",
            // PERBAIKAN: Ditambahkan dari kode referensi
            "Genymotion", "Andy", "Droid4X"
        )

        private val EMULATOR_MANUFACTURERS = listOf(
            "genymotion", "unknown", "android",
            // PERBAIKAN: Ditambahkan dari kode referensi
            "Genymotion"
        )

        private val EMULATOR_BRANDS = listOf(
            "generic", "generic_x86", "generic_x86_64", "android"
        )

        private val EMULATOR_DEVICES = listOf(
            "generic", "generic_x86", "generic_x86_64", "vbox86p", "emulator",
            // PERBAIKAN: Ditambahkan dari kode referensi
            "vbox86"
        )

        private val EMULATOR_PRODUCTS = listOf(
            "sdk", "google_sdk", "sdk_google", "sdk_x86", "vbox86p", "emulator"
        )

        private val EMULATOR_HARDWARE = listOf(
            "goldfish", "ranchu", "vbox86", "ttvm_x86",
            // PERBAIKAN: Ditambahkan dari kode referensi
            "ttVM_Hdragon"
        )

        // File system indicators
        private val EMULATOR_FILES = listOf(
            "/system/bin/qemu-props",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/bin/qemu",
            "/dev/qemu_pipe",
            "/system/bin/microvirt-prop",
            "/system/lib/libdroid4x.so",
            "/system/bin/windroye",
            "/system/bin/nox",
            "/system/bin/ttVM-prop",
            "/data/.bluestacks.prop",
            "/system/bin/duosconfig"
        )

        // Emulator packages
        private val EMULATOR_PACKAGES = listOf(
            "com.genymotion.superuser",
            "com.bluestacks.settings",
            "com.bluestacks.appmart",
            "com.bluestacks.BstCommandProcessor",
            "com.bluestacks.s2p",
            "com.bluestacks.searchapp",
            "com.microvirt.guide",
            "com.microvirt.market",
            "com.microvirt.memuplay",
            "com.nox.mopen",
            "com.vphone.launcher",
            "com.bignox.app"
        )

        // System properties
        private val EMULATOR_PROPERTIES = mapOf(
            "ro.kernel.qemu" to "1",
            "ro.kernel.android.qemu" to "1",
            "ro.hardware" to listOf("goldfish", "ranchu", "vbox86"),
            "ro.product.device" to listOf("generic", "generic_x86", "generic_x86_64"),
            "ro.build.product" to listOf("sdk", "google_sdk", "sdk_x86")
        )
    }

    private val logger = Logger.getInstance()

    /**
     * Perform comprehensive emulator detection
     */
    suspend fun detect(): EmulatorResult {
        logger.debug("Memulai deteksi emulator komprehensif...")

        // PERBAIKAN: 'detectedSigns' diganti nama menjadi 'detectedMethods' dan 'threats' ditambahkan.
        val detectedMethods = mutableListOf<String>()
        val threats = mutableListOf<ThreatInfo>()
        var totalScore = 0f
        val maxScore = 100f // Skor maksimal tetap 100

        // Check build properties
        totalScore += checkBuildProperties(detectedMethods, threats)

        // Check system properties
        totalScore += checkSystemProperties(detectedMethods, threats)

        // Check file system
        totalScore += checkFileSystem(detectedMethods, threats)

        // Check installed packages
        totalScore += checkEmulatorPackages(detectedMethods, threats)

        // Calculate confidence
        val confidence = (totalScore / maxScore).coerceIn(0f, 1f)
        // Keputusan isEmulator bisa didasarkan pada ambang batas skor atau confidence
        val isEmulator = confidence > 0.4f // Ambang batas bisa disesuaikan

        logger.debug("Deteksi emulator selesai. Confidence: $confidence, Methods: ${detectedMethods.size}")

        // PERBAIKAN: Mengembalikan objek EmulatorResult yang sudah disesuaikan
        return EmulatorResult(
            isEmulator = isEmulator,
            detectedMethods = detectedMethods.toList(),
            threats = threats.toList(),
            confidence = confidence
        )
    }

    private fun checkBuildProperties(detectedMethods: MutableList<String>, threats: MutableList<ThreatInfo>): Float {
        var score = 0f

        fun addDetection(sign: String, weight: Float) {
            detectedMethods.add(sign)
            threats.add(ThreatInfo(ThreatType.EMULATOR, sign, "MEDIUM", mapOf("source" to "BuildProperties")))
            score += weight
        }

        // Check fingerprint
        Build.FINGERPRINT?.let { fingerprint ->
            EMULATOR_BUILD_FINGERPRINTS.forEach { indicator ->
                if (fingerprint.contains(indicator, ignoreCase = true)) {
                    addDetection("Build fingerprint contains '$indicator'", 15f)
                }
            }
        }

        // Check model
        Build.MODEL?.let { model ->
            EMULATOR_MODELS.forEach { indicator ->
                if (model.contains(indicator, ignoreCase = true)) {
                    addDetection("Build model contains '$indicator'", 10f)
                }
            }
        }

        // Cek lainnya (manufacturer, brand, device, product, hardware) dengan cara yang sama...
        // ... (saya singkat untuk keringkasan, logikanya sama seperti di atas)
        Build.MANUFACTURER?.let { m -> EMULATOR_MANUFACTURERS.forEach { if(m.contains(it, true)) addDetection("Build manufacturer: $it", 8f) } }
        Build.BRAND?.let { b -> EMULATOR_BRANDS.forEach { if(b.contains(it, true)) addDetection("Build brand: $it", 8f) } }
        Build.DEVICE?.let { d -> EMULATOR_DEVICES.forEach { if(d.contains(it, true)) addDetection("Build device: $it", 10f) } }
        Build.PRODUCT?.let { p -> EMULATOR_PRODUCTS.forEach { if(p.contains(it, true)) addDetection("Build product: $it", 8f) } }
        Build.HARDWARE?.let { h -> EMULATOR_HARDWARE.forEach { if(h.contains(it, true)) addDetection("Build hardware: $it", 12f) } }


        return score.coerceAtMost(40f) // Max 40 points from build properties
    }

    private fun checkSystemProperties(detectedMethods: MutableList<String>, threats: MutableList<ThreatInfo>): Float {
        var score = 0f

        EMULATOR_PROPERTIES.forEach { (property, expectedValues) ->
            val value = SystemUtils.getSystemProperty(property)
            if (value != null) {
                val check = { expected: String, weight: Float ->
                    val sign = "System property '$property' matches '$expected'"
                    detectedMethods.add(sign)
                    threats.add(ThreatInfo(ThreatType.EMULATOR, sign, "HIGH", mapOf("property" to property, "value" to value)))
                    score += weight
                }

                when (expectedValues) {
                    is String -> if (value == expectedValues) check(value, 20f)
                    is List<*> -> {
                        expectedValues.forEach { expected ->
                            if (value.contains(expected.toString(), ignoreCase = true)) {
                                check(expected.toString(), 8f)
                            }
                        }
                    }
                }
            }
        }
        return score.coerceAtMost(30f) // Max 30 points
    }

    private fun checkFileSystem(detectedMethods: MutableList<String>, threats: MutableList<ThreatInfo>): Float {
        var score = 0f
        EMULATOR_FILES.forEach { filePath ->
            if (FileUtils.fileExists(filePath)) {
                val sign = "Emulator file exists: $filePath"
                val weight = when {
                    filePath.contains("qemu") -> 8f
                    else -> 5f
                }
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.EMULATOR, sign, "HIGH", mapOf("path" to filePath)))
                score += weight
            }
        }
        return score.coerceAtMost(20f) // Max 20 points
    }

    private fun checkEmulatorPackages(detectedMethods: MutableList<String>, threats: MutableList<ThreatInfo>): Float {
        var score = 0f
        EMULATOR_PACKAGES.forEach { packageName ->
            if (SystemUtils.isPackageInstalled(context, packageName)) {
                val sign = "Emulator package installed: $packageName"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.EMULATOR, sign, "LOW", mapOf("package" to packageName)))
                score += 3f
            }
        }
        return score.coerceAtMost(10f) // Max 10 points
    }
}