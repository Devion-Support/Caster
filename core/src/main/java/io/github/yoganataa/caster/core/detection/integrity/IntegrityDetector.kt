package io.github.yoganataa.caster.core.detection.integrity

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.util.Log
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import org.lsposed.lsparanoid.Obfuscate
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * [DISESUAIKAN] Kelas untuk mendeteksi integritas aplikasi Android.
 * Disesuaikan untuk menggunakan model data Caster dan pola detektor yang konsisten.
 * Metode verifikasi dan fungsi utility dipertahankan.
 */

@Obfuscate
class IntegrityDetector(private val context: Context) {

    companion object {
        private const val TAG = "IntegrityDetector"

        // [PENTING] Ganti dengan hash SHA-256 dari sertifikat RILIS Anda!
        // Gunakan `getCurrentCertificateHash()` untuk mendapatkannya saat development.
        private const val EXPECTED_CERTIFICATE_SHA256 = "4C:FF:C8:0F:88:C2:42:51:22:62:7C:31:E9:93:A1:7B:DA:3A:66:AC:A1:67:92:A4:D5:49:C0:2F:32:79:32:88"

        // [PENTING] Ganti dengan nilai CRC32 dari `classes.dex` RILIS Anda!
        // Gunakan `getCurrentDexCrc32()` untuk mendapatkannya saat development.
        private const val EXPECTED_DEX_CRC32 = 0L
    }

    /**
     * Hasil dari deteksi integritas.
     */
    data class Result(
        val isTampered: Boolean,
        val threats: List<ThreatInfo>,
        val detectedMethods: List<String>
    )

    /**
     * Fungsi utama untuk melakukan deteksi integritas.
     */
    fun detect(): Result {
        val threats = mutableListOf<ThreatInfo>()
        val detectedMethods = mutableListOf<String>()

        // Hanya jalankan pengecekan jika placeholder sudah diganti untuk menghindari false positive
        if (EXPECTED_CERTIFICATE_SHA256 != "PLACEHOLDER_CERTIFICATE_HASH_SHA256") {
            if (!verifyAppSignature()) {
                val sign = "App signature mismatch"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.TAMPERING, sign, "CRITICAL"))
            }
        }

        if (EXPECTED_DEX_CRC32 != 0L) {
            if (!verifyDexChecksum()) {
                val sign = "DEX file checksum mismatch"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.TAMPERING, sign, "CRITICAL"))
            }
        }

        return Result(threats.isNotEmpty(), threats, detectedMethods)
    }

    private fun verifyAppSignature(): Boolean {
        return try {
            val currentHash = getCurrentCertificateHash()
            Log.d(TAG, "Current cert hash: $currentHash")
            Log.d(TAG, "Expected cert hash: $EXPECTED_CERTIFICATE_SHA256")
            currentHash != null && currentHash.equals(EXPECTED_CERTIFICATE_SHA256, ignoreCase = true)
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying app signature", e)
            false
        }
    }

    private fun verifyDexChecksum(): Boolean {
        return try {
            val currentCrc = getCurrentDexCrc32()
            Log.d(TAG, "Current DEX CRC32: $currentCrc")
            Log.d(TAG, "Expected DEX CRC32: $EXPECTED_DEX_CRC32")
            currentCrc != null && currentCrc == EXPECTED_DEX_CRC32
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying DEX checksum", e)
            false
        }
    }

    /**
     * Fungsi utility untuk mendapatkan hash SHA-256 dari sertifikat saat ini.
     * Berguna untuk development - mendapatkan hash yang perlu di-hardcode.
     */
    fun getCurrentCertificateHash(): String? {
        try {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }
            val info = context.packageManager.getPackageInfo(context.packageName, flags)

            val signature: Signature? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                info.signingInfo?.apkContentsSigners?.firstOrNull() ?: info.signingInfo?.signingCertificateHistory?.firstOrNull()
            } else {
                @Suppress("DEPRECATION")
                info.signatures?.firstOrNull()
            }

            return signature?.let {
                val certFactory = CertificateFactory.getInstance("X.509")
                val cert = certFactory.generateCertificate(ByteArrayInputStream(it.toByteArray())) as X509Certificate
                val digest = MessageDigest.getInstance("SHA-256")
                val hash = digest.digest(cert.encoded)
                // Konversi ke format hex dengan pemisah ':' agar mudah dibaca seperti output keytool
                hash.joinToString(":") { "%02X".format(it) }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Gagal mendapatkan hash sertifikat saat ini", e)
            return null
        }
    }

    /**
     * Fungsi utility untuk mendapatkan CRC32 dari classes.dex saat ini.
     * Berguna untuk development - mendapatkan CRC32 yang perlu di-hardcode.
     */
    fun getCurrentDexCrc32(): Long? {
        try {
            val apkPath = context.applicationInfo.sourceDir
            ZipFile(apkPath).use {
                return it.getEntry("classes.dex")?.crc
            }
        } catch (e: Exception) {
            Log.e(TAG, "Gagal mendapatkan CRC DEX saat ini", e)
            return null
        }
    }
}