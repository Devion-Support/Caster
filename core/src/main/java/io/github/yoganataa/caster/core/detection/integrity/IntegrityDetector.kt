package io.github.yoganataa.caster.core.detection.integrity

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.util.Log
import androidx.annotation.Keep
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import org.lsposed.lsparanoid.Obfuscate
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Detector for identifying application integrity compromises.
 *
 * This class provides methods to verify the application's signature
 * against expected values to detect tampering.
 */

@Obfuscate
class IntegrityDetector(private val context: Context) {

    @Keep
    companion object {
        private const val TAG = "IntegrityDetector"

        /**
         * IMPORTANT: Replace with the SHA-256 hash of your RELEASE certificate!
         * Use `getCurrentCertificateHash()` during development to obtain this value.
         */
        private const val EXPECTED_SIGNING_CERT_HASH = "4C:FF:C8:0F:88:C2:42:51:22:62:7C:31:E9:93:A1:7B:DA:3A:66:AC:A1:67:92:A4:D5:49:C0:2F:32:79:32:88"
    }

    /**
     * Represents the result of the integrity detection.
     *
     * @property isTampered True if tampering is detected, false otherwise.
     * @property threats A list of [ThreatInfo] objects, providing detailed threat information.
     * @property detectedMethods A list of strings indicating the specific methods or signs that led to the detection.
     */
    data class Result(
        val isTampered: Boolean,
        val threats: List<ThreatInfo>,
        val detectedMethods: List<String>
    )

    /**
     * Performs integrity detection by verifying the app's signature.
     *
     * Checks are only performed if the placeholder value for the certificate hash
     * has been replaced with an actual release value.
     *
     * @return A [Result] object indicating whether tampering was detected.
     */
    fun detect(): Result {
        val threats = mutableListOf<ThreatInfo>()
        val detectedMethods = mutableListOf<String>()

        // Only run checks if placeholder has been replaced to avoid false positives
        if (EXPECTED_SIGNING_CERT_HASH != "PLACEHOLDER_CERTIFICATE_HASH_SHA256") {
            if (!verifyAppSignature()) {
                val sign = "App signature mismatch"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.TAMPERING, sign, "CRITICAL"))
            }
        }

        return Result(threats.isNotEmpty(), threats, detectedMethods)
    }

    /**
     * Verifies the application's signature against the [EXPECTED_SIGNING_CERT_HASH].
     *
     * @return True if the current app signature matches the expected signature, false otherwise.
     */
    private fun verifyAppSignature(): Boolean {
        return try {
            val currentHash = getCurrentCertificateHash()
            // Log only the status, not the hash values
            if (currentHash != null && currentHash.equals(EXPECTED_SIGNING_CERT_HASH, ignoreCase = true)) {
                Log.d(TAG, "App integrity: OK")
                true
            } else {
                Log.d(TAG, "App integrity: TAMPERED")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying app signature", e)
            false
        }
    }

    /**
     * Utility function to get the SHA-256 hash of the current application's signing certificate.
     * Useful during development to obtain the hash that needs to be hardcoded.
     *
     * @return The SHA-256 hash of the certificate as a colon-separated hex string, or null if an error occurs.
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
                // Convert to colon-separated hex format for readability, similar to keytool output
                hash.joinToString(":") { "%02X".format(it) }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get current certificate hash", e)
            return null
        }
    }
}
