package io.github.yoganataa.caster.core.detection.root.detectors

import android.content.Context
import io.github.yoganataa.caster.core.detection.root.RootDetectionResult
import io.github.yoganataa.caster.core.detection.root.RootDetectorInterface
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import io.github.yoganataa.caster.core.utils.FileUtils
import io.github.yoganataa.caster.core.utils.SystemUtils
import org.lsposed.lsparanoid.Obfuscate

/**
 * Detector for identifying SuperSU root solution.
 *
 * This detector checks for the presence of SuperSU-specific binaries, installed packages,
 * and system files commonly associated with SuperSU.
 *
 * @param context The application context.
 */
@Obfuscate
class SuperSUDetector(private val context: Context) : RootDetectorInterface {

    /**
     * Performs the detection for SuperSU.
     *
     * Checks include:
     * - Presence of common `su` binaries.
     * - Installation of known SuperSU applications.
     * - Presence of SuperSU-specific system files.
     * - Ability to execute `su` commands successfully.
     *
     * @return A [RootDetectionResult] indicating whether SuperSU is detected and by which methods.
     */
    override suspend fun detect(): RootDetectionResult {
        val detectedMethods = mutableListOf<String>()
        val threats = mutableListOf<ThreatInfo>()

        // Check for SuperSU binaries
        val suBinaries = FileUtils.checkSuBinary()
        if (suBinaries.isNotEmpty()) {
            detectedMethods.add("SU binaries detected")
            threats.add(ThreatInfo(
                type = ThreatType.ROOT_ACCESS,
                description = "SuperUser binaries found",
                severity = "HIGH",
                details = mapOf("binaries" to suBinaries)
            ))
        }

        // Check for SuperSU app packages
        val superSuPackages = listOf(
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.yellowes.su"
        )
        superSuPackages.forEach { pkg ->
            if (SystemUtils.isPackageInstalled(context, pkg)) {
                detectedMethods.add("SuperSU app: $pkg")
                threats.add(ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = "SuperSU application detected",
                    severity = "HIGH",
                    details = mapOf("package" to pkg)
                ))
            }
        }

        // Check SuperSU files
        val superSuFiles = listOf(
            "/system/app/SuperSU",
            "/system/priv-app/SuperSU",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu"
        )
        superSuFiles.forEach { file ->
            if (FileUtils.fileExists(file)) {
                detectedMethods.add("SuperSU file: $file")
                threats.add(ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = "SuperSU system file found",
                    severity = "HIGH",
                    details = mapOf("file" to file)
                ))
            }
        }

        // Test SU command execution
        val suTestResult = SystemUtils.executeCommand("su -c id")
        if (suTestResult != null && suTestResult.contains("uid=0")) {
            detectedMethods.add("SU command execution successful")
            threats.add(ThreatInfo(
                type = ThreatType.ROOT_ACCESS,
                description = "Root access via su command confirmed",
                severity = "CRITICAL",
                details = mapOf("output" to suTestResult)
            ))
        }

        val confidence = calculateConfidence(detectedMethods.size)
        return RootDetectionResult(
            isRooted = detectedMethods.isNotEmpty(),
            detectedMethods = detectedMethods,
            threats = threats,
            confidence = confidence
        )
    }

    /**
     * Calculates the confidence score based on the number of SuperSU detection methods triggered.
     *
     * @param detectionCount The number of SuperSU detection methods that returned true.
     * @return A float value (0.0 to 1.0) representing the confidence score.
     */
    private fun calculateConfidence(detectionCount: Int): Float {
        return when (detectionCount) {
            0 -> 0f
            1 -> 0.5f
            2 -> 0.8f
            else -> 1f
        }
    }
}