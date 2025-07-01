package io.github.yoganataa.caster.core.detection.root.detectors

import android.content.Context
import io.github.yoganataa.caster.core.detection.root.RootDetectionResult
import io.github.yoganataa.caster.core.detection.root.RootDetectorInterface
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import io.github.yoganataa.caster.core.utils.FileUtils
import io.github.yoganataa.caster.core.utils.SystemUtils

class MagiskDetector(private val context: Context) : RootDetectorInterface {

    override suspend fun detect(): RootDetectionResult {
        val detectedMethods = mutableListOf<String>()
        val threats = mutableListOf<ThreatInfo>()

        // Check for Magisk files
        val magiskFiles = FileUtils.checkMagiskFiles()
        if (magiskFiles.isNotEmpty()) {
            detectedMethods.add("Magisk files detected")
            threats.add(ThreatInfo(
                type = ThreatType.ROOT_ACCESS,
                description = "Magisk files found",
                severity = "HIGH",
                details = mapOf("files" to magiskFiles)
            ))
        }

        // Check for Magisk app
        val magiskPackages = listOf(
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk",
            "com.magisk.manager",
            "io.github.kitsune.mask",
            "io.github.vvb2060.magisk"
        )
        magiskPackages.forEach { pkg ->
            if (SystemUtils.isPackageInstalled(context, pkg)) {
                detectedMethods.add("Magisk app: $pkg")
                threats.add(ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = "Magisk application detected",
                    severity = "HIGH",
                    details = mapOf("package" to pkg)
                ))
            }
        }

        // Check Magisk properties
        val magiskProps = listOf(
            "ro.magisk.version",
            "ro.magisk.versioncode"
        )
        magiskProps.forEach { prop ->
            SystemUtils.getSystemProperty(prop)?.let {
                detectedMethods.add("Magisk property: $prop")
                threats.add(ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = "Magisk system property found",
                    severity = "HIGH",
                    details = mapOf("property" to prop, "value" to it)
                ))
            }
        }

        // Check for resetprop (Magisk utility)
        if (SystemUtils.executeCommand("which resetprop") != null) {
            detectedMethods.add("resetprop utility found")
            threats.add(ThreatInfo(
                type = ThreatType.ROOT_ACCESS,
                description = "Magisk resetprop utility detected",
                severity = "MEDIUM"
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

    private fun calculateConfidence(detectionCount: Int): Float {
        return when (detectionCount) {
            0 -> 0f
            1 -> 0.4f
            2 -> 0.7f
            else -> 1f
        }
    }
}