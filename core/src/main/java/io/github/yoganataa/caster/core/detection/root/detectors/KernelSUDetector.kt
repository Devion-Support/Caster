package io.github.yoganataa.caster.core.detection.root.detectors

import android.content.Context
import io.github.yoganataa.caster.core.detection.root.RootDetectionResult
import io.github.yoganataa.caster.core.detection.root.RootDetectorInterface
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType
import io.github.yoganataa.caster.core.utils.FileUtils
import io.github.yoganataa.caster.core.utils.SystemUtils

class KernelSUDetector(private val context: Context) : RootDetectorInterface {

    override suspend fun detect(): RootDetectionResult {
        val detectedMethods = mutableListOf<String>()
        val threats = mutableListOf<ThreatInfo>()

        // Check for KernelSU files
        val kernelSuFiles = FileUtils.checkKernelSuFiles()
        if (kernelSuFiles.isNotEmpty()) {
            detectedMethods.add("KernelSU files detected")
            threats.add(ThreatInfo(
                type = ThreatType.ROOT_ACCESS,
                description = "KernelSU files found",
                severity = "HIGH",
                details = mapOf("files" to kernelSuFiles)
            ))
        }

        // Check for KernelSU app
        val kernelSuPackages = listOf(
            "me.weishu.kernelsu",
            "com.rifsxd.ksunext",
            "io.github.tiann.kernelsu"
        )
        kernelSuPackages.forEach { pkg ->
            if (SystemUtils.isPackageInstalled(context, pkg)) {
                detectedMethods.add("KernelSU app: $pkg")
                threats.add(ThreatInfo(
                    type = ThreatType.ROOT_ACCESS,
                    description = "KernelSU application detected",
                    severity = "HIGH",
                    details = mapOf("package" to pkg)
                ))
            }
        }

        // Check kernel version for KernelSU modifications
        val kernelVersion = SystemUtils.getKernelVersion()
        if (kernelVersion != null && (kernelVersion.contains("KernelSU") || kernelVersion.contains("ksu"))) {
            detectedMethods.add("KernelSU kernel modification")
            threats.add(ThreatInfo(
                type = ThreatType.ROOT_ACCESS,
                description = "Kernel modified with KernelSU",
                severity = "HIGH",
                details = mapOf("kernel" to kernelVersion)
            ))
        }

        // Check for ksud binary
        if (SystemUtils.executeCommand("which ksud") != null) {
            detectedMethods.add("ksud binary found")
            threats.add(ThreatInfo(
                type = ThreatType.ROOT_ACCESS,
                description = "KernelSU daemon binary detected",
                severity = "HIGH"
            ))
        }

        // Check kernel module loading capability
        val lsmodResult = SystemUtils.executeCommand("lsmod")
        if (lsmodResult != null && lsmodResult.contains("kernelsu")) {
            detectedMethods.add("KernelSU module loaded")
            threats.add(ThreatInfo(
                type = ThreatType.ROOT_ACCESS,
                description = "KernelSU kernel module is loaded",
                severity = "CRITICAL"
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
            1 -> 0.6f
            2 -> 0.8f
            else -> 1f
        }
    }
}