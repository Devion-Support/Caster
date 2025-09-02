package io.github.yoganataa.caster.utils

import io.github.yoganataa.caster.logging.SecurityReport
import io.github.yoganataa.caster.logging.ThreatInfo
import io.github.yoganataa.caster.logging.ThreatSeverity
import io.github.yoganataa.caster.logging.RiskLevel
import java.text.SimpleDateFormat
import java.util.*

/**
 * Utility class for generating comprehensive security reports.
 */
object SecurityReportGenerator {
    
    /**
     * Generates a detailed human-readable security report.
     */
    fun generateDetailedReport(report: SecurityReport): String {
        val sb = StringBuilder()
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        
        sb.appendLine("========================================")
        sb.appendLine("         CASTER SECURITY REPORT")
        sb.appendLine("========================================")
        sb.appendLine()
        
        // Report metadata
        sb.appendLine("Report Generated: ${dateFormat.format(Date(report.timestamp))}")
        sb.appendLine("Application Package: ${report.appPackage}")
        sb.appendLine()
        
        // Device information
        sb.appendLine("DEVICE INFORMATION")
        sb.appendLine("------------------")
        sb.appendLine("Model: ${report.deviceInfo.model}")
        sb.appendLine("Manufacturer: ${report.deviceInfo.manufacturer}")
        sb.appendLine("Android Version: ${report.deviceInfo.androidVersion} (API ${report.deviceInfo.apiLevel})")
        sb.appendLine("Kernel Version: ${report.deviceInfo.kernelVersion ?: "Unknown"}")
        if (report.deviceInfo.buildFingerprint != null) {
            sb.appendLine("Build Fingerprint: ${report.deviceInfo.buildFingerprint}")
        }
        if (report.deviceInfo.securityPatch != null) {
            sb.appendLine("Security Patch: ${report.deviceInfo.securityPatch}")
        }
        if (report.deviceInfo.bootloaderStatus != null) {
            sb.appendLine("Bootloader Status: ${report.deviceInfo.bootloaderStatus}")
        }
        sb.appendLine()
        
        // Security status summary
        sb.appendLine("SECURITY STATUS")
        sb.appendLine("---------------")
        sb.appendLine("Overall Risk Level: ${report.securityStatus.riskLevel}")
        sb.appendLine("Overall Confidence: ${String.format("%.1f", report.securityStatus.overallConfidence * 100)}%")
        sb.appendLine("Device Rooted: ${if (report.securityStatus.isRooted) "YES" else "NO"}")
        sb.appendLine("Running in Emulator: ${if (report.securityStatus.isEmulator) "YES" else "NO"}")
        sb.appendLine("Screenshot Protection: ${if (report.securityStatus.flagSecureDisabled) "DISABLED" else "ENABLED"}")
        sb.appendLine("Malicious Apps Detected: ${if (report.securityStatus.maliciousAppsDetected) "YES" else "NO"}")
        sb.appendLine("System Integrity Compromised: ${if (report.securityStatus.isTampered) "YES" else "NO"}")
        sb.appendLine("Debugger Attached: ${if (report.securityStatus.isDebuggerAttached) "YES" else "NO"}")
        sb.appendLine("Hooking Detected: ${if (report.securityStatus.isHookingDetected) "YES" else "NO"}")
        sb.appendLine()
        
        // Detected threats
        if (report.detectedThreats.isEmpty()) {
            sb.appendLine("NO SECURITY THREATS DETECTED")
            sb.appendLine("=============================")
            sb.appendLine("The device appears to be secure.")
        } else {
            sb.appendLine("DETECTED THREATS")
            sb.appendLine("================")
            sb.appendLine("Total Threats: ${report.detectedThreats.size}")
            sb.appendLine()
            
            // Group threats by severity
            val criticalThreats = report.detectedThreats.filter { it.severity == ThreatSeverity.CRITICAL }
            val highThreats = report.detectedThreats.filter { it.severity == ThreatSeverity.HIGH }
            val mediumThreats = report.detectedThreats.filter { it.severity == ThreatSeverity.MEDIUM }
            val lowThreats = report.detectedThreats.filter { it.severity == ThreatSeverity.LOW }
            
            if (criticalThreats.isNotEmpty()) {
                sb.appendLine("CRITICAL THREATS (${criticalThreats.size})")
                sb.appendLine("----------------------------------------")
                criticalThreats.forEachIndexed { index, threat ->
                    appendThreatDetails(sb, threat, index + 1)
                }
                sb.appendLine()
            }
            
            if (highThreats.isNotEmpty()) {
                sb.appendLine("HIGH THREATS (${highThreats.size})")
                sb.appendLine("----------------------------------------")
                highThreats.forEachIndexed { index, threat ->
                    appendThreatDetails(sb, threat, index + 1)
                }
                sb.appendLine()
            }
            
            if (mediumThreats.isNotEmpty()) {
                sb.appendLine("MEDIUM THREATS (${mediumThreats.size})")
                sb.appendLine("----------------------------------------")
                mediumThreats.forEachIndexed { index, threat ->
                    appendThreatDetails(sb, threat, index + 1)
                }
                sb.appendLine()
            }
            
            if (lowThreats.isNotEmpty()) {
                sb.appendLine("LOW THREATS (${lowThreats.size})")
                sb.appendLine("----------------------------------------")
                lowThreats.forEachIndexed { index, threat ->
                    appendThreatDetails(sb, threat, index + 1)
                }
                sb.appendLine()
            }
        }
        
        // Recommendations
        val allRecommendations = report.detectedThreats.flatMap { it.recommendations }.distinct()
        if (allRecommendations.isNotEmpty()) {
            sb.appendLine("RECOMMENDATIONS")
            sb.appendLine("===============")
            allRecommendations.forEachIndexed { index, recommendation ->
                sb.appendLine("${index + 1}. $recommendation")
            }
            sb.appendLine()
        }
        
        // Security score
        val securityScore = calculateSecurityScore(report)
        sb.appendLine("SECURITY SCORE: ${String.format("%.1f", securityScore)}/100")
        when {
            securityScore >= 90 -> sb.appendLine("STATUS: EXCELLENT - Device is highly secure")
            securityScore >= 70 -> sb.appendLine("STATUS: GOOD - Device is reasonably secure")
            securityScore >= 50 -> sb.appendLine("STATUS: FAIR - Device has some security concerns")
            securityScore >= 30 -> sb.appendLine("STATUS: POOR - Device has significant security issues")
            else -> sb.appendLine("STATUS: CRITICAL - Device has severe security vulnerabilities")
        }
        
        sb.appendLine()
        sb.appendLine("========================================")
        sb.appendLine("          END OF SECURITY REPORT")
        sb.appendLine("========================================")
        
        return sb.toString()
    }
    
    /**
     * Generates a JSON representation of the security report.
     */
    fun generateJsonReport(report: SecurityReport): String {
        return com.google.gson.GsonBuilder()
            .setPrettyPrinting()
            .create()
            .toJson(report)
    }
    
    /**
     * Generates a summary report for quick overview.
     */
    fun generateSummaryReport(report: SecurityReport): String {
        val sb = StringBuilder()
        
        sb.appendLine("Caster Security Report Summary")
        sb.appendLine("==============================")
        sb.appendLine("Risk Level: ${report.securityStatus.riskLevel}")
        sb.appendLine("Threats Detected: ${report.detectedThreats.size}")
        sb.appendLine("Device Rooted: ${if (report.securityStatus.isRooted) "Yes" else "No"}")
        sb.appendLine("Emulator: ${if (report.securityStatus.isEmulator) "Yes" else "No"}")
        
        if (report.detectedThreats.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("Top Threats:")
            report.detectedThreats.take(3).forEach { threat ->
                sb.appendLine("- ${threat.description} (${threat.severity})")
            }
        }
        
        return sb.toString()
    }
    
    private fun appendThreatDetails(sb: StringBuilder, threat: ThreatInfo, index: Int) {
        sb.appendLine("$index. ${threat.description}")
        sb.appendLine("   Type: ${threat.type}")
        sb.appendLine("   Severity: ${threat.severity}")
        sb.appendLine("   Confidence: ${String.format("%.1f", threat.confidence * 100)}%")
        
        if (threat.detectionMethods.isNotEmpty()) {
            sb.appendLine("   Detection Methods:")
            threat.detectionMethods.take(5).forEach { method ->
                sb.appendLine("     - $method")
            }
            if (threat.detectionMethods.size > 5) {
                sb.appendLine("     ... and ${threat.detectionMethods.size - 5} more")
            }
        }
        
        if (threat.details.isNotEmpty()) {
            sb.appendLine("   Details:")
            threat.details.forEach { (key, value) ->
                sb.appendLine("     $key: $value")
            }
        }
        
        sb.appendLine()
    }
    
    private fun calculateSecurityScore(report: SecurityReport): Float {
        // Start with a base score
        var score = 100.0f
        
        // Deduct points based on risk level
        when (report.securityStatus.riskLevel) {
            RiskLevel.CRITICAL -> score -= 70
            RiskLevel.HIGH -> score -= 50
            RiskLevel.MEDIUM -> score -= 30
            RiskLevel.LOW -> score -= 10
            RiskLevel.NONE -> {} // No deduction
        }
        
        // Deduct points for each threat
        report.detectedThreats.forEach { threat ->
            when (threat.severity) {
                ThreatSeverity.CRITICAL -> score -= 25
                ThreatSeverity.HIGH -> score -= 15
                ThreatSeverity.MEDIUM -> score -= 8
                ThreatSeverity.LOW -> score -= 3
            }
        }
        
        // Ensure score doesn't go below 0
        return if (score < 0) 0.0f else score
    }
}