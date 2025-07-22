package io.github.yoganataa.caster.core.detection.tampering

import io.github.yoganataa.caster.core.logging.Logger
import io.github.yoganataa.caster.core.logging.ThreatInfo
import io.github.yoganataa.caster.core.logging.ThreatType

/**
 * Detector for identifying tampering attempts, hooking frameworks, and debugger attachments.
 *
 * This class utilizes native checks to detect various forms of application tampering,
 * including `tracerpid` checks, common hooking framework signatures, and Frida server presence.
 */
class AntiTamperingDetector {

    private var isNativeLibraryLoaded = false

    init {
        try {
            // Load the native library when the class is first accessed.
            System.loadLibrary("toolChecker")
            isNativeLibraryLoaded = true
        } catch (e: UnsatisfiedLinkError) {
            Logger.getInstance().error("Failed to load native library 'toolChecker' for AntiTampering", e)
            // Optionally, add a threat here if the library is critical
        }
    }

    /**
     * Represents the result of the anti-tampering detection.
     *
     * @property isDebuggerAttached True if a debugger is detected, false otherwise.
     * @property isHookingDetected True if a hooking framework or other tampering signs are detected, false otherwise.
     * @property threats A list of [ThreatInfo] objects, providing detailed threat information.
     * @property detectedMethods A list of strings indicating the specific methods or signs that led to the detection.
     */
    data class Result(
        val isDebuggerAttached: Boolean,
        val isHookingDetected: Boolean,
        val threats: List<ThreatInfo>,
        val detectedMethods: List<String>
    )

    /**
     * Performs all anti-tampering checks.
     *
     * This function combines all native detection logic into a single call.
     * It checks for debugger attachment, hooking frameworks, and Frida server presence.
     *
     * @return A [Result] object summarizing the anti-tampering detection outcome.
     */
    fun detect(): Result {
        val threats = mutableListOf<ThreatInfo>()
        val detectedMethods = mutableListOf<String>()
        var isDebuggerAttached = false
        var isHookingDetected = false

        // Check if the native library was successfully loaded
        if (!isNativeLibraryLoaded) {
            threats.add(ThreatInfo(ThreatType.CONFIGURATION_ERROR, "Native anti-tampering checks unavailable", "LOW", mapOf("reason" to "Native library 'toolChecker' failed to load")))
            return Result(false, false, threats, emptyList())
        }

        try {
            if (checkForTracerPid() == 1) {
                val sign = "Debugger Attached (TracerPid > 0)"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.DEBUGGING, sign, "CRITICAL"))
                isDebuggerAttached = true
            }

            if (checkForHookingFrameworks() == 1) {
                val sign = "Hooking Framework Detected (frida/xposed in maps)"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.TAMPERING, sign, "CRITICAL"))
                isHookingDetected = true
            }

            if (checkForFridaPort() == 1) {
                val sign = "Frida Server Port (27042) is Open"
                detectedMethods.add(sign)
                threats.add(ThreatInfo(ThreatType.TAMPERING, sign, "CRITICAL"))
                isHookingDetected = true // Detection of Frida also indicates hooking/tampering
            }
        } catch (t: Throwable) {
            Logger.getInstance().error("Error during native anti-tampering detection", t)
            threats.add(ThreatInfo(ThreatType.RUNTIME_ERROR, "Error during native anti-tampering checks", "HIGH", mapOf("exception" to t.javaClass.simpleName, "message" to (t.message ?: "Unknown"))))
        }

        return Result(
            isDebuggerAttached = isDebuggerAttached,
            isHookingDetected = isHookingDetected,
            threats = threats,
            detectedMethods = detectedMethods.distinct()
        )
    }

    // ================================
    // JNI Native Function Declarations
    // ================================
    private external fun checkForTracerPid(): Int
    private external fun checkForHookingFrameworks(): Int
    private external fun checkForFridaPort(): Int
}