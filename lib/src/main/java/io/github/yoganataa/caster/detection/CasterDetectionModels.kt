package io.github.yoganataa.caster.detection

/**
 * Data class to hold all detection results.
 */
data class CasterDetectionResult(
    val rootResult: RootDetectionResult,
    val emulatorResult: EmulatorResult,
    val integrityResult: IntegrityResult,
    val antiTamperingResult: AntiTamperingResult,
    val maliciousAppResult: MaliciousAppResult,
    val flagSecureResult: FlagSecureResult
)

data class RootDetectionResult(
    val isRooted: Boolean,
    val detectedMethods: List<String>,
    val confidence: Float
)

data class EmulatorResult(
    val isEmulator: Boolean,
    val detectedMethods: List<String>,
    val confidence: Float
)

data class IntegrityResult(
    val isTampered: Boolean,
    val detectedMethods: List<String>,
)

data class AntiTamperingResult(
    val isDebuggerAttached: Boolean,
    val isHookingDetected: Boolean,
    val detectedMethods: List<String>,
)

data class MaliciousAppResult(
    val hasMaliciousApps: Boolean,
    val detectedApps: List<String>,
    val riskScore: Float
)

data class FlagSecureResult(
    val isFlagSecureDisabled: Boolean,
    val detectedMethods: List<String>,
    val confidence: Float
)