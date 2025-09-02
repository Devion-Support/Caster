#ifndef CASTER_ANTI_TAMPERING_DETECTOR_H
#define CASTER_ANTI_TAMPERING_DETECTOR_H

#include "../caster_detector.h"
#include <jni.h>
#include <string>
#include <vector>

// ================================
// Anti-Tampering Detection Functions
// ================================

/**
 * @brief Checks for TracerPid in /proc/self/status to detect debugger attachment.
 *
 * @return true if debugging is detected (TracerPid > 0), false otherwise.
 */
bool checkForTracerPid();

/**
 * @brief Checks for the presence of hooking frameworks by inspecting /proc/self/maps.
 *
 * @return Vector of detected hooking frameworks.
 */
std::vector<std::string> checkForHookingFrameworks();

/**
 * @brief Checks for the presence of Frida-specific artifacts.
 *
 * @return Vector of detected Frida artifacts.
 */
std::vector<std::string> checkForFridaArtifacts();

/**
 * @brief Checks if a Frida server is running by attempting a TCP connection.
 *
 * @return true if a Frida server is detected, false otherwise.
 */
bool checkForFridaPort();

/**
 * @brief Checks for emulator-specific debugging artifacts.
 *
 * @return true if debugging artifacts are detected, false otherwise.
 */
bool checkForDebuggingArtifacts();

/**
 * @brief Checks for common reverse engineering tools and artifacts.
 *
 * @return Vector of detected reverse engineering tools.
 */
std::vector<std::string> checkForReverseEngineeringTools();

/**
 * @brief Performs timing checks to detect instrumentation.
 *
 * @return true if timing anomalies are detected, false otherwise.
 */
bool checkForTimingAnomalies();

/**
 * @brief Performs comprehensive anti-tampering detection.
 *
 * @return AntiTamperingResult containing the detection results.
 */
AntiTamperingResult detectAntiTampering();

#endif //CASTER_ANTI_TAMPERING_DETECTOR_H