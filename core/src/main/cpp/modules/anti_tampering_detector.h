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
 * @return 1 if debugging is detected (TracerPid > 0), 0 otherwise.
 */
int checkForTracerPid();

/**
 * @brief Checks for the presence of hooking frameworks by inspecting /proc/self/maps.
 *
 * @return 1 if a hooking framework is detected, 0 otherwise.
 */
int checkForHookingFrameworks();

/**
 * @brief Checks if a Frida server is running by attempting a TCP connection.
 *
 * @return 1 if a Frida server is detected, 0 otherwise.
 */
int checkForFridaPort();

/**
 * @brief Checks for emulator-specific debugging artifacts.
 *
 * @return 1 if debugging artifacts are detected, 0 otherwise.
 */
int checkForDebuggingArtifacts();

/**
 * @brief Performs comprehensive anti-tampering detection.
 *
 * @return AntiTamperingResult containing the detection results.
 */
AntiTamperingResult detectAntiTampering();

#endif //CASTER_ANTI_TAMPERING_DETECTOR_H