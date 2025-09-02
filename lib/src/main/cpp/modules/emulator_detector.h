#ifndef CASTER_EMULATOR_DETECTOR_H
#define CASTER_EMULATOR_DETECTOR_H

#include "../caster_detector.h"
#include <jni.h>
#include <string>
#include <vector>

// ================================
// Emulator Detection Functions
// ================================

/**
 * @brief Checks system properties for emulator indicators.
 *
 * @return Vector of detected emulator properties.
 */
std::vector<std::string> checkEmulatorProperties();

/**
 * @brief Checks for emulator-specific files.
 *
 * @return Vector of detected emulator files.
 */
std::vector<std::string> checkEmulatorFiles();

/**
 * @brief Checks for emulator-specific hardware characteristics.
 *
 * @return 1 if emulator hardware is detected, 0 otherwise.
 */
int checkEmulatorHardware();

/**
 * @brief Checks for emulator-specific network interfaces.
 *
 * @return Vector of detected suspicious network interfaces.
 */
std::vector<std::string> checkEmulatorNetworkInterfaces();

/**
 * @brief Performs comprehensive emulator detection.
 *
 * @return EmulatorDetectionResult containing the detection results.
 */
EmulatorDetectionResult detectEmulator();

#endif //CASTER_EMULATOR_DETECTOR_H