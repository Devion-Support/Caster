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
 * @return 1 if emulator properties are detected, 0 otherwise.
 */
int checkEmulatorProperties();

/**
 * @brief Checks for emulator-specific files.
 *
 * @return 1 if emulator files are detected, 0 otherwise.
 */
int checkEmulatorFiles();

/**
 * @brief Checks for emulator-specific hardware characteristics.
 *
 * @return 1 if emulator hardware is detected, 0 otherwise.
 */
int checkEmulatorHardware();

/**
 * @brief Checks for emulator-specific sensors.
 *
 * @return 1 if emulator sensors are detected, 0 otherwise.
 */
int checkEmulatorSensors();

/**
 * @brief Performs comprehensive emulator detection.
 *
 * @return EmulatorDetectionResult containing the detection results.
 */
EmulatorDetectionResult detectEmulator();

#endif //CASTER_EMULATOR_DETECTOR_H