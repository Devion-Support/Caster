#ifndef CASTER_FLAG_SECURE_DETECTOR_H
#define CASTER_FLAG_SECURE_DETECTOR_H

#include "../caster_detector.h"
#include <jni.h>
#include <string>
#include <vector>

// ================================
// Flag Secure Detection Functions
// ================================

/**
 * @brief Checks if FLAG_SECURE is disabled for the application.
 *
 * @return 1 if FLAG_SECURE is disabled, 0 otherwise.
 */
int checkFlagSecureDisabled();

/**
 * @brief Checks for screenshot protection bypass.
 *
 * @return 1 if screenshot protection is bypassed, 0 otherwise.
 */
int checkScreenshotProtection();

/**
 * @brief Performs comprehensive flag secure detection.
 *
 * @return FlagSecureResult containing the detection results.
 */
FlagSecureResult detectFlagSecure();

#endif //CASTER_FLAG_SECURE_DETECTOR_H