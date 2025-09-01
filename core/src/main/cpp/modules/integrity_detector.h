#ifndef CASTER_INTEGRITY_DETECTOR_H
#define CASTER_INTEGRITY_DETECTOR_H

#include "../caster_detector.h"
#include <jni.h>
#include <string>
#include <vector>

// ================================
// Integrity Detection Functions
// ================================

/**
 * @brief Checks application signature integrity.
 *
 * @param packageName The package name of the application to check.
 * @return 1 if signature tampering is detected, 0 otherwise.
 */
int checkSignatureIntegrity(const char* packageName);

/**
 * @brief Checks for APK modification.
 *
 * @param packageName The package name of the application to check.
 * @return 1 if APK modification is detected, 0 otherwise.
 */
int checkApkModification(const char* packageName);

/**
 * @brief Checks for debuggable flag in application manifest.
 *
 * @param packageName The package name of the application to check.
 * @return 1 if debuggable flag is set, 0 otherwise.
 */
int checkDebuggableFlag(const char* packageName);

/**
 * @brief Performs comprehensive integrity detection.
 *
 * @param packageName The package name of the application to check.
 * @return IntegrityDetectionResult containing the detection results.
 */
IntegrityDetectionResult detectIntegrity(const char* packageName);

#endif //CASTER_INTEGRITY_DETECTOR_H