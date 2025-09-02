#ifndef CASTER_MALICIOUS_APP_DETECTOR_H
#define CASTER_MALICIOUS_APP_DETECTOR_H

#include "../caster_detector.h"
#include <jni.h>
#include <string>
#include <vector>

// ================================
// Malicious App Detection Functions
// ================================

/**
 * @brief Scans for known malicious app packages.
 *
 * @return 1 if malicious apps are detected, 0 otherwise.
 */
std::vector<std::string> scanForMaliciousApps();

/**
 * @brief Checks for suspicious app permissions.
 *
 * @return 1 if suspicious permissions are detected, 0 otherwise.
 */
int checkSuspiciousPermissions();

/**
 * @brief Checks for apps with debuggable flag set.
 *
 * @return 1 if debuggable apps are detected, 0 otherwise.
 */
std::vector<std::string> checkDebuggableApps();

/**
 * @brief Performs comprehensive malicious app detection.
 *
 * @return MaliciousAppResult containing the detection results.
 */
MaliciousAppResult detectMaliciousApps();

#endif //CASTER_MALICIOUS_APP_DETECTOR_H