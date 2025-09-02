#ifndef CASTER_ROOT_DETECTOR_H
#define CASTER_ROOT_DETECTOR_H

#include "../caster_detector.h"
#include <jni.h>
#include <string>
#include <vector>

// ================================
// Root Detection Functions
// ================================

/**
 * @brief Checks for the presence of root binaries in specified paths.
 *
 * @param paths Array of paths to check for root binaries.
 * @param pathCount Number of paths in the array.
 * @return 1 if root binaries are found, 0 otherwise.
 */
int checkForRootBinaries(const char* paths[], int pathCount);

/**
 * @brief Checks for Magisk-specific files and directories.
 *
 * @return 1 if Magisk artifacts are found, 0 otherwise.
 */
std::vector<std::string> checkForMagiskArtifacts();

/**
 * @brief Checks for the presence of Magisk via its Unix Domain Socket.
 *
 * @return 1 if Magisk UDS is detected, 0 otherwise.
 */
std::vector<std::string> checkForMagiskUDS();

/**
 * @brief Checks for SuperSU-specific files and directories.
 *
 * @return 1 if SuperSU artifacts are found, 0 otherwise.
 */
std::vector<std::string> checkForSuperSUArtifacts();

/**
 * @brief Checks for KernelSU-specific files and directories.
 *
 * @return 1 if KernelSU artifacts are found, 0 otherwise.
 */
std::vector<std::string> checkForKernelSUArtifacts();

/**
 * @brief Performs comprehensive root detection.
 *
 * @return RootDetectionResult containing the detection results.
 */
RootDetectionResult detectRoot();

#endif //CASTER_ROOT_DETECTOR_H