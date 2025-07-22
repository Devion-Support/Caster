package io.github.yoganataa.caster.core.utils

import java.io.File

/**
 * Utility object for common file system operations.
 */
object FileUtils {

    /**
     * Checks if a file or directory exists at the specified path.
     *
     * @param path The absolute path to the file or directory.
     * @return True if the file or directory exists, false otherwise.
     */
    fun fileExists(path: String): Boolean {
        return try {
            File(path).exists()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks if a file at the specified path is readable.
     *
     * @param path The absolute path to the file.
     * @return True if the file is readable, false otherwise.
     */
    fun isFileReadable(path: String): Boolean {
        return try {
            File(path).canRead()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks if a file at the specified path is executable.
     *
     * @param path The absolute path to the file.
     * @return True if the file is executable, false otherwise.
     */
    fun isFileExecutable(path: String): Boolean {
        return try {
            File(path).canExecute()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Reads the content of a text file at the specified path.
     *
     * @param path The absolute path to the text file.
     * @return The content of the file as a String, or null if an error occurs.
     */
    fun readFile(path: String): String? {
        return try {
            File(path).readText()
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Lists the names of files and subdirectories within a specified directory.
     *
     * @param directory The absolute path to the directory.
     * @return A list of names of files and subdirectories, or an empty list if an error occurs or the directory is empty.
     */
    fun listFiles(directory: String): List<String> {
        return try {
            File(directory).listFiles()?.map { it.name } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Checks for the presence of common `su` binaries in known locations.
     *
     * @return A list of paths where `su` binaries were found.
     */
    fun checkSuBinary(): List<String> {
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/system/app/SuperSU/SuperSU.apk",
            "/data/local/bin/su",
            "/data/local/xbin/su"
        )

        return suPaths.filter { fileExists(it) }
    }

    /**
     * Checks for the presence of common Magisk-related files in known locations.
     *
     * @return A list of paths where Magisk files were found.
     */
    fun checkMagiskFiles(): List<String> {
        val magiskPaths = listOf(
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/data/adb/magisk",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/magisk.apk",
            "/data/adb/modules"
        )

        return magiskPaths.filter { fileExists(it) }
    }

    /**
     * Checks for the presence of common KernelSU-related files in known locations.
     *
     * @return A list of paths where KernelSU files were found.
     */
    fun checkKernelSuFiles(): List<String> {
        val kernelSuPaths = listOf(
            "/data/adb/ksu",
            "/data/adb/ksud",
            "/dev/kernelsu",
            "/sys/kernel/security/kernelsu"
        )

        return kernelSuPaths.filter { fileExists(it) }
    }
}