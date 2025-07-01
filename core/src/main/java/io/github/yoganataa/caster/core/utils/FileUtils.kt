package io.github.yoganataa.caster.core.utils

import java.io.File

object FileUtils {

    fun fileExists(path: String): Boolean {
        return try {
            File(path).exists()
        } catch (e: Exception) {
            false
        }
    }

    fun isFileReadable(path: String): Boolean {
        return try {
            File(path).canRead()
        } catch (e: Exception) {
            false
        }
    }

    fun isFileExecutable(path: String): Boolean {
        return try {
            File(path).canExecute()
        } catch (e: Exception) {
            false
        }
    }

    fun readFile(path: String): String? {
        return try {
            File(path).readText()
        } catch (e: Exception) {
            null
        }
    }

    fun listFiles(directory: String): List<String> {
        return try {
            File(directory).listFiles()?.map { it.name } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

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