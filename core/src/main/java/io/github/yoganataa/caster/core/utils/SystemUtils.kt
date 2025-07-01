package io.github.yoganataa.caster.core.utils

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.BufferedReader
import java.io.InputStreamReader

object SystemUtils {

    fun getSystemProperty(property: String): String? {
        return try {
            val process = Runtime.getRuntime().exec("getprop $property")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            reader.close()
            process.waitFor()
            result?.takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            null
        }
    }

    fun executeCommand(command: String): String? {
        return try {
            val process = Runtime.getRuntime().exec(command)
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            reader.close()
            process.waitFor()
            output.takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            null
        }
    }

    fun isPackageInstalled(context: Context, packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    fun getInstalledPackages(context: Context): List<String> {
        return try {
            context.packageManager.getInstalledPackages(0)
                .map { it.packageName }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun isDebuggingEnabled(context: Context): Boolean {
        return Settings.Secure.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED, 0
        ) == 1
    }

    fun getKernelVersion(): String? {
        return try {
            val process = Runtime.getRuntime().exec("cat /proc/version")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val version = reader.readLine()
            reader.close()
            process.waitFor()
            version
        } catch (e: Exception) {
            null
        }
    }

    fun getBuildInfo(): Map<String, String> {
        return mapOf(
            "model" to Build.MODEL,
            "manufacturer" to Build.MANUFACTURER,
            "brand" to Build.BRAND,
            "device" to Build.DEVICE,
            "board" to Build.BOARD,
            "hardware" to Build.HARDWARE,
            "product" to Build.PRODUCT,
            "fingerprint" to Build.FINGERPRINT,
            "bootloader" to Build.BOOTLOADER,
            "radio" to (Build.getRadioVersion() ?: "unknown")
        )
    }
}