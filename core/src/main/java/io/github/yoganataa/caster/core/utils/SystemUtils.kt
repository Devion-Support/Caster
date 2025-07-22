package io.github.yoganataa.caster.core.utils

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Utility object for common system-related operations.
 */
object SystemUtils {

    /**
     * Retrieves the value of a system property.
     *
     * @param property The name of the system property to retrieve (e.g., "ro.build.version.release").
     * @return The value of the system property as a String, or null if the property is not found or an error occurs.
     */
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

    /**
     * Executes a shell command and returns its output.
     *
     * @param command The shell command to execute (e.g., "ls -l /system/bin").
     * @return The output of the command as a String, or null if an error occurs or the output is blank.
     */
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

    /**
     * Checks if a specific package is installed on the device.
     *
     * @param context The application context.
     * @param packageName The package name to check.
     * @return True if the package is installed, false otherwise.
     */
    fun isPackageInstalled(context: Context, packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    /**
     * Retrieves a list of all installed package names on the device.
     *
     * @param context The application context.
     * @return A list of package names as Strings, or an empty list if an error occurs.
     */
    fun getInstalledPackages(context: Context): List<String> {
        return try {
            context.packageManager.getInstalledPackages(0)
                .map { it.packageName }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Checks if USB debugging is currently enabled on the device.
     *
     * @param context The application context.
     * @return True if debugging is enabled, false otherwise.
     */
    fun isDebuggingEnabled(context: Context): Boolean {
        return Settings.Secure.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED, 0
        ) == 1
    }

    /**
     * Retrieves the kernel version of the Android device.
     *
     * @return The kernel version as a String, or null if it cannot be retrieved.
     */
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

    /**
     * Retrieves various build information about the device.
     *
     * @return A Map containing build properties like model, manufacturer, brand, etc.
     */
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