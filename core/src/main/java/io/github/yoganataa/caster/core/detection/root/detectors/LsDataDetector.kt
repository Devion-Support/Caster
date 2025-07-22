package io.github.yoganataa.caster.core.detection.root.detectors

import android.content.Context
import android.util.Log
import org.lsposed.lsparanoid.Obfuscate

@Obfuscate
class LsDataDetector(private val context: Context) {

    private val TAG = "LsDataDetector"

    init {
        System.loadLibrary("caster_native")
    }

    private external fun executeLsDataCommand(): String

    /**
     * Attempts to get a list of package names by executing 'ls /sdcard/Android/data' command.
     * This method is highly unreliable on non-rooted devices due to Android's security restrictions.
     *
     * @return A list of package names found, or an empty list if access is denied or an error occurs.
     */
    fun getPackagesFromLsData(): List<String> {
        val packageNames = mutableListOf<String>()
        try {
            val output = executeLsDataCommand()
            Log.d(TAG, "ls /sdcard/Android/data raw output: $output")

            if (output.isNotBlank() && !output.contains("Permission denied", ignoreCase = true)) {
                // Parse the output to extract package names
                // Assuming each line is a package name or an empty line
                output.lines().forEach { line ->
                    val trimmedLine = line.trim()
                    if (trimmedLine.isNotBlank()) {
                        packageNames.add(trimmedLine)
                    }
                }
                Log.d(TAG, "Successfully retrieved ${packageNames.size} package names from ls /sdcard/Android/data")
            } else {
                Log.w(TAG, "Access to /sdcard/Android/data denied or command failed.")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error executing ls /sdcard/Android/data command", e)
        }
        return packageNames
    }
}