package io.github.yoganataa.caster.logging

import android.util.Log
import com.google.gson.Gson
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class Logger private constructor() {

    companion object {
        private const val TAG = "CasterSecurity"
        private var instance: Logger? = null
        private var logEndpoint: String? = null
        private var logLevel: LogLevel = LogLevel.INFO
        private val gson = Gson()
        private val httpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()

        fun getInstance(): Logger {
            return instance ?: synchronized(this) {
                instance ?: Logger().also { instance = it }
            }
        }

        fun configure(endpoint: String?, minLogLevel: LogLevel = LogLevel.INFO) {
            logEndpoint = endpoint
            logLevel = minLogLevel
        }
    }

    fun debug(message: String, throwable: Throwable? = null) {
        log(LogLevel.DEBUG, message, throwable)
    }

    fun info(message: String, throwable: Throwable? = null) {
        log(LogLevel.INFO, message, throwable)
    }

    fun warn(message: String, throwable: Throwable? = null) {
        log(LogLevel.WARN, message, throwable)
    }

    fun error(message: String, throwable: Throwable? = null) {
        log(LogLevel.ERROR, message, throwable)
    }

    private fun log(level: LogLevel, message: String, throwable: Throwable?) {
        if (level.priority >= logLevel.priority) {
            when (level) {
                LogLevel.DEBUG -> Log.d(TAG, message, throwable)
                LogLevel.INFO -> Log.i(TAG, message, throwable)
                LogLevel.WARN -> Log.w(TAG, message, throwable)
                LogLevel.ERROR -> Log.e(TAG, message, throwable)
            }
        }
    }

    fun sendSecurityReport(report: SecurityReport, callback: ((Boolean, String?) -> Unit)? = null) {
        logEndpoint?.let { endpoint ->
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val json = gson.toJson(report)
                    val requestBody = json.toRequestBody("application/json".toMediaType())

                    val request = Request.Builder()
                        .url(endpoint)
                        .post(requestBody)
                        .addHeader("Content-Type", "application/json")
                        .addHeader("User-Agent", "CasterSecurity/1.0")
                        .build()

                    val response = httpClient.newCall(request).execute()
                    val success = response.isSuccessful
                    val message = if (success) "Report sent successfully" else "Failed to send report: ${response.code}"

                    CoroutineScope(Dispatchers.Main).launch {
                        callback?.invoke(success, message)
                    }

                    response.close()
                } catch (e: Exception) {
                    error("Failed to send security report", e)
                    CoroutineScope(Dispatchers.Main).launch {
                        callback?.invoke(false, e.message)
                    }
                }
            }
        } ?: run {
            warn("No log endpoint configured")
            callback?.invoke(false, "No endpoint configured")
        }
    }
}