package io.github.yoganataa.caster.network

import android.util.Log
import io.github.yoganataa.caster.CasterConfig
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Response
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * Secure HTTP client for sending security reports to remote endpoints.
 */
class SecureHttpClient(private val config: CasterConfig) {
    
    private val client: OkHttpClient
    
    init {
        client = createSecureClient()
    }
    
    /**
     * Creates a secure HTTP client with proper SSL configuration.
     */
    private fun createSecureClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .followRedirects(false)
            .followSslRedirects(false)
        
        // Add custom headers if provided
        if (config.customHeaders.isNotEmpty()) {
            builder.addInterceptor { chain ->
                val request = chain.request().newBuilder()
                config.customHeaders.forEach { (key, value) ->
                    request.addHeader(key, value)
                }
                chain.proceed(request.build())
            }
        }
        
        return builder.build()
    }
    
    /**
     * Sends a security report to the configured endpoint securely.
     */
    fun sendSecurityReport(reportJson: String): Boolean {
        return try {
            val endpoint = config.logEndpoint ?: return false
            
            // Validate URL format
            val url = URL(endpoint)
            if (url.protocol != "https") {
                Log.w("SecureHttpClient", "Security reports should only be sent over HTTPS")
                return false
            }
            
            val requestBody = RequestBody.create("application/json".toMediaType(), reportJson)
            val request = Request.Builder()
                .url(endpoint)
                .post(requestBody)
                .addHeader("Content-Type", "application/json")
                .addHeader("User-Agent", "Caster-Security-Client/1.0")
                .build()
            
            client.newCall(request).execute().use { response ->
                handleResponse(response)
            }
        } catch (e: Exception) {
            Log.e("SecureHttpClient", "Failed to send security report", e)
            false
        }
    }
    
    /**
     * Handles the HTTP response from the server.
     */
    private fun handleResponse(response: Response): Boolean {
        return try {
            when {
                response.isSuccessful -> {
                    Log.d("SecureHttpClient", "Security report sent successfully. Response: ${response.code}")
                    true
                }
                response.code >= 400 -> {
                    Log.w("SecureHttpClient", "Server returned error: ${response.code} - ${response.message}")
                    false
                }
                else -> {
                    Log.w("SecureHttpClient", "Unexpected response code: ${response.code}")
                    false
                }
            }
        } finally {
            response.close()
        }
    }
    
    /**
     * Performs certificate pinning for enhanced security.
     * In a production implementation, you would add specific certificate fingerprints here.
     */
    private fun createPinnedClient(): OkHttpClient {
        // This is a placeholder for certificate pinning implementation
        // In a real implementation, you would add specific certificate fingerprints
        return OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}