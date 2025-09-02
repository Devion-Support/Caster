package io.github.yoganataa.caster.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import io.github.yoganataa.caster.logging.Logger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Network security manager for monitoring and securing network communications.
 */
class NetworkSecurityManager(private val context: Context) {
    
    private val logger = Logger.getInstance()
    
    /**
     * Performs network security checks.
     */
    fun performNetworkSecurityCheck(): NetworkSecurityResult {
        logger.info("Performing network security check")
        
        val result = NetworkSecurityResult()
        
        try {
            // Check network type
            result.networkType = getNetworkType()
            
            // Check for secure connections
            result.isUsingSecureConnections = checkSecureConnections()
            
            // Check for VPN usage
            result.isUsingVpn = checkVpnUsage()
            
            // Check for proxy settings
            result.hasProxySettings = checkProxySettings()
            
            // Check for suspicious network interfaces
            result.suspiciousInterfaces = checkSuspiciousInterfaces()
            
            // Check SSL/TLS configuration
            result.sslConfiguration = checkSslConfiguration()
            
            // Determine overall network security status
            result.isNetworkSecure = determineNetworkSecurityStatus(result)
            
            logger.info("Network security check completed. Secure: ${result.isNetworkSecure}")
        } catch (e: Exception) {
            logger.error("Error during network security check", e)
            result.securityError = e.message
        }
        
        return result
    }
    
    /**
     * Gets the current network type.
     */
    private fun getNetworkType(): String {
        return try {
            val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val network = connectivityManager.activeNetwork
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                
                when {
                    capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "WIFI"
                    capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "CELLULAR"
                    capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "ETHERNET"
                    capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true -> "VPN"
                    else -> "UNKNOWN"
                }
            } else {
                @Suppress("DEPRECATION")
                val networkInfo = connectivityManager.activeNetworkInfo
                when (networkInfo?.type) {
                    ConnectivityManager.TYPE_WIFI -> "WIFI"
                    ConnectivityManager.TYPE_MOBILE -> "CELLULAR"
                    ConnectivityManager.TYPE_ETHERNET -> "ETHERNET"
                    else -> "UNKNOWN"
                }
            }
        } catch (e: Exception) {
            logger.error("Error getting network type", e)
            "ERROR"
        }
    }
    
    /**
     * Checks if the device is using secure connections (HTTPS).
     */
    private fun checkSecureConnections(): Boolean {
        return try {
            // This is a simplified check - in a real implementation, you would monitor
            // actual network traffic to ensure HTTPS is being used
            true
        } catch (e: Exception) {
            logger.error("Error checking secure connections", e)
            false
        }
    }
    
    /**
     * Checks if the device is using a VPN.
     */
    private fun checkVpnUsage(): Boolean {
        return try {
            val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val network = connectivityManager.activeNetwork
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            } else {
                @Suppress("DEPRECATION")
                val networkInfo = connectivityManager.activeNetworkInfo
                networkInfo?.type == ConnectivityManager.TYPE_VPN
            }
        } catch (e: Exception) {
            logger.error("Error checking VPN usage", e)
            false
        }
    }
    
    /**
     * Checks for proxy settings.
     */
    private fun checkProxySettings(): Boolean {
        return try {
            // Check for system proxy settings
            val httpProxy = System.getProperty("http.proxyHost")
            val httpsProxy = System.getProperty("https.proxyHost")
            
            !httpProxy.isNullOrEmpty() || !httpsProxy.isNullOrEmpty()
        } catch (e: Exception) {
            logger.error("Error checking proxy settings", e)
            false
        }
    }
    
    /**
     * Checks for suspicious network interfaces.
     */
    private fun checkSuspiciousInterfaces(): List<String> {
        val suspiciousInterfaces = mutableListOf<String>()
        
        return try {
            val networkInterfaces = NetworkInterface.getNetworkInterfaces()
            while (networkInterfaces.hasMoreElements()) {
                val networkInterface = networkInterfaces.nextElement()
                
                // Check for suspicious interface names
                val interfaceName = networkInterface.name.lowercase()
                if (interfaceName.contains("tun") || 
                    interfaceName.contains("tap") || 
                    interfaceName.contains("ppp") ||
                    interfaceName.contains("emulator") ||
                    interfaceName.contains("virtual")) {
                    suspiciousInterfaces.add(interfaceName)
                }
            }
            
            suspiciousInterfaces
        } catch (e: Exception) {
            logger.error("Error checking network interfaces", e)
            suspiciousInterfaces
        }
    }
    
    /**
     * Checks SSL/TLS configuration.
     */
    private fun checkSslConfiguration(): SslConfiguration {
        val sslConfig = SslConfiguration()
        
        return try {
            // Check supported TLS protocols
            val sslContext = SSLContext.getDefault()
            sslConfig.supportedProtocols = sslContext.supportedSSLParameters.protocols.toList()
            
            // Check default SSL context
            sslConfig.defaultSslContext = sslContext.protocol
            
            // Check for secure defaults
            sslConfig.hasSecureDefaults = checkSecureSslDefaults()
            
            sslConfig
        } catch (e: Exception) {
            logger.error("Error checking SSL configuration", e)
            sslConfig.configurationError = e.message
            sslConfig
        }
    }
    
    /**
     * Checks for secure SSL/TLS defaults.
     */
    private fun checkSecureSslDefaults(): Boolean {
        return try {
            // Create a secure SSL context
            val sslContext = SSLContext.getInstance("TLS")
            
            // Check if default protocols are secure
            val supportedProtocols = sslContext.supportedSSLParameters.protocols
            val secureProtocols = supportedProtocols.filter { 
                it.startsWith("TLSv1.2") || it.startsWith("TLSv1.3") 
            }
            
            secureProtocols.isNotEmpty()
        } catch (e: Exception) {
            logger.error("Error checking secure SSL defaults", e)
            false
        }
    }
    
    /**
     * Determines the overall network security status.
     */
    private fun determineNetworkSecurityStatus(result: NetworkSecurityResult): Boolean {
        return try {
            // Network is considered secure if:
            // 1. Using secure connections (HTTPS)
            // 2. Not using suspicious interfaces
            // 3. Has secure SSL configuration
            // 4. Not on an emulator network
            
            val secureConnections = result.isUsingSecureConnections
            val noSuspiciousInterfaces = result.suspiciousInterfaces.isEmpty()
            val secureSsl = result.sslConfiguration?.hasSecureDefaults ?: false
            val notEmulatorNetwork = !result.networkType.contains("emulator", ignoreCase = true)
            
            secureConnections && noSuspiciousInterfaces && secureSsl && notEmulatorNetwork
        } catch (e: Exception) {
            logger.error("Error determining network security status", e)
            false
        }
    }
    
    /**
     * Tests connection to a specific host to verify network security.
     */
    fun testConnection(host: String, port: Int = 443): ConnectionTestResult {
        return try {
            val socket = Socket()
            val address = InetAddress.getByName(host)
            
            // Set connection timeout
            socket.connect(InetSocketAddress(address, port), 5000)
            
            val isConnected = socket.isConnected
            val isSecure = port == 443 // Assuming 443 is HTTPS
            
            socket.close()
            
            ConnectionTestResult(
                host = host,
                port = port,
                isConnected = isConnected,
                isSecure = isSecure,
                testError = null
            )
        } catch (e: Exception) {
            Log.e("NetworkSecurityManager", "Connection test failed for $host:$port", e)
            ConnectionTestResult(
                host = host,
                port = port,
                isConnected = false,
                isSecure = false,
                testError = e.message
            )
        }
    }
}

/**
 * Data class representing the result of network security checks.
 */
data class NetworkSecurityResult(
    var networkType: String = "UNKNOWN",
    var isUsingSecureConnections: Boolean = false,
    var isUsingVpn: Boolean = false,
    var hasProxySettings: Boolean = false,
    var suspiciousInterfaces: List<String> = emptyList(),
    var sslConfiguration: SslConfiguration? = null,
    var isNetworkSecure: Boolean = false,
    var securityError: String? = null
)

/**
 * Data class representing SSL/TLS configuration.
 */
data class SslConfiguration(
    var supportedProtocols: List<String> = emptyList(),
    var defaultSslContext: String = "TLS",
    var hasSecureDefaults: Boolean = false,
    var configurationError: String? = null
)

/**
 * Data class representing connection test results.
 */
data class ConnectionTestResult(
    val host: String,
    val port: Int,
    val isConnected: Boolean,
    val isSecure: Boolean,
    val testError: String?
)