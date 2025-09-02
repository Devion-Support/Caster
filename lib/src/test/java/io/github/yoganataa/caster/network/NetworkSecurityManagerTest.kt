package io.github.yoganataa.caster.network

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config

@RunWith(AndroidJUnit4::class)
@Config(sdk = [28])
class NetworkSecurityManagerTest {

    private lateinit var context: Context
    private lateinit var networkSecurityManager: NetworkSecurityManager

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        networkSecurityManager = NetworkSecurityManager(context)
    }

    @Test
    fun `NetworkSecurityManager should be created successfully`() {
        assertThat(networkSecurityManager).isNotNull()
    }

    @Test
    fun `performNetworkSecurityCheck should return valid result`() {
        val result = networkSecurityManager.performNetworkSecurityCheck()
        
        assertThat(result).isNotNull()
        assertThat(result.networkType).isNotNull()
        assertThat(result.isUsingSecureConnections).isNotNull()
        assertThat(result.isUsingVpn).isNotNull()
        assertThat(result.hasProxySettings).isNotNull()
        assertThat(result.suspiciousInterfaces).isNotNull()
        assertThat(result.sslConfiguration).isNotNull()
        assertThat(result.isNetworkSecure).isNotNull()
    }

    @Test
    fun `getNetworkType should return valid type`() {
        // Use reflection to access private method
        val method = NetworkSecurityManager::class.java.getDeclaredMethod("getNetworkType")
        method.isAccessible = true
        val networkType = method.invoke(networkSecurityManager) as String
        
        assertThat(networkType).isNotNull()
        // In Robolectric environment, it might be "UNKNOWN" or "ERROR"
        assertThat(networkType).isIn(listOf("UNKNOWN", "ERROR", "WIFI", "CELLULAR", "ETHERNET"))
    }

    @Test
    fun `checkSecureConnections should return boolean`() {
        // Use reflection to access private method
        val method = NetworkSecurityManager::class.java.getDeclaredMethod("checkSecureConnections")
        method.isAccessible = true
        val isSecure = method.invoke(networkSecurityManager) as Boolean
        
        assertThat(isSecure).isNotNull()
    }

    @Test
    fun `checkVpnUsage should return boolean`() {
        // Use reflection to access private method
        val method = NetworkSecurityManager::class.java.getDeclaredMethod("checkVpnUsage")
        method.isAccessible = true
        val isUsingVpn = method.invoke(networkSecurityManager) as Boolean
        
        assertThat(isUsingVpn).isNotNull()
    }

    @Test
    fun `checkProxySettings should return boolean`() {
        // Use reflection to access private method
        val method = NetworkSecurityManager::class.java.getDeclaredMethod("checkProxySettings")
        method.isAccessible = true
        val hasProxy = method.invoke(networkSecurityManager) as Boolean
        
        assertThat(hasProxy).isNotNull()
    }

    @Test
    fun `checkSslConfiguration should return valid configuration`() {
        // Use reflection to access private method
        val method = NetworkSecurityManager::class.java.getDeclaredMethod("checkSslConfiguration")
        method.isAccessible = true
        val sslConfig = method.invoke(networkSecurityManager) as SslConfiguration
        
        assertThat(sslConfig).isNotNull()
        assertThat(sslConfig.supportedProtocols).isNotNull()
        assertThat(sslConfig.defaultSslContext).isNotNull()
        assertThat(sslConfig.hasSecureDefaults).isNotNull()
    }

    @Test
    fun `testConnection should return valid result`() {
        // Test with a known host
        val result = networkSecurityManager.testConnection("google.com", 443)
        
        assertThat(result).isNotNull()
        assertThat(result.host).isEqualTo("google.com")
        assertThat(result.port).isEqualTo(443)
        assertThat(result.isConnected).isNotNull()
        assertThat(result.isSecure).isNotNull()
    }
}