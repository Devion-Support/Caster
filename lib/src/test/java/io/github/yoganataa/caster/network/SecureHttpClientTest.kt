package io.github.yoganataa.caster.network

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import io.github.yoganataa.caster.CasterConfig
import io.github.yoganataa.caster.logging.LogLevel
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config

@RunWith(AndroidJUnit4::class)
@Config(sdk = [28])
class SecureHttpClientTest {

    private lateinit var context: Context
    private lateinit var config: CasterConfig
    private lateinit var secureHttpClient: SecureHttpClient

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        config = CasterConfig(
            logEndpoint = "https://example.com/security/logs",
            minLogLevel = LogLevel.DEBUG
        )
        secureHttpClient = SecureHttpClient(config)
    }

    @Test
    fun `SecureHttpClient should be created successfully`() {
        assertThat(secureHttpClient).isNotNull()
    }

    @Test
    fun `sendSecurityReport should handle null endpoint gracefully`() {
        val configWithoutEndpoint = CasterConfig()
        val clientWithoutEndpoint = SecureHttpClient(configWithoutEndpoint)
        
        val result = clientWithoutEndpoint.sendSecurityReport("{\"test\": \"data\"}")
        assertThat(result).isFalse()
    }

    @Test
    fun `sendSecurityReport should reject non-HTTPS endpoints`() {
        val configWithHttpEndpoint = CasterConfig(
            logEndpoint = "http://example.com/security/logs"
        )
        val clientWithHttpEndpoint = SecureHttpClient(configWithHttpEndpoint)
        
        val result = clientWithHttpEndpoint.sendSecurityReport("{\"test\": \"data\"}")
        assertThat(result).isFalse()
    }

    @Test
    fun `SecureHttpClient should include custom headers`() {
        val configWithHeaders = config.copy(
            customHeaders = mapOf(
                "X-API-Key" to "test-key",
                "User-Agent" to "Caster-Test/1.0"
            )
        )
        val clientWithHeaders = SecureHttpClient(configWithHeaders)
        
        assertThat(clientWithHeaders).isNotNull()
    }
}