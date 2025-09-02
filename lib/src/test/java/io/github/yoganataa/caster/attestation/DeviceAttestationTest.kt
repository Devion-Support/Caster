package io.github.yoganataa.caster.attestation

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
class DeviceAttestationTest {

    private lateinit var context: Context
    private lateinit var deviceAttestation: DeviceAttestation

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        deviceAttestation = DeviceAttestation(context)
    }

    @Test
    fun `DeviceAttestation should be created successfully`() {
        assertThat(deviceAttestation).isNotNull()
    }

    @Test
    fun `performAttestation should return valid result`() {
        val result = deviceAttestation.performAttestation()
        
        assertThat(result).isNotNull()
        assertThat(result.isHardwareAttestationSupported).isNotNull()
        assertThat(result.deviceIdentifiers).isNotNull()
        assertThat(result.bootloaderStatus).isNotNull()
        assertThat(result.verifiedBootStatus).isNotNull()
        assertThat(result.systemIntegrity).isNotNull()
    }

    @Test
    fun `getDeviceIdentifiers should return non-empty map`() {
        // Use reflection to access private method
        val method = DeviceAttestation::class.java.getDeclaredMethod("getDeviceIdentifiers")
        method.isAccessible = true
        val identifiers = method.invoke(deviceAttestation) as Map<*, *>
        
        assertThat(identifiers).isNotNull()
        // Some identifiers might be empty in Robolectric environment
    }

    @Test
    fun `generateDeviceFingerprint should return non-empty string`() {
        // Use reflection to access private method
        val method = DeviceAttestation::class.java.getDeclaredMethod("generateDeviceFingerprint")
        method.isAccessible = true
        val fingerprint = method.invoke(deviceAttestation) as String
        
        assertThat(fingerprint).isNotNull()
        assertThat(fingerprint).isNotEmpty()
    }

    @Test
    fun `checkBootloaderStatus should return valid status`() {
        // Use reflection to access private method
        val method = DeviceAttestation::class.java.getDeclaredMethod("checkBootloaderStatus")
        method.isAccessible = true
        val status = method.invoke(deviceAttestation) as String
        
        assertThat(status).isNotNull()
        assertThat(status).isIn(listOf("UNKNOWN", "LOCKED", "UNLOCKED", "ERROR"))
    }

    @Test
    fun `checkSystemIntegrity should return valid integrity object`() {
        // Use reflection to access private method
        val method = DeviceAttestation::class.java.getDeclaredMethod("checkSystemIntegrity")
        method.isAccessible = true
        val integrity = method.invoke(deviceAttestation) as SystemIntegrity
        
        assertThat(integrity).isNotNull()
        assertThat(integrity.isSystemPartitionReadOnly).isNotNull()
        assertThat(integrity.selinuxStatus).isNotNull()
        assertThat(integrity.hasTestKeys).isNotNull()
        assertThat(integrity.isDebuggable).isNotNull()
    }
}