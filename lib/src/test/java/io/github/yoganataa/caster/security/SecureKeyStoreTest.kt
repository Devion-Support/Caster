package io.github.yoganataa.caster.security

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
class SecureKeyStoreTest {

    private lateinit var context: Context
    private lateinit var secureKeyStore: SecureKeyStore

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        secureKeyStore = SecureKeyStore(context)
    }

    @Test
    fun `SecureKeyStore should be created successfully`() {
        assertThat(secureKeyStore).isNotNull()
    }

    @Test
    fun `isAvailable should return boolean`() {
        val isAvailable = secureKeyStore.isAvailable()
        assertThat(isAvailable).isNotNull()
    }

    @Test
    fun `encrypt and decrypt should work correctly`() {
        val testData = "This is a test string for encryption"
        val encryptedData = secureKeyStore.encrypt(testData)
        
        assertThat(encryptedData).isNotNull()
        assertThat(encryptedData.encryptedData).isNotNull()
        assertThat(encryptedData.iv).isNotNull()
        assertThat(encryptedData.encryptedData).isNotEmpty()
        assertThat(encryptedData.iv).isNotEmpty()
        
        val decryptedData = secureKeyStore.decrypt(encryptedData)
        assertThat(decryptedData).isEqualTo(testData)
    }

    @Test
    fun `generateSecureToken should return non-empty string`() {
        val token = secureKeyStore.generateSecureToken()
        assertThat(token).isNotNull()
        assertThat(token).isNotEmpty()
        
        // Test with custom length
        val customToken = secureKeyStore.generateSecureToken(16)
        assertThat(customToken).isNotNull()
        assertThat(customToken).isNotEmpty()
    }

    @Test
    fun `store and retrieve encrypted data should work`() {
        val testKey = "test_key"
        val testData = "This is test data to store securely"
        
        secureKeyStore.storeEncryptedData(testKey, testData)
        val retrievedData = secureKeyStore.retrieveEncryptedData(testKey)
        
        assertThat(retrievedData).isEqualTo(testData)
    }

    @Test
    fun `retrieveEncryptedData should return null for non-existent key`() {
        val retrievedData = secureKeyStore.retrieveEncryptedData("non_existent_key")
        assertThat(retrievedData).isNull()
    }

    @Test
    fun `clearAllData should not throw exceptions`() {
        // Store some data first
        secureKeyStore.storeEncryptedData("test_key", "test_data")
        
        // Clear all data
        secureKeyStore.clearAllData()
        
        // Try to retrieve data - should return null
        val retrievedData = secureKeyStore.retrieveEncryptedData("test_key")
        assertThat(retrievedData).isNull()
    }
}