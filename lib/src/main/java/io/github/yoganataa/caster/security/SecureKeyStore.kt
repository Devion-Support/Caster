package io.github.yoganataa.caster.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secure key storage using Android Keystore for protecting sensitive data.
 */
class SecureKeyStore(private val context: Context) {
    
    private val keyStore: KeyStore
    private val preferences: SharedPreferences
    private val alias = "caster_secure_key"
    
    init {
        keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        preferences = context.getSharedPreferences("caster_secure_prefs", Context.MODE_PRIVATE)
    }
    
    /**
     * Generates or retrieves a secure encryption key.
     */
    private fun getOrCreateKey(): SecretKey {
        return try {
            if (keyStore.containsAlias(alias)) {
                // Key already exists, retrieve it
                val key = keyStore.getKey(alias, null)
                if (key is SecretKey) {
                    key
                } else {
                    // Key exists but is not a SecretKey, generate a new one
                    generateKey()
                }
            } else {
                // Key doesn't exist, generate a new one
                generateKey()
            }
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Error retrieving or generating key", e)
            // Fallback to generating a new key
            generateKey()
        }
    }
    
    /**
     * Generates a new secure encryption key.
     */
    private fun generateKey(): SecretKey {
        return try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )
            
            val keyGenSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(true)
                .build()
            
            keyGenerator.init(keyGenSpec)
            keyGenerator.generateKey()
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Error generating key", e)
            throw SecurityException("Failed to generate secure key", e)
        }
    }
    
    /**
     * Encrypts data using the secure key.
     */
    fun encrypt(data: String): EncryptedData {
        return try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            
            val encryptedBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
            val iv = cipher.iv
            
            EncryptedData(
                encryptedData = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP),
                iv = Base64.encodeToString(iv, Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Error encrypting data", e)
            throw SecurityException("Failed to encrypt data", e)
        }
    }
    
    /**
     * Decrypts data using the secure key.
     */
    fun decrypt(encryptedData: EncryptedData): String {
        return try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            
            val encryptedBytes = Base64.decode(encryptedData.encryptedData, Base64.NO_WRAP)
            val iv = Base64.decode(encryptedData.iv, Base64.NO_WRAP)
            
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            
            val decryptedBytes = cipher.doFinal(encryptedBytes)
            String(decryptedBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Error decrypting data", e)
            throw SecurityException("Failed to decrypt data", e)
        }
    }
    
    /**
     * Generates a secure random token.
     */
    fun generateSecureToken(length: Int = 32): String {
        return try {
            val random = SecureRandom()
            val bytes = ByteArray(length)
            random.nextBytes(bytes)
            Base64.encodeToString(bytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Error generating secure token", e)
            throw SecurityException("Failed to generate secure token", e)
        }
    }
    
    /**
     * Stores encrypted data in secure preferences.
     */
    fun storeEncryptedData(key: String, data: String) {
        try {
            val encryptedData = encrypt(data)
            val editor = preferences.edit()
            editor.putString("${key}_data", encryptedData.encryptedData)
            editor.putString("${key}_iv", encryptedData.iv)
            editor.apply()
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Error storing encrypted data", e)
            throw SecurityException("Failed to store encrypted data", e)
        }
    }
    
    /**
     * Retrieves and decrypts data from secure preferences.
     */
    fun retrieveEncryptedData(key: String): String? {
        return try {
            val encryptedData = preferences.getString("${key}_data", null)
            val iv = preferences.getString("${key}_iv", null)
            
            if (encryptedData != null && iv != null) {
                val data = EncryptedData(encryptedData, iv)
                decrypt(data)
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Error retrieving encrypted data", e)
            null
        }
    }
    
    /**
     * Clears all stored encrypted data.
     */
    fun clearAllData() {
        try {
            val editor = preferences.edit()
            editor.clear()
            editor.apply()
            
            // Delete the key from keystore
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Error clearing data", e)
        }
    }
    
    /**
     * Checks if the secure key store is available and properly initialized.
     */
    fun isAvailable(): Boolean {
        return try {
            getOrCreateKey()
            true
        } catch (e: Exception) {
            Log.e("SecureKeyStore", "Secure key store is not available", e)
            false
        }
    }
}

/**
 * Data class representing encrypted data with its initialization vector.
 */
data class EncryptedData(
    val encryptedData: String,
    val iv: String
)