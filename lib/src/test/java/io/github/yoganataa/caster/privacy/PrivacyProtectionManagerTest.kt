package io.github.yoganataa.caster.privacy

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
class PrivacyProtectionManagerTest {

    private lateinit var context: Context
    private lateinit var privacyProtectionManager: PrivacyProtectionManager

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        privacyProtectionManager = PrivacyProtectionManager(context)
    }

    @Test
    fun `PrivacyProtectionManager should be created successfully`() {
        assertThat(privacyProtectionManager).isNotNull()
    }

    @Test
    fun `performPrivacyCheck should return valid result`() {
        val result = privacyProtectionManager.performPrivacyCheck()
        
        assertThat(result).isNotNull()
        assertThat(result.appPermissions).isNotNull()
        assertThat(result.sensitiveDataExposure).isNotNull()
        assertThat(result.dataStorageSecurity).isNotNull()
        assertThat(result.analyticsTracking).isNotNull()
        assertThat(result.privacySettings).isNotNull()
        assertThat(result.isPrivacyProtected).isNotNull()
    }

    @Test
    fun `checkAppPermissions should return valid permissions object`() {
        // Use reflection to access private method
        val method = PrivacyProtectionManager::class.java.getDeclaredMethod("checkAppPermissions")
        method.isAccessible = true
        val permissions = method.invoke(privacyProtectionManager) as AppPermissions
        
        assertThat(permissions).isNotNull()
        assertThat(permissions.allPermissions).isNotNull()
        assertThat(permissions.sensitivePermissions).isNotNull()
        assertThat(permissions.dangerousPermissions).isNotNull()
    }

    @Test
    fun `checkSensitiveDataExposure should return valid exposure object`() {
        // Use reflection to access private method
        val method = PrivacyProtectionManager::class.java.getDeclaredMethod("checkSensitiveDataExposure")
        method.isAccessible = true
        val exposure = method.invoke(privacyProtectionManager) as SensitiveDataExposure
        
        assertThat(exposure).isNotNull()
        assertThat(exposure.logFilesWithSensitiveData).isNotNull()
        assertThat(exposure.cacheFilesWithSensitiveData).isNotNull()
        assertThat(exposure.sharedPrefsWithSensitiveData).isNotNull()
        assertThat(exposure.tempFilesWithSensitiveData).isNotNull()
    }

    @Test
    fun `checkDataStorageSecurity should return valid storage object`() {
        // Use reflection to access private method
        val method = PrivacyProtectionManager::class.java.getDeclaredMethod("checkDataStorageSecurity")
        method.isAccessible = true
        val storageSecurity = method.invoke(privacyProtectionManager) as DataStorageSecurity
        
        assertThat(storageSecurity).isNotNull()
        assertThat(storageSecurity.isDataEncrypted).isNotNull()
        assertThat(storageSecurity.isExternalStorageSecure).isNotNull()
        assertThat(storageSecurity.isBackupSecure).isNotNull()
    }

    @Test
    fun `checkAnalyticsTracking should return valid analytics object`() {
        // Use reflection to access private method
        val method = PrivacyProtectionManager::class.java.getDeclaredMethod("checkAnalyticsTracking")
        method.isAccessible = true
        val analytics = method.invoke(privacyProtectionManager) as AnalyticsTracking
        
        assertThat(analytics).isNotNull()
        assertThat(analytics.detectedAnalyticsLibraries).isNotNull()
        assertThat(analytics.hasTrackingIdentifiers).isNotNull()
        assertThat(analytics.dataCollectionPractices).isNotNull()
    }

    @Test
    fun `checkPrivacySettings should return valid settings object`() {
        // Use reflection to access private method
        val method = PrivacyProtectionManager::class.java.getDeclaredMethod("checkPrivacySettings")
        method.isAccessible = true
        val privacySettings = method.invoke(privacyProtectionManager) as PrivacySettings
        
        assertThat(privacySettings).isNotNull()
        assertThat(privacySettings.compliesWithPrivacyRegulations).isNotNull()
        assertThat(privacySettings.hasPrivacyPolicy).isNotNull()
        assertThat(privacySettings.hasUserConsentMechanisms).isNotNull()
    }

    @Test
    fun `isSensitivePermission should correctly identify sensitive permissions`() {
        // Use reflection to access private method
        val method = PrivacyProtectionManager::class.java.getDeclaredMethod(
            "isSensitivePermission", String::class.java
        )
        method.isAccessible = true
        
        // Test with a sensitive permission
        val isSensitive = method.invoke(privacyProtectionManager, "android.permission.READ_CONTACTS") as Boolean
        assertThat(isSensitive).isTrue()
        
        // Test with a non-sensitive permission
        val isNotSensitive = method.invoke(privacyProtectionManager, "android.permission.INTERNET") as Boolean
        assertThat(isNotSensitive).isFalse()
    }
}