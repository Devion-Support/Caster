# Getting Started

This guide will help you integrate Caster into your Android project and start using its security features.

## Prerequisites

- Android Studio or compatible IDE
- Android SDK API level 27 or higher
- Kotlin 1.5+ (recommended)
- Gradle 7.0+

## Installation

### Step 1: Add Dependency

Add the Caster library dependency to your app module's `build.gradle.kts` file:

```kotlin
dependencies {
    implementation("io.github.yoganataa.caster:caster:1.0.0")
}
```

### Step 2: Add Maven Local Repository

Make sure your project's `settings.gradle.kts` includes the Maven Local repository:

```kotlin
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        mavenLocal() // Add this line
    }
}
```

### Step 3: Publish to Local Maven (Development Only)

If you're using a local development version, publish the library to your local Maven repository:

```bash
./gradlew publishToMavenLocal
```

## Basic Usage

### Initialize Caster

Initialize Caster in your Application class:

```kotlin
import android.app.Application
import io.github.yoganataa.caster.Caster
import io.github.yoganataa.caster.logging.LogLevel

class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Configure Caster using the Builder pattern
        Caster.Builder(this)
            .setLogLevel(if (BuildConfig.DEBUG) LogLevel.DEBUG else LogLevel.WARN)
            .enableRootDetection(true)
            .enableEmulatorDetection(true)
            .enableIntegrityChecks(true)
            .enableAntiTampering(true)
            .build()
    }
}
```

### Perform Security Analysis

Use Caster in your Activity to perform security analysis:

```kotlin
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import io.github.yoganataa.caster.Caster
import io.github.yoganataa.caster.models.CasterResult
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Get the singleton instance of Caster
        val caster = Caster.getInstance()
        
        // Perform security analysis
        lifecycleScope.launch {
            try {
                val result: CasterResult = caster.analyze(this@MainActivity)
                
                // Process the results
                if (result.isSecure) {
                    // Device is secure
                    handleSecureDevice(result)
                } else {
                    // Handle security threats
                    handleSecurityThreats(result)
                }
            } catch (e: Exception) {
                // Handle analysis error
                handleAnalysisError(e)
            }
        }
    }
    
    private fun handleSecureDevice(result: CasterResult) {
        // Device passed all security checks
        println("Device is secure")
    }
    
    private fun handleSecurityThreats(result: CasterResult) {
        // Device has security issues
        when (result.threatLevel) {
            ThreatLevel.CRITICAL -> handleCriticalThreat(result)
            ThreatLevel.HIGH -> handleHighThreat(result)
            ThreatLevel.MEDIUM -> handleMediumThreat(result)
            ThreatLevel.LOW -> handleLowThreat(result)
            ThreatLevel.NONE -> {} // No threats
        }
    }
    
    // ... other handler methods
}
```

## Next Steps

- Learn about [Core Concepts](../core-concepts/README.md)
- Explore [Configuration Options](../configuration/README.md)
- Understand [Security Features](../security-features/README.md)
