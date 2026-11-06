package io.github.yoganataa.caster.app

import android.app.Application
import io.github.yoganataa.caster.Caster
import io.github.yoganataa.caster.logging.LogLevel

class MainApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Configure Caster using the Builder pattern.
        // This should be done only once, when the application starts.
        Caster.Builder(this)
            .setLogLevel(if (BuildConfig.DEBUG) LogLevel.DEBUG else LogLevel.WARN)
            .enableParallelDetection(true)
            .enableRootDetection(true)
            .enableEmulatorDetection(true)
            .enableIntegrityChecks(true)
            .enableAntiTampering(true)
            // Example of disabling a feature:
            // .enableFlagSecureDetection(false)
            .build()
    }
}
