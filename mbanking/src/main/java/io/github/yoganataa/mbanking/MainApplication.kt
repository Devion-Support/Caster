package io.github.yoganataa.mbanking

import android.app.Application
import io.github.yoganataa.caster.core.Caster
import io.github.yoganataa.caster.core.logging.LogLevel

class MainApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize Caster on app startup
        Caster.Builder(this)
            .setLogLevel(if (BuildConfig.DEBUG) LogLevel.DEBUG else LogLevel.WARN)
            .build()
    }
}
