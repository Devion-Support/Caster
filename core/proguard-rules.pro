# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html
# jni
-keepclasseswithmembernames class * {
    native <methods>;
}

# gson
-keep class io.github.yoganataa.caster.core.logging.** { *; }

# hiddenapi
-keep class org.lsposed.hiddenapibypass.** { *; }

# models
-keep class io.github.yoganataa.caster.core.models.** { *; }
-keep class io.github.yoganataa.caster.core.Caster { *; }
-keep class io.github.yoganataa.caster.core.CasterConfig { *; }

# Keep Caster's inner classes (Builder, Companion)
-keep class io.github.yoganataa.caster.core.Caster$* { *; }
