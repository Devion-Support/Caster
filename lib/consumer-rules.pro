# Keep the library's public API
-keep class io.github.yoganataa.caster.Caster { *; }
-keep class io.github.yoganataa.caster.CasterConfig { *; }
-keep class io.github.yoganataa.caster.models.** { *; }

# Keep annotation class
-keep @interface io.github.yoganataa.caster.Keep
-keep @io.github.yoganataa.caster.Keep class *
-keepclassmembers class * {
    @io.github.yoganataa.caster.Keep *;
}