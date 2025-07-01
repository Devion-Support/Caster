# ===================================================================
# Aturan Proguard untuk Konsumen Pustaka Caster Core
# ===================================================================

# PERBAIKAN: Aturan ini memberitahu R8 untuk tidak menghapus atau mengubah
# nama kelas-kelas API publik utama dari pustaka Caster.
# Ini menyelesaikan error "Missing class" untuk Caster dan CasterConfig.
-keep class io.github.yoganataa.caster.core.Caster { *; }
-keep class io.github.yoganataa.caster.core.CasterConfig { *; }

# Aturan ini menjaga semua model data (CasterResult, RootResult, dll.)
# yang digunakan sebagai bagian dari API.
-keep class io.github.yoganataa.caster.core.models.** { *; }

# Aturan untuk menjaga fungsi native (JNI) agar tetap bisa dipanggil.
-keepclasseswithmembernames class * {
    native <methods>;
}

# Aturan untuk pustaka pihak ketiga yang mungkin menggunakan refleksi.
-keep class org.lsposed.hiddenapibypass.** { *; }