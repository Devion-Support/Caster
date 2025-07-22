# Instalasi

Untuk menggunakan Caster, tambahkan dependensi berikut ke file `build.gradle.kts` (atau `build.gradle`) modul aplikasi Anda.

### 1. Tambahkan Repositori

Pastikan Anda memiliki `mavenCentral()` di file `settings.gradle.kts` Anda:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral() // Pastikan ini ada
    }
}
```

### 2. Tambahkan Dependensi Caster

Tambahkan baris berikut ke blok `dependencies` di file `build.gradle.kts` level modul (`app/build.gradle.kts`):

```kotlin
dependencies {
    // ... dependensi lain
    implementation("io.github.yoganataa.caster:core:1.0.0") // Ganti dengan versi terbaru
}
```

### 3. Tambahkan Izin (Permission)

Untuk fitur deteksi aplikasi berbahaya, Caster memerlukan izin untuk menanyakan semua aplikasi yang terinstal. Tambahkan izin berikut ke `AndroidManifest.xml`:

```xml
<!-- Di dalam tag <manifest> -->
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"
    tools:ignore="QueryAllPackagesPermission" />
```

Setelah langkah-langkah ini, sinkronkan proyek Gradle Anda. Sekarang Anda siap untuk menginisialisasi library.
