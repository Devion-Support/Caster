# Caster

## Deskripsi

Caster adalah sebuah library Android yang bertujuan untuk menyediakan fungsionalitas inti yang dapat digunakan kembali di berbagai aplikasi Android. Library ini dirancang untuk modularitas dan kemudahan integrasi.

## Fitur

- **Fungsionalitas Inti**: Menyediakan komponen dasar yang sering dibutuhkan dalam pengembangan aplikasi Android.
- **Modular**: Dirancang sebagai modul terpisah (`core`) untuk integrasi yang mudah.
- **Ringan**: Dioptimalkan untuk kinerja dan ukuran aplikasi yang minimal.
- **Native Implementation**: Versi baru dengan logika deteksi yang dipindahkan ke kode native C++ untuk keamanan yang lebih baik.

## Instalasi

Untuk menggunakan library Caster di proyek Android Anda, tambahkan dependensi berikut ke file `build.gradle.kts` modul aplikasi Anda:

```kotlin
dependencies {
    implementation(project(":core"))
}
```

Pastikan `settings.gradle.kts` Anda menyertakan modul `:core`:

```kotlin
include(':app', ':core')
```

## Penggunaan

Setelah library `core` dipublikasikan secara lokal (misalnya, dengan menjalankan `./gradlew publishToMavenLocal` di proyek Caster), Anda dapat menggunakannya di proyek Android lain di mesin Anda.

### Penggunaan Standar

1. **Tambahkan repositori Maven lokal** ke file `settings.gradle.kts` proyek yang ingin menggunakan library:

    ```kotlin
    dependencyResolutionManagement {
        repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
        repositories {
            google()
            mavenCentral()
            mavenLocal() // Tambahkan baris ini
        }
    }
    ```

2. **Tambahkan dependensi** ke modul aplikasi Anda (`app/build.gradle.kts` atau modul lain yang relevan):

    ```kotlin
    dependencies {
        implementation("io.github.yoganataa.caster:core:1.0.0")
    }
    ```

3. **Contoh penggunaan kode**:

    ```kotlin
    import io.github.yoganataa.caster.core.Caster
    
    class MyActivity : AppCompatActivity() {
        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            setContentView(R.layout.activity_main)
            
            // Inisialisasi Caster di kelas Application Anda
            // Caster.Builder(this)
            //     .enableRootDetection(true)
            //     .build()
            
            // Gunakan Caster untuk analisis keamanan
            // val caster = Caster.getInstance()
            // lifecycleScope.launch {
            //     val result = caster.analyze(this@MyActivity)
            //     // Proses hasil analisis
            // }
        }
    }
    ```

### Penggunaan Native Implementation (Lebih Aman)

Untuk keamanan yang lebih tinggi, Anda dapat menggunakan implementasi native yang memindahkan semua logika deteksi ke kode C++:

```kotlin
import io.github.yoganataa.caster.core.CasterNative

class MyActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Inisialisasi CasterNative
        CasterNative.Builder()
            .enableRootDetection(true)
            .enableEmulatorDetection(true)
            .enableFlagSecureDetection(true)
            .build()
        
        // Gunakan CasterNative untuk analisis keamanan
        val caster = CasterNative.getInstance()
        val result = caster.analyze(this)
        // Proses hasil analisis
    }
}
```

## Kontribusi

Kontribusi sangat dihargai! Jika Anda ingin berkontribusi, silakan fork repositori ini dan buat pull request dengan perubahan Anda. Pastikan untuk mengikuti panduan kontribusi yang ada (jika ada) dan sertakan tes untuk perubahan Anda.

## Lisensi

Library ini dilisensikan di bawah [LICENSE](LICENSE) file di root repositori ini.
