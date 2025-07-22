# Caster

## Deskripsi

Caster adalah sebuah library Android yang bertujuan untuk menyediakan fungsionalitas inti yang dapat digunakan kembali di berbagai aplikasi Android. Library ini dirancang untuk modularitas dan kemudahan integrasi.

## Fitur

- **Fungsionalitas Inti**: Menyediakan komponen dasar yang sering dibutuhkan dalam pengembangan aplikasi Android.
- **Modular**: Dirancang sebagai modul terpisah (`core`) untuk integrasi yang mudah.
- **Ringan**: Dioptimalkan untuk kinerja dan ukuran aplikasi yang minimal.

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

1.  **Tambahkan repositori Maven lokal** ke file `settings.gradle.kts` proyek yang ingin menggunakan library:

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

2.  **Tambahkan dependensi** ke modul aplikasi Anda (`app/build.gradle.kts` atau modul lain yang relevan):

    ```kotlin
    dependencies {
        implementation("io.github.yoganataa.caster:core:1.0.0")
    }
    ```

3.  **Contoh penggunaan kode** (ini adalah placeholder, ganti dengan fungsionalitas aktual dari library Anda):

    ```kotlin
    // import io.github.yoganataa.caster.core.SomeClass // Ganti dengan import yang benar
    //
    // class MyActivity : AppCompatActivity() {
    //     override fun onCreate(savedInstanceState: Bundle?) {
    //         super.onCreate(savedInstanceState)
    //         setContentView(R.layout.activity_main)
    //
    //         val instance = SomeClass() // Ganti dengan kelas/fungsi yang benar
    //         instance.doSomething() // Ganti dengan metode/fungsi yang benar
    //     }
    // }
    ```

## Kontribusi

Kontribusi sangat dihargai! Jika Anda ingin berkontribusi, silakan fork repositori ini dan buat pull request dengan perubahan Anda. Pastikan untuk mengikuti panduan kontribusi yang ada (jika ada) dan sertakan tes untuk perubahan Anda.

## Lisensi

Library ini dilisensikan di bawah [LICENSE](LICENSE) file di root repositori ini.
