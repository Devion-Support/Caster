# Inisialisasi

Caster harus diinisialisasi sekali saja saat aplikasi Anda pertama kali dimulai. Tempat terbaik untuk melakukan ini adalah di dalam metode `onCreate()` dari kelas `Application` kustom Anda.

### Mengapa di Kelas `Application`?

Dengan menginisialisasi Caster di sini, Anda memastikan bahwa:
1.  Hanya ada **satu instance** (singleton) dari Caster yang berjalan di seluruh aplikasi.
2.  Caster siap digunakan kapan pun dan di mana pun di dalam aplikasi Anda.

### Contoh Implementasi

1.  Buat atau buka kelas `Application` kustom Anda.
2.  Panggil `Caster.Builder` di dalam metode `onCreate()`.

```kotlin
// file: app/src/main/java/com/yourpackage/MainApplication.kt

package com.yourpackage

import android.app.Application
import io.github.yoganataa.caster.core.Caster
import io.github.yoganataa.caster.core.logging.LogLevel

class MainApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Inisialisasi Caster dengan konfigurasi dasar
        Caster.Builder(this)
            .setLogLevel(LogLevel.INFO) // Atur level log sesuai kebutuhan
            .build()
    }
}
```

3.  Jangan lupa untuk mendaftarkan kelas `Application` ini di `AndroidManifest.xml`:

```xml
<application
    android:name=".MainApplication"
    ...>
    ...
</application>
```

Setelah ini, Anda dapat memanggil `Caster.getInstance()` dari mana saja di aplikasi Anda untuk mendapatkan instance yang sudah dikonfigurasi.
