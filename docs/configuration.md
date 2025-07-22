# Konfigurasi Lanjutan

Caster dirancang untuk menjadi sangat fleksibel. Anda dapat mengontrol hampir setiap aspek perilakunya menggunakan metode pada `Caster.Builder` saat inisialisasi.

Berikut adalah daftar lengkap metode konfigurasi yang tersedia:

---

### `setLogLevel(level: LogLevel)`
Mengatur tingkat minimum log yang akan dicatat oleh Caster.
- **Pilihan:** `LogLevel.DEBUG`, `LogLevel.INFO`, `LogLevel.WARN`, `LogLevel.ERROR`, `LogLevel.CRITICAL`.
- **Default:** `LogLevel.INFO`
- **Contoh:** `.setLogLevel(LogLevel.DEBUG)`

---

### `setLogEndpoint(url: String?)`
Mengatur URL endpoint untuk mengirim log keamanan secara remote. Jika `null`, log tidak akan dikirim.
- **Default:** `null`
- **Contoh:** `.setLogEndpoint("https://api.example.com/logs")`

---

### `enableParallelDetection(enable: Boolean)`
Mengaktifkan atau menonaktifkan analisis paralel. Analisis paralel lebih cepat tetapi menggunakan lebih banyak sumber daya.
- **Default:** `true`
- **Contoh:** `.enableParallelDetection(false)`

---

### `enable...` (Metode untuk Mengaktifkan/Menonaktifkan Deteksi)
Anda dapat mengontrol setiap jenis deteksi secara individual.
- `.enableRootDetection(enable: Boolean)` (Default: `true`)
- `.enableEmulatorDetection(enable: Boolean)` (Default: `true`)
- `.enableFlagSecureDetection(enable: Boolean)` (Default: `true`)
- `.enableMaliciousAppDetection(enable: Boolean)` (Default: `true`)
- `.enableIntegrityChecks(enable: Boolean)` (Default: `true`)
- `.enableAntiTampering(enable: Boolean)` (Default: `true`)
- `.enableNativeChecks(enable: Boolean)` (Default: `true`)
- `.enableLsDataDetection(enable: Boolean)` (Default: `false`)

---

### `addCustomMaliciousApps(packageNames: Set<String>)`
Menambahkan daftar nama paket kustom yang harus dianggap berbahaya oleh Caster.
- **Contoh:** `.addCustomMaliciousApps(setOf("com.suspicious.app1", "com.another.badapp"))`

---

### `setDetectionTimeout(timeoutMs: Long)`
Mengatur batas waktu maksimum (dalam milidetik) untuk beberapa proses deteksi.
- **Default:** `5000L` (5 detik)
- **Contoh:** `.setDetectionTimeout(10000L)`

---

### `addCustomHeaders(headers: Map<String, String>)`
Menambahkan header HTTP kustom yang akan dikirim bersama dengan log ke `logEndpoint`.
- **Contoh:** `.addCustomHeaders(mapOf("X-API-Key" to "your-secret-key"))`

---

### `includeDeviceInfo(include: Boolean)`
Menentukan apakah informasi perangkat (model, versi OS) harus disertakan dalam laporan keamanan.
- **Default:** `true`
- **Contoh:** `.includeDeviceInfo(false)`

---

### `includeAppInfo(include: Boolean)`
Menentukan apakah informasi aplikasi (nama paket) harus disertakan dalam laporan keamanan.
- **Default:** `true`
- **Contoh:** `.includeAppInfo(false)`

### Contoh Konfigurasi Lengkap

```kotlin
// Di MainApplication.kt
Caster.Builder(this)
    .setLogLevel(if (BuildConfig.DEBUG) LogLevel.DEBUG else LogLevel.WARN)
    .enableParallelDetection(true)
    .enableAntiTampering(true)
    .enableFlagSecureDetection(false) // Nonaktifkan deteksi ini
    .setLogEndpoint("https://my-company.com/security-logs")
    .addCustomHeaders(mapOf("X-Client-Version" to BuildConfig.VERSION_NAME))
    .addCustomMaliciousApps(setOf("com.fake.installer"))
    .build()
```
