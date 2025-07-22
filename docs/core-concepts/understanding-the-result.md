# Memahami Hasil (`CasterResult`)

Fungsi `analyze()` mengembalikan objek `CasterResult`. Objek ini berisi rincian lengkap dari semua pemeriksaan yang dilakukan.

`CasterResult` adalah sebuah `data class` yang terdiri dari beberapa objek hasil lainnya.

### Struktur `CasterResult`

-   `rootResult: RootResult`: Hasil dari deteksi root.
    -   `isRooted: Boolean`: `true` jika perangkat terdeteksi di-root.
    -   `detectedMethods: List<String>`: Daftar metode atau bukti yang ditemukan.
    -   `confidence: Float`: Tingkat kepercayaan deteksi (0.0 hingga 1.0).
-   `emulatorResult: EmulatorResult`: Hasil dari deteksi emulator.
    -   `isEmulator: Boolean`: `true` jika perangkat terdeteksi sebagai emulator.
-   `flagSecureResult: FlagSecureResult`: Hasil pemeriksaan `FLAG_SECURE`.
    -   `isFlagSecureDisabled: Boolean`: `true` jika bypass terdeteksi.
-   `maliciousAppsResult: MaliciousAppsResult`: Hasil pemindaian aplikasi berbahaya.
    -   `hasMaliciousApps: Boolean`: `true` jika ditemukan aplikasi yang mencurigakan.
    -   `detectedApps: List<MaliciousAppInfo>`: Daftar aplikasi yang terdeteksi.
-   `integrityResult: IntegrityResult`: Hasil pemeriksaan integritas aplikasi.
    -   `isTampered: Boolean`: `true` jika tanda tangan aplikasi tidak cocok.
-   `tamperingResult: TamperingResult`: Hasil deteksi tampering.
    -   `isDebuggerAttached: Boolean`: `true` jika debugger terpasang.
    -   `isHookingDetected: Boolean`: `true` jika framework hooking (Frida, Xposed) terdeteksi.
-   `securityReport: SecurityReport`: Laporan ringkasan.
    -   `riskLevel: RiskLevel`: Tingkat risiko keseluruhan (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
    -   `detectedThreats: List<ThreatInfo>`: Daftar semua ancaman yang ditemukan.

### Contoh Penggunaan Hasil

Setelah Anda mendapatkan objek `result`, Anda dapat dengan mudah mengakses properti-propertinya untuk menampilkan informasi di UI atau mengambil tindakan.

```kotlin
// Di dalam Composable atau Activity Anda
val result: CasterResult = uiState.scanResult

if (result.rootResult.isRooted) {
    Log.w("SecurityCheck", "Perangkat ini di-root! Metode: ${result.rootResult.detectedMethods}")
    // Tampilkan peringatan kepada pengguna
}

if (result.tamperingResult.isDebuggerAttached) {
    // Ambil tindakan, misalnya, hentikan aplikasi
    finishAffinity()
}

// Menampilkan ringkasan
Text("Tingkat Risiko: ${result.securityReport.riskLevel}")
```
