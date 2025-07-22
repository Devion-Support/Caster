# Melakukan Analisis

Fungsi utama dari Caster adalah `analyze()`. Fungsi ini menjalankan semua pemeriksaan keamanan yang telah Anda aktifkan selama inisialisasi.

### Poin Penting

-   `analyze()` adalah sebuah `suspend function`. Ini berarti ia harus dipanggil dari dalam sebuah coroutine (misalnya, menggunakan `viewModelScope` atau `lifecycleScope`).
-   Fungsi ini memerlukan sebuah `Activity` sebagai parameter. Beberapa deteksi (seperti `FlagSecureDetector`) memerlukan konteks `Activity` untuk bekerja dengan benar.

### Contoh di ViewModel

Berikut adalah contoh umum tentang cara memanggil `analyze()` dari dalam sebuah `ViewModel` dan memperbarui UI state.

```kotlin
// Di dalam SecurityViewModel.kt Anda

class SecurityViewModel : ViewModel() {
    
    var uiState by mutableStateOf(SecurityUiState())
        private set

    fun startSecurityScan(activity: Activity) {
        // Dapatkan instance singleton Caster
        val caster = Caster.getInstance()

        viewModelScope.launch {
            uiState = uiState.copy(isScanning = true)
            try {
                // Jalankan analisis di thread I/O
                val result = withContext(Dispatchers.IO) {
                    caster.analyze(activity)
                }
                // Perbarui UI dengan hasil yang sukses
                uiState = uiState.copy(isScanning = false, scanResult = result)
            } catch (e: Exception) {
                // Tangani error jika analisis gagal
                uiState = uiState.copy(isScanning = false, errorMessage = e.message)
            }
        }
    }
}
```

Di UI Anda (misalnya, Jetpack Compose), Anda cukup memanggil `viewModel.startSecurityScan(activity)`.

```kotlin
// Di dalam Composable Anda
val context = LocalContext.current
Button(onClick = {
    (context as? Activity)?.let { activity ->
        viewModel.startSecurityScan(activity)
    }
}) {
    Text("Mulai Pindai")
}
```
