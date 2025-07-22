# Pendahuluan: Caster Security Library

Selamat datang di dokumentasi Caster, sebuah library keamanan Android yang dirancang untuk membantu developer mendeteksi kerentanan umum langsung di perangkat pengguna.

### Apa itu Caster?

Caster adalah library yang mudah diintegrasikan yang menyediakan serangkaian alat untuk melakukan analisis keamanan pada lingkungan aplikasi Anda. Tujuannya adalah untuk memberikan lapisan pertahanan tambahan dengan mengidentifikasi risiko seperti perangkat yang di-root, emulator, atau upaya perusakan aplikasi.

### Fitur Utama

- **Deteksi Root:** Mengidentifikasi berbagai metode root, termasuk SuperSU, Magisk, dan lainnya.
- **Deteksi Emulator:** Membedakan antara perangkat fisik dan lingkungan virtual (emulator).
- **Pemeriksaan Integritas:** Memverifikasi tanda tangan (signature) aplikasi untuk mendeteksi tampering.
- **Anti-Tampering:** Mendeteksi debugger yang terpasang dan framework hooking seperti Frida.
- **Deteksi Aplikasi Berbahaya:** Memindai aplikasi yang terinstal berdasarkan daftar paket yang dicurigai.
- **Pemeriksaan `FLAG_SECURE`:** Mendeteksi upaya bypass pada `FLAG_SECURE` yang melindungi dari tangkapan layar.
- **Sangat Dapat Dikonfigurasi:** Kontrol penuh atas fitur mana yang akan diaktifkan, level logging, dan lainnya melalui Builder Pattern yang bersih.
- **Laporan Komprehensif:** Memberikan hasil yang terstruktur dan skor risiko untuk setiap analisis.
