# HILLCRYPT v5.1 — Integrated Flow Fix

## Perbaikan alur enkripsi/dekripsi
- Hasil enkripsi terbaru disimpan sebagai satu artefak sesi dan otomatis disinkronkan ke input paket `.hce` serta input Base64 pada menu Dekripsi.
- Hasil dekripsi lama dibersihkan ketika enkripsi baru berhasil dibuat.
- Jalur `.hce` tetap memverifikasi fingerprint kunci, metadata, dan HMAC integritas.
- Jalur Base64 memeriksa fingerprint dan metadata jika ciphertext sama dengan hasil enkripsi terakhir pada sesi aplikasi yang sama.
- Base64 eksternal/yang tidak dikenali tetap dapat dihitung, tetapi hasilnya diberi status **belum terverifikasi**, bukan diklaim valid.
- Perubahan kunci, encoding, ordo matriks, atau panjang byte terdeteksi untuk Base64 yang dikenali dari sesi saat ini.

## Batasan yang disengaja
Base64 mentah tidak membawa metadata/fingerprint. Jika Base64 berasal dari luar sesi atau aplikasi ditutup lalu dibuka kembali, kecocokan kunci tidak dapat dibuktikan dari Base64 saja. Gunakan paket `.hce` untuk verifikasi kuat.

## Fitur yang dipertahankan
Graph Key Lab, Laboratorium Matriks, mode ASCII/Windows-1252/UTF-8, ordo matriks 1–16, riwayat aktivitas, pembelajaran, pengujian sistem, dan ekspor Base64 serta `.hce`.
