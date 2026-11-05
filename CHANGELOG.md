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


# HILLCRYPT v5.2 — Educational Content Expansion (development)

## Identitas dan konsistensi
- Memperbarui identitas antarmuka dan halaman Tentang menjadi v5.2.
- Memperbarui judul halaman browser dan keterangan versi di sidebar.

## Pengembangan pembelajaran
- Menambahkan sepuluh bab pembelajaran dalam Bahasa Indonesia dan Inggris.
- Setiap bab memuat tujuan pembelajaran, konsep inti, rumus, contoh pembahasan, dan evaluasi pilihan ganda.
- Materi mencakup dasar kriptografi, aljabar linear, aritmetika modular, Hill Cipher, encoding, padding dan HCE, teori graf, keamanan, serta praktikum.
- Contoh modulo 26 diberi penanda sebagai ilustrasi alfabet, bukan mode byte aplikasi.
- Menjelaskan perbedaan unimodular (determinannya ±1) dan invertibilitas modulo m (gcd(det(K),m)=1).

## Catatan status
Perubahan ini berada pada branch pengembangan. Pengujian otomatis dan manual serta verifikasi deployment publik harus dilakukan sebelum merge ke main dan rilis produksi.
