# HILLCRYPT v5.0 — Rancangan Implementasi Terpadu

## Keputusan desain
- Format `.hce`/JSON menjadi paket lengkap yang menyimpan encoding, modulus, ordo, panjang byte asli, ciphertext, sumber kunci, fingerprint, dan autentikasi integritas.
- Base64 tetap disediakan sebagai format ringkas untuk interoperabilitas/manual. Base64 mentah **tidak** dapat membuktikan kecocokan kunci atau integritas karena tidak membawa metadata autentikasi.
- Paket v4 memakai fingerprint SHA-256 untuk penolakan kunci yang berbeda serta HMAC-SHA256 atas metadata dan ciphertext. Kunci autentikasi diturunkan dengan scrypt dan salt acak per paket.
- Paket v3 lama masih dapat didekripsi untuk kompatibilitas, tetapi tidak memiliki autentikasi integritas paket.
- Manual dan Graph Key Lab memakai mesin Hill Cipher dan fungsi paket yang sama. Sumber kunci dicatat sebagai metadata; kecocokan didasarkan pada kunci aktual, bukan label sumbernya.

## Validasi
1. Validasi input dan encoding.
2. Validasi matriks: `gcd(det(K), modulus) = 1`.
3. Validasi metadata paket: format, versi, mode, modulus, encoding, ordo, dan panjang byte.
4. Validasi fingerprint: menolak kata kunci yang berbeda.
5. Validasi HMAC: mendeteksi perubahan metadata/ciphertext setelah paket dibuat.
6. Dekripsi dan decoding strict; kesalahan decoding tidak ditampilkan sebagai keberhasilan.

## Batasan keamanan yang wajib dinyatakan
Hill Cipher tetap algoritma klasik untuk edukasi dan bukan algoritma aman bagi data rahasia modern. HMAC pada paket ini mengautentikasi paket dalam konteks aplikasi edukasi, tetapi passphrase lemah tetap rentan ditebak secara offline. Jangan gunakan untuk melindungi data sensitif. Untuk keamanan nyata gunakan AEAD modern seperti AES-GCM atau ChaCha20-Poly1305.

## Fitur yang dipertahankan
- Antarmuka bilingual dan desain responsif.
- ASCII 0–127, Windows-1252 0–255, dan UTF-8.
- Matriks 1×1 sampai 16×16.
- Enkripsi/dekripsi manual dan Graph Key Lab.
- Laboratorium Matriks, visualisasi graf, Belajar Kriptografi, Uji Sistem, Riwayat Aktivitas, Tentang.
- Upload plaintext, ekspor Base64, ekspor paket `.hce`, dan unduh plaintext.

## Menjalankan aplikasi
1. Ekstrak ZIP ke folder lokal.
2. Jalankan `INSTALL_DEPENDENCIES.bat` satu kali.
3. Jalankan `RUN_HILLCRYPT.bat`.
4. Buka alamat lokal yang ditampilkan Streamlit.

## Pengujian yang disarankan sebelum rilis
- Uji round-trip untuk semua mode encoding dan beberapa ordo matriks.
- Uji paket v4 dengan kunci benar dan kunci salah.
- Ubah satu karakter ciphertext, metadata encoding, ordo, dan panjang byte; paket harus ditolak.
- Uji paket v3 lama untuk kompatibilitas.
- Uji Base64 mentah dan pastikan UI memperingatkan bahwa validasi fingerprint tidak tersedia.
