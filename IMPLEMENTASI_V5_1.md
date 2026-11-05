# Implementasi HILLCRYPT v5.1

## Tujuan
Memperbaiki sinkronisasi antara menu Enkripsi dan Dekripsi ketika pengguna menggunakan dua format ciphertext: Base64 mentah dan paket `.hce`.

## Alur baru
1. Pengguna memilih kunci manual atau menerapkan passphrase dari Graph Key Lab.
2. Pengguna mengenkripsi plaintext.
3. Aplikasi membuat paket `.hce` dan Base64 dari ciphertext yang sama.
4. Paket, Base64, fingerprint kunci, encoding, ordo, modulus, dan panjang byte asli disimpan sebagai artefak enkripsi terakhir pada sesi Streamlit.
5. Ketika pengguna membuka menu Dekripsi, input `.hce` dan Base64 otomatis terisi dari hasil enkripsi terakhir. Pengguna tetap dapat mengganti input dengan berkas atau ciphertext lain.
6. Untuk `.hce`, aplikasi memeriksa fingerprint, metadata, dan HMAC paket.
7. Untuk Base64 yang cocok persis dengan hasil enkripsi terakhir pada sesi yang sama, aplikasi memeriksa fingerprint dan metadata sesi sebelum dekripsi.
8. Untuk Base64 eksternal/tidak dikenal, dekripsi tetap tersedia tetapi statusnya secara eksplisit belum terverifikasi.

## Mengapa Base64 eksternal tidak bisa dijamin
Base64 hanya representasi teks dari byte ciphertext. Ia tidak menyimpan identitas kunci, encoding, ordo, modulus, atau panjang plaintext. Karena itu, aplikasi tidak dapat secara matematis membuktikan bahwa kunci yang dimasukkan sama dengan kunci enkripsi jika tidak ada metadata tepercaya. Paket `.hce` adalah format yang direkomendasikan untuk proses yang memerlukan pemeriksaan tersebut.

## Pengujian
Pengujian otomatis bawaan: `python -m unittest discover -s tests -v`.

Pengujian manual yang tetap diperlukan:
- Enkripsi manual lalu dekripsi `.hce` dengan kunci sama dan berbeda.
- Enkripsi Graph Key Lab lalu dekripsi dengan passphrase graf yang sama dan kunci manual berbeda.
- Periksa sinkronisasi otomatis Base64 dan `.hce` setelah berpindah menu.
- Uji Base64 eksternal dan pastikan statusnya menyebut belum terverifikasi.
- Ubah encoding, ordo, atau panjang byte saat memakai Base64 yang dikenal pada sesi yang sama.
