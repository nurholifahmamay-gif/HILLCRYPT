# HILLCRYPT 4.2 – Panduan Publikasi dan Akses Lintas Perangkat

## A. Menjalankan secara lokal
1. Ekstrak ZIP.
2. Jalankan `INSTALL_DEPENDENCIES.bat` sekali pada Windows.
3. Jalankan `RUN_HILLCRYPT.bat`.
4. Browser membuka alamat lokal Streamlit. Alamat `localhost` hanya berlaku pada perangkat yang menjalankan server.

## B. Mempublikasikan agar dapat dibuka dosen dan pengguna lain
HILLCRYPT adalah aplikasi web Streamlit. Agar dapat diakses dari internet, source code perlu di-hosting; ZIP lokal saja tidak otomatis menjadi website.

1. Buat akun GitHub dan buat repository baru bernama, misalnya, `hillcrypt`.
2. Unggah isi folder HILLCRYPT (termasuk `app.py`, `hill_cipher.py`, `requirements.txt`, folder `assets`, `.streamlit`, dan dokumentasi) ke repository tersebut.
3. Buka Streamlit Community Cloud di `https://share.streamlit.io` dan masuk menggunakan GitHub.
4. Pilih **Create app**, pilih repository, branch, dan file utama `app.py`.
5. Tentukan subdomain aplikasi yang mudah diingat jika tersedia, lalu klik **Deploy**.
6. Setelah proses selesai, salin URL HTTPS `*.streamlit.app` dan bagikan kepada dosen pembimbing.
7. Untuk aplikasi yang hanya boleh dilihat dosen tertentu, atur akses private/viewer pada pengaturan sharing. Jika ingin semua orang mengakses, pilih pengaturan public.

## C. Membuka pada berbagai perangkat
- Windows/macOS/Linux: buka URL HTTPS menggunakan browser.
- Android: buka URL melalui Chrome, menu browser, lalu pilih **Add to Home screen** bila tersedia.
- iPhone/iPad: buka URL melalui Safari, tombol **Share**, lalu **Add to Home Screen**.
- Tablet: gunakan browser; layout aplikasi responsif mengikuti ukuran layar.

Ini adalah aplikasi web responsif/PWA-like melalui browser, bukan paket aplikasi native `.exe`, `.apk`, atau `.ipa`. Pengguna tidak perlu memasang Python jika memakai versi hosting online.

## D. Hal keamanan yang harus dipahami
- Hill Cipher adalah algoritma klasik untuk pendidikan. Jangan gunakan untuk kata sandi, data pribadi, dokumen rahasia, atau komunikasi sensitif.
- Pada versi hosting, teks yang dimasukkan diproses oleh server hosting, bukan hanya komputer pengguna.
- Jangan memasukkan data rahasia. Untuk penelitian dan demonstrasi gunakan data contoh.
- Jangan memasukkan token, API key, atau kredensial ke source code atau repository.
- Pastikan lisensi library pihak ketiga dipatuhi.

## E. Berbagi dengan dosen
Kirimkan dua hal: (1) URL HTTPS aplikasi online agar dosen dapat mencoba, dan (2) ZIP source code + README + panduan metode/pengujian untuk dokumentasi akademik. Sertakan versi aplikasi dan tanggal pengujian.
