# Panduan Materi Pembelajaran HILLCRYPT v5.2

Dokumen pendamping ini menjelaskan urutan belajar, konsep matematis, contoh, dan aktivitas praktikum yang tersedia pada menu **Belajar Kriptografi**.

## Capaian pembelajaran

Setelah menyelesaikan seluruh bab, pembelajar diharapkan mampu:
1. Menjelaskan istilah dasar kriptografi dan batas penggunaan cipher klasik.
2. Melakukan operasi matriks dan vektor yang digunakan dalam Hill Cipher.
3. Menggunakan kongruensi, FPB, dan invers perkalian modulo.
4. Memeriksa syarat invertibilitas matriks kunci pada modulus komposit.
5. Menghitung enkripsi dan dekripsi blok secara manual.
6. Membedakan karakter, code point, dan byte pada ASCII, Windows-1252, serta UTF-8.
7. Menjelaskan padding, metadata, Base64, dan paket HCE.
8. Menafsirkan matriks sebagai graf berarah berbobot serta membedakan unimodularitas dari invertibilitas modular.
9. Menilai keterbatasan keamanan Hill Cipher.
10. Melakukan praktikum dan uji pemulihan plaintext.

## Bab 1 — Dasar-Dasar Kriptografi

Kriptografi mempelajari metode transformasi informasi. Plaintext adalah pesan sebelum enkripsi; ciphertext adalah hasil enkripsi. Enkripsi mengubah plaintext menjadi ciphertext, sedangkan dekripsi berusaha memulihkan plaintext menggunakan parameter yang sesuai.

Dalam keamanan informasi modern, tujuan yang sering dibahas meliputi kerahasiaan, integritas, autentikasi, dan ketersediaan. Hill Cipher merupakan contoh cipher klasik untuk pembelajaran transformasi matematis; jangan menganggapnya memenuhi semua tujuan keamanan modern.

**Alur:** P —(E_K)→ C —(D_K)→ P.

## Bab 2 — Dasar Aljabar Linear

Matriks adalah susunan elemen dalam baris dan kolom. Matriks kunci K berordo n × n. Setiap blok pesan berukuran n byte direpresentasikan sebagai vektor kolom P berordo n × 1. Hasil perkalian K P juga berordo n × 1.

Contoh:
K = [[1,1],[1,2]], P = [2,3]ᵀ.

K P = [1(2)+1(3), 1(2)+2(3)]ᵀ = [5,8]ᵀ.

Determinan matriks K adalah 1(2)−1(1)=1.

## Bab 3 — Aritmetika Modular

a ≡ b (mod m) berarti m membagi a−b. Invers perkalian a modulo m adalah x yang memenuhi ax ≡ 1 (mod m). Invers ada jika dan hanya jika gcd(a,m)=1.

Contoh: 7⁻¹ ≡ 15 (mod 26), sebab 7×15=105=4×26+1. Bilangan 2 tidak memiliki invers modulo 26 karena gcd(2,26)=2.

Modulus 128 dan 256 adalah bilangan komposit. Karena itu, elemen bukan nol belum tentu mempunyai invers.

## Bab 4 — Teori Hill Cipher

Model enkripsi: C ≡ KP (mod m). Model dekripsi: P ≡ K⁻¹C (mod m).

Syarat perlu dan cukup agar K memiliki invers modulo m adalah:

gcd(det(K),m)=1.

Jika syarat terpenuhi, K⁻¹ ≡ (det K)⁻¹ adj(K) (mod m). Determinan yang sekadar bukan nol tidak cukup untuk modulus komposit.

## Bab 5 — Contoh Enkripsi dan Dekripsi Manual

Contoh pedagogis berikut menggunakan modulo 26 dan angka alfabet A=0,…,Z=25. Ini bukan salah satu mode byte aplikasi.

Ambil:
K = [[1,1],[1,2]], P = [2,3]ᵀ, m=26.

Enkripsi:
C = KP = [5,8]ᵀ (mod 26).

Determinan K=1. Adjugat K=[[2,−1],[−1,1]], sehingga:
K⁻¹ = [[2,25],[25,1]] (mod 26).

Dekripsi:
K⁻¹C = [2(5)−8, −5+8]ᵀ = [2,3]ᵀ (mod 26).

Pesan numerik awal berhasil dipulihkan.

## Bab 6 — Encoding dan Byte

ASCII standar memuat 128 kode (0–127). Windows-1252 adalah encoding satu byte untuk karakter yang didukung, dengan beberapa posisi byte tidak terdefinisi. UTF-8 mengodekan Unicode menjadi satu hingga empat byte per code point.

Karena itu, jumlah karakter tidak selalu sama dengan jumlah byte. Contoh: karakter “é” pada UTF-8 diwakili oleh byte C3 A9 (195 dan 169). Aplikasi menggunakan modulus 128 untuk ASCII dan 256 untuk Windows-1252 serta UTF-8.

## Bab 7 — Blok, Padding, Base64, dan HCE

Pesan diproses per blok berukuran n byte. Jika panjang pesan tidak habis dibagi n, zero padding ditambahkan sampai kelipatan n. Panjang byte asli disimpan untuk menghapus padding secara tepat setelah dekripsi.

Base64 hanya mengubah representasi byte menjadi teks; Base64 mentah tidak membawa encoding, ordo matriks, atau panjang byte asli. Paket HCE/JSON menyimpan metadata yang diperlukan.

HMAC dapat digunakan untuk memeriksa integritas paket apabila proses verifikasi dan pengelolaan kuncinya benar. Fingerprint kunci bukan pengganti autentikasi pesan.

## Bab 8 — Matriks dan Teori Graf

Dengan konvensi matriks ketetanggaan, entri Aᵢⱼ yang tidak nol merepresentasikan sisi berarah vᵢ→vⱼ dengan bobot Aᵢⱼ. Interpretasi ini membantu menghubungkan matriks dan graf.

Graph Key Lab membangun struktur graf yang divalidasi lalu menghasilkan passphrase deterministik untuk pembentukan matriks kunci melalui aplikasi. Matriks kunci tidak otomatis merupakan graf; graf adalah interpretasi tambahan.

Perbedaan penting:
- Unimodular: matriks bilangan bulat dengan det(A)=±1.
- Invertibel modulo m: gcd(det(A),m)=1.

Keduanya bukan pernyataan yang sama.

## Bab 9 — Analisis Keamanan

Hill Cipher bersifat linear dan rentan terhadap known-plaintext attack dalam kondisi yang sesuai. Pasangan plaintext-ciphertext yang cukup dapat membentuk sistem persamaan untuk memperoleh matriks kunci. Hill Cipher tidak menyediakan keamanan modern dan tidak boleh digunakan untuk data rahasia.

Pemeriksaan integritas paket HCE tidak mengubah Hill Cipher menjadi algoritma enkripsi modern. Untuk kebutuhan nyata, gunakan algoritma authenticated encryption yang telah teruji, misalnya AES-GCM atau ChaCha20-Poly1305.

## Bab 10 — Praktikum HILLCRYPT

1. Pilih mode encoding.
2. Pilih ordo matriks dan passphrase.
3. Pastikan status matriks menyatakan invertibel modulo m.
4. Masukkan pesan uji, lalu jalankan enkripsi.
5. Simpan paket .hce.
6. Buka menu Dekripsi dan pulihkan paket.
7. Bandingkan plaintext hasil dekripsi dengan teks awal.
8. Ulangi pada UTF-8 menggunakan teks non-ASCII.
9. Catat encoding, modulus, ordo matriks, panjang karakter, panjang byte, dan status pengujian.

Jangan mengirimkan informasi rahasia ke aplikasi edukasi yang di-host secara publik.

## Referensi belajar lanjutan

Materi aplikasi ini adalah pengantar. Untuk pendalaman, pelajari buku teks aljabar linear, teori bilangan elementer, pengantar kriptografi, dokumentasi standar Unicode/UTF-8, serta dokumentasi resmi Python mengenai codec teks. Pastikan setiap definisi dan teorema yang digunakan dalam karya ilmiah dirujuk pada sumber akademik yang sesuai.
