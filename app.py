import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from graph_key_lab import (
    SUPPORTED_ORDERS, GraphKeyError, adjacency_matrix, bipartite_unimodular_graph, complete_graph,
    decrypt_bytes as graph_decrypt_bytes, encrypt_bytes as graph_encrypt_bytes,
    path_graph, unique_perfect_matching_tree, validate_adjacency, derive_graph_passphrase,
)

from hill_cipher import (
    MODES, create_package, decrypt_package, decode_plaintext, key_fingerprint,
    encode_plaintext, derive_key_matrix, matrix_inverse_mod,
    matrix_determinant, decrypt_bytes
)

st.set_page_config(
    page_title="HILLCRYPT 5.2 | Matrix Cryptography",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Language ----------
LANG = {
"id": {
 "home":"Beranda","enc":"Enkripsi","dec":"Dekripsi","lab":"Laboratorium Matriks","graphkey":"GRAPH KEY LAB",
 "learn":"Belajar Kriptografi","test":"Uji Sistem","about":"Tentang",
 "encoding":"Mode Encoding","matrix":"Pengaturan Matriks","order":"Ordo matriks (n × n)",
 "key":"Kata kunci (passphrase)","system":"Informasi Sistem","hero":"Platform Pembelajaran Kriptografi Matriks",
 "hero_sub":"Pelajari matematika. Pahami kriptografi. Eksplorasi transformasi pesan.",
 "welcome":"Selamat datang di HILLCRYPT","home_desc":"Platform edukasi interaktif untuk mempelajari Hill Cipher melalui aljabar linear dan aritmetika modulo.",
 "encryption":"Enkripsi Pesan","decryption":"Dekripsi Pesan","encrypt_desc":"Ubah plaintext menjadi ciphertext menggunakan matriks kunci yang dapat dikustomisasi.",
 "decrypt_desc":"Pulihkan ciphertext menjadi plaintext dengan matriks invers modular.",
 "plain":"Plaintext / Pesan asli","cipher":"Ciphertext / Paket","paste":"Tempel teks atau paket ciphertext di sini...",
 "upload_plain":"Unggah file plaintext (.txt)","upload_cipher":"Unggah paket ciphertext (.hce / .json)",
 "encrypt_now":"ENKRIPSI SEKARANG","decrypt_now":"DEKRIPSI SEKARANG","result":"Hasil Dekripsi",
 "copy_hint":"Paket JSON menyimpan encoding, ordo matriks, panjang byte asli, dan ciphertext sehingga dapat dipulihkan tanpa menebak parameter.",
 "raw_mode":"Jika hanya memiliki Base64 mentah, isi juga encoding, ordo, dan panjang byte asli.",
 "package_mode":"Paket HILLCRYPT (JSON / HCE)","raw_b64":"Ciphertext Base64 mentah",
 "original_len":"Panjang byte plaintext asli","success_enc":"Enkripsi berhasil. Simpan atau salin paket untuk proses dekripsi.",
 "success_dec":"Dekripsi berhasil. Plaintext berhasil dipulihkan.",
 "download_pkg":"Unduh paket ciphertext (.hce)","download_text":"Unduh plaintext (.txt)",
 "equations":"Persamaan Dasar Hill Cipher","flow":"Alur Proses","encrypt":"Enkripsi (Encryption)","decrypt":"Dekripsi (Decryption)",
 "condition":"Syarat matriks kunci invertibel:","plain_vector":"vektor plaintext","cipher_vector":"vektor ciphertext","key_matrix":"matriks kunci berordo n × n","modulus":"modulus encoding",
 "encoding_info":"Pilih ASCII untuk kode 0–127, Windows-1252 untuk karakter satu-byte CP1252, atau UTF-8 untuk seluruh karakter Unicode.",
 "start":"Mulai eksplorasi","long":"Teks panjang didukung selama kapasitas memori dan batas unggah perangkat mencukupi.",
 "matrix_show":"Tampilkan matriks kunci dan validasi","matrix_ok":"Matriks kunci invertibel modulo",
 "bad_cipher":"Ciphertext tidak valid atau metadata tidak cocok.",
 "learn_intro":"Materi ringkas untuk memahami konsep dan matematika di balik Hill Cipher.",
 "about_desc":"HILLCRYPT adalah media pembelajaran interaktif yang menghubungkan kriptografi klasik dengan aljabar linear dan aritmetika modulo.",
 "local_note":"Mode lokal memproses data pada komputer yang menjalankan aplikasi. Jika dipublikasikan, data diproses oleh server hosting.",
 "warning":"Hill Cipher merupakan algoritma klasik untuk edukasi, bukan perlindungan data rahasia. Gunakan enkripsi modern terautentikasi untuk keamanan nyata.",
 "roundtrip":"JALANKAN UJI ROUND-TRIP","pass":"PASS — hasil dekripsi identik dengan plaintext awal.",
 "no_text":"Belum ada teks.","details":"Detail hasil","matrix_title":"Matriks kunci",
 "download_raw":"Unduh ciphertext Base64 (.txt)","input_method":"Metode input","text_package":"Teks / Paket JSON","file":"Unggah File",
 "language":"Bahasa","system_encoding":"Encoding aktif","block":"Ukuran blok","bytes":"byte",
 "key_help":"Kata kunci dapat dikustomisasi. Gunakan kata kunci yang sama saat dekripsi; menggantinya tidak akan mengubah pengaturan encoding atau fitur lain.",
 "matrix_minus":"Kurangi ordo matriks","matrix_plus":"Tambah ordo matriks",
 "cipher_only":"Ciphertext saja (Base64)","cipher_copy_help":"Salin hanya teks Base64 berikut untuk dibagikan atau ditempel pada mode Base64 mentah.",
 "chars":"karakter","byte":"byte","empty_text":"Belum ada teks. Jumlah saat ini: 0 karakter · 0 byte.",
 "auto_length":"Panjang byte dibaca otomatis dari paket HILLCRYPT. Untuk Base64 mentah, panjang asli tidak tersimpan sehingga tidak dapat diketahui secara pasti.",
 "manual_raw_length":"Panjang byte asli (khusus Base64 mentah; diperlukan untuk menghapus padding secara tepat)",
 "manual_calc":"Kalkulator Matriks Manual","manual_calc_desc":"Masukkan dua matriks persegi, lalu hitung hasil perkalian modulo encoding yang sedang dipilih.",
 "matrix_a":"Matriks A","matrix_b":"Matriks B","calculate":"Hitung A × B modulo m","manual_result":"Hasil A × B (mod m)",
 "vector_calc":"Simulasi perkalian K dengan vektor plaintext","vector_input":"Masukkan elemen vektor P dipisahkan koma",
 "vector_help":"Masukkan tepat n bilangan bulat. Nilai akan direduksi modulo m.",
 "vector_result":"Vektor ciphertext C","calculation_steps":"Langkah perhitungan per baris",
 "graph_title":"Visualisasi Graf Berbobot dari Matriks Kunci","graph_desc":"Setiap simpul mewakili indeks baris/kolom. Sisi berarah i → j ditampilkan jika entri Kᵢⱼ tidak nol; bobot sisi adalah Kᵢⱼ modulo m.",
 "graph_empty":"Matriks ini tidak memiliki sisi berbobot nonnol untuk divisualisasikan.",
 "graph_limit":"Visualisasi dibatasi sampai ordo 12 agar graf tetap terbaca.",
 "ascii_title":"Tabel ASCII dan Windows-1252","ascii_desc":"Jelajahi kode desimal, heksadesimal, biner, dan karakter. Kode kontrol ASCII ditampilkan dengan nama standarnya.",
 "ascii_range":"Rentang tabel","ascii_search":"Cari kode atau karakter","ascii_standard":"ASCII standar (0–127)","ascii_extended":"Windows-1252 (128–255)","ascii_all":"Gabungan 0–255",
 "about_key":"Kunci dan validasi","about_padding":"Pembagian blok dan padding","about_encoding":"Encoding teks","about_graph":"Hubungan matriks dan graf","about_security":"Batas keamanan",
 "dashboard_matrix":"Ordo matriks","roundtrip_formula":"D_K(E_K(P)) = P","roundtrip_label":"Uji pemulihan plaintext","matrix_card_desc":"Ordo matriks persegi dapat dikustomisasi.",
 "history":"Riwayat Aktivitas",
 "history_desc":"Riwayat proses enkripsi dan dekripsi pada sesi aplikasi ini.",
 "history_empty":"Belum ada aktivitas yang tercatat pada sesi ini.",
 "history_clear_one":"Hapus riwayat",
 "history_clear_all":"Hapus semua riwayat",
 "memory_clear":"Bersihkan memori sementara",
 "memory_clear_help":"Menghapus riwayat, hasil operasi terakhir, dan data sementara dalam sesi aplikasi.",
 "memory_done":"Memori sementara dan riwayat sesi telah dibersihkan.",
 "history_time":"Waktu",
 "history_operation":"Operasi",
 "history_encoding":"Encoding",
 "history_order":"Ordo",
 "history_chars":"Karakter",
 "history_bytes":"Byte",
 "history_status":"Status",
 "graph_operation_title":"Graf Transformasi Operasi Terakhir",
 "graph_encrypt_title":"Graf Transformasi Enkripsi",
 "graph_decrypt_title":"Graf Transformasi Dekripsi",
 "graph_operation_desc":"Graf bipartit berarah ini menunjukkan kontribusi setiap komponen vektor masukan terhadap setiap komponen vektor keluaran. Bobot sisi berasal dari entri matriks transformasi modulo m.",
 "graph_no_operation":"Belum ada operasi enkripsi atau dekripsi pada sesi ini. Lakukan enkripsi atau dekripsi terlebih dahulu agar graf transformasi dapat dibentuk.",
 "graph_input":"Vektor masukan",
 "graph_output":"Vektor keluaran","graph_first_block":"Graf menampilkan blok pertama dari operasi terakhir sebagai contoh visual. Blok berikutnya diproses dengan matriks transformasi yang sama.",
 "graph_encrypt_caption":"Enkripsi: simpul Pⱼ terhubung ke Cᵢ dengan bobot kᵢⱼ.",
 "graph_decrypt_caption":"Dekripsi: simpul Cⱼ terhubung ke Pᵢ dengan bobot (K⁻¹)ᵢⱼ.",
 "copyright":"© 2026 Mamay Nurholifah. HILLCRYPT – Platform Pembelajaran Kriptografi Matriks. Hak cipta dilindungi.",
 "copyright_note":"Pemberitahuan hak cipta aplikasi. Komponen dan pustaka pihak ketiga tetap mengikuti lisensinya masing-masing.",
 "history_privacy":"Riwayat hanya menyimpan metadata aktivitas. Plaintext, ciphertext, dan kata kunci tidak disimpan dalam riwayat.",
 "equation_symbols":"Keterangan simbol",
 "symbol_n":"n: ordo matriks kunci dan panjang setiap blok vektor.",
 "symbol_m":"m: modulus yang ditentukan oleh mode encoding.",
 "symbol_p":"P: vektor kolom plaintext; pⱼ adalah komponen ke-j.",
 "symbol_c":"C: vektor kolom ciphertext; cᵢ adalah komponen ke-i.",
 "symbol_k":"K: matriks kunci berordo n × n; kᵢⱼ adalah elemen baris ke-i kolom ke-j.",
 "symbol_kinv":"K⁻¹: invers modular matriks kunci K.",
 "symbol_ek":"Eₖ: fungsi enkripsi menggunakan matriks kunci K.",
 "symbol_dk":"Dₖ: fungsi dekripsi menggunakan invers modular K⁻¹.",
 "symbol_det":"det(K): determinan matriks K; gcd(det(K),m)=1 merupakan syarat invertibilitas.",
 "language_id":"Bahasa Indonesia","language_en":"Bahasa Inggris",
 "matrix_formula":"Invers matriks modular","inverse_formula":"Rumus invers matriks modular",
 "ascii_decimal":"Desimal","ascii_hex":"Heksadesimal","ascii_binary":"Biner","ascii_character":"Karakter","ascii_type":"Jenis",
 "ascii_control":"Kontrol","ascii_printable":"Dapat dicetak","ascii_cp1252":"Windows-1252","ascii_undefined":"Tidak terdefinisi",
 "order_label":"Ordo","manual_expected":"Masukkan tepat",
 "hero_eyebrow":"KRIPTOGRAFI MATRIKS · BELAJAR · EKSPLORASI · EKSPERIMEN",
 "hero_tagline":"Jelajahi Matematika. Pahami Kriptografi. Lindungi Informasi.",
 "long_desc":"Teks panjang didukung selama kapasitas memori dan batas perangkat mencukupi.",
 "lab_desc":"Eksplorasi matriks kunci, determinan, dan invers modular.",
 "test_desc":"Verifikasi konsistensi enkripsi dan dekripsi.",
 "nav_heading":"NAVIGASI","platform_subtitle":"PLATFORM KRIPTOGRAFI MATRIKS",
 "metric_characters":"Karakter","metric_cipherbytes":"Byte ciphertext","metric_matrixorder":"Ordo matriks",
 "loaded_file":"File berhasil dimuat","package_expander":"Lihat isi paket ciphertext",
 "raw_info":"Jika hanya memiliki Base64 mentah, isi juga encoding, ordo matriks, dan panjang byte asli.",
 "raw_placeholder":"Tempel ciphertext Base64 saja…",
 "about_objectives":"Tujuan pembelajaran","about_obj_1":"Memahami plaintext, ciphertext, enkripsi, dan dekripsi.",
 "about_obj_2":"Merepresentasikan teks sebagai byte dan vektor kolom.",
 "about_obj_3":"Mengeksplorasi perkalian matriks dan aritmetika modulo.",
 "about_obj_4":"Memeriksa determinan dan syarat invers modular.",
 "about_obj_5":"Membandingkan encoding ASCII, Windows-1252, dan UTF-8.",
 "cross_device":"Akses lintas perangkat","cross_device_desc":"Publikasikan proyek Streamlit ini ke hosting publik agar dapat diakses melalui browser dari Windows, Android, iOS, dan perangkat lain. Tambahkan URL publik ke layar utama ponsel agar terasa seperti aplikasi.",
},
"en": {
 "home":"Home","enc":"Encryption","dec":"Decryption","lab":"Matrix Laboratory","graphkey":"GRAPH KEY LAB",
 "learn":"Learn Cryptography","test":"System Test","about":"About",
 "encoding":"Encoding Mode","matrix":"Matrix Settings","order":"Matrix order (n × n)",
 "key":"Key / Passphrase","system":"System Information","hero":"Matrix Cryptography Learning Platform",
 "hero_sub":"Explore mathematics. Understand cryptography. Experiment with message transformations.",
 "welcome":"Welcome to HILLCRYPT","home_desc":"An interactive learning platform for the Hill Cipher using linear algebra and modular arithmetic.",
 "encryption":"Message Encryption","decryption":"Message Decryption","encrypt_desc":"Transform plaintext into ciphertext using a customizable key matrix.",
 "decrypt_desc":"Recover plaintext from ciphertext using the modular inverse matrix.",
 "plain":"Plaintext / Original message","cipher":"Ciphertext / Package","paste":"Paste ciphertext text or package here...",
 "upload_plain":"Upload plaintext file (.txt)","upload_cipher":"Upload ciphertext package (.hce / .json)",
 "encrypt_now":"ENCRYPT NOW","decrypt_now":"DECRYPT NOW","result":"Decryption Result",
 "copy_hint":"The JSON package stores encoding, matrix order, original byte length, and ciphertext so it can be restored without guessing parameters.",
 "raw_mode":"If you only have raw Base64, also provide encoding, matrix order, and original byte length.",
 "package_mode":"HILLCRYPT Package (JSON / HCE)","raw_b64":"Raw Base64 Ciphertext",
 "original_len":"Original plaintext byte length","success_enc":"Encryption successful. Save or copy the package for decryption.",
 "success_dec":"Decryption successful. Plaintext has been restored.",
 "download_pkg":"Download ciphertext package (.hce)","download_text":"Download plaintext (.txt)",
 "equations":"Hill Cipher Core Equations","flow":"Process Flow","encrypt":"Encryption","decrypt":"Decryption",
 "condition":"Key matrix invertibility condition:","plain_vector":"plaintext vector","cipher_vector":"ciphertext vector","key_matrix":"n × n key matrix","modulus":"encoding modulus",
 "encoding_info":"Choose ASCII for codes 0–127, Windows-1252 for one-byte CP1252 characters, or UTF-8 for all Unicode characters.",
 "start":"Explore features","long":"Long text is supported within the memory and upload limits of the device.",
 "matrix_show":"Show key matrix and validation","matrix_ok":"Key matrix is invertible modulo",
 "bad_cipher":"Ciphertext is invalid or its metadata does not match.",
 "learn_intro":"Learning materials to understand the concepts and mathematics behind the Hill Cipher.",
 "about_desc":"HILLCRYPT is an interactive learning resource connecting classical cryptography with linear algebra and modular arithmetic.",
 "local_note":"Local mode processes data on the computer running the app. When publicly hosted, data is processed by the hosting server.",
 "warning":"Hill Cipher is a classical educational algorithm, not a method for protecting confidential data. Use modern authenticated encryption for real security.",
 "roundtrip":"RUN ROUND-TRIP TEST","pass":"PASS — decrypted result matches the original plaintext.",
 "no_text":"No text yet.","details":"Result details","matrix_title":"Key matrix",
 "download_raw":"Download Base64 ciphertext (.txt)","input_method":"Input method","text_package":"Text / JSON Package","file":"Upload File",
 "language":"Language","system_encoding":"Active encoding","block":"Block size","bytes":"bytes",
 "key_help":"The key can be customized. Use the same key for decryption; changing it does not alter the encoding settings or other features.",
 "matrix_minus":"Decrease matrix order","matrix_plus":"Increase matrix order",
 "cipher_only":"Ciphertext only (Base64)","cipher_copy_help":"Copy only the Base64 text below to share it or paste it into raw Base64 mode.",
 "chars":"characters","byte":"bytes","empty_text":"No text yet. Current count: 0 characters · 0 bytes.",
 "auto_length":"The byte length is read automatically from a HILLCRYPT package. Raw Base64 does not store the original length, so it cannot be determined exactly.",
 "manual_raw_length":"Original byte length (raw Base64 only; required to remove padding exactly)",
 "manual_calc":"Manual Matrix Calculator","manual_calc_desc":"Enter two square matrices, then calculate their product modulo the currently selected encoding modulus.",
 "matrix_a":"Matrix A","matrix_b":"Matrix B","calculate":"Calculate A × B modulo m","manual_result":"A × B result (mod m)",
 "vector_calc":"Simulate multiplication of K by a plaintext vector","vector_input":"Enter vector P elements separated by commas",
 "vector_help":"Enter exactly n integers. Values will be reduced modulo m.",
 "vector_result":"Ciphertext vector C","calculation_steps":"Row-by-row calculation steps",
 "graph_title":"Weighted Graph Visualization of the Key Matrix","graph_desc":"Each vertex represents a row/column index. A directed edge i → j appears when Kᵢⱼ is nonzero; its weight is Kᵢⱼ modulo m.",
 "graph_empty":"This matrix has no nonzero weighted edges to visualize.",
 "graph_limit":"Visualization is limited to order 12 to keep the graph readable.",
 "ascii_title":"ASCII and Windows-1252 Table","ascii_desc":"Explore decimal, hexadecimal, binary codes, and characters. ASCII control codes are displayed using their standard names.",
 "ascii_range":"Table range","ascii_search":"Search code or character","ascii_standard":"Standard ASCII (0–127)","ascii_extended":"Windows-1252 (128–255)","ascii_all":"Combined 0–255",
 "about_key":"Key and validation","about_padding":"Block division and padding","about_encoding":"Text encoding","about_graph":"Connection between matrices and graphs","about_security":"Security limitations",
 "dashboard_matrix":"Matrix order","roundtrip_formula":"D_K(E_K(P)) = P","roundtrip_label":"Plaintext recovery test","matrix_card_desc":"Customizable square matrix order.",
 "history":"Activity History",
 "history_desc":"Encryption and decryption activity recorded during this app session.",
 "history_empty":"No activity has been recorded in this session yet.",
 "history_clear_one":"Delete history item",
 "history_clear_all":"Delete all history",
 "memory_clear":"Clear temporary memory",
 "memory_clear_help":"Clears history, the latest operation result, and temporary data stored in this app session.",
 "memory_done":"Temporary session memory and history have been cleared.",
 "history_time":"Time",
 "history_operation":"Operation",
 "history_encoding":"Encoding",
 "history_order":"Order",
 "history_chars":"Characters",
 "history_bytes":"Bytes",
 "history_status":"Status",
 "graph_operation_title":"Latest Operation Transformation Graph",
 "graph_encrypt_title":"Encryption Transformation Graph",
 "graph_decrypt_title":"Decryption Transformation Graph",
 "graph_operation_desc":"This directed bipartite graph shows how each input-vector component contributes to each output-vector component. Edge weights come from the transformation matrix modulo m.",
 "graph_no_operation":"No encryption or decryption has been performed in this session. Run an operation first to build its transformation graph.",
 "graph_input":"Input vector",
 "graph_output":"Output vector","graph_first_block":"The graph displays the first block of the latest operation as a visual example. Subsequent blocks use the same transformation matrix.",
 "graph_encrypt_caption":"Encryption: each Pⱼ vertex connects to Cᵢ with weight kᵢⱼ.",
 "graph_decrypt_caption":"Decryption: each Cⱼ vertex connects to Pᵢ with weight (K⁻¹)ᵢⱼ.",
 "copyright":"© 2026 Mamay Nurholifah. HILLCRYPT – Matrix Cryptography Learning Platform. All rights reserved.",
 "copyright_note":"Application copyright notice. Third-party components and libraries remain subject to their respective licenses.",
 "history_privacy":"History stores activity metadata only. Plaintext, ciphertext, and passphrases are not stored in history.",
 "equation_symbols":"Symbol definitions",
 "symbol_n":"n: order of the key matrix and length of each vector block.",
 "symbol_m":"m: modulus determined by the selected encoding mode.",
 "symbol_p":"P: plaintext column vector; pⱼ is its j-th component.",
 "symbol_c":"C: ciphertext column vector; cᵢ is its i-th component.",
 "symbol_k":"K: n × n key matrix; kᵢⱼ is the entry in row i, column j.",
 "symbol_kinv":"K⁻¹: modular inverse of the key matrix K.",
 "symbol_ek":"Eₖ: encryption function using key matrix K.",
 "symbol_dk":"Dₖ: decryption function using modular inverse K⁻¹.",
 "symbol_det":"det(K): determinant of K; gcd(det(K),m)=1 is the invertibility condition.",
 "language_id":"Indonesian","language_en":"English",
 "matrix_formula":"Modular matrix inverse","inverse_formula":"Modular matrix inverse formula",
 "ascii_decimal":"Decimal","ascii_hex":"Hexadecimal","ascii_binary":"Binary","ascii_character":"Character","ascii_type":"Type",
 "ascii_control":"Control","ascii_printable":"Printable","ascii_cp1252":"Windows-1252","ascii_undefined":"Undefined",
 "order_label":"Order","manual_expected":"Enter exactly",
 "hero_eyebrow":"MATRIX CRYPTOGRAPHY · LEARN · EXPLORE · EXPERIMENT",
 "hero_tagline":"Explore Mathematics. Understand Cryptography. Protect Information.",
 "long_desc":"Long text is supported within the available memory and device limits.",
 "lab_desc":"Explore key matrices, determinants, and modular inverses.",
 "test_desc":"Verify encryption and decryption consistency.",
 "nav_heading":"NAVIGATION","platform_subtitle":"MATRIX CRYPTOGRAPHY PLATFORM",
 "metric_characters":"Characters","metric_cipherbytes":"Ciphertext bytes","metric_matrixorder":"Matrix order",
 "loaded_file":"File loaded successfully","package_expander":"View ciphertext package",
 "raw_info":"If you only have raw Base64, also provide the encoding, matrix order, and original byte length.",
 "raw_placeholder":"Paste Base64 ciphertext only…",
 "about_objectives":"Learning objectives","about_obj_1":"Understand plaintext, ciphertext, encryption, and decryption.",
 "about_obj_2":"Represent text as bytes and column vectors.",
 "about_obj_3":"Explore matrix multiplication and modular arithmetic.",
 "about_obj_4":"Check determinants and modular invertibility.",
 "about_obj_5":"Compare ASCII, Windows-1252, and UTF-8 encodings.",
 "cross_device":"Cross-device access","cross_device_desc":"Deploy this Streamlit project to a public host to access it through a browser on Windows, Android, iOS, and other devices. Add the public URL to your phone's home screen for an app-like experience.",
}
}
if "language" not in st.session_state:
    st.session_state.language = "id"
lang_choice = st.sidebar.radio(
    "Bahasa / Language", ["🇮🇩 Indonesia", "🇬🇧 English"],
    index=0 if st.session_state.language == "id" else 1,
    horizontal=True, label_visibility="visible", key="language_choice"
)
st.session_state.language = "id" if lang_choice.startswith("🇮🇩") else "en"
T = LANG[st.session_state.language]
def tr(k):
    return T.get(k, k)

# ---------- Styling ----------
ASSET = Path(__file__).parent / "assets" / "cyber_background.svg"
bg_uri = ""
if ASSET.exists():
    import base64 as _b64
    bg_uri = "data:image/svg+xml;base64," + _b64.b64encode(ASSET.read_bytes()).decode()
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
html, body, [class*="css"] {{ font-family:'DM Sans',sans-serif; }}
.stApp {{ background:linear-gradient(145deg,#07182d 0%,#0b2340 23%,#edf3f9 23.1%,#f4f7fb 100%); color:#173650; }}
.block-container {{ max-width:1440px; padding-top:1.15rem; padding-bottom:3rem; }}
[data-testid="stHeader"] {{ background:transparent !important; border:0 !important; box-shadow:none !important; backdrop-filter:none !important; }}
[data-testid="stToolbar"] {{ background:transparent !important; }}
[data-testid="stDecoration"] {{ display:none !important; }}
[data-testid="stSidebar"] {{ background:linear-gradient(180deg,#07182d 0%,#123b63 100%); border-right:1px solid rgba(70,190,230,.28); }}
[data-testid="stSidebar"] * {{ color:#eaf4ff; }}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] label {{ color:#eaf4ff !important; }}
.hero {{
 border-radius:23px; padding:2.35rem 2.5rem;
 background-image:linear-gradient(90deg,rgba(5,20,39,.97) 0%,rgba(8,39,68,.86) 58%,rgba(8,39,68,.58)),url("{bg_uri}");
 background-size:cover; background-position:center; color:white; margin-bottom:1.35rem;
 min-height:205px; box-shadow:0 15px 40px rgba(6,23,43,.20); border:1px solid rgba(67,194,235,.38);
}}
.hero h1 {{ font-family:'Space Grotesk'; font-size:clamp(2.2rem,5vw,3.4rem); letter-spacing:.07em; color:white; margin:0; }}
.hero p {{ color:#d9edf9; margin:.5rem 0; }}
.eyebrow {{ color:#71d7e7 !important; font-size:.72rem; letter-spacing:.18em; font-weight:700; }}
h1,h2,h3,h4 {{ font-family:'Space Grotesk','DM Sans',sans-serif; color:#123653; }}
.section-banner {{
 border-radius:18px; padding:1.25rem 1.55rem;
 background-image:linear-gradient(90deg,rgba(5,20,39,.97),rgba(8,39,68,.84)),url("{bg_uri}");
 background-size:cover; background-position:center; color:#fff; margin:0 0 1.25rem;
 border:1px solid rgba(42,164,207,.35); box-shadow:0 9px 26px rgba(10,35,60,.12);
}}
.section-banner h1 {{ color:#fff; margin:0; font-size:clamp(1.45rem,3vw,2rem); }}
.section-banner p {{ color:#d9edf9; margin:.45rem 0 0; }}
.card,.panel,.kpi {{ background:#fff; border:1px solid #dce6f0; border-radius:17px; padding:1.15rem 1.3rem; box-shadow:0 7px 22px rgba(15,44,73,.07); margin-bottom:.8rem; }}
.kpi .value,.kpi .v {{ font-size:1.9rem; font-weight:750; color:#123b63; font-family:'Space Grotesk'; }}
.kpi .label,.kpi .l,.kpi .desc,.muted,.small-muted {{ color:#687d91; font-size:.88rem; }}
/* High-contrast editable fields in both main content and sidebar. */
div[data-baseweb="input"] input, div[data-baseweb="textarea"] textarea,
div[data-baseweb="select"] > div, div[data-baseweb="select"] input,
[data-testid="stNumberInput"] input, [data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea {{
 background:#f7fbff !important; color:#102b45 !important;
 -webkit-text-fill-color:#102b45 !important; caret-color:#102b45 !important;
 border:1px solid #b9cfe2 !important; border-radius:10px !important;
}}
div[data-baseweb="input"] input::placeholder, div[data-baseweb="textarea"] textarea::placeholder,
[data-testid="stTextInput"] input::placeholder, [data-testid="stTextArea"] textarea::placeholder {{
 color:#71879b !important; -webkit-text-fill-color:#71879b !important; opacity:1 !important;
}}
[data-testid="stFileUploader"] section {{ background:#f7fbff !important; border:1px dashed #9db9d2 !important; border-radius:12px !important; }}
[data-testid="stFileUploader"] section *, [data-testid="stFileUploader"] button {{ color:#183a58 !important; -webkit-text-fill-color:#183a58 !important; }}
[data-testid="stSidebar"] div[data-baseweb="input"] input,
[data-testid="stSidebar"] div[data-baseweb="textarea"] textarea,
[data-testid="stSidebar"] [data-testid="stNumberInput"] input,
[data-testid="stSidebar"] [data-testid="stTextInput"] input,
[data-testid="stSidebar"] div[data-baseweb="select"] input {{ color:#102b45 !important; -webkit-text-fill-color:#102b45 !important; }}
.stTextArea textarea {{ min-height:130px; }}
.stButton>button,.stDownloadButton>button {{ border-radius:11px; font-weight:700; min-height:2.65rem; border:1px solid #148db8; color:white; background:linear-gradient(100deg,#087fa8,#1769b4); }}
.stButton>button:hover,.stDownloadButton>button:hover {{ border-color:#0b638c; color:white; filter:brightness(1.08); }}
[data-testid="stMetric"] {{ background:#fff; border:1px solid #dce6f0; border-radius:14px; padding:12px; }}
[data-testid="stMetricLabel"] {{ color:#62788c !important; }} [data-testid="stMetricValue"] {{ color:#123b63 !important; }}
.math-card {{ background:#fff; border:1px solid #dce6f0; border-radius:15px; padding:1rem 1.2rem; box-shadow:0 5px 16px rgba(15,44,73,.05); }}
div[data-testid="stExpander"] {{ background:rgba(255,255,255,.86); border:1px solid #dce6f0; border-radius:12px; }}
hr {{ border-color:rgba(91,130,160,.25); }}
@media(max-width:800px) {{ .block-container {{ padding-left:1rem; padding-right:1rem; }} .hero {{ padding:1.4rem; min-height:165px; }} .section-banner {{ padding:1rem; }} }}
</style>
""", unsafe_allow_html=True)

# ---------- Header / navigation ----------
st.markdown(f"""
<div class="hero">
 <div class="eyebrow">{tr("hero_eyebrow")}</div>
 <h1>HILLCRYPT <span style="color:#71d7e7;font-size:1.05rem">v5.2</span></h1>
 <p>{tr('hero')}</p>
 <p style="font-size:.9rem;margin-top:.65rem">{tr("hero_tagline")}</p>
</div>""", unsafe_allow_html=True)

def _apply_graph_passphrase(passphrase: str, graph_order: int) -> None:
    """Apply a validated graph-derived passphrase to the main Hill Cipher."""
    st.session_state["global_key"] = passphrase
    st.session_state["matrix_order"] = int(graph_order)
    st.session_state["graph_key_active"] = True
    st.session_state["graph_key_passphrase"] = passphrase
    st.session_state["page_key"] = "enc"


# ---------- Navigation and global settings ----------
page_keys = ["home","enc","dec","lab","graphkey","learn","test","history","about"]
nav_labels = [tr(k) for k in page_keys]
if "page_key" not in st.session_state:
    st.session_state.page_key = "home"

with st.sidebar:
    st.markdown("# 🔐 HILLCRYPT")
    st.caption(tr("platform_subtitle"))
    st.divider()
    st.markdown("### "+tr("nav_heading"))
    nav_index = page_keys.index(st.session_state.page_key)
    selected_label = st.radio(
        "Navigation", nav_labels, index=nav_index,
        label_visibility="collapsed", key=f"navigation_{st.session_state.language}"
    )
    page_key = page_keys[nav_labels.index(selected_label)]
    st.session_state.page_key = page_key
    st.divider()
    st.markdown(f"### ◈ {tr('encoding')}")
    encoding_labels = ["ASCII Standard (0–127)","Windows-1252 (0–255)","UTF-8 / Unicode"]
    if "global_encoding" not in st.session_state:
        st.session_state.global_encoding = "utf8"
    default_index = {"ascii":0,"windows1252":1,"utf8":2}[st.session_state.global_encoding]
    chosen = st.radio("Encoding",encoding_labels,index=default_index,
                      label_visibility="collapsed",key="encoding_choice")
    mode = "ascii" if chosen.startswith("ASCII") else "windows1252" if chosen.startswith("Windows") else "utf8"
    st.session_state.global_encoding = mode
    st.caption(tr("encoding_info"))
    st.divider()
    st.markdown(f"### ▦ {tr('matrix')}")
    if "matrix_order" not in st.session_state:
        st.session_state.matrix_order = 4
    minus_col, order_col, plus_col = st.columns([1,2,1])
    with minus_col:
        st.button("−", key="matrix_order_minus", help=tr("matrix_minus"),
                  use_container_width=True,
                  on_click=lambda: setattr(st.session_state, "matrix_order", max(1, st.session_state.matrix_order-1)))
    with order_col:
        st.markdown(f"<div style='text-align:center;padding:.55rem .2rem;font-size:1.08rem;font-weight:700;color:#eaf4ff'>{st.session_state.matrix_order} × {st.session_state.matrix_order}</div>",unsafe_allow_html=True)
    with plus_col:
        st.button("+", key="matrix_order_plus", help=tr("matrix_plus"),
                  use_container_width=True,
                  on_click=lambda: setattr(st.session_state, "matrix_order", min(16, st.session_state.matrix_order+1)))
    n = int(st.session_state.matrix_order)
    st.caption(tr("order") + f": {n} × {n} · 1–16")
    if "global_key" not in st.session_state:
        st.session_state["global_key"] = "THEKINGOFGEMINOR"
    key = st.text_input(tr("key"),type="default",key="global_key")
    if st.session_state.get("graph_key_active") and key == st.session_state.get("graph_key_passphrase"):
        st.caption("Sumber kata kunci: GRAPH KEY LAB. Kata kunci ini dapat digunakan kembali untuk dekripsi." if st.session_state.language == "id" else "Key source: GRAPH KEY LAB. Reuse this passphrase for decryption.")
    else:
        st.caption(tr("key_help"))
    st.divider()
    st.markdown(f"### ⓘ {tr('system')}")
    st.markdown(f"""
    <div class="small-muted">
    {tr('system_encoding')}: <b>{MODES[mode]['label']}</b><br>
    Modulus (m): <b>{MODES[mode]['modulus']}</b><br>
    {tr('order')}: <b>{n} × {n}</b><br>
    {tr('block')}: <b>{n} {tr('bytes')}</b>
    </div>""",unsafe_allow_html=True)
    st.divider()
    st.caption("HILLCRYPT v5.2 · Aplikasi Web Responsif" if st.session_state.language=="id" else "HILLCRYPT v5.2 · Responsive Web App")

m = MODES[mode]["modulus"]

def banner(title, subtitle):
    st.markdown(f'<div class="section-banner"><h1>{title}</h1><p>{subtitle}</p></div>',unsafe_allow_html=True)

def show_equations():
    st.subheader(tr("equations"))
    left, right = st.columns(2, gap="large")
    with left:
        st.markdown(f'<div class="math-card"><h4>{tr("encrypt")}</h4></div>', unsafe_allow_html=True)
        st.latex(r"\mathbf{C} = E_K(\mathbf{P}) \equiv K\mathbf{P} \pmod{m}")
        st.caption("Enkripsi: setiap blok plaintext diubah menjadi blok ciphertext." if st.session_state.language=="id" else "Encryption transforms each plaintext block into a ciphertext block.")
    with right:
        st.markdown(f'<div class="math-card"><h4>{tr("decrypt")}</h4></div>', unsafe_allow_html=True)
        st.latex(r"\mathbf{P} = D_K(\mathbf{C}) \equiv K^{-1}\mathbf{C} \pmod{m}")
        st.caption("Dekripsi: ciphertext dikalikan dengan invers modular matriks kunci." if st.session_state.language=="id" else "Decryption multiplies ciphertext by the modular inverse of the key matrix.")
    st.markdown("### "+("Uji pemulihan (round-trip)" if st.session_state.language=="id" else "Plaintext recovery (round-trip)"))
    st.latex(r"D_K(E_K(\mathbf{P})) \equiv \mathbf{P} \pmod{m}")
    st.info(tr("condition") + "  " + r"\(\gcd(\det(K),m)=1\).")
    st.markdown("**"+tr("inverse_formula")+"**")
    st.latex(r"K^{-1} \equiv (\det K)^{-1}\operatorname{adj}(K) \pmod{m}")
    st.markdown("**"+tr("equation_symbols")+"**")
    st.markdown("\n".join("- "+tr(k) for k in ["symbol_p","symbol_c","symbol_k","symbol_kinv","symbol_m","symbol_n","symbol_ek","symbol_dk","symbol_det"]))
    st.markdown("**"+("Persamaan komponen" if st.session_state.language=="id" else "Component equations")+"**")
    st.latex(r"c_i \equiv \sum_{j=1}^{n} k_{ij}p_j \pmod{m}")
    st.latex(r"p_i \equiv \sum_{j=1}^{n} (K^{-1})_{ij}c_j \pmod{m}")
    st.caption("Indeks i menunjukkan baris keluaran dan j menunjukkan komponen masukan." if st.session_state.language=="id" else "Index i denotes an output row and j denotes an input component.")

def add_history(operation, mode_used, order_used, characters, byte_count):
    """Store metadata only; never retain plaintext, ciphertext, or passphrases."""
    if "activity_history" not in st.session_state: st.session_state.activity_history=[]
    ts=datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    st.session_state.activity_history.insert(0,{"id":datetime.now().timestamp(),"time":ts,"operation":operation,"encoding":MODES[mode_used]["label"],"order":f"{order_used} × {order_used}","characters":int(characters),"bytes":int(byte_count),"status":"Berhasil" if st.session_state.language=="id" else "Success"})
    st.session_state.activity_history=st.session_state.activity_history[:100]

def record_last_operation(direction,input_vector,output_vector,transform_matrix,order_used,modulus,mode_used):
    st.session_state.last_operation_graph={"direction":direction,"input":[int(x) for x in input_vector],"output":[int(x) for x in output_vector],"matrix":[[int(x) for x in row] for row in transform_matrix],"n":int(order_used),"modulus":int(modulus),"mode":mode_used}

def make_bipartite_dot(matrix,input_vector,output_vector,direction,modulus):
    n_local=len(matrix); left="P" if direction=="encrypt" else "C"; right="C" if direction=="encrypt" else "P"
    dot=["digraph HillOperation {","rankdir=LR; splines=true; nodesep=0.42; ranksep=1.0;",'graph [bgcolor="transparent", pad="0.3"];','node [shape=box, style="rounded,filled", color="#277fa5", fontcolor="#123653", fontname="Arial"];','edge [color="#1688ad", fontcolor="#123653", fontname="Arial", penwidth=1.5];','subgraph cluster_input { label="INPUT"; color="#9abbd0"; style="rounded";']
    for j,v in enumerate(input_vector): dot.append(f'{left}{j+1} [label="{left}{j+1} = {int(v)}", fillcolor="#dff4ff"];')
    dot.append("}"); dot.append('subgraph cluster_output { label="OUTPUT"; color="#9abbd0"; style="rounded";')
    for i,v in enumerate(output_vector): dot.append(f'{right}{i+1} [label="{right}{i+1} = {int(v)}", fillcolor="#dff9ef"];')
    dot.append("}")
    for i in range(n_local):
        for j in range(n_local):
            w=int(matrix[i][j])%modulus
            if w: dot.append(f'{left}{j+1} -> {right}{i+1} [label="{w}"];')
    dot.append("}"); return "\n".join(dot)

# ---------- Pages ----------
if page_key == "home":
    st.header(tr("welcome"))
    st.write(tr("home_desc"))
    cols=st.columns(4)
    cards=[
        ("3",tr("encoding"),"ASCII · Windows-1252 · UTF-8"),
        ("n × n",tr("dashboard_matrix"),tr("matrix_card_desc")),
        ("Dₖ(Eₖ(P)) ≡ P",tr("roundtrip_label"),"modulo m"),
        ("∞","Teks panjang" if st.session_state.language=="id" else "Long text",tr("long_desc"))
    ]
    for col,(v,l,d) in zip(cols,cards):
        col.markdown(f'<div class="kpi"><div class="label">{l}</div><div class="value">{v}</div><div class="desc">{d}</div></div>',unsafe_allow_html=True)
    st.subheader(tr("start"))
    c1,c2,c3=st.columns(3)
    for col,ico,title,desc in [(c1,"🔒",tr("enc"),tr("encrypt_desc")),(c2,"🔓",tr("dec"),tr("decrypt_desc")),(c3,"▦",tr("lab"),tr("lab_desc"))]:
        col.markdown(f'<div class="panel"><h3>{ico} {title}</h3><p>{desc}</p></div>',unsafe_allow_html=True)
    st.info(tr("encoding_info"))
    st.caption(tr("long"))
    show_equations()

elif page_key == "enc":
    banner("🔒 "+tr("encryption"),tr("encrypt_desc"))
    left,right=st.columns([1,1],gap="large")
    with left:
        st.markdown(f"#### {tr('encoding')}")
        st.info(f"{MODES[mode]['label']} · modulo {m}")
        st.markdown(f"#### {tr('matrix')}")
        st.write(f"{tr('order')}: **{n} × {n}**")
        passphrase=key
        try:
            matrix=derive_key_matrix(passphrase,int(n),m)
            det=matrix_determinant(matrix)
            st.success(f"{tr('matrix_ok')} {m}. det(K) = {det}; gcd = 1.")
            with st.expander(tr("matrix_show")):
                inverse = matrix_inverse_mod(matrix, m)
                mat_left, mat_right = st.columns(2, gap="medium")
                with mat_left:
                    st.markdown("**"+("Matriks kunci K" if st.session_state.language=="id" else "Key matrix K")+"**")
                    st.dataframe(pd.DataFrame(matrix),hide_index=True,use_container_width=True)
                with mat_right:
                    st.markdown("**"+("Invers modular K⁻¹" if st.session_state.language=="id" else "Modular inverse K⁻¹")+"**")
                    st.dataframe(pd.DataFrame(inverse),hide_index=True,use_container_width=True)
                st.caption(f"det(K) = {det} · det(K) mod {m} = {det % m} · gcd(det(K), {m}) = 1")
        except Exception as exc:
            st.error(str(exc))
            matrix=None
    with right:
        st.markdown("#### "+("Masukkan plaintext" if st.session_state.language=="id" else "Enter plaintext"))
        uploaded=st.file_uploader(
            tr("upload_plain"),
            type=["txt"],
            key="enc_upload",
            help=("Unggah file .txt. Pastikan encoding file sesuai dengan mode encoding yang dipilih."
                  if st.session_state.language=="id" else
                  "Upload a .txt file. Make sure its encoding matches the selected encoding mode.")
        )
        if uploaded is not None:
            try:
                uploaded_bytes = uploaded.getvalue()
                upload_fingerprint = hashlib.sha256(uploaded_bytes).hexdigest()
                if st.session_state.get("plain_upload_fingerprint") != upload_fingerprint:
                    st.session_state["plain_input"] = decode_plaintext(uploaded_bytes, mode)
                    st.session_state["plain_upload_fingerprint"] = upload_fingerprint
                st.success(f"{tr('loaded_file')}: {uploaded.name}")
            except Exception as exc:
                st.error(str(exc))
        else:
            st.session_state.pop("plain_upload_fingerprint", None)

        text=st.text_area(
            tr("plain"),
            height=245,
            placeholder="Write any message, paragraph, or long text here…",
            key="plain_input"
        )
        try:
            byte_count=len(encode_plaintext(text,mode)) if text else 0
        except Exception as exc:
            byte_count=0
            st.error(str(exc))
        if text:
            char_label = "karakter" if st.session_state.language=="id" else "characters"
            byte_label = "byte" if st.session_state.language=="id" else "bytes"
            st.caption(f"{len(text):,} {char_label} · {byte_count:,} {byte_label}")
        else:
            st.caption(tr("empty_text"))
    if st.button("🔐 "+tr("encrypt_now"),type="primary",use_container_width=True,disabled=(not bool(text) or matrix is None)):
        try:
            package,info=create_package(text,key,int(n),mode, "GRAPH_KEY_LAB" if (st.session_state.get("graph_key_active") and key == st.session_state.get("graph_key_passphrase")) else "MANUAL")
            raw_json=json.dumps(package,ensure_ascii=False,indent=2)
            # Keep one authoritative record for the most recent encryption.
            # Both decryption input routes are pre-filled from this exact artifact.
            st.session_state["last_encrypt_package"] = package
            st.session_state["last_encrypt_package_json"] = raw_json
            st.session_state["last_encrypt_base64"] = package["ciphertext_b64"]
            st.session_state["last_encrypt_key_fingerprint"] = package["key_fingerprint"]
            st.session_state["last_encrypt_metadata"] = {
                "mode": mode, "matrix_order": int(n), "modulus": int(m),
                "original_byte_length": int(package["original_byte_length"]),
                "key_source": package.get("key_source", "UNKNOWN"),
            }
            st.session_state["package_input"] = raw_json
            st.session_state["raw_b64_input"] = package["ciphertext_b64"]
            st.session_state["dec_raw_length"] = int(package["original_byte_length"])
            # A fresh encryption invalidates visible results from an older run.
            st.session_state.pop("restored_package", None)
            st.session_state.pop("restored_raw", None)
            raw_input=encode_plaintext(text,mode)
            padded=raw_input+(b"\x00"*((-len(raw_input))%int(n)))
            cipher_bytes=base64.b64decode(package["ciphertext_b64"])
            key_matrix=derive_key_matrix(key,int(n),m)
            record_last_operation("encrypt",padded[:int(n)],cipher_bytes[:int(n)],key_matrix,int(n),m,mode)
            add_history("Enkripsi" if st.session_state.language=="id" else "Encryption",mode,int(n),len(text),len(raw_input))
            st.success(tr("success_enc"))
            a,b,c=st.columns(3)
            a.metric("Characters",f"{len(text):,}")
            b.metric(tr("metric_cipherbytes"),f"{info['ciphertext_bytes']:,}")
            c.metric(tr("metric_matrixorder"),f"{n} × {n}")
            st.markdown("#### "+tr("cipher_only"))
            st.caption(tr("cipher_copy_help"))
            st.code(package["ciphertext_b64"],language="text")
            st.markdown("#### "+tr("package_mode"))
            with st.expander(tr("package_expander")):
                st.code(raw_json,language="json")
            st.download_button("⬇ "+tr("download_pkg"),raw_json.encode("utf-8"),"HILLCRYPT_ciphertext.hce","application/json",use_container_width=True)
            st.download_button("⬇ "+tr("download_raw"),package["ciphertext_b64"].encode("ascii"),"HILLCRYPT_ciphertext_base64.txt","text/plain",use_container_width=True)
            st.info(tr("copy_hint"))
        except Exception as exc:
            st.error(str(exc))

elif page_key == "dec":
    banner("🔓 "+tr("decryption"),tr("decrypt_desc"))
    st.markdown(f"#### {tr('input_method')}")
    input_type=st.radio(tr("input_method"),[tr("package_mode"),tr("raw_b64")],horizontal=True)
    if input_type==tr("package_mode"):
        c1,c2=st.columns([1,1],gap="large")
        with c1:
            uploaded=st.file_uploader(tr("upload_cipher"),type=["hce","json"],key="dec_upload")
            pasted=st.text_area(tr("cipher"),height=230,placeholder=tr("paste"),key="package_input")
            if st.session_state.get("last_encrypt_package") and not uploaded:
                st.caption("Paket otomatis disinkronkan dari enkripsi terakhir pada sesi ini. Kamu tetap dapat menggantinya dengan paket lain." if st.session_state.language=="id" else "The latest package from this session is synced automatically. You can replace it with another package.")
        with c2:
            st.markdown("#### "+tr("result"))
            st.caption(tr("copy_hint"))
            st.caption("Disarankan: gunakan file .hce hasil unduhan agar metadata tidak perlu diisi manual." if st.session_state.language=="id" else "Recommended: use the downloaded .hce file so metadata is filled automatically.")
            if uploaded is not None:
                try:
                    package_text=uploaded.getvalue().decode("utf-8-sig")
                    st.success(f"{tr('loaded_file')}: {uploaded.name}")
                except UnicodeDecodeError:
                    package_text=""
                    st.error("File paket harus berupa teks JSON UTF-8 yang valid." if st.session_state.language=="id" else "The package file must contain valid UTF-8 JSON text.")
            else:
                package_text=pasted
            try:
                preview_package = json.loads(package_text) if package_text.strip() else None
            except (json.JSONDecodeError, TypeError):
                preview_package = None
            is_complete_package = isinstance(preview_package, dict) and bool(preview_package.get("format"))
            if is_complete_package:
                raw_length = 0
                st.caption(tr("auto_length"))
            else:
                st.caption(tr("auto_length"))
                raw_length = st.number_input(
                    tr("manual_raw_length"),
                    min_value=0, value=0, step=1, key="dec_raw_length"
                )
            if st.button("🔓 "+tr("decrypt_now"),type="primary",use_container_width=True,key="dec_package",disabled=not bool(package_text.strip())):
                try:
                    # Accept both a complete HILLCRYPT JSON package and the
                    # Base64-only ciphertext displayed by earlier app builds.
                    try:
                        parsed = json.loads(package_text)
                    except (json.JSONDecodeError, TypeError):
                        parsed = None
                    if isinstance(parsed, dict) and parsed.get("format"):
                        plaintext,info=decrypt_package(parsed,key)
                        pmode=parsed["mode"]; pmod=MODES[pmode]["modulus"]; pn=int(parsed["matrix_order"])
                        cdata=base64.b64decode(parsed["ciphertext_b64"],validate=True); pdata=encode_plaintext(plaintext,pmode)
                        pdata_original_length=len(pdata)
                        pdata=pdata+(b"\x00"*max(0,pn-len(pdata)))
                        invmat=matrix_inverse_mod(derive_key_matrix(key,pn,pmod),pmod)
                        record_last_operation("decrypt",cdata[:pn],pdata[:pn],invmat,pn,pmod,pmode)
                        add_history("Dekripsi" if st.session_state.language=="id" else "Decryption",pmode,pn,len(plaintext),pdata_original_length)
                    else:
                        compact_b64 = "".join(package_text.split())
                        ciphertext = base64.b64decode(compact_b64, validate=True)
                        if raw_length <= 0:
                            raise ValueError(
                                ("Input terdeteksi sebagai Base64 mentah. Isi 'Panjang byte asli' sesuai jumlah byte plaintext sebelum padding."
                                 if st.session_state.language=="id" else
                                 "Raw Base64 input detected. Enter the original plaintext byte length before padding.")
                            )
                        raw = decrypt_bytes(ciphertext,key,int(n),m,int(raw_length))
                        plaintext = decode_plaintext(raw,mode)
                        info = {"encoding":MODES[mode]["encoding"],"modulus":m,
                                "n":int(n),"original_bytes":len(raw)}
                        raw_graph=raw+(b"\x00"*max(0,int(n)-len(raw)))
                        invmat=matrix_inverse_mod(derive_key_matrix(key,int(n),m),m)
                        record_last_operation("decrypt",ciphertext[:int(n)],raw_graph[:int(n)],invmat,int(n),m,mode)
                        add_history("Dekripsi" if st.session_state.language=="id" else "Decryption",mode,int(n),len(plaintext),len(raw))
                    st.success(tr("success_dec"))
                    st.text_area(tr("result"),plaintext,height=230,key="restored_package")
                    st.download_button("⬇ "+tr("download_text"),plaintext.encode("utf-8"),"HILLCRYPT_plaintext.txt","text/plain",use_container_width=True)
                    if st.session_state.language=="id":
                        st.caption(f"Encoding: {info['encoding']} · Modulo: {info['modulus']} · Matriks: {info['n']} × {info['n']} · Byte asli: {info['original_bytes']:,}")
                    else:
                        st.caption(f"Encoding: {info['encoding']} · Modulus: {info['modulus']} · Matrix: {info['n']} × {info['n']} · Original bytes: {info['original_bytes']:,}")
                except Exception as exc:
                    st.error(str(exc))
        st.info(tr("copy_hint"))
        st.caption("Paket .hce v4 memverifikasi kecocokan kunci dan integritas metadata/ciphertext. Paket v3 lama tetap dapat dibaca, tetapi belum memiliki autentikasi integritas.")
    else:
        st.info(tr("raw_info"))
        st.warning("Base64 mentah tidak membawa fingerprint kunci atau metadata autentikasi. Dekripsi dengan kunci yang berbeda tetap dapat dihitung secara matematis dan mungkin menghasilkan teks acak; gunakan paket .hce untuk verifikasi kecocokan kunci dan integritas.")
        raw_text=st.text_area(tr("raw_b64"),height=160,placeholder=tr("raw_placeholder"),key="raw_b64_input")
        original_len=st.number_input(tr("original_len"),min_value=0,value=0,step=1)
        if st.button("🔓 "+tr("decrypt_now"),type="primary",use_container_width=True,disabled=not raw_text.strip(),key="dec_raw"):
            try:
                compact_input="".join(raw_text.split())
                ciphertext=base64.b64decode(compact_input,validate=True)
                # If this Base64 matches the latest in-session encryption, we have
                # trustworthy local metadata and can reject a changed key/config.
                known_b64=st.session_state.get("last_encrypt_base64")
                known_meta=st.session_state.get("last_encrypt_metadata") or {}
                is_known=bool(known_b64 and compact_input==known_b64)
                if is_known:
                    if st.session_state.get("last_encrypt_key_fingerprint") != key_fingerprint(key):
                        raise ValueError("Kata kunci tidak cocok dengan ciphertext hasil enkripsi terakhir.")
                    if (known_meta.get("mode")!=mode or known_meta.get("matrix_order")!=int(n)
                            or known_meta.get("modulus")!=int(m)
                            or known_meta.get("original_byte_length")!=int(original_len)):
                        raise ValueError("Konfigurasi dekripsi tidak cocok dengan metadata enkripsi terakhir. Periksa encoding, ordo matriks, dan panjang byte asli.")
                raw=decrypt_bytes(ciphertext,key,int(n),m,int(original_len))
                plaintext=decode_plaintext(raw,mode)
                raw_graph=raw+(b"\x00"*max(0,int(n)-len(raw)))
                invmat=matrix_inverse_mod(derive_key_matrix(key,int(n),m),m)
                record_last_operation("decrypt",ciphertext[:int(n)],raw_graph[:int(n)],invmat,int(n),m,mode)
                add_history("Dekripsi" if st.session_state.language=="id" else "Decryption",mode,int(n),len(plaintext),len(raw))
                if is_known:
                    st.success("Dekripsi berhasil. Kunci dan konfigurasi cocok dengan enkripsi terakhir pada sesi ini." if st.session_state.language=="id" else "Decryption successful. Key and settings match the latest encryption in this session.")
                else:
                    st.warning("Perhitungan dekripsi selesai, tetapi kecocokan kunci tidak dapat diverifikasi karena Base64 mentah tidak menyimpan fingerprint. Periksa apakah plaintext hasilnya benar. Untuk verifikasi kuat, gunakan paket .hce." if st.session_state.language=="id" else "Decryption was computed, but key matching cannot be verified because raw Base64 has no key fingerprint. Check whether the plaintext is correct. Use the .hce package for strong verification.")
                st.text_area(tr("result"),plaintext,height=220,key="restored_raw")
                st.download_button("⬇ "+tr("download_text"),plaintext.encode("utf-8"),"HILLCRYPT_plaintext.txt","text/plain",use_container_width=True)
            except Exception as exc:
                st.error(str(exc))

elif page_key == "lab":
    banner("▦ "+tr("lab"),tr("lab_desc"))
    matrix = None
    try:
        matrix=derive_key_matrix(key,int(n),m)
        det=matrix_determinant(matrix)
        inv=matrix_inverse_mod(matrix,m)
        st.success(f"{tr('matrix_ok')} {m}. det(K) = {det}; gcd(det(K), {m}) = 1.")
        a,b=st.columns(2)
        with a:
            st.markdown("#### "+("Matriks kunci K" if st.session_state.language=="id" else "Key matrix K"))
            st.dataframe(pd.DataFrame(matrix),hide_index=True,use_container_width=True)
        with b:
            st.markdown("#### "+("Invers K⁻¹ (mod m)" if st.session_state.language=="id" else "Inverse K⁻¹ (mod m)"))
            st.dataframe(pd.DataFrame(inv),hide_index=True,use_container_width=True)
        identity=[[sum(matrix[i][k]*inv[k][j] for k in range(int(n)))%m for j in range(int(n))] for i in range(int(n))]
        st.markdown("#### "+("K × K⁻¹ (mod m)" if st.session_state.language=="id" else "K × K⁻¹ (mod m)"))
        st.dataframe(pd.DataFrame(identity),hide_index=True,use_container_width=True)
        st.latex(r"K K^{-1}\equiv I_n\pmod{m}")
    except Exception as exc:
        st.error(str(exc))
    st.divider()
    st.subheader(tr("graph_title"))
    st.caption(tr("graph_desc"))
    if matrix is None:
        st.warning("Periksa kata kunci sebelum menggunakan alat matriks." if st.session_state.language=="id" else "Check the passphrase before using matrix tools.")
    elif int(n)<=12:
        dot=["digraph KeyMatrix {","rankdir=LR;",'graph [bgcolor="transparent", pad="0.25"];','node [shape=circle, style=filled, fillcolor="#e7f4ff", color="#167da5", fontcolor="#123653"];','edge [color="#1596bd", fontcolor="#123653"];']
        for i in range(int(n)): dot.append(f'v{i+1} [label="v{i+1}"];')
        for i in range(int(n)):
            for j in range(int(n)):
                w=int(matrix[i][j])%m
                if w: dot.append(f'v{i+1} -> v{j+1} [label="{w}"];')
        dot.append("}"); st.graphviz_chart("\n".join(dot),use_container_width=True)
    else: st.info(tr("graph_limit"))
    st.divider(); st.subheader(tr("graph_operation_title")); st.caption(tr("graph_operation_desc"))
    last=st.session_state.get("last_operation_graph")
    if last:
        enc=last["direction"]=="encrypt"
        st.markdown("**"+(tr("graph_encrypt_title") if enc else tr("graph_decrypt_title"))+"**")
        st.caption(tr("graph_encrypt_caption") if enc else tr("graph_decrypt_caption"))
        st.caption(tr("graph_first_block"))
        st.markdown("**"+tr("graph_input")+"**: `"+", ".join(map(str,last["input"]))+"`")
        st.markdown("**"+tr("graph_output")+"**: `"+", ".join(map(str,last["output"]))+"`")
        st.graphviz_chart(make_bipartite_dot(last["matrix"],last["input"],last["output"],last["direction"],last["modulus"]),use_container_width=True)
        if enc: st.latex(r"c_i \equiv \sum_{j=1}^{n} k_{ij}p_j \pmod{m}")
        else: st.latex(r"p_i \equiv \sum_{j=1}^{n} (K^{-1})_{ij}c_j \pmod{m}")
    else: st.info(tr("graph_no_operation"))

    st.divider()
    st.subheader(tr("manual_calc"))
    st.caption(tr("manual_calc_desc"))
    calc_n = st.selectbox(tr("order_label"), [2,3,4], index=0, key="manual_calc_order")
    ca, cb = st.columns(2)
    default_a = pd.DataFrame([[1 if i==j else 0 for j in range(calc_n)] for i in range(calc_n)],
                             columns=[f"C{j+1}" for j in range(calc_n)])
    default_b = pd.DataFrame([[1 if i==j else 0 for j in range(calc_n)] for i in range(calc_n)],
                             columns=[f"C{j+1}" for j in range(calc_n)])
    with ca:
        st.markdown("**"+tr("matrix_a")+"**")
        A_df = st.data_editor(default_a,key=f"manual_A_{calc_n}",use_container_width=True,hide_index=True)
    with cb:
        st.markdown("**"+tr("matrix_b")+"**")
        B_df = st.data_editor(default_b,key=f"manual_B_{calc_n}",use_container_width=True,hide_index=True)
    if st.button(tr("calculate"),key="manual_matrix_calculate"):
        try:
            A = [[int(A_df.iloc[i,j]) for j in range(calc_n)] for i in range(calc_n)]
            B = [[int(B_df.iloc[i,j]) for j in range(calc_n)] for i in range(calc_n)]
            product = [[sum(A[i][k]*B[k][j] for k in range(calc_n)) % m
                        for j in range(calc_n)] for i in range(calc_n)]
            st.markdown("#### "+tr("manual_result"))
            st.dataframe(pd.DataFrame(product),hide_index=True,use_container_width=True)
            st.latex(r"(AB)_{ij} \equiv \sum_{k=1}^{n} a_{ik}b_{kj} \pmod{m}")
        except Exception as exc:
            st.error(str(exc))

    st.markdown("#### "+tr("vector_calc"))
    vector_text = st.text_input(tr("vector_input"),value=",".join(["1"]*int(n)),key="manual_vector_input")
    st.caption(tr("vector_help"))
    if st.button(tr("calculate")+" · K × P",key="manual_vector_calculate",disabled=matrix is None):
        try:
            values = [int(x.strip()) for x in vector_text.split(",") if x.strip()!=""]
            if len(values) != int(n):
                raise ValueError(f"{tr('manual_expected')} {n} {'bilangan bulat' if st.session_state.language=='id' else 'integers'}.")
            values = [x % m for x in values]
            output = [sum(int(matrix[i][j])*values[j] for j in range(int(n))) % m for i in range(int(n))]
            st.markdown("#### "+tr("calculation_steps"))
            for i in range(int(n)):
                terms = " + ".join(f"({int(matrix[i][j])}×{values[j]})" for j in range(int(n)))
                st.write(f"C{i+1} = ({terms}) mod {m} = {output[i]}")
            st.markdown("#### "+tr("vector_result"))
            st.code(str(output))
        except Exception as exc:
            st.error(str(exc))
    show_equations()

elif page_key == "learn":
    banner("📘 "+tr("learn"),tr("learn_intro"))
    content_id=[
      ("1. Pengertian kriptografi","Kriptografi mempelajari teknik transformasi informasi. Plaintext adalah pesan asli, ciphertext adalah pesan tersandi, enkripsi mengubah plaintext menjadi ciphertext, sedangkan dekripsi memulihkannya."),
      ("2. Hill Cipher","Hill Cipher adalah cipher klasik yang menggunakan matriks persegi dan aritmetika modulo. Pesan diubah menjadi bilangan, dibagi menjadi blok berukuran n, kemudian ditransformasikan dengan matriks kunci."),
      ("3. Representasi vektor","Setiap blok plaintext direpresentasikan sebagai vektor kolom p berukuran n × 1. Matriks kunci K berukuran n × n menghasilkan vektor ciphertext c."),
      ("4. Enkripsi","Persamaan enkripsi adalah c ≡ Kp (mod m). Perkalian matriks dilakukan terlebih dahulu, kemudian setiap entri direduksi modulo m."),
      ("5. Dekripsi","Persamaan dekripsi adalah p ≡ K⁻¹c (mod m). K⁻¹ merupakan invers matriks K pada aritmetika modulo m."),
      ("6. Syarat invers modular","Matriks K memiliki invers modulo m jika dan hanya jika gcd(det(K),m)=1. Karena modulus 128 atau 256 bukan bilangan prima, determinan harus relatif prima terhadap modulus."),
      ("7. ASCII Standard","ASCII standar menggunakan 7 bit dan memiliki 128 kode (0–127), termasuk huruf Latin dasar, angka, tanda baca, spasi, dan karakter kontrol."),
      ("8. Windows-1252","Windows-1252 merupakan encoding satu byte. Rentang 0–127 sama dengan ASCII, sedangkan 128–255 memuat karakter tambahan. Lima byte tidak terdefinisi sebagai karakter CP1252: 129, 141, 143, 144, dan 157."),
      ("9. UTF-8 dan Unicode","UTF-8 mengodekan karakter Unicode sebagai satu hingga empat byte. Hill Cipher memproses urutan byte tersebut pada modulus 256; satu karakter Unicode dapat menempati beberapa byte."),
      ("10. Padding dan panjang pesan","Jika jumlah byte tidak habis dibagi n, byte nol ditambahkan di akhir blok. Paket menyimpan panjang byte asli agar byte padding dapat dibuang setelah dekripsi."),
      ("11. Keterbatasan keamanan","Hill Cipher bersifat linear, tidak menyediakan autentikasi, dan rentan terhadap serangan known-plaintext. Algoritma ini sesuai untuk pembelajaran, bukan untuk melindungi informasi rahasia."),
      ("12. Kustomisasi kata kunci","Kata kunci digunakan untuk membangkitkan matriks kunci secara deterministik. Pengguna boleh mengganti kata kunci. Pengirim dan penerima harus menggunakan kata kunci yang sama, ordo matriks yang sama, dan mode encoding yang sama. Paket HCE menyimpan sidik jari kunci untuk mendeteksi ketidakcocokan kunci, bukan untuk mengautentikasi pesan."),
      ("13. Hubungan matriks dengan graf","Matriks persegi dapat dipandang sebagai matriks ketetanggaan berbobot suatu graf berarah. Indeks baris dan kolom menjadi simpul, sedangkan entri tak nol Kᵢⱼ menjadi sisi berarah dari simpul i ke simpul j dengan bobot Kᵢⱼ. Visualisasi ini membantu menghubungkan aljabar linear, teori graf, dan transformasi Hill Cipher."),
      ("14. Proses enkripsi per blok","Byte plaintext dibagi menjadi blok berukuran n. Setiap blok disusun sebagai vektor kolom p. Matriks K dikalikan dengan p, lalu hasilnya direduksi modulo m. Jika blok terakhir tidak penuh, padding nol ditambahkan agar panjang blok menjadi n."),
      ("15. Mengapa panjang asli disimpan","Padding membuat ciphertext memiliki panjang kelipatan n. Dari ciphertext Base64 mentah saja, panjang byte plaintext sebelum padding tidak dapat ditentukan secara unik. Karena itu paket HCE menyimpan panjang byte asli agar dekripsi dapat membuang padding secara tepat.")
    ]
    content_en=[
      ("1. Cryptography","Cryptography studies transformations used to protect information. Plaintext is the original message, ciphertext is the transformed message, encryption converts plaintext to ciphertext, and decryption restores it."),
      ("2. Hill Cipher","The Hill Cipher is a classical cipher using square matrices and modular arithmetic. A message is converted to numbers, divided into blocks of size n, and transformed using a key matrix."),
      ("3. Vector representation","Each plaintext block is represented as an n × 1 column vector p. The n × n key matrix K produces a ciphertext vector c."),
      ("4. Encryption","The encryption equation is c ≡ Kp (mod m). Perform matrix multiplication first, then reduce each entry modulo m."),
      ("5. Decryption","The decryption equation is p ≡ K⁻¹c (mod m). K⁻¹ is the inverse of K in modular arithmetic."),
      ("6. Modular inverse condition","K has an inverse modulo m if and only if gcd(det(K),m)=1. Since 128 and 256 are composite, the determinant must be coprime to the modulus."),
      ("7. ASCII Standard","Standard ASCII uses 7 bits and has 128 codes (0–127), including basic Latin letters, digits, punctuation, spaces, and control characters."),
      ("8. Windows-1252","Windows-1252 is a single-byte encoding. Codes 0–127 match ASCII, while 128–255 contain additional characters. Five byte positions are undefined in CP1252: 129, 141, 143, 144, and 157."),
      ("9. UTF-8 and Unicode","UTF-8 encodes Unicode characters into one to four bytes. The Hill Cipher processes these bytes modulo 256; one Unicode character may occupy multiple bytes."),
      ("10. Padding and message length","If the byte count is not divisible by n, zero bytes are appended. The package stores the original byte length so padding can be removed after decryption."),
      ("11. Security limitations","The Hill Cipher is linear, provides no authentication, and is vulnerable to known-plaintext attacks. It is suitable for education, not for protecting confidential information."),
      ("12. Customizable passphrase","The passphrase deterministically derives the key matrix. Users may change it. Sender and recipient must use the same passphrase, matrix order, and encoding mode. The HCE package stores a key fingerprint to detect a mismatch; it does not authenticate the message."),
      ("13. Matrix and graph connection","A square matrix can be interpreted as the weighted adjacency matrix of a directed graph. Row and column indices become vertices, while nonzero entries Kᵢⱼ become directed edges from vertex i to vertex j with weight Kᵢⱼ. This visualization connects linear algebra, graph theory, and the Hill transformation."),
      ("14. Block encryption process","Plaintext bytes are divided into blocks of length n. Each block becomes a column vector p. The key matrix K multiplies p, and each result is reduced modulo m. If the last block is incomplete, zero padding is added to reach n bytes."),
      ("15. Why the original length is stored","Padding makes ciphertext length a multiple of n. The original plaintext byte length cannot be uniquely determined from raw Base64 ciphertext alone. Therefore, an HCE package stores the original byte length so decryption can remove padding exactly.")
    ]
    for title,body in (content_id if st.session_state.language=="id" else content_en):
        with st.expander(title):
            st.write(body)
            if title.startswith(("3.","4.","5.")):
                if title.startswith("4."): st.latex(r"\mathbf{c}\equiv K\mathbf{p}\pmod{m}")
                elif title.startswith("5."): st.latex(r"\mathbf{p}\equiv K^{-1}\mathbf{c}\pmod{m}")

    st.divider()
    st.header("📚 Modul Pembelajaran HILLCRYPT v5.2" if st.session_state.language=="id" else "📚 HILLCRYPT v5.2 Learning Modules")
    st.write("Sepuluh bab berikut disusun bertahap dari konsep dasar hingga praktikum. Buka setiap bab, pelajari contoh, lalu jawab evaluasi singkat." if st.session_state.language=="id" else "These ten chapters progress from foundations to practical work. Open each chapter, study the example, and answer the short assessment.")
    chapters_id = [
      {"title":"BAB 1 — Dasar-Dasar Kriptografi","goal":"Membedakan istilah dan tujuan dasar kriptografi.","concept":"Kriptografi mempelajari metode untuk mengubah informasi agar maknanya tidak langsung dipahami pihak yang tidak berwenang. Plaintext adalah pesan sebelum transformasi; ciphertext adalah hasil transformasi. Enkripsi mengubah plaintext menjadi ciphertext, sedangkan dekripsi berusaha mengembalikannya menggunakan informasi kunci yang sesuai. Tujuan keamanan modern sering dibahas melalui kerahasiaan, integritas, autentikasi, dan ketersediaan; Hill Cipher klasik terutama digunakan untuk mempelajari transformasi, bukan memenuhi seluruh tujuan tersebut.","formula":"P \xrightarrow{E_K} C \qquad C \xrightarrow{D_K} P","example":"Contoh alur: pesan P = “HI” dipetakan ke representasi angka menurut encoding yang dipilih. Algoritma mengenkripsi representasi tersebut menjadi C. Penerima menerapkan dekripsi dengan kunci dan parameter yang sama untuk memperoleh kembali “HI”. Istilah ciphertext tidak berarti pesan sudah aman dari semua serangan.","practice":"Jika pesan asli sebelum dienkripsi disebut …","options":["Ciphertext","Plaintext","Matriks invers"],"answer":1,"explain":"Plaintext adalah pesan asli sebelum proses enkripsi."},
      {"title":"BAB 2 — Dasar Aljabar Linear","goal":"Memahami matriks, vektor, determinan, dan perkalian yang digunakan Hill Cipher.","concept":"Matriks adalah susunan elemen dalam baris dan kolom. Matriks kunci K berordo n × n, sedangkan satu blok pesan direpresentasikan sebagai vektor kolom P berukuran n × 1. Perkalian K P terdefinisi karena banyak kolom K sama dengan banyak baris P. Determinan digunakan untuk menguji apakah matriks mempunyai kandidat invers; pada aritmetika modular, syaratnya perlu diperiksa terhadap modulus.","formula":"K = (k_{ij})_{n\times n}, \quad P\in R^{n\times1}, \quad C=KP","example":"Untuk K = [[1,1],[1,2]] dan P = [2,3]ᵀ, diperoleh KP = [1·2+1·3, 1·2+2·3]ᵀ = [5,8]ᵀ. Determinan K = 1·2 − 1·1 = 1.","practice":"Jika K berordo 3 × 3 dan P berordo 3 × 1, ordo KP adalah …","options":["3 × 3","1 × 3","3 × 1"],"answer":2,"explain":"Hasil perkalian memiliki jumlah baris K dan jumlah kolom P, yaitu 3 × 1."},
      {"title":"BAB 3 — Aritmetika Modular","goal":"Melakukan operasi kongruensi dan menentukan invers perkalian modulo.","concept":"Dua bilangan a dan b kongruen modulo m jika m membagi a−b. Setelah operasi bilangan bulat dilakukan, hasil direduksi menjadi sisa pembagian oleh m. Invers perkalian a modulo m adalah bilangan x yang memenuhi ax ≡ 1 (mod m). Invers ada tepat ketika gcd(a,m)=1. Modulo 128 dan 256 adalah komposit, sehingga tidak setiap elemen bukan nol memiliki invers.","formula":"a\equiv b\pmod m \iff m\mid(a-b); \quad a^{-1}a\equiv1\pmod m","example":"Invers 7 modulo 26 adalah 15 karena 7×15 = 105 = 4×26+1, sehingga 105 ≡ 1 (mod 26). Sebaliknya, 2 tidak memiliki invers modulo 26 karena gcd(2,26)=2, bukan 1.","practice":"Invers perkalian 7 modulo 26 adalah …","options":["11","15","19"],"answer":1,"explain":"7 × 15 = 105 dan 105 mod 26 = 1."},
      {"title":"BAB 4 — Teori dan Syarat Hill Cipher","goal":"Menjelaskan model Hill Cipher dan syarat invertibilitas matriks kunci.","concept":"Hill Cipher mengenkripsi blok vektor dengan mengalikan matriks kunci. Untuk dekripsi unik pada setiap blok, K harus invertibel pada Z_m. Syarat perlu dan cukupnya adalah gcd(det(K),m)=1. Jika syarat terpenuhi, invers determinan modulo m dapat dikalikan dengan adjugat K. Syarat ini berlaku juga ketika m komposit; tidak cukup hanya memastikan determinan bukan nol.","formula":"C\equiv KP\pmod m; \quad P\equiv K^{-1}C\pmod m; \quad \gcd(\det K,m)=1","example":"K = [[1,1],[1,2]] mempunyai det(K)=1. Karena gcd(1,26)=1, matriks ini invertibel modulo 26. Untuk modulus 128, pemeriksaan yang sama harus menggunakan gcd(det(K),128).","practice":"Kriteria matriks K invertibel modulo m adalah …","options":["det(K) ≠ 0 saja","gcd(det(K),m)=1","Semua entri K harus ganjil"],"answer":1,"explain":"Determinan harus mempunyai invers modulo m, ekuivalen dengan gcd(det(K),m)=1."},
      {"title":"BAB 5 — Perhitungan Enkripsi dan Dekripsi","goal":"Mengikuti satu contoh hitung lengkap menggunakan vektor kolom.","concept":"Urutan perhitungan: ubah pesan menjadi angka sesuai encoding; bagi menjadi blok n byte; susun setiap blok sebagai vektor kolom; hitung KP; reduksi setiap komponen modulo m. Dekripsi menggunakan K⁻¹ dan parameter yang sama. Contoh di bawah memakai alfabet angka sederhana A=0,…,Z=25 hanya untuk ilustrasi modulo 26, bukan mode byte aplikasi.","formula":"K^{-1}\equiv(\det K)^{-1}\operatorname{adj}(K)\pmod m","example":"Ambil K=[[1,1],[1,2]], P=[2,3]ᵀ, m=26. Enkripsi: C=[5,8]ᵀ. Invers K adalah [[2,−1],[−1,1]], atau modulo 26 [[2,25],[25,1]]. Dekripsi: K⁻¹C = [2·5−8, −5+8]ᵀ = [2,3]ᵀ modulo 26. Jadi P pulih tepat.","practice":"Dengan contoh tersebut, komponen pertama C sebelum reduksi adalah …","options":["3","5","8"],"answer":1,"explain":"Baris pertama K dikalikan P: 1×2 + 1×3 = 5."},
      {"title":"BAB 6 — Encoding, ASCII, Windows-1252, dan UTF-8","goal":"Membedakan karakter, kode, dan byte dalam pemrosesan pesan.","concept":"Karakter adalah simbol teks; encoding menentukan representasi byte-nya. ASCII standar memetakan 128 kode 0–127. Windows-1252 menggunakan satu byte untuk karakter yang didukung dan memiliki beberapa posisi byte yang tidak terdefinisi. UTF-8 mengodekan Unicode menjadi satu hingga empat byte per karakter. Karena itu, jumlah karakter tidak selalu sama dengan jumlah byte. Aplikasi menerapkan modulus 128 untuk ASCII dan 256 untuk Windows-1252/UTF-8.","formula":"\text{ASCII: }0\le b<128; \qquad \text{byte: }0\le b<256","example":"Huruf “A” memiliki byte 65 pada ASCII dan UTF-8. Karakter “é” pada UTF-8 direpresentasikan oleh dua byte heksadesimal C3 A9 (195 dan 169). Satu karakter tersebut berarti dua byte; inilah sebabnya aplikasi menghitung karakter dan byte secara terpisah.","practice":"Dalam UTF-8, satu karakter Unicode dapat direpresentasikan oleh …","options":["Selalu tepat satu byte","Satu hingga empat byte","Selalu delapan byte"],"answer":1,"explain":"UTF-8 memakai satu sampai empat byte untuk satu code point Unicode."},
      {"title":"BAB 7 — Blok, Padding, Base64, dan Paket HCE","goal":"Memahami pengolahan blok dan metadata untuk pemulihan pesan.","concept":"Hill Cipher memproses blok dengan panjang n byte. Jika jumlah byte pesan bukan kelipatan n, aplikasi menambahkan zero padding pada blok terakhir. Panjang byte asli harus disimpan agar padding dapat dibuang secara tepat. Base64 hanyalah representasi teks dari byte ciphertext; Base64 mentah tidak menyimpan parameter algoritma atau panjang asli. Paket HCE/JSON membawa metadata yang diperlukan. HMAC pada paket dapat membantu mendeteksi perubahan paket jika verifikasi kunci dilakukan benar; fingerprint kunci sendiri bukan autentikasi pesan.","formula":"L_{pad}=n\left\lceil\frac{L}{n}\right\rceil","example":"Jika panjang pesan 10 byte dan ukuran blok n=4, panjang setelah padding menjadi 12 byte. Dua byte padding ditambahkan. Paket menyimpan panjang asli 10 agar dua byte tambahan tidak ikut menjadi plaintext setelah dekripsi.","practice":"Mengapa panjang byte asli disimpan dalam paket?","options":["Untuk menentukan warna antarmuka","Untuk membuang padding secara tepat","Untuk memperbesar matriks"],"answer":1,"explain":"Panjang asli memberi tahu berapa byte hasil dekripsi yang merupakan pesan, bukan padding."},
      {"title":"BAB 8 — Matriks dan Teori Graf","goal":"Menjelaskan interpretasi graf dari matriks dan peran Graph Key Lab.","concept":"Matriks persegi dapat ditafsirkan sebagai matriks ketetanggaan berbobot graf berarah dengan konvensi tertentu: entri baris i kolom j menyatakan bobot sisi i→j. Namun, matriks kunci Hill Cipher tidak otomatis merupakan graf; visualisasi graf adalah interpretasi matematis tambahan. Graph Key Lab membangun graf/struktur yang divalidasi lalu menghasilkan passphrase deterministik untuk membentuk matriks kunci melalui mekanisme aplikasi. Syarat unimodular det(A)=±1 berbeda dari syarat invertibel modulo m, yaitu gcd(det(A),m)=1.","formula":"A_{ij}\ne0\Rightarrow v_i\to v_j; \quad A\text{ unimodular jika }\det(A)=\pm1","example":"Untuk A=[[0,2],[3,0]], interpretasi grafnya memiliki sisi v₁→v₂ berbobot 2 dan v₂→v₁ berbobot 3. Determinan A adalah −6, sehingga matriks ini bukan unimodular. Akan tetapi, invertibilitas modulo m harus diperiksa terpisah melalui gcd(−6,m).","practice":"Matriks disebut unimodular jika determinannya …","options":["0","±1","Bilangan prima apa pun"],"answer":1,"explain":"Definisi matriks unimodular adalah matriks bilangan bulat dengan determinan 1 atau −1."},
      {"title":"BAB 9 — Analisis Keamanan dan Batas Hill Cipher","goal":"Menilai kegunaan edukatif dan keterbatasan keamanan Hill Cipher.","concept":"Hill Cipher merupakan cipher klasik linear. Hubungan linear membuatnya rentan terhadap known-plaintext attack: pasangan plaintext-ciphertext yang cukup dan independen dapat memberi persamaan untuk memperoleh matriks kunci dalam kondisi yang sesuai. Cipher ini tidak dirancang untuk autentikasi modern dan tidak boleh dipakai untuk melindungi data rahasia. HMAC pada paket aplikasi merupakan lapisan pemeriksaan integritas format paket; hal tersebut tidak mengubah kelemahan dasar algoritma Hill Cipher menjadi cipher modern.","formula":"\mathbf C=K\mathbf P\pmod m","example":"Jika penyerang mengetahui beberapa blok plaintext dan ciphertext yang sesuai, ia dapat menyusun sistem persamaan modular untuk mencari K apabila matriks blok plaintext memenuhi syarat invertibilitas. Ini menunjukkan mengapa linearitas menjadi kelemahan mendasar.","practice":"Hill Cipher paling tepat digunakan untuk …","options":["Menyimpan kata sandi bank","Pembelajaran aljabar dan kriptografi klasik","Mengamankan data medis rahasia"],"answer":1,"explain":"Hill Cipher berguna untuk memahami matriks dan aritmetika modular, bukan perlindungan data sensitif."},
      {"title":"BAB 10 — Praktikum dan Evaluasi HILLCRYPT","goal":"Menggunakan fitur aplikasi dengan parameter yang konsisten dan memeriksa hasilnya.","concept":"Praktikum dimulai dengan memilih encoding, ordo matriks, dan passphrase. Periksa status invertibilitas matriks sebelum enkripsi. Enkripsi teks contoh, simpan paket HCE, lalu buka menu dekripsi dan pulihkan plaintext. Ulangi dengan Base64 mentah untuk memahami kebutuhan metadata dan panjang byte. Uji juga mode UTF-8 dengan teks non-ASCII. Catat hasil, parameter, dan pesan kesalahan; jangan gunakan data rahasia pada layanan web publik.","formula":"D_K(E_K(P))=P","example":"Checklist praktikum: (1) pilih ASCII dan ordo 2; (2) pastikan gcd(det(K),128)=1; (3) enkripsi pesan uji; (4) simpan .hce; (5) dekripsi paket; (6) bandingkan hasil dengan plaintext awal. Ulangi dengan UTF-8 untuk mengamati perbedaan jumlah karakter dan byte.","practice":"Apa indikator utama uji round-trip berhasil?","options":["Ciphertext lebih panjang","Plaintext hasil dekripsi identik dengan plaintext awal","Determinan selalu sama dengan 1"],"answer":1,"explain":"Uji round-trip berhasil jika dekripsi atas hasil enkripsi memulihkan pesan awal secara identik."}
    ]
    chapters_en = [
      {"title":"CHAPTER 1 — Cryptography Foundations","goal":"Distinguish the basic terms and goals of cryptography.","concept":"Cryptography studies methods for transforming information. Plaintext is the message before transformation; ciphertext is the transformed result. Encryption maps plaintext to ciphertext, while decryption attempts to recover it using the appropriate key information. Modern security goals include confidentiality, integrity, authentication, and availability. The classical Hill Cipher is primarily a learning model and does not provide all these goals.","formula":"P \xrightarrow{E_K} C \qquad C \xrightarrow{D_K} P","example":"A message P = “HI” is mapped to numbers using a selected encoding. Encryption transforms that representation into C. The recipient decrypts it with matching key parameters to recover “HI”. Ciphertext does not mean a message is secure against every attack.","practice":"The original message before encryption is called …","options":["Ciphertext","Plaintext","Inverse matrix"],"answer":1,"explain":"Plaintext is the original message before encryption."},
      {"title":"CHAPTER 2 — Linear Algebra Foundations","goal":"Understand matrices, vectors, determinants, and multiplication in the Hill Cipher.","concept":"A matrix is an array of entries arranged in rows and columns. The key matrix K has order n × n, while one message block is a column vector P of size n × 1. KP is defined because the number of columns of K equals the number of rows of P. The determinant is used to test invertibility; modular invertibility must be checked against the modulus.","formula":"K=(k_{ij})_{n\times n},\quad P\in R^{n\times1},\quad C=KP","example":"For K=[[1,1],[1,2]] and P=[2,3]ᵀ, KP=[5,8]ᵀ. The determinant is 1·2−1·1=1.","practice":"If K is 3 × 3 and P is 3 × 1, the order of KP is …","options":["3 × 3","1 × 3","3 × 1"],"answer":2,"explain":"The product has the row count of K and column count of P: 3 × 1."},
      {"title":"CHAPTER 3 — Modular Arithmetic","goal":"Use congruences and find multiplicative inverses modulo m.","concept":"Integers a and b are congruent modulo m when m divides a−b. After integer arithmetic, reduce the result to its remainder modulo m. A multiplicative inverse x of a satisfies ax ≡ 1 (mod m). It exists exactly when gcd(a,m)=1. Moduli 128 and 256 are composite, so not every nonzero element is invertible.","formula":"a\equiv b\pmod m\iff m\mid(a-b);\quad a^{-1}a\equiv1\pmod m","example":"The inverse of 7 modulo 26 is 15 because 7×15=105=4×26+1. Thus 105 ≡ 1 (mod 26). The number 2 has no inverse modulo 26 because gcd(2,26)=2.","practice":"The multiplicative inverse of 7 modulo 26 is …","options":["11","15","19"],"answer":1,"explain":"7 × 15 = 105 and 105 mod 26 = 1."},
      {"title":"CHAPTER 4 — Hill Cipher and Invertibility","goal":"Explain the Hill Cipher model and key-matrix invertibility.","concept":"The Hill Cipher encrypts a vector block by multiplying it by a key matrix. For unique block decryption, K must be invertible over Z_m. The necessary and sufficient condition is gcd(det(K),m)=1. The inverse of the determinant modulo m is multiplied by adj(K). A nonzero determinant alone is not sufficient when working modulo a composite number.","formula":"C\equiv KP\pmod m;\quad P\equiv K^{-1}C\pmod m;\quad\gcd(\det K,m)=1","example":"K=[[1,1],[1,2]] has determinant 1. Since gcd(1,26)=1, it is invertible modulo 26. For modulus 128, test gcd(det(K),128).","practice":"The criterion for K to be invertible modulo m is …","options":["det(K) ≠ 0 only","gcd(det(K),m)=1","Every entry of K must be odd"],"answer":1,"explain":"The determinant must have a multiplicative inverse modulo m."},
      {"title":"CHAPTER 5 — Encryption and Decryption Calculation","goal":"Follow a complete worked example using column vectors.","concept":"Convert text to numbers using the selected encoding; split bytes into blocks of length n; arrange each block as a column vector; calculate KP; reduce each component modulo m. Decryption uses K⁻¹ and matching parameters. The example below uses A=0,…,Z=25 only to illustrate modulo 26, not the application's byte modes.","formula":"K^{-1}\equiv(\det K)^{-1}\operatorname{adj}(K)\pmod m","example":"Let K=[[1,1],[1,2]], P=[2,3]ᵀ, m=26. Encryption gives C=[5,8]ᵀ. K⁻¹=[[2,−1],[−1,1]], or modulo 26 [[2,25],[25,1]]. Decryption gives [2·5−8, −5+8]ᵀ=[2,3]ᵀ modulo 26, recovering P exactly.","practice":"In this example, the first component of C before reduction is …","options":["3","5","8"],"answer":1,"explain":"The first row gives 1×2 + 1×3 = 5."},
      {"title":"CHAPTER 6 — Encoding, ASCII, Windows-1252, and UTF-8","goal":"Distinguish characters, code points, and bytes.","concept":"A character is a text symbol; an encoding defines its byte representation. Standard ASCII maps 128 codes, 0–127. Windows-1252 uses one byte for supported characters and has undefined byte positions. UTF-8 encodes Unicode using one to four bytes per character. Character count and byte count therefore may differ. The application uses modulus 128 for ASCII and 256 for Windows-1252/UTF-8.","formula":"\text{ASCII: }0\le b<128;\quad\text{byte: }0\le b<256","example":"“A” is byte 65 in ASCII and UTF-8. In UTF-8, “é” is represented by hexadecimal bytes C3 A9 (195 and 169). One character therefore occupies two bytes.","practice":"In UTF-8, one Unicode character can use …","options":["Exactly one byte","One to four bytes","Always eight bytes"],"answer":1,"explain":"UTF-8 uses one to four bytes per Unicode code point."},
      {"title":"CHAPTER 7 — Blocks, Padding, Base64, and HCE Packages","goal":"Understand block processing and metadata for message recovery.","concept":"The Hill Cipher processes blocks of n bytes. If the message byte count is not divisible by n, zero padding is appended to the last block. The original byte length must be stored to remove padding exactly. Base64 is only a text representation of ciphertext bytes; raw Base64 does not contain algorithm parameters or original length. An HCE/JSON package carries required metadata. HMAC can detect package modification when verification is correctly performed; a key fingerprint alone is not message authentication.","formula":"L_{pad}=n\left\lceil\frac{L}{n}\right\rceil","example":"For a 10-byte message and block size n=4, the padded length is 12 bytes. Two padding bytes are appended. The package stores 10 so the extra bytes are removed after decryption.","practice":"Why is the original byte length stored in the package?","options":["To choose interface colors","To remove padding exactly","To enlarge the matrix"],"answer":1,"explain":"The original length identifies which recovered bytes belong to the message."},
      {"title":"CHAPTER 8 — Matrices and Graph Theory","goal":"Explain graph interpretation of matrices and Graph Key Lab.","concept":"A square matrix can be interpreted as the weighted adjacency matrix of a directed graph under a chosen convention: entry row i, column j represents the weight of edge i→j. A Hill key matrix is not automatically a graph; graph visualization is an additional mathematical interpretation. Graph Key Lab validates a graph/structure and derives a deterministic passphrase used by the app to generate a key matrix. Unimodularity det(A)=±1 differs from modular invertibility gcd(det(A),m)=1.","formula":"A_{ij}\ne0\Rightarrow v_i\to v_j;\quad A\text{ is unimodular if }\det(A)=\pm1","example":"For A=[[0,2],[3,0]], the graph has edges v₁→v₂ with weight 2 and v₂→v₁ with weight 3. Its determinant is −6, so it is not unimodular. Modular invertibility must separately be tested using gcd(−6,m).","practice":"A matrix is unimodular when its determinant is …","options":["0","±1","Any prime number"],"answer":1,"explain":"An integer matrix is unimodular when its determinant is 1 or −1."},
      {"title":"CHAPTER 9 — Security Analysis and Limitations","goal":"Assess the educational use and security limits of the Hill Cipher.","concept":"The Hill Cipher is a classical linear cipher. Its linear relation makes it vulnerable to known-plaintext attacks: enough independent plaintext/ciphertext block pairs can reveal the key matrix under suitable conditions. It is not designed for modern authentication and must not protect confidential data. HMAC in the app's package format is an integrity layer for that package; it does not turn the underlying Hill Cipher into a modern cipher.","formula":"\mathbf C=K\mathbf P\pmod m","example":"If an attacker knows matching plaintext and ciphertext blocks, they can form modular equations to solve for K when the plaintext block matrix is invertible. This illustrates the fundamental weakness of linearity.","practice":"The Hill Cipher is most appropriate for …","options":["Bank password storage","Learning algebra and classical cryptography","Protecting confidential medical data"],"answer":1,"explain":"It is useful for learning matrices and modular arithmetic, not for sensitive data protection."},
      {"title":"CHAPTER 10 — HILLCRYPT Practical Lab and Assessment","goal":"Use the application with consistent parameters and verify the result.","concept":"Start by selecting encoding, matrix order, and passphrase. Check key-matrix invertibility before encryption. Encrypt sample text, save the HCE package, then open decryption and restore the plaintext. Repeat with raw Base64 to understand metadata and original-length requirements. Test UTF-8 with non-ASCII text. Record parameters and results; do not use confidential data on a public web service.","formula":"D_K(E_K(P))=P","example":"Practical checklist: (1) select ASCII and order 2; (2) confirm gcd(det(K),128)=1; (3) encrypt a test message; (4) save .hce; (5) decrypt the package; (6) compare recovered text with the original. Repeat with UTF-8 to observe character and byte counts.","practice":"What is the main indicator of a successful round-trip test?","options":["Ciphertext is longer","Decrypted plaintext exactly matches the original","The determinant is always 1"],"answer":1,"explain":"A round-trip succeeds when decryption exactly restores the original plaintext."}
    ]
    chapters = chapters_id if st.session_state.language=="id" else chapters_en
    for chapter_index, chapter in enumerate(chapters):
        with st.expander(chapter["title"], expanded=False):
            st.markdown("**Tujuan pembelajaran**" if st.session_state.language=="id" else "**Learning objective**")
            st.write(chapter["goal"])
            st.markdown("**Konsep inti**" if st.session_state.language=="id" else "**Core concept**")
            st.write(chapter["concept"])
            st.markdown("**Rumus penting**" if st.session_state.language=="id" else "**Key formula**")
            st.latex(chapter["formula"])
            st.markdown("**Contoh dan pembahasan**" if st.session_state.language=="id" else "**Worked example**")
            st.write(chapter["example"])
            st.markdown("**Evaluasi singkat**" if st.session_state.language=="id" else "**Quick assessment**")
            answer_key = f"v52_quiz_{chapter_index}_{st.session_state.language}"
            selected_answer = st.radio(chapter["practice"], chapter["options"], key=answer_key, index=None)
            if st.button("Periksa jawaban" if st.session_state.language=="id" else "Check answer", key=f"v52_check_{chapter_index}_{st.session_state.language}"):
                if selected_answer is None:
                    st.info("Pilih jawaban terlebih dahulu." if st.session_state.language=="id" else "Choose an answer first.")
                elif chapter["options"].index(selected_answer) == chapter["answer"]:
                    st.success(("Benar. " if st.session_state.language=="id" else "Correct. ") + chapter["explain"])
                else:
                    st.error(("Belum tepat. " if st.session_state.language=="id" else "Not quite. ") + chapter["explain"])

    show_equations()
    st.warning(tr("warning"))
    st.divider()
    st.subheader(tr("ascii_title"))
    st.caption(tr("ascii_desc"))
    range_choice = st.selectbox(tr("ascii_range"),
        [tr("ascii_standard"),tr("ascii_extended"),tr("ascii_all")],key="ascii_table_range")
    search_ascii = st.text_input(tr("ascii_search"),key="ascii_table_search")
    if range_choice == tr("ascii_standard"):
        codes = range(0,128)
    elif range_choice == tr("ascii_extended"):
        codes = range(128,256)
    else:
        codes = range(0,256)
    control_names = {
        0:"NUL",1:"SOH",2:"STX",3:"ETX",4:"EOT",5:"ENQ",6:"ACK",7:"BEL",
        8:"BS",9:"TAB",10:"LF",11:"VT",12:"FF",13:"CR",14:"SO",15:"SI",
        16:"DLE",17:"DC1",18:"DC2",19:"DC3",20:"DC4",21:"NAK",22:"SYN",
        23:"ETB",24:"CAN",25:"EM",26:"SUB",27:"ESC",28:"FS",29:"GS",
        30:"RS",31:"US",127:"DEL"
    }
    ascii_rows=[]
    for code in codes:
        if code < 128:
            char = control_names.get(code, chr(code) if code >= 32 else tr("ascii_control"))
            description = tr("ascii_control") if code < 32 or code == 127 else tr("ascii_printable")
        else:
            try:
                char = bytes([code]).decode("cp1252")
                if not char.isprintable(): char = "—"
            except UnicodeDecodeError:
                char = tr("ascii_undefined")
            description = tr("ascii_cp1252")
        ascii_rows.append({tr("ascii_decimal"):code,tr("ascii_hex"):f"0x{code:02X}",tr("ascii_binary"):f"{code:08b}",tr("ascii_character"):char,tr("ascii_type"):description})
    ascii_df=pd.DataFrame(ascii_rows)
    if search_ascii:
        q=search_ascii.casefold()
        ascii_df=ascii_df[ascii_df.apply(lambda row:any(q in str(v).casefold() for v in row),axis=1)]
    st.dataframe(ascii_df,use_container_width=True,hide_index=True,height=420)


elif page_key == "graphkey":
    banner("GRAPH KEY LAB", "Matriks ketetanggaan graf menjadi sumber pembentukan kata kunci Hill Cipher.")
    st.info("Graf valid menghasilkan passphrase secara deterministik. Passphrase tersebut diteruskan ke menu Enkripsi dan Dekripsi untuk membentuk matriks kunci Hill Cipher.")
    st.markdown("### 1. Pembentukan graf")
    method = st.radio("Metode pembentukan", ["Otomatis", "Manual"], horizontal=True, key="gkl_method")
    order = st.selectbox("Ordo graf (n × n)", SUPPORTED_ORDERS, index=3, key="gkl_order")
    matrix = None
    if method == "Otomatis":
        if order % 2 == 0:
            generator_options = [
                "Graf lintasan Pₙ",
                "Graf lengkap Kₙ",
                "Pohon dengan perfect matching tunggal",
                "Graf bipartit unimodular",
            ]
        else:
            generator_options = ["Graf lintasan Pₙ", "Graf lengkap Kₙ"]
            st.info(
                "Ordo ganjil tetap dapat diuji. Untuk graf sederhana tak berarah, "
                "determinan matriks ketetanggaan berordo ganjil selalu genap, "
                "sehingga tidak dapat memenuhi syarat unimodular ±1. Sistem tetap "
                "menghitung determinan untuk keperluan eksplorasi."
            )
        generator = st.selectbox("Pilih generator", generator_options, key="gkl_generator")
        if generator == "Graf lintasan Pₙ":
            matrix = path_graph(order)
        elif generator == "Graf lengkap Kₙ":
            matrix = complete_graph(order)
        elif generator == "Pohon dengan perfect matching tunggal":
            matrix = unique_perfect_matching_tree(order)
        else:
            matrix = bipartite_unimodular_graph(order)
    else:
        st.caption("Masukkan sisi sebagai pasangan nomor simpul mulai dari 1. Contoh untuk P4: 1-2, 2-3, 3-4.")
        edge_text = st.text_area("Daftar sisi", "1-2, 2-3, 3-4", key="gkl_edges")
        if st.button("Bentuk matriks ketetanggaan", key="gkl_build"):
            try:
                edges = []
                for item in edge_text.split(","):
                    item = item.strip()
                    if not item:
                        continue
                    pair = item.split("-")
                    if len(pair) != 2:
                        raise GraphKeyError("Format sisi harus berupa u-v, dipisahkan koma.")
                    edges.append((int(pair[0].strip())-1, int(pair[1].strip())-1))
                st.session_state["gkl_manual_matrix"] = adjacency_matrix(order, edges)
                st.session_state["gkl_manual_order"] = order
            except Exception as exc:
                st.error(str(exc))
        if st.session_state.get("gkl_manual_order") == order:
            matrix = st.session_state.get("gkl_manual_matrix")
    if matrix is not None:
        report = validate_adjacency(matrix)
        st.markdown("### 2. Matriks ketetanggaan")
        st.dataframe(pd.DataFrame(matrix, index=[f"v{i+1}" for i in range(order)],
                                  columns=[f"v{i+1}" for i in range(order)]),
                     use_container_width=True)
        st.markdown("### 3. Visualisasi graf")
        # Bangun graf tak berarah langsung dari matriks ketetanggaan.
        # Gunakan ID simpul eksplisit dan latar putih agar hasil konsisten
        # pada berbagai tema Streamlit.
        dot = [
            "graph G {",
            '  graph [bgcolor="#ffffff", pad="0.35", rankdir=LR, splines=true];',
            '  node [shape=circle, style=filled, fillcolor="#dff4fb", '
            'color="#2786a5", fontcolor="#123653", penwidth=1.5, width=0.75, height=0.75];',
            '  edge [color="#39758a", penwidth=1.8];',
        ]
        for i in range(order):
            dot.append(f'  v{i+1} [label="v{i+1}"];')
        for i in range(order):
            for j in range(i + 1, order):
                if int(matrix[i][j]) != 0:
                    dot.append(f"  v{i+1} -- v{j+1};")
        dot.append("}")
        st.graphviz_chart("\n".join(dot), use_container_width=True)
        st.markdown("### 4. Validasi kunci graf")
        col1, col2, col3 = st.columns(3)
        col1.metric("Ordo", f"{order} × {order}")
        col2.metric("Determinan eksak", str(report["determinant"]))
        col3.metric("Status", "VALID" if report["is_hill_key"] else "TIDAK VALID")
        if report["is_hill_key"]:
            st.success("Graf memenuhi syarat: determinan tepat +1 atau −1.")
            graph_passphrase = derive_graph_passphrase(matrix)
            st.markdown("### 5. Kata kunci yang dibentuk dari graf")
            st.caption("Passphrase dibentuk dari fingerprint SHA-256 atas ordo dan seluruh entri matriks ketetanggaan. Graf yang sama menghasilkan passphrase yang sama.")
            st.code(graph_passphrase, language=None)
            st.button(
                "Gunakan kata kunci graf pada HILLCRYPT",
                type="primary",
                key="gkl_apply_passphrase",
                on_click=_apply_graph_passphrase,
                args=(graph_passphrase, order),
                use_container_width=True,
            )
            st.info("Saat tombol ditekan, kata kunci graf akan mengisi passphrase utama, menyamakan ordo matriks, lalu membuka menu Enkripsi. Gunakan passphrase yang sama dan ordo yang sama saat dekripsi.")
            st.markdown("### 6. Uji enkripsi dan dekripsi dengan kata kunci graf")
            st.caption(
                "Pengujian ini menggunakan passphrase hasil graf sebagai kunci Hill Cipher, "
                "bukan memakai matriks ketetanggaan secara langsung. Untuk dekripsi, kata kunci "
                "pada sidebar harus sama dengan passphrase graf."
            )
            graph_encoding = st.selectbox("Mode encoding", [
                "ASCII (mod 128)", "Windows-1252 (mod 256)", "UTF-8 / Unicode (mod 256)"
            ], index=2, key="gkl_encoding")
            graph_mode = "ascii" if graph_encoding.startswith("ASCII") else (
                "windows1252" if graph_encoding.startswith("Windows") else "utf8"
            )
            graph_modulus = MODES[graph_mode]["modulus"]
            graph_text = st.text_area("Plaintext", "HILLCRYPT GRAPH KEY LAB", key="gkl_plain")

            st.session_state.setdefault("gkl_cipher_input", "")
            st.session_state.setdefault("gkl_original_length_input", 0)
            st.session_state.setdefault("gkl_decrypt_result", None)
            st.session_state.setdefault("gkl_graph_key_snapshot", None)
            st.session_state.setdefault("gkl_package", None)

            current_graph_snapshot = (
                tuple(tuple(int(v) for v in row) for row in matrix),
                graph_mode,
                graph_passphrase,
            )

            if st.button("Enkripsi dengan kata kunci graf", type="primary", key="gkl_encrypt"):
                try:
                    package, package_info = create_package(
                        graph_text, graph_passphrase, int(order), graph_mode, "GRAPH_KEY_LAB"
                    )
                    st.session_state["gkl_package"] = package
                    st.session_state["gkl_cipher_input"] = package["ciphertext_b64"]
                    st.session_state["gkl_original_length_input"] = package["original_byte_length"]
                    st.session_state["gkl_graph_key_snapshot"] = current_graph_snapshot
                    st.session_state["gkl_decrypt_result"] = None
                    st.success(
                        "Enkripsi berhasil menggunakan passphrase graf. "
                        "Paket menyimpan fingerprint kunci untuk pemeriksaan saat dekripsi."
                    )
                except Exception as exc:
                    st.session_state["gkl_package"] = None
                    st.session_state["gkl_graph_key_snapshot"] = None
                    st.session_state["gkl_decrypt_result"] = None
                    st.error(f"Enkripsi gagal: {exc}")

            cipher_b64 = st.text_area("Ciphertext Base64", key="gkl_cipher_input")
            original_len = st.number_input(
                "Panjang byte plaintext asli", min_value=0, step=1,
                key="gkl_original_length_input"
            )

            if st.button("Dekripsi ciphertext", key="gkl_decrypt"):
                try:
                    saved_package = st.session_state.get("gkl_package")
                    if not cipher_b64.strip():
                        raise GraphKeyError("Ciphertext masih kosong. Lakukan enkripsi terlebih dahulu.")
                    if saved_package is None:
                        raise GraphKeyError(
                            "Metadata paket dan fingerprint kunci tidak tersedia. "
                            "Lakukan enkripsi ulang pada sesi ini atau gunakan paket .hce lengkap."
                        )
                    if st.session_state.get("gkl_graph_key_snapshot") != current_graph_snapshot:
                        raise GraphKeyError(
                            "Graf atau mode encoding telah berubah. Enkripsi ulang dengan pengaturan saat ini."
                        )
                    if cipher_b64.strip() != saved_package.get("ciphertext_b64"):
                        raise GraphKeyError(
                            "Ciphertext berubah dari hasil enkripsi yang tersimpan. "
                            "Lakukan enkripsi ulang atau gunakan paket lengkap yang sesuai."
                        )
                    if int(original_len) != int(saved_package.get("original_byte_length", -1)):
                        raise GraphKeyError("Panjang byte tidak sesuai dengan metadata hasil enkripsi.")
                    # Intentionally use the current sidebar key here. decrypt_package
                    # checks its SHA-256 fingerprint against the key used at encryption.
                    text_result, _ = decrypt_package(saved_package, key)
                    st.session_state["gkl_decrypt_result"] = text_result
                    st.success("Dekripsi berhasil. Fingerprint kunci cocok dengan kunci saat enkripsi.")
                except Exception as exc:
                    st.session_state["gkl_decrypt_result"] = None
                    st.error(f"Dekripsi gagal: {exc}")

            if st.session_state.get("gkl_decrypt_result") is not None:
                st.text_area(
                    "Hasil dekripsi", st.session_state["gkl_decrypt_result"],
                    height=120, disabled=True
                )

        else:
            st.warning("Graf terbentuk, tetapi tidak dapat menjadi sumber kata kunci karena determinannya bukan +1 atau −1. Coba struktur graf lain atau ordo genap.")
    else:
        st.caption("Bentuk graf otomatis atau masukkan daftar sisi untuk melihat matriks dan hasil validasinya.")

elif page_key == "test":
    banner("🧪 "+tr("test"),tr("test_desc"))
    test_text=st.text_area(tr("plain"),"HILLCRYPT test 123 — 🔐\nUnicode, symbols, and line breaks.",height=150)
    if st.button("▶ "+tr("roundtrip"),type="primary",use_container_width=True):
        try:
            package,info=create_package(test_text,key,int(n),mode)
            restored,_=decrypt_package(package,key)
            if restored==test_text: st.success(tr("pass"))
            else: st.error("GAGAL — teks hasil pemulihan berbeda." if st.session_state.language=="id" else "FAIL — restored text differs.")
            a,b,c=st.columns(3)
            a.metric("Karakter" if st.session_state.language=="id" else "Characters",f"{len(test_text):,}")
            b.metric("Byte asli" if st.session_state.language=="id" else "Original bytes",f"{info['original_bytes']:,}")
            c.metric("Byte ciphertext" if st.session_state.language=="id" else "Ciphertext bytes",f"{info['ciphertext_bytes']:,}")
        except Exception as exc:
            st.error(str(exc))

elif page_key == "history":
    banner("◷ "+tr("history"),tr("history_desc")); st.info(tr("history_privacy"))
    records=st.session_state.get("activity_history",[])
    if records:
        display_rows=[{tr("history_time"):x["time"],tr("history_operation"):x["operation"],tr("history_encoding"):x["encoding"],tr("history_order"):x["order"],tr("history_chars"):x["characters"],tr("history_bytes"):x["bytes"],tr("history_status"):x["status"]} for x in records]
        st.dataframe(pd.DataFrame(display_rows),use_container_width=True,hide_index=True)
        ids=[x["id"] for x in records]
        selected=st.selectbox(tr("history_clear_one"),ids,format_func=lambda v:next((f"{x['time']} · {x['operation']} · {x['encoding']}" for x in records if x["id"]==v),str(v)),key="history_delete_select")
        ca,cb=st.columns(2)
        with ca:
            if st.button("🗑 "+tr("history_clear_one"),use_container_width=True):
                st.session_state.activity_history=[x for x in records if x["id"]!=selected]; st.rerun()
        with cb:
            if st.button("🗑 "+tr("history_clear_all"),use_container_width=True):
                st.session_state.activity_history=[]; st.session_state.pop("last_operation_graph",None); st.rerun()
    else: st.info(tr("history_empty"))
    st.divider(); st.subheader(tr("memory_clear")); st.caption(tr("memory_clear_help"))
    if st.button("🧹 "+tr("memory_clear"),type="primary",use_container_width=True):
        st.session_state.activity_history=[]; st.session_state.pop("last_operation_graph",None)
        for k in ["last_encrypt_package","last_plaintext","last_ciphertext","plain_input","package_input","restored_package","restored_raw"]: st.session_state.pop(k,None)
        st.cache_data.clear(); st.cache_resource.clear(); st.success(tr("memory_done")); st.rerun()

elif page_key == "about":
    banner("ℹ️ "+tr("about"),tr("about_desc"))
    st.markdown(f"""
    <div class="panel">
    <h3>HILLCRYPT v5.2</h3>
    <p>{tr('about_desc')}</p>
    <h4>{tr('about_objectives')}</h4>
    <ol>
    <li>{tr('about_obj_1')}</li>
    <li>{tr('about_obj_2')}</li>
    <li>{tr('about_obj_3')}</li>
    <li>{tr('about_obj_4')}</li>
    <li>{tr('about_obj_5')}</li>
    </ol></div>""",unsafe_allow_html=True)
    st.warning(tr("warning"))
    st.info(tr("local_note"))
    st.divider()
    st.markdown("### "+("Hak Cipta dan Kepemilikan" if st.session_state.language=="id" else "Copyright and Ownership"))
    st.markdown(f"**{tr('copyright')}**")
    st.caption(tr("copyright_note"))
    st.markdown("**"+tr("cross_device")+"**")
    st.write(tr("cross_device_desc"))
    st.caption(tr("copyright"))


st.markdown("<div style='text-align:center;color:#71879b;font-size:.78rem;padding:1.2rem 0;border-top:1px solid #dce6f0'>© 2026 Mamay Nurholifah · HILLCRYPT</div>", unsafe_allow_html=True)
