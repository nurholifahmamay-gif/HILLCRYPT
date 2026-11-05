"""Educational Hill Cipher implementation for ASCII, Windows-1252 and UTF-8."""
import base64
import hashlib
import json
import math
import hmac
import secrets
from sympy import Matrix

MODES = {
    "ascii": {
        "label": "ASCII Standard",
        "description": "7-bit ASCII, code 0–127",
        "modulus": 128,
        "encoding": "ascii",
    },
    "windows1252": {
        "label": "Windows-1252",
        "description": "8-bit character table, byte 0–255",
        "modulus": 256,
        "encoding": "cp1252",
    },
    "utf8": {
        "label": "UTF-8 / Unicode",
        "description": "Unicode text encoded as UTF-8 bytes",
        "modulus": 256,
        "encoding": "utf-8",
    },
}
PACKAGE_FORMAT = "HILLCRYPT-PACKAGE-V4"
LEGACY_PACKAGE_FORMAT = "HILLCRYPT-PACKAGE-V3"
MIN_ORDER = 1
MAX_ORDER = 16

def matrix_determinant(a):
    return int(Matrix([[int(x) for x in row] for row in a]).det())

def matrix_inverse_mod(a, modulus):
    if modulus not in (128, 256):
        raise ValueError("Modulus harus 128 atau 256.")
    M = Matrix([[int(x) for x in row] for row in a])
    if M.rows != M.cols or M.rows == 0:
        raise ValueError("Matriks kunci harus persegi dan tidak kosong.")
    det = int(M.det())
    if math.gcd(det, modulus) != 1:
        raise ValueError(
            f"Matriks tidak invertibel: gcd(det(K), {modulus}) harus 1, "
            f"sedangkan hasilnya {math.gcd(det, modulus)}."
        )
    inv = M.inv_mod(modulus)
    return [[int(inv[i, j]) % modulus for j in range(inv.cols)]
            for i in range(inv.rows)]

def derive_key_matrix(key, n, modulus):
    if not isinstance(key, str) or not key.strip():
        raise ValueError("Kata kunci tidak boleh kosong.")
    if not isinstance(n, int) or not MIN_ORDER <= n <= MAX_ORDER:
        raise ValueError(f"Ordo matriks harus {MIN_ORDER} sampai {MAX_ORDER}.")
    if modulus not in (128, 256):
        raise ValueError("Modulus harus 128 atau 256.")
    seed = (
        b"HILLCRYPT-V3|" + str(modulus).encode("ascii") + b"|"
        + str(n).encode("ascii") + b"|" + key.encode("utf-8")
    )
    # Deterministic generation makes the same passphrase reproducible.
    # The candidate is accepted only if det(K) is a unit modulo modulus.
    for counter in range(100000):
        raw = hashlib.shake_256(seed + b"|" + str(counter).encode("ascii")).digest(n*n)
        matrix = [[raw[i*n+j] % modulus for j in range(n)] for i in range(n)]
        if math.gcd(matrix_determinant(matrix), modulus) == 1:
            return matrix
    raise ValueError("Tidak berhasil membentuk matriks invertibel. Coba ordo lain.")

def key_fingerprint(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def transform_bytes(data, matrix, modulus):
    n = len(matrix)
    if n == 0 or any(len(row) != n for row in matrix):
        raise ValueError("Matriks kunci harus persegi.")
    if len(data) % n:
        raise ValueError("Panjang byte harus merupakan kelipatan ordo matriks.")
    output = bytearray()
    for offset in range(0, len(data), n):
        block = data[offset:offset+n]
        # Column-vector convention: output_i = sum(K_ij * input_j).
        for row in matrix:
            output.append(sum(int(row[j]) * block[j] for j in range(n)) % modulus)
    return bytes(output)

def encrypt_bytes(data, key, n, modulus):
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise ValueError("Data plaintext tidak boleh kosong.")
    matrix = derive_key_matrix(key, n, modulus)
    padding = (-len(data)) % n
    padded = bytes(data) + (b"\x00" * padding)
    ciphertext = transform_bytes(padded, matrix, modulus)
    return ciphertext, {
        "padding_bytes": padding,
        "original_bytes": len(data),
        "ciphertext_bytes": len(ciphertext),
    }

def decrypt_bytes(ciphertext, key, n, modulus, original_length):
    if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) == 0:
        raise ValueError("Ciphertext kosong.")
    if len(ciphertext) % n:
        raise ValueError("Ukuran ciphertext tidak sesuai dengan ordo matriks.")
    if not isinstance(original_length, int) or isinstance(original_length, bool):
        raise ValueError("Metadata panjang asli tidak valid.")
    if original_length < 0 or original_length > len(ciphertext):
        raise ValueError("Metadata panjang asli tidak valid.")
    inverse = matrix_inverse_mod(derive_key_matrix(key, n, modulus), modulus)
    return transform_bytes(bytes(ciphertext), inverse, modulus)[:original_length]

def encode_plaintext(text, mode):
    if mode not in MODES:
        raise ValueError("Mode encoding tidak dikenal.")
    encoding = MODES[mode]["encoding"]
    try:
        return text.encode(encoding, errors="strict")
    except UnicodeEncodeError as exc:
        if mode == "ascii":
            message = "ASCII hanya menerima karakter dengan kode 0–127. Pilih Windows-1252 atau UTF-8."
        elif mode == "windows1252":
            message = ("Karakter tidak tersedia pada tabel Windows-1252. "
                       "Pilih UTF-8 untuk karakter Unicode yang lebih luas.")
        else:
            message = "Teks tidak dapat dikodekan sebagai UTF-8."
        raise ValueError(message) from exc

def decode_plaintext(data, mode):
    if mode not in MODES:
        raise ValueError("Mode encoding tidak dikenal.")
    try:
        return bytes(data).decode(MODES[mode]["encoding"], errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Byte hasil dekripsi tidak membentuk teks valid pada mode ini. "
            "Periksa kata kunci, paket, dan mode encoding."
        ) from exc

def _canonical_package_bytes(package):
    """Stable serialization used for package authentication."""
    payload = {k: v for k, v in package.items() if k != "auth_tag"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _derive_package_auth_key(key, salt):
    """Derive a package-specific authentication key from the passphrase.

    scrypt makes offline guessing more expensive, but this educational
    construction is not a replacement for a modern authenticated cipher.
    """
    return hashlib.scrypt(
        key.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )

def create_package(text, key, n, mode, key_source="MANUAL"):
    if not isinstance(text, str) or text == "":
        raise ValueError("Plaintext tidak boleh kosong.")
    if not isinstance(n, int) or isinstance(n, bool) or not MIN_ORDER <= n <= MAX_ORDER:
        raise ValueError(f"Ordo matriks harus {MIN_ORDER} sampai {MAX_ORDER}.")
    if mode not in MODES:
        raise ValueError("Mode encoding tidak dikenal.")
    if not isinstance(key_source, str) or not key_source.strip():
        raise ValueError("Sumber kata kunci tidak valid.")
    raw = encode_plaintext(text, mode)
    modulus = MODES[mode]["modulus"]
    ciphertext, info = encrypt_bytes(raw, key, n, modulus)
    salt = secrets.token_bytes(16)
    package = {
        "format": PACKAGE_FORMAT,
        "version": 4,
        "algorithm": "Educational Hill Cipher",
        "mode": mode,
        "encoding": MODES[mode]["encoding"],
        "modulus": modulus,
        "matrix_order": n,
        "block_size": n,
        "original_byte_length": len(raw),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "key_fingerprint": key_fingerprint(key),
        "key_source": key_source.upper(),
        "auth": "HMAC-SHA256-SCRYPT",
        "auth_salt_b64": base64.b64encode(salt).decode("ascii"),
    }
    auth_key = _derive_package_auth_key(key, salt)
    package["auth_tag"] = hmac.new(auth_key, _canonical_package_bytes(package), hashlib.sha256).hexdigest()
    return package, info

def decrypt_package(package, key):
    if isinstance(package, str):
        try:
            package = json.loads(package)
        except Exception as exc:
            raise ValueError("Isi paket ciphertext bukan JSON yang valid.") from exc
    if not isinstance(package, dict):
        raise ValueError("Format paket ciphertext tidak dikenali.")
    package_format = package.get("format")
    if package_format not in (PACKAGE_FORMAT, LEGACY_PACKAGE_FORMAT):
        raise ValueError("Format paket tidak dikenali. Gunakan paket HILLCRYPT (.hce/.json).")
    mode = package.get("mode")
    if mode not in MODES:
        raise ValueError("Mode encoding pada paket tidak valid.")
    n = package.get("matrix_order")
    modulus = MODES[mode]["modulus"]
    if (not isinstance(n, int) or isinstance(n, bool)
            or not MIN_ORDER <= n <= MAX_ORDER
            or package.get("modulus") != modulus
            or package.get("block_size") != n
            or package.get("encoding") != MODES[mode]["encoding"]):
        raise ValueError("Metadata paket tidak konsisten atau telah diubah.")
    if not isinstance(key, str) or package.get("key_fingerprint") != key_fingerprint(key):
        raise ValueError("Kata kunci tidak cocok dengan ciphertext.")
    if package_format == PACKAGE_FORMAT:
        if package.get("auth") != "HMAC-SHA256-SCRYPT":
            raise ValueError("Metode autentikasi paket tidak dikenali.")
        try:
            salt = base64.b64decode(package["auth_salt_b64"], validate=True)
            supplied_tag = package["auth_tag"]
        except Exception as exc:
            raise ValueError("Metadata autentikasi paket rusak atau tidak lengkap.") from exc
        if len(salt) != 16 or not isinstance(supplied_tag, str):
            raise ValueError("Metadata autentikasi paket tidak valid.")
        auth_key = _derive_package_auth_key(key, salt)
        expected_tag = hmac.new(auth_key, _canonical_package_bytes(package), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise ValueError("Integritas paket gagal: metadata atau ciphertext telah berubah.")
    try:
        ciphertext = base64.b64decode(package["ciphertext_b64"], validate=True)
    except Exception as exc:
        raise ValueError("Data ciphertext Base64 rusak.") from exc
    original_length = package.get("original_byte_length")
    raw = decrypt_bytes(ciphertext, key, n, modulus, original_length)
    plaintext = decode_plaintext(raw, mode)
    return plaintext, {
        "mode": mode,
        "encoding": MODES[mode]["encoding"],
        "n": n,
        "modulus": modulus,
        "original_bytes": len(raw),
        "ciphertext_bytes": len(ciphertext),
        "key_source": package.get("key_source", "UNKNOWN"),
        "package_version": package.get("version", 3),
        "integrity_verified": package_format == PACKAGE_FORMAT,
    }

