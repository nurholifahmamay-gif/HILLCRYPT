import unittest
from hill_cipher import (
    MODES, create_package, decrypt_package, derive_key_matrix,
    matrix_inverse_mod, matrix_determinant, encode_plaintext
)

KEY = "THEKINGOFGEMINOR"

class HillCipherV3Tests(unittest.TestCase):
    def round_trip(self, text, mode, n=4):
        package, info = create_package(text, KEY, n, mode)
        restored, details = decrypt_package(package, KEY)
        self.assertEqual(restored, text)
        self.assertEqual(details["mode"], mode)
        self.assertEqual(info["original_bytes"], len(encode_plaintext(text, mode)))
        return package

    def test_ascii_round_trip(self):
        self.round_trip("ASCII text 123!\nTab\tSpace ", "ascii", 3)

    def test_ascii_rejects_non_ascii(self):
        with self.assertRaises(ValueError):
            create_package("café", KEY, 3, "ascii")

    def test_windows1252_round_trip(self):
        self.round_trip("Euro € · copyright © · café · naïve · ÿ", "windows1252", 5)

    def test_windows1252_rejects_unsupported_unicode(self):
        with self.assertRaises(ValueError):
            create_package("Hello 🔐 漢字", KEY, 4, "windows1252")

    def test_utf8_unicode_emoji_round_trip(self):
        self.round_trip("Halo 🔐 ∑ 漢字 — café\nbaris kedua", "utf8", 4)

    def test_long_text_all_modes(self):
        self.round_trip("Long ASCII 123! " * 10000, "ascii", 7)
        self.round_trip("Euro € café " * 10000, "windows1252", 6)
        self.round_trip("Unicode 🔐 漢字 ∑ " * 10000, "utf8", 8)

    def test_various_matrix_orders(self):
        for mode in MODES:
            modulus = MODES[mode]["modulus"]
            for n in (1, 2, 3, 4, 5, 8, 12, 16):
                matrix = derive_key_matrix(KEY, n, modulus)
                inverse = matrix_inverse_mod(matrix, modulus)
                for i in range(n):
                    for j in range(n):
                        value = sum(matrix[i][k]*inverse[k][j] for k in range(n)) % modulus
                        self.assertEqual(value, 1 if i == j else 0)

    def test_wrong_key_is_rejected(self):
        package, _ = create_package("secret text", KEY, 3, "utf8")
        with self.assertRaises(ValueError):
            decrypt_package(package, "WRONGKEY")

    def test_package_tampering_is_rejected(self):
        package, _ = create_package("test", KEY, 3, "ascii")
        package["modulus"] = 256
        with self.assertRaises(ValueError):
            decrypt_package(package, KEY)

    def test_custom_passphrase_round_trip(self):
        custom_key = "Custom Key 2026!"
        for mode, message in (
            ("ascii", "Custom key works with ASCII 123!"),
            ("windows1252", "Custom key € café"),
            ("utf8", "Custom key 🔐 漢字"),
        ):
            package, _ = create_package(message, custom_key, 5, mode)
            restored, _ = decrypt_package(package, custom_key)
            self.assertEqual(restored, message)
            with self.assertRaises(ValueError):
                decrypt_package(package, KEY)

    def test_key_default_matrix_is_deterministic(self):
        a = derive_key_matrix(KEY, 4, 256)
        b = derive_key_matrix(KEY, 4, 256)
        self.assertEqual(a, b)

if __name__ == "__main__":
    unittest.main()
