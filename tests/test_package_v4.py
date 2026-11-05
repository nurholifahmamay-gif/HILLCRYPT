import copy
import unittest
from hill_cipher import create_package, decrypt_package

class PackageV4Tests(unittest.TestCase):
    def test_round_trip_and_wrong_key(self):
        package, _ = create_package("HILLCRYPT Uji Unicode — ✓", "KUNCI-UJI", 4, "utf8")
        restored, info = decrypt_package(package, "KUNCI-UJI")
        self.assertEqual(restored, "HILLCRYPT Uji Unicode — ✓")
        self.assertTrue(info["integrity_verified"])
        with self.assertRaisesRegex(ValueError, "Kata kunci tidak cocok"):
            decrypt_package(package, "KUNCI-LAIN")

    def test_tampering_is_rejected(self):
        package, _ = create_package("TES INTEGRITAS", "KUNCI-UJI", 4, "utf8")
        changed = copy.deepcopy(package)
        changed["ciphertext_b64"] = changed["ciphertext_b64"][:-2] + "AA"
        with self.assertRaisesRegex(ValueError, "Integritas paket gagal"):
            decrypt_package(changed, "KUNCI-UJI")

    def test_metadata_tampering_is_rejected(self):
        package, _ = create_package("TES METADATA", "KUNCI-UJI", 4, "utf8")
        changed = copy.deepcopy(package)
        changed["key_source"] = "MANUAL" if changed["key_source"] != "MANUAL" else "GRAPH_KEY_LAB"
        with self.assertRaisesRegex(ValueError, "Integritas paket gagal"):
            decrypt_package(changed, "KUNCI-UJI")

if __name__ == "__main__":
    unittest.main()
