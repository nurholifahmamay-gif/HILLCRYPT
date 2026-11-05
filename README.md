# HILLCRYPT v5.2 — Educational Content Expansion

Interactive matrix-cryptography learning application built with Python and Streamlit.

HILLCRYPT v5.2 preserves the v5.1 encryption/decryption workflow and expands the learning area into ten structured chapters in Indonesian and English. This release is prepared on the development branch for review; it is not yet the production release until the pull request is reviewed, merged, and the hosted app is verified.

## Core application features retained from v5.1

- Indonesian and English interface.
- ASCII Standard (0–127, modulus 128), Windows-1252 (single-byte CP1252, modulus 256), and UTF-8/Unicode (UTF-8 bytes, modulus 256).
- Configurable square key matrix order n × n, from 1 to 16.
- Customizable passphrase and modular invertibility validation.
- Encryption and decryption using the Hill matrix transformation.
- HCE/JSON package and raw Base64 output.
- Metadata-aware decryption, key fingerprint checks, and package integrity verification as implemented in v5.1.
- Matrix laboratory, key/inverse inspection, modular multiplication, and vector calculation.
- Weighted directed graph visualization and Graph Key Lab.
- Activity history and system tests.

## v5.2 learning expansion

The Learn Cryptography page contains ten chapters, each with learning objectives, concept explanations, mathematical formulas, worked examples, and a short multiple-choice assessment:

1. Cryptography foundations.
2. Linear algebra foundations.
3. Modular arithmetic and multiplicative inverses.
4. Hill Cipher and modular invertibility.
5. Worked encryption/decryption calculation.
6. ASCII, Windows-1252, UTF-8, characters, and bytes.
7. Blocks, zero padding, Base64, and HCE packages.
8. Matrices, directed graphs, and Graph Key Lab.
9. Security analysis and limitations of classical Hill Cipher.
10. HILLCRYPT practical lab and round-trip assessment.

The learning material is available in Indonesian and English. Examples explicitly distinguish the illustrative modulo-26 alphabet model from the application's byte-based modes (modulo 128 or 256).

## Mathematical model

For a plaintext column vector P, ciphertext column vector C, key matrix K, and modulus m:

`C ≡ KP (mod m)`

`P ≡ K⁻¹C (mod m)`

The key matrix is invertible modulo m if and only if:

`gcd(det(K), m) = 1`

When this condition holds:

`K⁻¹ ≡ (det K)⁻¹ adj(K) (mod m)`

This condition is important for composite moduli such as 128 and 256. A nonzero determinant alone is not sufficient.

## Important encoding and package notes

- ASCII Standard supports byte values 0–127.
- Windows-1252 uses one byte for supported CP1252 characters; undefined byte positions are 129, 141, 143, 144, and 157.
- UTF-8 represents a Unicode code point using one to four bytes. Character count and byte count may therefore differ.
- If the byte count is not divisible by the matrix order n, zero padding is appended. The original byte length is needed to remove padding exactly.
- Base64 is only a byte-to-text representation. Raw Base64 does not carry encoding, matrix order, or original plaintext length.
- The HCE/JSON package is the recommended format when the metadata is needed for decryption.

## Security limitations

The Hill Cipher is a classical linear cipher and is vulnerable to known-plaintext and other cryptanalytic attacks. It is an educational tool, not a modern secure encryption scheme. Package integrity checks do not remove the underlying cryptographic weaknesses of Hill Cipher. Do not submit confidential information to a publicly hosted educational application. Use a vetted authenticated encryption scheme such as AES-GCM or ChaCha20-Poly1305 for real confidentiality and integrity requirements.

## Run locally on Windows

1. Install Python 3.10 or newer.
2. Extract the project ZIP.
3. Install dependencies with `python -m pip install -r requirements.txt`.
4. Run `python -m streamlit run app.py`.
5. Open the local URL shown by Streamlit, usually `http://localhost:8501`.

## Tests

Run the automated test suite from the project root:

`python -m unittest discover -s tests -v`

Manual acceptance testing is still required for the Streamlit interface, HCE file upload/download, session synchronization, and public hosting behavior.
