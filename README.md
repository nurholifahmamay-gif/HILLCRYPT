# HILLCRYPT 4.2 — Refined Unified Edition

Interactive matrix-cryptography learning application built with Python and Streamlit.

HILLCRYPT 4.2 preserves the visual identity and working encryption/decryption core of v4.0 while refining the exact interface and learning features requested by the user.

## Features

- Indonesian and English interface.
- Three byte encodings:
  - **ASCII Standard:** codes 0–127, modulus 128.
  - **Windows-1252:** one-byte CP1252 encoding, modulus 256. Undefined byte positions are 129, 141, 143, 144, and 157.
  - **UTF-8 / Unicode:** UTF-8 bytes, modulus 256; supports emoji and non-Latin scripts.
- Configurable square key matrix order **n × n**, from 1 to 16, with explicit visible minus/plus controls.
- Customizable passphrase. Encryption and decryption must use the same passphrase, matrix order, and encoding.
- Automatic modular invertibility validation and modular inverse calculation.
- Long plaintext, multiline text, and `.txt` uploads.
- Live character and encoded-byte count while entering plaintext.
- Separate copy-ready Base64 ciphertext output and retained expandable HILLCRYPT JSON package.
- Downloadable `.hce`/JSON package and raw Base64 `.txt`.
- Decryption from complete HILLCRYPT package, with encoding, matrix order, and original byte length read from package metadata.
- Legacy/raw Base64 decryption remains available.
- Matrix laboratory with key matrix, inverse matrix, identity check, manual matrix multiplication modulo m, and manual K × P vector calculation.
- Weighted directed graph visualization derived from the key matrix (nonzero Kᵢⱼ entries become directed weighted edges).
- Searchable ASCII 0–127 and Windows-1252 128–255 code table, including decimal, hexadecimal, binary, character, and type.
- Expanded learning materials covering Hill Cipher, modular arithmetic, encodings, padding, passphrase handling, graph representation, and security limitations.

## Mathematical model

For plaintext column vector \(\mathbf{p}\), ciphertext column vector \(\mathbf{c}\), key matrix \(K\), and encoding modulus \(m\):

**Encryption**

\[
\mathbf{c} \equiv K\mathbf{p} \pmod m
\]

**Decryption**

\[
\mathbf{p} \equiv K^{-1}\mathbf{c} \pmod m
\]

**Invertibility condition**

\[
\gcd(\det(K),m)=1
\]

When the condition holds, the modular inverse can be expressed as:

\[
K^{-1} \equiv (\det K)^{-1}\operatorname{adj}(K) \pmod m
\]

A complete plaintext is restored block-by-block. If the final byte block is incomplete, zero padding is added during encryption and removed using the original byte length stored in the package.

## Important note about automatic byte length

For a complete `.hce`/JSON package, the original byte length is read automatically. Raw Base64 ciphertext alone does **not** contain the original plaintext byte length. Because the final block may have zero padding, that original length cannot be inferred uniquely from raw Base64. Therefore, raw Base64 mode retains a manual original-byte-length field for exact recovery. For easier use, share the complete `.hce` package.

## Run on Windows

1. Install Python 3.10 or newer from https://www.python.org/downloads/.
2. During setup, enable **Add Python to PATH**.
3. Extract the ZIP.
4. Open the extracted `HILLCRYPT_v4_2` folder.
5. Double-click `INSTALL_DEPENDENCIES.bat` once.
6. After installation finishes, double-click `RUN_HILLCRYPT.bat`.
7. Open the local URL shown in the terminal, usually `http://localhost:8501`.

Manual commands:

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Public access from Windows, Android, iOS, and other devices

`localhost` is available only on the computer running the application. To access HILLCRYPT from anywhere, deploy the project to a public Streamlit-compatible host (for example, Streamlit Community Cloud) and use the public URL from a browser. On Android or iOS, the URL can be added to the home screen.

This is a responsive web application, not a native APK, IPA, or EXE. When hosted publicly, submitted text is processed by the hosting server. Do not submit confidential data.

## Educational graph visualization

The graph panel interprets the current key matrix as a weighted directed adjacency matrix:
- Matrix index i corresponds to vertex vᵢ.
- A nonzero entry Kᵢⱼ creates a directed edge vᵢ → vⱼ.
- The edge label is the entry reduced modulo m.

This is an educational visualization connecting matrices and graph theory; it is not a claim that Hill Cipher itself requires graph traversal.

## Security limitations

Hill Cipher is a classical linear cipher. It is vulnerable to known-plaintext and other cryptanalytic attacks, provides no authentication, and is not suitable for protecting confidential data. The deterministic passphrase-to-matrix derivation is intended for reproducible education, not modern password-based key derivation. The package key fingerprint detects key mismatch but is not a message authentication code.

Use a vetted authenticated encryption scheme such as AES-GCM or ChaCha20-Poly1305 for real confidentiality and integrity requirements.


## HILLCRYPT 4.2 additions
- Operation-specific weighted bipartite graph for the latest encryption/decryption block.
- Session history and manual deletion controls.
- Temporary session memory cleanup.
- Copyright notice.
- Correct round-trip equation and expanded symbol explanations.
