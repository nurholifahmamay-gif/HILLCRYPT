# HILLCRYPT 4.2 – Graph, History & Copyright Edition

- Corrected the round-trip equation to D_K(E_K(P)) ≡ P (mod m).
- Added encryption/decryption component equations and symbol explanations.
- Added operation-specific directed weighted bipartite graph for the latest operation.
- Preserved the existing key-matrix graph.
- Added session activity history and manual deletion of one/all entries.
- Added temporary-memory cleanup for history, last operation graph, temporary input/result keys, and Streamlit caches.
- Added application copyright notice.
- Added History navigation in Indonesian and English.
- Expanded the manual matrix calculator order selector.

## Privacy
History stores metadata only (time, operation, encoding, matrix order, character/byte counts, status). It does not store plaintext, ciphertext, or passphrases. Session data is temporary.

## Compatibility
Existing HILLCRYPT package format, key derivation, ASCII, Windows-1252, UTF-8, and cipher operations are retained. Hill Cipher is for education, not confidential-data protection.
