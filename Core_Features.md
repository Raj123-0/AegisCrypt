# Core Features ✨

AegisCrypt is built with security and usability in mind. Here is a deeper dive into the core features:

## 1. Robust Key Derivation
AegisCrypt uses **PBKDF2-HMAC-SHA256** to derive a strong AES key from your passphrase. 
*   **Default Iterations:** Set to a secure 200,000 iterations to thwart brute-force attacks.
*   **Salt:** A random 16-byte salt is generated for every encryption.

## 2. Authenticated Encryption
It utilizes **AES-GCM** (Galois/Counter Mode).
*   Ensures that ciphertext cannot be tampered with (integrity).
*   Uses a fresh random 12-byte nonce for every encryption operation.

## 3. Secure Key Management
Keys are strictly requested at runtime. This prevents hardcoding secrets into source code.
*   Interactive hidden prompts for manual entry.
*   Support for loading keys from secure local files (`--key-file`).
*   Support for reading from environment variables (`--key-env`).

## 4. Future-Proof Payload
Implements a versioned, self-describing binary format.
*   Magic bytes ensure the ciphertext is actually an AegisCrypt payload.
*   Built-in legacy support allows decoding of older payloads (e.g., `CX2` magic bytes).
