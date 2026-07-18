# AegisCrypt 🛡️

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-AES--GCM-red)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen)

> A cryptographically strong symmetric cipher utility built in Python for runtime-only authenticated encryption. This is a real cryptographic construction, not a custom toy cipher.

AegisCrypt ensures your secrets stay secure by strictly keeping keys out of your source code. By leveraging modern cryptographic primitives, it guarantees both the confidentiality and the integrity of your data.

---

##  Table of Contents
1. [Core Features](#-core-features)
2. [Installation](#-installation)
3. [Usage Guide](#-usage-guide)
    - [Interactive Mode](#interactive-mode)
    - [CLI: Encoding](#cli-encoding)
    - [CLI: Decoding](#cli-decoding)
4. [Payload Architecture](#-payload-architecture)
5. [Author & Contributions](#-author--contributions)

---

##  Core Features

*   **Robust Key Derivation:** Uses **PBKDF2-HMAC-SHA256** to derive a strong AES key from your passphrase.
*   **Authenticated Encryption:** Utilizes **AES-GCM** with a fresh random nonce to ensure ciphertext cannot be tampered with.
*   **Future-Proof Payload:** Implements a versioned, self-describing binary format for future compatibility.
*   **Secure Key Management:** Keys are only requested at runtime. Supports optional key loading from a file or environment variables for secure management.

---

##  Installation

Clone the repository and install the required dependencies. AegisCrypt relies on the widely trusted `cryptography` library.

```bash
# Clone the repository
git clone [https://github.com/_ranveerpardeshi_/AegisCrypt.git](https://github.com/_ranveerpardeshi_/AegisCrypt.git)

# Navigate to the directory
cd AegisCrypt

# Install the dependencies
pip install cryptography
