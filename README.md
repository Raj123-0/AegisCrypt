# AegisCrypt 

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-AES--GCM-red)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen)

> A cryptographically strong symmetric cipher utility built in Python for runtime-only authenticated encryption[cite: 7]. 

AegisCrypt ensures your secrets stay secure by strictly keeping keys out of your source code. By leveraging modern cryptographic primitives—specifically **AES-GCM** for authenticated encryption and **PBKDF2-HMAC-SHA256** for robust key derivation—it guarantees both the confidentiality and the integrity of your data. This is a real cryptographic construction designed for secure key management, not a custom toy cipher.

---

##  Table of Contents

For a deep dive into the architecture and full documentation, check out the detailed guides:

1. [Core Features](Core_Features.md)
2. [Installation](Installation.md)
3. [Usage Guide](Usage_Guide.md)
4. [Payload Architecture](Payload_Architecture.md)
5. [Author & Contributions](Author_and_Contributions.md)

---

##  Quick Start

Get up and running in seconds. For full requirements and setup details, see the [Installation](Installation.md) guide.

### 1. Install Dependencies
AegisCrypt is lightweight and only relies on the widely trusted `cryptography` library.
```bash
git https://github.com/Raj123-0/AegisCrypt.git
cd AegisCrypt
pip install cryptography
