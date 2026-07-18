# Payload Architecture 

AegisCrypt generates a versioned binary blob before encoding it to Base64. This securely bundles the cryptographic parameters with the ciphertext.

## Binary Format Breakdown (Version 2)

| Byte Offset | Size (Bytes) | Description |
| :--- | :--- | :--- |
| `[0:2]` | 2 | **Magic Bytes:** `CX` (Identifies the blob) |
| `[2:3]` | 1 | **Version:** `0x02` (AegisCrypt Version 2) |
| `[3:7]` | 4 | **Iterations:** PBKDF2 iteration count (big-endian) |
| `[7:23]` | 16 | **Salt:** Randomly generated per encryption |
| `[23:35]` | 12 | **Nonce:** Fresh random nonce for AES-GCM |
| `[35:]` | Variable | **Ciphertext:** Encrypted data + GCM authentication tag |

*Note: Older payloads starting with `CX2` are automatically detected and decoded using legacy parameters.*
