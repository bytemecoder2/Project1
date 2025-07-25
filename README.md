# Project1
# 🔐 Secure File Encryption & Decryption Tool

This Python-based tool provides robust and secure file encryption and decryption using modern cryptographic standards. It is designed for data protection, integrity, and secure deletion, making it suitable for personal or professional security workflows.

## ✨ Features

- **AES-GCM Encryption**  
  Ensures confidentiality and authenticity with authenticated encryption.

- **Argon2id Key Derivation**  
  Uses a memory-hard, GPU-resistant KDF to derive encryption keys from passwords securely.

- **HMAC Integrity Verification**  
  Verifies file and header integrity to detect tampering or corruption.

- **Versioned Header Structure**  
  Modular and extensible header system using a factory pattern to support future upgrades.

- **Secure File Deletion**  
  Implements optional secure wiping of plaintext and sensitive data after encryption/decryption.

- **Buffered Streaming I/O**  
  Processes large files in chunks with progress display via `tqdm`.

- **Optional ECC Support**  
  Public key encryption (Elliptic Curve Cryptography) for secure sharing of AES keys.

## 📦 Requirements

- Python 3.8+
- `cryptography`
- `argon2-cffi`
- `tqdm`

Install requirements:
```bash
pip install -r requirements.txt
