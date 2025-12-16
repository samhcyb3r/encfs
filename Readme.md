# Encrypted In-Memory File System (encfs)

A lightweight **encrypted in-memory file system** implemented with **FUSE (Filesystem in Userspace)**.  
All file contents are stored **only in memory and always encrypted**, providing strong runtime data protection without modifying the kernel.

---

## ✨ Features

- In-memory file system using FUSE
- AES-256-GCM authenticated encryption (AEAD)
- Per-file encryption keys
- Secure key derivation using PBKDF2 with per-file salt
- Strict access control: no key, no access
- Automated testing with observable system evidence

---

## 🧠 Design Overview

### 1. In-Memory File System

- Files and directories exist only in memory
- No plaintext data is written to disk
- Each file or directory is represented by an in-memory node

### 2. Encryption Model

- File contents are encrypted using **AES-256-GCM**
- AES-GCM provides both:
  - Confidentiality (encryption)
  - Integrity (authentication tag)
- Plaintext exists only temporarily during read/write operations

### 3. Per-File Key Management

- Each file has its **own encryption key**
- Keys are derived using **PBKDF2** with:
  - User-supplied passphrase
  - Per-file random salt
- Even if the same passphrase is reused, different files produce different keys

### 4. Key Provision Mechanism

- Encryption keys are provided via **extended attributes (xattr)**
- The key must be explicitly supplied before accessing a file
- Access is denied if the key is missing or incorrect

---

## 🔐 Encryption Workflow

1. User sets a passphrase for a file via `setxattr`
2. The system derives an AES-256 key using PBKDF2
3. File data is encrypted before being stored in memory
4. On read/write:
   - Data is decrypted temporarily
   - Operation is performed
   - Data is immediately re-encrypted
5. Incorrect or missing keys result in access denial

---

## 🚀 Getting Started

### Set encryption key
```bash
setfattr -n user.key -v "mypassword" file.txt
```
