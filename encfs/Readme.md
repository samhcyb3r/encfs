# 加密記憶體檔案系統（Encrypted In-Memory Filesystem using FUSE）


# 1. 簡介（Introduction）

本作業旨在建立一個運作於使用者空間的檔案系統（FUSE），並在檔案內容層加入 AES-256-GCM 加密，以確保資料在記憶體中的安全性。本系統採用 in-memory filesystem 設計，不會在磁碟上留下任何資料。

本系統支援：

- 基本檔案系統操作（create / open / read / write / rename / unlink / mkdir / truncate…）
- AES-256-GCM 檔案內容加密
- 每檔案獨立金鑰（per-file key）
- `.keyring` 管理金鑰（per-PID）
- rename 後仍可正常解密（fid-based AAD）
- 附完整自動化測試腳本

---

# 2. 系統架構（System Overview）

```
                ┌────────────────────┐
                │ 使用者程式 (cat, mv)│
                └─────────┬──────────┘
                          │ Linux syscall
                ┌─────────▼──────────┐
                │        FUSE         │
                │ encrypted_memfs.py  │
                └─────────┬──────────┘
      plaintext <───► 加密/解密 ───► cipher
                ┌─────────▼──────────┐
                │  記憶體儲存空間       │
                │  FileNode 物件樹    │
                └─────────────────────┘
```

---

# 3. 環境建置（Part 1）

```bash
sudo apt-get install fuse libfuse-dev
pip3 install fusepy cryptography
```

啟動：

```bash
mkdir -p /mnt/efs
python3 encrypted_memfs.py /mnt/efs -f
```

---

# 4. 記憶體檔案系統設計（Part 2）

## 4.1 FileNode 物件模型

- `mode`
- `nlink`
- `size`
- `cipher`
- `header = { salt , nonce , fid }`
- `children`

## 4.2 支援的 FUSE 操作

| 操作 | 說明 |
|------|------|
| create | 建立檔案 |
| open | 解密 |
| read | plaintext buffer |
| write | plaintext buffer |
| release | 關閉 → 加密 |
| truncate | 重建 plaintext |
| rename | 使用 fid 做 AAD，不破壞密文 |
| mkdir/rmdir | 目錄操作 |
| unlink | 刪除 |

---

# 5. AES-256-GCM 加密（Part 3）

加密流程：

```
plaintext → HKDF(master_key, salt) → AES_key
nonce → AAD=fid → cipher
```

解密流程包含 fallback（舊 path-based AAD）。

---

# 6. 金鑰管理（Part 4）

`.keyring` 檔案負責 per-PID keyring。

新增金鑰：

```bash
echo "ADD /secret.txt <hex>" > /mnt/efs/.keyring
```

刪除：

```bash
echo "DEL /secret.txt" > /mnt/efs/.keyring
```

查詢：

```bash
cat /mnt/efs/.keyring
```

---

# 7. 加密檔案操作語意（Part 5）

| 操作 | 行為 |
|------|----------|
| open | 檢查金鑰並解密 |
| read | plaintext |
| write | plaintext |
| release | 加密 |
| rename | 使用 fid 保證安全 |

---

# 8. 測試與驗證（Part 6）

使用：

```bash
./test.sh /mnt/efs
```

結果：

```
=== ALL TESTS PASSED ===
```

---

# 9. 設計難點（Part 7）

## 9.1 rename 問題

path-based AAD 會因 rename 而失效 → 必須使用固定 fid。

若舊密文成功以 path 解密 → 自動升級為 fid 版本。

---

# 10. 結論（Conclusion）

成功實作：

- FUSE in-memory FS
- AES-256-GCM 加密
- HKDF per-file key
- per-PID keyring
- rename 安全
- 全測試通過

---

# 11. 附錄（Appendix）

- `encrypted_memfs.py`
- `test.sh`
