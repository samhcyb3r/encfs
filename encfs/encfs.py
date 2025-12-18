#!/usr/bin/env python3
import os
import sys
import time
import errno
from dataclasses import dataclass, field
from stat import S_IFDIR, S_IFREG
from typing import Dict, Set, Optional

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

# pip3 install cryptography fusepy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def _current_timestamp():
    """獲取當前時間戳記"""
    return time.time()


def _get_parent_path(filepath: str) -> str:
    """取得父目錄路徑"""
    if filepath == "/":
        return "/"
    parent_dir = os.path.dirname(filepath.rstrip("/"))
    return parent_dir if parent_dir else "/"


def _extract_filename(filepath: str) -> str:
    """提取檔案名稱"""
    return os.path.basename(filepath.rstrip("/")) or "/"


@dataclass
class FileNode:
    """檔案系統節點（File/Directory）"""
    st_mode: int
    st_nlink: int
    st_size: int = 0
    st_ctime: float = field(default_factory=_current_timestamp)
    st_mtime: float = field(default_factory=_current_timestamp)
    st_atime: float = field(default_factory=_current_timestamp)
    child_entries: Set[str] = field(default_factory=set)  # 子項目集合

    # 加密相關屬性（檔案專用）
    kdf_salt: Optional[bytes] = None              # KDF 派生用 salt
    gcm_nonce: Optional[bytes] = None             # GCM 模式的 nonce
    encrypted_data: bytes = b""                   # 加密後內容
    derived_aes_key: Optional[bytes] = None       # 派生的 AES 金鑰（快取）


class EncryptedMemFS(LoggingMixIn, Operations):
    """
    記憶體加密檔案系統（In-Memory Encrypted FS）
    - 密碼透過 setxattr -n user.passphrase -v "pwd" <file> 提供
    - 金鑰透過 PBKDF2(passphrase, salt, iterations) 派生 -> 32 bytes
    - 資料使用 AESGCM(key, nonce) 加密
    """
    def __init__(self):
        self.filesystem_nodes: Dict[str, FileNode] = {}
        self.next_file_descriptor = 0

        # 建立根目錄
        root_node = FileNode(st_mode=(S_IFDIR | 0o755), st_nlink=2)
        self.filesystem_nodes["/"] = root_node

    # -------- 輔助方法 --------
    def _verify_path_exists(self, filepath: str) -> FileNode:
        """驗證路徑存在"""
        node = self.filesystem_nodes.get(filepath)
        if node is None:
            raise FuseOSError(errno.ENOENT)
        return node

    def _verify_is_file(self, filepath: str) -> FileNode:
        """驗證是一般檔案"""
        node = self._verify_path_exists(filepath)
        if (node.st_mode & S_IFDIR) == S_IFDIR:
            raise FuseOSError(errno.EISDIR)
        return node

    def _verify_is_directory(self, filepath: str) -> FileNode:
        """驗證是目錄"""
        node = self._verify_path_exists(filepath)
        if (node.st_mode & S_IFDIR) != S_IFDIR:
            raise FuseOSError(errno.ENOTDIR)
        return node

    def _update_timestamps(self, node: FileNode, *, access_time=False, modify_time=False):
        """更新時間戳記"""
        timestamp = _current_timestamp()
        if access_time:
            node.st_atime = timestamp
        if modify_time:
            node.st_mtime = timestamp

    def _perform_key_derivation(self, user_passphrase: bytes, salt_value: bytes, 
                                kdf_iterations: int = 200_000) -> bytes:
        """執行 PBKDF2 金鑰派生"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 需要 32 bytes
            salt=salt_value,
            iterations=kdf_iterations,
            backend=default_backend(),
        )
        return kdf.derive(user_passphrase)

    def _enforce_key_presence(self, node: FileNode):
        """強制檢查金鑰存在"""
        if node.derived_aes_key is None:
            raise FuseOSError(errno.EACCES)

    def _perform_encryption(self, node: FileNode, plaintext_data: bytes):
        """執行加密並更新節點"""
        self._enforce_key_presence(node)
        if node.gcm_nonce is None:
            # GCM 建議使用 12 bytes nonce
            node.gcm_nonce = os.urandom(12)
        
        aes_cipher = AESGCM(node.derived_aes_key)
        node.encrypted_data = aes_cipher.encrypt(node.gcm_nonce, plaintext_data, None)
        node.st_size = len(plaintext_data)
        self._update_timestamps(node, modify_time=True)

    def _perform_decryption(self, node: FileNode) -> bytes:
        """執行解密並回傳明文"""
        self._enforce_key_presence(node)
        if not node.encrypted_data:
            return b""
        if node.gcm_nonce is None:
            raise FuseOSError(errno.EACCES)
        
        try:
            aes_cipher = AESGCM(node.derived_aes_key)
            plaintext = aes_cipher.decrypt(node.gcm_nonce, node.encrypted_data, None)
            self._update_timestamps(node, access_time=True)
            return plaintext
        except Exception:
            # 金鑰錯誤或資料損毀
            raise FuseOSError(errno.EACCES)

    # -------- FUSE 操作實作 --------
    def getattr(self, path, fh=None):
        """取得檔案屬性"""
        node = self._verify_path_exists(path)
        attributes = {
            "st_mode": node.st_mode,
            "st_nlink": node.st_nlink,
            "st_size": node.st_size,
            "st_ctime": node.st_ctime,
            "st_mtime": node.st_mtime,
            "st_atime": node.st_atime,
            "st_uid": os.getuid(),
            "st_gid": os.getgid(),
        }
        return attributes

    def readdir(self, path, fh):
        """讀取目錄內容"""
        directory = self._verify_is_directory(path)
        dir_entries = [".", ".."]
        dir_entries.extend(sorted(directory.child_entries))
        return dir_entries

    def mkdir(self, path, mode):
        """建立目錄"""
        parent_path = _get_parent_path(path)
        dir_name = _extract_filename(path)
        parent_dir = self._verify_is_directory(parent_path)
        
        if path in self.filesystem_nodes:
            raise FuseOSError(errno.EEXIST)

        self.filesystem_nodes[path] = FileNode(st_mode=(S_IFDIR | mode), st_nlink=2)
        parent_dir.child_entries.add(dir_name)
        parent_dir.st_nlink += 1
        self._update_timestamps(parent_dir, modify_time=True)

    def rmdir(self, path):
        """刪除目錄"""
        if path == "/":
            raise FuseOSError(errno.EPERM)
        
        directory = self._verify_is_directory(path)
        if directory.child_entries:
            raise FuseOSError(errno.ENOTEMPTY)

        parent_path = _get_parent_path(path)
        dir_name = _extract_filename(path)
        parent_dir = self._verify_is_directory(parent_path)

        parent_dir.child_entries.discard(dir_name)
        parent_dir.st_nlink = max(2, parent_dir.st_nlink - 1)
        self._update_timestamps(parent_dir, modify_time=True)

        self.filesystem_nodes.pop(path, None)

    def create(self, path, mode, fi=None):
        """建立檔案"""
        parent_path = _get_parent_path(path)
        file_name = _extract_filename(path)
        parent_dir = self._verify_is_directory(parent_path)
        
        if path in self.filesystem_nodes:
            raise FuseOSError(errno.EEXIST)

        new_node = FileNode(st_mode=(S_IFREG | mode), st_nlink=1)
        # 為每個檔案產生專屬 salt（確保 per-file 金鑰）
        new_node.kdf_salt = os.urandom(16)
        self.filesystem_nodes[path] = new_node
        parent_dir.child_entries.add(file_name)
        self._update_timestamps(parent_dir, modify_time=True)

        self.next_file_descriptor += 1
        return self.next_file_descriptor

    def open(self, path, flags):
        """開啟檔案"""
        self._verify_path_exists(path)
        self.next_file_descriptor += 1
        return self.next_file_descriptor

    def unlink(self, path):
        """刪除檔案"""
        if path == "/":
            raise FuseOSError(errno.EPERM)
        
        node = self._verify_is_file(path)

        parent_path = _get_parent_path(path)
        file_name = _extract_filename(path)
        parent_dir = self._verify_is_directory(parent_path)

        parent_dir.child_entries.discard(file_name)
        self._update_timestamps(parent_dir, modify_time=True)

        # 移除節點並清除敏感資料
        self.filesystem_nodes.pop(path, None)
        node.derived_aes_key = None
        node.encrypted_data = b""

    def truncate(self, path, length, fh=None):
        """截斷檔案"""
        node = self._verify_is_file(path)
        self._enforce_key_presence(node)

        plaintext = self._perform_decryption(node)
        if length == 0:
            new_plaintext = b""
        else:
            new_plaintext = plaintext[:length].ljust(length, b"\x00")
        
        self._perform_encryption(node, new_plaintext)
        return 0

    def utimens(self, path, times=None):
        """更新檔案時間"""
        node = self._verify_path_exists(path)
        current_time = _current_timestamp()
        access_time, modify_time = times if times else (current_time, current_time)
        node.st_atime = access_time
        node.st_mtime = modify_time

    def read(self, path, size, offset, fh):
        """讀取檔案內容"""
        node = self._verify_is_file(path)
        plaintext = self._perform_decryption(node)
        return plaintext[offset: offset + size]

    def write(self, path, data, offset, fh):
        """寫入檔案內容"""
        node = self._verify_is_file(path)
        self._enforce_key_presence(node)

        plaintext = self._perform_decryption(node)
        if offset > len(plaintext):
            plaintext = plaintext + b"\x00" * (offset - len(plaintext))
        
        updated_plaintext = plaintext[:offset] + data + plaintext[offset + len(data):]
        self._perform_encryption(node, updated_plaintext)
        return len(data)

    # -------- 擴充屬性（用於密碼傳遞）--------
    def setxattr(self, path, name, value, options, position=0):
        """設定擴充屬性（處理密碼輸入）"""
        # setfattr -n user.passphrase -v "mypwd" <file>
        if name != "user.passphrase":
            return 0
        
        node = self._verify_is_file(path)

        if node.kdf_salt is None:
            node.kdf_salt = os.urandom(16)

        user_passphrase = bytes(value)
        node.derived_aes_key = self._perform_key_derivation(user_passphrase, node.kdf_salt)
        return 0

    def getxattr(self, path, name, position=0):
        """取得擴充屬性（避免洩漏資訊）"""
        return b""

    def listxattr(self, path):
        """列出擴充屬性"""
        return []

    def removexattr(self, path, name):
        """移除擴充屬性"""
        if name == "user.passphrase":
            node = self._verify_is_file(path)
            node.derived_aes_key = None
        return 0


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <mountpoint>")
        sys.exit(1)
    
    mountpoint = sys.argv[1]
    FUSE(EncryptedMemFS(), mountpoint, foreground=True, nothreads=True)


if __name__ == "__main__":
    main()
