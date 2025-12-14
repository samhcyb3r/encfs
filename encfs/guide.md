#!/usr/bin/env python3
# ============================================================================
# 基於 FUSE 的加密記憶體檔案系統（AES-256-GCM，每檔案獨立金鑰，per-PID keyring）
# 強化版本：支援 rename 安全的 AAD（file-id），向後相容，以及額外功能
#
# 執行方式：
#   mkdir -p /tmp/mnt
#   python3 encrypted_memfs.py /tmp/mnt -f
#
# 金鑰供應（透過特殊控制檔案的 per-PID keyring）：
#   echo 'ADD /hello.txt 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' > /tmp/mnt/.keyring
#   echo hi > /tmp/mnt/hello.txt
# ============================================================================

from __future__ import annotations

import errno          # 錯誤代碼常數
import logging        # 日誌記錄
import os            # 作業系統介面
import stat          # 檔案狀態常數
import time          # 時間函式
import threading     # 執行緒鎖
from collections import defaultdict  # 預設字典
from dataclasses import dataclass, field  # 資料類別
from typing import Dict, Optional  # 型別提示

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context

from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # 金鑰衍生函式
from cryptography.hazmat.primitives import hashes          # 雜湊演算法
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM 加密
import secrets  # 安全隨機數生成


# ============================================================================
# 工具函式區
# ============================================================================

def now() -> float:
    """取得當前時間戳記（浮點數秒數）"""
    return time.time()

def is_dir(mode: int) -> bool:
    """檢查 mode 是否為目錄類型"""
    return stat.S_ISDIR(mode)

def is_file(mode: int) -> bool:
    """檢查 mode 是否為一般檔案類型"""
    return stat.S_ISREG(mode)

def hkdf_derive(file_salt: bytes, user_key: bytes) -> bytes:
    """
    使用 HKDF (HMAC-based Key Derivation Function) 從使用者金鑰衍生檔案專用金鑰
    
    參數：
        file_salt: 每個檔案獨特的隨機鹽值（16 bytes）
        user_key: 使用者提供的主金鑰（32 bytes）
    
    返回：
        衍生出的 AES-256 金鑰（32 bytes）
    
    說明：
        即使使用相同的主金鑰，不同檔案因有不同的 salt，
        會衍生出完全不同的加密金鑰，提升安全性
    """
    return HKDF(
        algorithm=hashes.SHA256(),      # 使用 SHA-256 雜湊
        length=32,                       # 輸出 32 bytes (AES-256)
        salt=file_salt,                  # 每檔案唯一的鹽值
        info=b"encrypted-memfs-v1",     # 應用程式資訊字串
    ).derive(user_key)


# ============================================================================
# 記憶體節點資料結構
# ============================================================================

@dataclass
class FileNode:
    """
    代表檔案系統中的一個節點（檔案或目錄）
    所有資料都儲存在記憶體中，不寫入磁碟
    """
    mode: int                               # 檔案類型與權限（例如：0o100600）
    nlink: int = 1                          # 硬連結數量
    uid: int = os.getuid()                  # 擁有者 UID
    gid: int = os.getgid()                  # 群組 GID
    size: int = 0                           # 明文大小（bytes）
    atime: float = field(default_factory=now)  # 最後存取時間
    mtime: float = field(default_factory=now)  # 最後修改時間
    ctime: float = field(default_factory=now)  # 狀態改變時間
    
    # === 一般檔案專用欄位 ===
    cipher: bytes = b""                     # 加密後的內容
    header: Dict[str, bytes] = field(default_factory=dict)  
    # header 包含：
    #   - "salt": 用於 HKDF 的隨機鹽值（16 bytes）
    #   - "nonce": AES-GCM 的 nonce（12 bytes）
    #   - "fid": 檔案唯一識別碼（16 bytes），用作 AAD
    
    # === 目錄專用欄位 ===
    children: set = field(default_factory=set)  # 子項目名稱集合


@dataclass
class Handle:
    """
    代表一個已開啟檔案的 handle（檔案描述符）
    當檔案被 open() 時建立，release() 時銷毀
    """
    path: str                    # 檔案路徑
    flags: int                   # 開啟旗標（O_RDONLY, O_WRONLY, O_APPEND 等）
    plaintext: bytearray         # 解密後的明文緩衝區（可修改）
    key_used: Optional[bytes]    # 用於此檔案的使用者金鑰（32 bytes）
    append: bool                 # 是否為 append 模式（O_APPEND）


# ============================================================================
# 加密記憶體檔案系統主類別
# ============================================================================

class EncryptedMemFS(LoggingMixIn, Operations):
    """
    基於 FUSE 的記憶體加密檔案系統
    
    特色：
    - 所有檔案內容使用 AES-256-GCM 加密
    - 每個檔案使用獨立的 salt 衍生不同的加密金鑰
    - 透過 /.keyring 控制檔案管理每個 PID 的金鑰
    - 使用檔案 ID (fid) 作為 AAD，確保 rename 後仍能正確解密
    - 向後相容舊版本（path-based AAD）
    """
    
    # 預設權限設定
    DEFAULT_FILE_PERM = 0o600   # 檔案預設權限：擁有者可讀寫
    DEFAULT_DIR_PERM  = 0o755   # 目錄預設權限：擁有者全權限，其他人可讀執行

    def __init__(self):
        """初始化檔案系統"""
        # 檔案系統主要資料結構
        self.files: Dict[str, FileNode] = {}        # 路徑 -> FileNode 映射
        self.parent: Dict[str, str] = {}            # 子路徑 -> 父路徑映射
        self.handles: Dict[int, Handle] = {}        # 檔案描述符 -> Handle 映射
        self._fh_next = 3                           # 下一個可用的檔案描述符（從 3 開始）
        
        # 金鑰管理：PID -> {路徑 -> 金鑰} 的雙層映射
        # 每個 process 有自己獨立的 keyring
        self.keyring: Dict[int, Dict[str, bytes]] = defaultdict(dict)
        
        # 執行緒鎖，確保多執行緒安全
        self._lock = threading.RLock()

        # 建立根目錄和金鑰控制檔案
        self._mkroot()
        self._mkkeyring()

    # ========================================================================
    # 生命週期管理
    # ========================================================================

    def destroy(self, path):
        """
        檔案系統卸載時的清理工作
        安全地清除所有敏感資料
        """
        with self._lock:
            # 清空所有明文緩衝區（避免記憶體殘留）
            for h in list(self.handles.values()):
                self._secure_zero(h.plaintext)
            self.handles.clear()
            
            # 清空所有金鑰
            self.keyring.clear()
            
            # 清空加密內容（最佳努力）
            for node in self.files.values():
                node.cipher = b""

    # ========================================================================
    # 內部輔助函式
    # ========================================================================

    def _mkroot(self):
        """建立根目錄 /"""
        root = FileNode(
            mode=(stat.S_IFDIR | self.DEFAULT_DIR_PERM),  # 目錄類型 + 預設權限
            nlink=2  # . 和 .. 兩個連結
        )
        self.files["/"] = root

    def _mkkeyring(self):
        """建立特殊控制檔案 /.keyring 用於金鑰管理"""
        node = FileNode(mode=(stat.S_IFREG | 0o600))  # 一般檔案，僅擁有者可讀寫
        self.files["/.keyring"] = node
        self.files["/"].children.add(".keyring")
        self.parent["/.keyring"] = "/"

    def _lookup(self, path: str) -> FileNode:
        """
        查找路徑對應的節點
        若不存在則拋出 ENOENT 錯誤
        """
        if path not in self.files:
            raise FuseOSError(errno.ENOENT)  # No such file or directory
        return self.files[path]

    def _must_exist_dir(self, path: str):
        """
        確認路徑存在且為目錄
        否則拋出 ENOENT 錯誤
        """
        if path not in self.files or not is_dir(self.files[path].mode):
            raise FuseOSError(errno.ENOENT)

    def _add_child(self, parent_path: str, name: str, node: FileNode, full_path: str):
        """
        將子節點加入父目錄
        
        參數：
            parent_path: 父目錄路徑
            name: 子項目名稱（不含路徑）
            node: 子節點物件
            full_path: 子項目完整路徑
        """
        self.files[full_path] = node
        self.parent[full_path] = parent_path
        self.files[parent_path].children.add(name)

    def _unlink_child(self, path: str):
        """
        從父目錄移除子節點並刪除節點本身
        """
        par = self.parent.get(path, "/")
        name = os.path.basename(path)
        if par in self.files:
            self.files[par].children.discard(name)
        self.parent.pop(path, None)
        self.files.pop(path, None)

    def _alloc_fh(self, path: str, flags: int, plaintext: bytes, 
                  key_used: Optional[bytes]) -> int:
        """
        分配一個新的檔案描述符（file handle）
        
        返回：
            整數檔案描述符
        """
        fh = self._fh_next
        self._fh_next += 1
        append = bool(flags & os.O_APPEND)  # 檢查是否為 append 模式
        self.handles[fh] = Handle(
            path=path, 
            flags=flags, 
            plaintext=bytearray(plaintext), 
            key_used=key_used, 
            append=append
        )
        return fh

    def _aad_for_node(self, node: FileNode, path: str) -> bytes:
        """
        取得用於 AES-GCM 的 AAD (Additional Authenticated Data)
        
        優先使用固定的檔案 ID (fid)，若不存在則回退到路徑
        
        說明：
            使用 fid 作為 AAD 可確保檔案 rename 後仍能正確解密
            因為 fid 不會隨路徑改變而改變
        
        返回：
            AAD bytes
        """
        fid = node.header.get("fid")
        return fid if fid else path.encode()

    def _encrypt_and_store(self, path: str, plaintext: bytearray, user_key: bytes):
        """
        加密明文並儲存到節點
        
        流程：
            1. 確保有 salt 和 fid（若無則生成）
            2. 生成新的 nonce
            3. 使用 HKDF 從 user_key 和 salt 衍生 AES 金鑰
            4. 使用 AES-GCM 加密，AAD 為 fid
            5. 更新節點的 cipher、nonce、size、時間戳記
        """
        node = self._lookup(path)
        
        # 確保有 salt（用於 HKDF）
        if not node.header.get("salt"):
            node.header["salt"] = secrets.token_bytes(16)
        
        # 確保有 fid（用於 AAD），舊檔案可能沒有
        if not node.header.get("fid"):
            node.header["fid"] = secrets.token_bytes(16)

        # 生成新的 nonce（每次加密都要不同）
        nonce = secrets.token_bytes(12)
        
        # 衍生 AES 金鑰
        aes_key = hkdf_derive(node.header["salt"], user_key)
        aes = AESGCM(aes_key)
        
        # 加密：使用 fid 作為 AAD
        aad = self._aad_for_node(node, path)
        cipher = aes.encrypt(nonce, bytes(plaintext), associated_data=aad)
        
        # 更新節點
        node.cipher = cipher
        node.header["nonce"] = nonce
        node.size = len(plaintext)
        t = now()
        node.mtime = t
        node.ctime = t

    @staticmethod
    def _secure_zero(buf: bytearray):
        """
        安全地清空 bytearray 內容
        避免敏感資料殘留在記憶體中
        """
        for i in range(len(buf)):
            buf[i] = 0

    # ========================================================================
    # FUSE 操作實作 - 屬性與狀態
    # ========================================================================

    def getattr(self, path, fh=None):
        """
        取得檔案/目錄屬性（stat）
        
        返回：
            包含 st_mode, st_size, st_atime 等欄位的字典
        """
        with self._lock:
            node = self._lookup(path)
            return {
                "st_mode": node.mode,
                "st_nlink": node.nlink,
                "st_uid": node.uid,
                "st_gid": node.gid,
                "st_size": node.size if is_file(node.mode) else 0,
                "st_atime": node.atime,
                "st_mtime": node.mtime,
                "st_ctime": node.ctime,
            }

    def statfs(self, path):
        """
        取得檔案系統統計資訊
        
        返回：
            包含區塊大小、總區塊數、可用區塊數等資訊
        """
        block_size = 4096
        total_blocks = 1024 * 1024   # 約 4GB 邏輯空間
        with self._lock:
            # 計算已使用的空間
            used = sum(n.size for n in self.files.values() if is_file(n.mode))
        return {
            "f_bsize": block_size,
            "f_frsize": block_size,
            "f_blocks": total_blocks,
            "f_bfree": max(0, total_blocks - used // block_size - 1),
            "f_bavail": max(0, total_blocks - used // block_size - 1),
            "f_files": len(self.files),
            "f_ffree": 1_000_000,
        }

    def access(self, path, mode):
        """
        檢查檔案存取權限
        
        參數：
            path: 檔案路徑
            mode: 要檢查的權限（R_OK, W_OK, X_OK）
        """
        with self._lock:
            if path not in self.files:
                raise FuseOSError(errno.ENOENT)
            node = self.files[path]
            # 簡化的權限檢查（僅檢查擁有者權限）
            if mode & os.R_OK and not (node.mode & stat.S_IRUSR):
                raise FuseOSError(errno.EACCES)
            if mode & os.W_OK and not (node.mode & stat.S_IWUSR):
                raise FuseOSError(errno.EACCES)
            if mode & os.X_OK and not (node.mode & stat.S_IXUSR):
                raise FuseOSError(errno.EACCES)
        return 0

    def readdir(self, path, fh):
        """
        讀取目錄內容（ls 指令會呼叫）
        
        產生：
            目錄中的每個項目名稱
        """
        with self._lock:
            node = self._lookup(path)
            if not is_dir(node.mode):
                raise FuseOSError(errno.ENOTDIR)
            # 返回 . 和 .. 以及所有子項目
            entries = [".", ".."] + sorted(node.children)
            for e in entries:
                yield e

    # ========================================================================
    # FUSE 操作實作 - 節點建立與刪除
    # ========================================================================

    def mkdir(self, path, mode):
        """
        建立目錄
        
        參數：
            path: 要建立的目錄路徑
            mode: 目錄權限
        """
        with self._lock:
            parent = os.path.dirname(path) or "/"
            name = os.path.basename(path)
            self._must_exist_dir(parent)
            
            # 檢查是否已存在
            if name in self.files[parent].children:
                raise FuseOSError(errno.EEXIST)
            
            # 建立新目錄節點
            node = FileNode(
                mode=(stat.S_IFDIR | ((mode & 0o7777) or self.DEFAULT_DIR_PERM)), 
                nlink=2
            )
            node.children = set()
            self._add_child(parent, name, node, path)
            self.files[parent].nlink += 1  # 父目錄的 nlink 增加
        return 0

    def rmdir(self, path):
        """
        刪除目錄（必須為空）
        """
        with self._lock:
            node = self._lookup(path)
            if not is_dir(node.mode):
                raise FuseOSError(errno.ENOTDIR)
            if node.children:
                raise FuseOSError(errno.ENOTEMPTY)  # 目錄非空
            
            parent = self.parent.get(path, "/")
            self._unlink_child(path)
            if parent in self.files:
                self.files[parent].nlink = max(2, self.files[parent].nlink - 1)
        return 0

    def create(self, path, mode, fi=None):
        """
        建立新檔案
        
        返回：
            檔案描述符
        """
        with self._lock:
            parent = os.path.dirname(path) or "/"
            name = os.path.basename(path)
            self._must_exist_dir(parent)
            
            # 檢查是否已存在
            if name in self.files[parent].children:
                raise FuseOSError(errno.EEXIST)
            
            # 建立新檔案節點
            node = FileNode(
                mode=(stat.S_IFREG | ((mode & 0o7777) or self.DEFAULT_FILE_PERM))
            )
            # 初始化加密標頭
            node.header = {
                "salt": secrets.token_bytes(16),   # HKDF 鹽值
                "nonce": secrets.token_bytes(12),  # AES-GCM nonce
                "fid":  secrets.token_bytes(16),   # 檔案 ID（用於 AAD）
            }
            node.cipher = b""
            node.size = 0
            self._add_child(parent, name, node, path)
            
            # 返回一個空的 handle（create 時不需要金鑰）
            fh = self._alloc_fh(path, flags=0, plaintext=b"", key_used=None)
        return fh

    def unlink(self, path):
        """刪除檔案"""
        with self._lock:
            node = self._lookup(path)
            if is_dir(node.mode):
                raise FuseOSError(errno.EISDIR)  # 是目錄，應使用 rmdir
            self._unlink_child(path)
        return 0

    def rename(self, old, new):
        """
        重新命名或移動檔案/目錄
        
        重要：
            因為使用 fid 作為 AAD，rename 不會影響加密內容的可解密性
            這是本系統的關鍵設計
        """
        with self._lock:
            # 禁止 rename .keyring
            if old == "/.keyring" or new == "/.keyring":
                raise FuseOSError(errno.EPERM)
            
            node = self._lookup(old)
            old_parent = self.parent.get(old, "/")
            new_parent = os.path.dirname(new) or "/"
            new_name = os.path.basename(new)
            self._must_exist_dir(new_parent)
            
            # 檢查目標是否已存在
            if new_name in self.files[new_parent].children:
                raise FuseOSError(errno.EEXIST)
            
            # 移動連結
            self.files[new_parent].children.add(new_name)
            self.files[old_parent].children.discard(os.path.basename(old))
            self.parent[new] = new_parent
            self.files[new] = node
            
            # 移除舊索引
            self.parent.pop(old, None)
            self.files.pop(old, None)
        return 0

    # ========================================================================
    # FUSE 操作實作 - 權限與中繼資料
    # ========================================================================

    def chmod(self, path, mode):
        """改變檔案權限"""
        with self._lock:
            node = self._lookup(path)
            node.mode = (node.mode & ~0o7777) | (mode & 0o7777)
            node.ctime = now()
        return 0

    def chown(self, path, uid, gid):
        """改變檔案擁有者"""
        with self._lock:
            node = self._lookup(path)
            if uid != -1:
                node.uid = uid
            if gid != -1:
                node.gid = gid
            node.ctime = now()
        return 0

    def utimens(self, path, times=None):
        """更新檔案存取和修改時間"""
        with self._lock:
            node = self._lookup(path)
            at, mt = times if times else (now(), now())
            node.atime, node.mtime = at, mt
        return 0

    # ========================================================================
    # FUSE 操作實作 - 檔案開啟/讀取/寫入
    # ========================================================================

    def open(self, path, flags):
        """
        開啟檔案
        
        流程：
            1. 檢查是否為 .keyring（特殊處理）
            2. 從當前 PID 的 keyring 取得此檔案的金鑰
            3. 若無金鑰則拒絕存取
            4. 解密檔案內容到 plaintext buffer
            5. 處理 O_TRUNC 旗標（清空內容）
            6. 返回檔案描述符
        
        返回：
            檔案描述符
        """
        with self._lock:
            # .keyring 特殊處理
            if path == "/.keyring":
                return self._alloc_fh(path, flags, b"", key_used=None)

            # 取得當前 process 的 PID
            pid, _, _ = fuse_get_context()
            user_key = self.keyring.get(pid, {}).get(path)
            
            # 若無金鑰則拒絕存取
            if not user_key:
                raise FuseOSError(errno.EACCES)

            node = self._lookup(path)
            if not is_file(node.mode):
                raise FuseOSError(errno.EISDIR)

            plaintext = b""
            if node.cipher:
                # 解密流程
                salt = node.header["salt"]
                nonce = node.header["nonce"]
                aes_key = hkdf_derive(salt, user_key)
                aes = AESGCM(aes_key)

                # 先嘗試使用 fid AAD 解密（新格式）
                try:
                    aad = self._aad_for_node(node, path)
                    plaintext = aes.decrypt(nonce, node.cipher, associated_data=aad)
                except Exception:
                    # 向後相容：嘗試使用舊的 path AAD
                    try:
                        plaintext = aes.decrypt(nonce, node.cipher, 
                                               associated_data=path.encode())
                        # 成功解密後立即升級到 fid 格式
                        self._encrypt_and_store(path, bytearray(plaintext), user_key)
                    except Exception:
                        raise FuseOSError(errno.EKEYREJECTED)  # 金鑰錯誤

            # 處理 O_TRUNC：清空檔案內容
            if flags & os.O_TRUNC:
                plaintext = b""
                node.size = 0
                node.mtime = now()

            fh = self._alloc_fh(path, flags, plaintext, key_used=user_key)
        return fh

    def read(self, path, size, offset, fh):
        """
        讀取檔案內容
        
        參數：
            path: 檔案路徑
            size: 要讀取的 bytes 數
            offset: 開始讀取的位置
            fh: 檔案描述符
        
        返回：
            讀取的 bytes
        """
        with self._lock:
            h = self.handles[fh]
            
            # .keyring 特殊處理：顯示當前 PID 的 keyring 內容
            if path == "/.keyring":
                pid, _, _ = fuse_get_context()
                entries = sorted(list(self.keyring.get(pid, {}).keys()))
                data = ("# per-PID keyring entries (PID: %d)\n" % pid).encode()
                for p in entries:
                    data += ("- %s\n" % p).encode()
                return data[offset: offset + size]
            
            # 一般檔案：從 plaintext buffer 讀取
            buf = h.plaintext
            return bytes(buf[offset: offset + size])

    def write(self, path, data, offset, fh):
        """
        寫入檔案內容
        
        參數：
            path: 檔案路徑
            data: 要寫入的 bytes
            offset: 寫入的起始位置
            fh: 檔案描述符
        
        返回：
            實際寫入的 bytes 數
        """
        with self._lock:
            # .keyring 特殊處理：解析金鑰管理指令
            if path == "/.keyring":
                self._keyring_write(data)
                node = self._lookup(path)
                node.size = len(data)
                node.mtime = now()
                return len(data)

            h = self.handles[fh]
            
            # O_APPEND 語意：從檔案末端寫入
            if h.append:
                offset = len(h.plaintext)

            # 擴展 buffer 若需要
            end = offset + len(data)
            if en
