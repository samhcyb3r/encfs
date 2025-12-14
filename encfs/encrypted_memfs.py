#!/usr/bin/env python3
# Encrypted In-Memory FS on FUSE (AES-256-GCM, per-file key via per-PID keyring)
# Robust edition with rename-safe AAD (file-id), backward compatibility, and extras.
#
# Run:
#   mkdir -p /tmp/mnt
#   python3 encrypted_memfs.py /tmp/mnt -f
#
# Key supply (per-PID keyring via special control file):
#   echo 'ADD /hello.txt 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' > /tmp/mnt/.keyring
#   echo hi > /tmp/mnt/hello.txt
from __future__ import annotations

import errno
import logging
import os
import stat
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets


# ---------------- Utilities ----------------

def now() -> float:
    return time.time()

def is_dir(mode: int) -> bool:
    return stat.S_ISDIR(mode)

def is_file(mode: int) -> bool:
    return stat.S_ISREG(mode)

def hkdf_derive(file_salt: bytes, user_key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=file_salt,
        info=b"encrypted-memfs-v1",
    ).derive(user_key)


# ---------------- In-memory nodes ----------------

@dataclass
class FileNode:
    mode: int
    nlink: int = 1
    uid: int = os.getuid()
    gid: int = os.getgid()
    size: int = 0                       # plaintext size
    atime: float = field(default_factory=now)
    mtime: float = field(default_factory=now)
    ctime: float = field(default_factory=now)
    # Regular files: encrypted blob + header
    # header keys: {"salt": bytes, "nonce": bytes, "fid": bytes}
    cipher: bytes = b""
    header: Dict[str, bytes] = field(default_factory=dict)
    # Directories: children names
    children: set = field(default_factory=set)

@dataclass
class Handle:
    path: str
    flags: int
    plaintext: bytearray                # decrypted buffer
    key_used: Optional[bytes]           # user-supplied 32-byte key (raw)
    append: bool                        # O_APPEND


# ---------------- Filesystem ----------------

class EncryptedMemFS(LoggingMixIn, Operations):
    """
    In-memory encrypted FS with per-file salt(HKDF) and AES-256-GCM.
    Keys are held per-PID in a keyring, provided via /.keyring control file.
    Uses a path-independent file-id (fid) as AAD so rename won't break decryption.
    Backward compatible: if an old ciphertext was AAD=path, we migrate to fid on first open.
    """
    DEFAULT_FILE_PERM = 0o600
    DEFAULT_DIR_PERM  = 0o755

    def __init__(self):
        self.files: Dict[str, FileNode] = {}
        self.parent: Dict[str, str] = {}
        self.handles: Dict[int, Handle] = {}
        self._fh_next = 3
        self.keyring: Dict[int, Dict[str, bytes]] = defaultdict(dict)
        self._lock = threading.RLock()

        self._mkroot()
        self._mkkeyring()

    # ---------- lifecycle ----------

    def destroy(self, path):
        with self._lock:
            # wipe plaintext buffers
            for h in list(self.handles.values()):
                self._secure_zero(h.plaintext)
            self.handles.clear()
            # wipe keyrings
            self.keyring.clear()
            # clear encrypted blobs (best effort)
            for node in self.files.values():
                node.cipher = b""

    # ---------- helpers ----------

    def _mkroot(self):
        root = FileNode(mode=(stat.S_IFDIR | self.DEFAULT_DIR_PERM), nlink=2)
        self.files["/"] = root

    def _mkkeyring(self):
        node = FileNode(mode=(stat.S_IFREG | 0o600))
        self.files["/.keyring"] = node
        self.files["/"].children.add(".keyring")
        self.parent["/.keyring"] = "/"

    def _lookup(self, path: str) -> FileNode:
        if path not in self.files:
            raise FuseOSError(errno.ENOENT)
        return self.files[path]

    def _must_exist_dir(self, path: str):
        if path not in self.files or not is_dir(self.files[path].mode):
            raise FuseOSError(errno.ENOENT)

    def _add_child(self, parent_path: str, name: str, node: FileNode, full_path: str):
        self.files[full_path] = node
        self.parent[full_path] = parent_path
        self.files[parent_path].children.add(name)

    def _unlink_child(self, path: str):
        par = self.parent.get(path, "/")
        name = os.path.basename(path)
        if par in self.files:
            self.files[par].children.discard(name)
        self.parent.pop(path, None)
        self.files.pop(path, None)

    def _alloc_fh(self, path: str, flags: int, plaintext: bytes, key_used: Optional[bytes]) -> int:
        fh = self._fh_next
        self._fh_next += 1
        append = bool(flags & os.O_APPEND)
        self.handles[fh] = Handle(path=path, flags=flags, plaintext=bytearray(plaintext), key_used=key_used, append=append)
        return fh

    def _aad_for_node(self, node: FileNode, path: str) -> bytes:
        """
        Prefer a stable, path-independent file-id (fid). If missing (old file), fall back to path.
        """
        fid = node.header.get("fid")
        return fid if fid else path.encode()

    def _encrypt_and_store(self, path: str, plaintext: bytearray, user_key: bytes):
        node = self._lookup(path)
        if not node.header.get("salt"):
            node.header["salt"] = secrets.token_bytes(16)
        if not node.header.get("fid"):
            node.header["fid"] = secrets.token_bytes(16)   # add fid for old files

        nonce = secrets.token_bytes(12)
        aes_key = hkdf_derive(node.header["salt"], user_key)
        aes = AESGCM(aes_key)
        aad = self._aad_for_node(node, path)
        cipher = aes.encrypt(nonce, bytes(plaintext), associated_data=aad)
        node.cipher = cipher
        node.header["nonce"] = nonce
        node.size = len(plaintext)
        t = now()
        node.mtime = t
        node.ctime = t

    @staticmethod
    def _secure_zero(buf: bytearray):
        for i in range(len(buf)):
            buf[i] = 0

    # ---------- FUSE ops ----------

    # Attributes / stat
    def getattr(self, path, fh=None):
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
        block_size = 4096
        total_blocks = 1024 * 1024   # ~4GB logical
        with self._lock:
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
        with self._lock:
            if path not in self.files:
                raise FuseOSError(errno.ENOENT)
            node = self.files[path]
            if mode & os.R_OK and not (node.mode & stat.S_IRUSR):
                raise FuseOSError(errno.EACCES)
            if mode & os.W_OK and not (node.mode & stat.S_IWUSR):
                raise FuseOSError(errno.EACCES)
            if mode & os.X_OK and not (node.mode & stat.S_IXUSR):
                raise FuseOSError(errno.EACCES)
        return 0

    def readdir(self, path, fh):
        with self._lock:
            node = self._lookup(path)
            if not is_dir(node.mode):
                raise FuseOSError(errno.ENOTDIR)
            entries = [".", ".."] + sorted(node.children)
            for e in entries:
                yield e

    # Node creation / removal
    def mkdir(self, path, mode):
        with self._lock:
            parent = os.path.dirname(path) or "/"
            name = os.path.basename(path)
            self._must_exist_dir(parent)
            if name in self.files[parent].children:
                raise FuseOSError(errno.EEXIST)
            node = FileNode(mode=(stat.S_IFDIR | ((mode & 0o7777) or self.DEFAULT_DIR_PERM)), nlink=2)
            node.children = set()
            self._add_child(parent, name, node, path)
            self.files[parent].nlink += 1
        return 0

    def rmdir(self, path):
        with self._lock:
            node = self._lookup(path)
            if not is_dir(node.mode):
                raise FuseOSError(errno.ENOTDIR)
            if node.children:
                raise FuseOSError(errno.ENOTEMPTY)
            parent = self.parent.get(path, "/")
            self._unlink_child(path)
            if parent in self.files:
                self.files[parent].nlink = max(2, self.files[parent].nlink - 1)
        return 0

    def create(self, path, mode, fi=None):
        with self._lock:
            parent = os.path.dirname(path) or "/"
            name = os.path.basename(path)
            self._must_exist_dir(parent)
            if name in self.files[parent].children:
                raise FuseOSError(errno.EEXIST)
            node = FileNode(mode=(stat.S_IFREG | ((mode & 0o7777) or self.DEFAULT_FILE_PERM)))
            node.header = {
                "salt": secrets.token_bytes(16),
                "nonce": secrets.token_bytes(12),
                "fid":  secrets.token_bytes(16),   # stable AAD
            }
            node.cipher = b""
            node.size = 0
            self._add_child(parent, name, node, path)
            # return a handle with empty plaintext; key not required for create()
            fh = self._alloc_fh(path, flags=0, plaintext=b"", key_used=None)
        return fh

    def unlink(self, path):
        with self._lock:
            node = self._lookup(path)
            if is_dir(node.mode):
                raise FuseOSError(errno.EISDIR)
            self._unlink_child(path)
        return 0

    def rename(self, old, new):
        with self._lock:
            if old == "/.keyring" or new == "/.keyring":
                raise FuseOSError(errno.EPERM)
            node = self._lookup(old)
            old_parent = self.parent.get(old, "/")
            new_parent = os.path.dirname(new) or "/"
            new_name = os.path.basename(new)
            self._must_exist_dir(new_parent)
            if new_name in self.files[new_parent].children:
                raise FuseOSError(errno.EEXIST)
            # Move link
            self.files[new_parent].children.add(new_name)
            self.files[old_parent].children.discard(os.path.basename(old))
            self.parent[new] = new_parent
            self.files[new] = node
            # Remove old index
            self.parent.pop(old, None)
            self.files.pop(old, None)
        return 0

    # Permissions / metadata
    def chmod(self, path, mode):
        with self._lock:
            node = self._lookup(path)
            node.mode = (node.mode & ~0o7777) | (mode & 0o7777)
            node.ctime = now()
        return 0

    def chown(self, path, uid, gid):
        with self._lock:
            node = self._lookup(path)
            if uid != -1:
                node.uid = uid
            if gid != -1:
                node.gid = gid
            node.ctime = now()
        return 0

    def utimens(self, path, times=None):
        with self._lock:
            node = self._lookup(path)
            at, mt = times if times else (now(), now())
            node.atime, node.mtime = at, mt
        return 0

    # Open/Read/Write
    def open(self, path, flags):
        with self._lock:
            if path == "/.keyring":
                return self._alloc_fh(path, flags, b"", key_used=None)

            # Require per-PID key
            pid, _, _ = fuse_get_context()
            user_key = self.keyring.get(pid, {}).get(path)
            if not user_key:
                raise FuseOSError(errno.EACCES)

            node = self._lookup(path)
            if not is_file(node.mode):
                raise FuseOSError(errno.EISDIR)

            plaintext = b""
            if node.cipher:
                salt = node.header["salt"]
                nonce = node.header["nonce"]
                aes_key = hkdf_derive(salt, user_key)
                aes = AESGCM(aes_key)

                # Try decrypt with fid AAD (new format)
                try:
                    aad = self._aad_for_node(node, path)
                    plaintext = aes.decrypt(nonce, node.cipher, associated_data=aad)
                except Exception:
                    # Backward-compat: try old AAD=path; if success, re-encrypt to fid format
                    try:
                        plaintext = aes.decrypt(nonce, node.cipher, associated_data=path.encode())
                        # migrate to fid immediately
                        self._encrypt_and_store(path, bytearray(plaintext), user_key)
                    except Exception:
                        raise FuseOSError(errno.EKEYREJECTED)

            # O_TRUNC handling
            if flags & os.O_TRUNC:
                plaintext = b""
                node.size = 0
                node.mtime = now()

            fh = self._alloc_fh(path, flags, plaintext, key_used=user_key)
        return fh

    def read(self, path, size, offset, fh):
        with self._lock:
            h = self.handles[fh]
            if path == "/.keyring":
                pid, _, _ = fuse_get_context()
                entries = sorted(list(self.keyring.get(pid, {}).keys()))
                data = ("# per-PID keyring entries (PID: %d)\n" % pid).encode()
                for p in entries:
                    data += ("- %s\n" % p).encode()
                return data[offset: offset + size]
            buf = h.plaintext
            return bytes(buf[offset: offset + size])

    def write(self, path, data, offset, fh):
        with self._lock:
            if path == "/.keyring":
                self._keyring_write(data)
                node = self._lookup(path)
                node.size = len(data)
                node.mtime = now()
                return len(data)

            h = self.handles[fh]
            # O_APPEND semantics
            if h.append:
                offset = len(h.plaintext)

            end = offset + len(data)
            if end > len(h.plaintext):
                h.plaintext.extend(b"\x00" * (end - len(h.plaintext)))
            h.plaintext[offset:end] = data

            node = self._lookup(path)
            node.size = max(node.size, end)
            t = now()
            node.mtime = t
            node.atime = t
            return len(data)

    def truncate(self, path, length, fh=None):
        with self._lock:
            if path == "/.keyring":
                node = self._lookup(path)
                node.size = length
                node.mtime = now()
                return 0

            if fh is not None and fh in self.handles:
                h = self.handles[fh]
                if length < len(h.plaintext):
                    del h.plaintext[length:]
                else:
                    h.plaintext.extend(b"\x00" * (length - len(h.plaintext)))
                node = self._lookup(path)
                node.size = length
                node.mtime = now()
                return 0

            # No handle: require key to decrypt then re-encrypt truncated content
            pid, _, _ = fuse_get_context()
            user_key = self.keyring.get(pid, {}).get(path)
            if not user_key:
                raise FuseOSError(errno.EACCES)

            node = self._lookup(path)
            plaintext = b""
            if node.cipher:
                try:
                    aes_key = hkdf_derive(node.header["salt"], user_key)
                    aes = AESGCM(aes_key)
                    aad = self._aad_for_node(node, path)
                    plaintext = aes.decrypt(node.header["nonce"], node.cipher, associated_data=aad)
                except Exception:
                    # old AAD=path fallback
                    try:
                        plaintext = aes.decrypt(node.header["nonce"], node.cipher, associated_data=path.encode())
                    except Exception:
                        raise FuseOSError(errno.EKEYREJECTED)

            buf = bytearray(plaintext)
            if length < len(buf):
                del buf[length:]
            else:
                buf.extend(b"\x00" * (length - len(buf)))

            self._encrypt_and_store(path, buf, user_key)
        return 0

    def flush(self, path, fh):
        return 0

    def fsync(self, path, datasync, fh):
        return 0

    def release(self, path, fh):
        with self._lock:
            h = self.handles.pop(fh, None)
            if h is None:
                return 0
            if path == "/.keyring":
                return 0
            if h.key_used is None:
                raise FuseOSError(errno.EACCES)
            try:
                self._encrypt_and_store(path, h.plaintext, h.key_used)
            finally:
                self._secure_zero(h.plaintext)
        return 0

    # ---------- Keyring control via /.keyring ----------

    def _keyring_write(self, data: bytes):
        """
        Lines:
           ADD <path> <hex64>
           DEL <path>
        """
        pid, _, _ = fuse_get_context()
        text = data.decode(errors="ignore")
        for line in text.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            cmd = parts[0].upper()
            if cmd == "ADD" and len(parts) == 3:
                path, hexkey = parts[1], parts[2]
                try:
                    key = bytes.fromhex(hexkey)
                except Exception:
                    raise FuseOSError(errno.EINVAL)
                if len(key) != 32:
                    raise FuseOSError(errno.EINVAL)
                self.keyring[pid][path] = key
            elif cmd == "DEL" and len(parts) == 2:
                path = parts[1]
                self.keyring.get(pid, {}).pop(path, None)
            else:
                raise FuseOSError(errno.EINVAL)


# ---------------- Entrypoint ----------------

def main(mountpoint, foreground=True):
    logging.basicConfig(level=logging.INFO)
    FUSE(EncryptedMemFS(), mountpoint, foreground=foreground, allow_other=False)

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Encrypted In-Memory FS (Python + AES-256-GCM)")
    ap.add_argument("mountpoint", help="Directory to mount the FS")
    ap.add_argument("-f", "--foreground", action="store_true", help="Run in foreground")
    args = ap.parse_args()
    main(args.mountpoint, foreground=args.foreground)
