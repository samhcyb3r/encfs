#!/usr/bin/env python3
# encfs_aesgcm.py
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


def _now():
    return time.time()


def _parent(p: str) -> str:
    if p == "/":
        return "/"
    d = os.path.dirname(p.rstrip("/"))
    return d if d else "/"


def _basename(p: str) -> str:
    return os.path.basename(p.rstrip("/")) or "/"


@dataclass
class Node:
    st_mode: int
    st_nlink: int
    st_size: int = 0
    st_ctime: float = field(default_factory=_now)
    st_mtime: float = field(default_factory=_now)
    st_atime: float = field(default_factory=_now)
    children: Set[str] = field(default_factory=set)  # for directories

    # encryption-related (for files)
    salt: Optional[bytes] = None              # per-file salt for KDF
    nonce: Optional[bytes] = None             # AESGCM nonce
    ciphertext: bytes = b""                   # encrypted content (includes tag in AESGCM)
    key_cached: Optional[bytes] = None        # derived 32-byte key (session cache)


class EncryptedMemFS(LoggingMixIn, Operations):
    """
    In-memory FS + per-file encryption.
    Passphrase is provided via setxattr -n user.key -v "pwd" <file>.
    Key = PBKDF2(passphrase, salt, iterations) -> 32 bytes.
    Data encrypted by AESGCM(key, nonce).
    """
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.fd = 0

        # root
        root = Node(st_mode=(S_IFDIR | 0o755), st_nlink=2)
        self.nodes["/"] = root

    # -------- helpers --------
    def _ensure_exists(self, path: str) -> Node:
        n = self.nodes.get(path)
        if n is None:
            raise FuseOSError(errno.ENOENT)
        return n

    def _ensure_file(self, path: str) -> Node:
        n = self._ensure_exists(path)
        if (n.st_mode & S_IFDIR) == S_IFDIR:
            raise FuseOSError(errno.EISDIR)
        return n

    def _ensure_dir(self, path: str) -> Node:
        n = self._ensure_exists(path)
        if (n.st_mode & S_IFDIR) != S_IFDIR:
            raise FuseOSError(errno.ENOTDIR)
        return n

    def _touch_times(self, n: Node, *, atime=False, mtime=False):
        t = _now()
        if atime:
            n.st_atime = t
        if mtime:
            n.st_mtime = t

    def _derive_key(self, passphrase: bytes, salt: bytes, iterations: int = 200_000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        return kdf.derive(passphrase)

    def _require_key(self, n: Node):
        if n.key_cached is None:
            raise FuseOSError(errno.EACCES)

    def _encrypt_into_node(self, n: Node, plaintext: bytes):
        self._require_key(n)
        if n.nonce is None:
            # 12 bytes nonce is recommended for GCM
            n.nonce = os.urandom(12)
        aesgcm = AESGCM(n.key_cached)
        n.ciphertext = aesgcm.encrypt(n.nonce, plaintext, None)
        n.st_size = len(plaintext)
        self._touch_times(n, mtime=True)

    def _decrypt_from_node(self, n: Node) -> bytes:
        self._require_key(n)
        if not n.ciphertext:
            return b""
        if n.nonce is None:
            raise FuseOSError(errno.EACCES)
        try:
            aesgcm = AESGCM(n.key_cached)
            pt = aesgcm.decrypt(n.nonce, n.ciphertext, None)
            self._touch_times(n, atime=True)
            return pt
        except Exception:
            # wrong key / corrupted data
            raise FuseOSError(errno.EACCES)

    # -------- FUSE ops --------
    def getattr(self, path, fh=None):
        n = self._ensure_exists(path)
        st = {
            "st_mode": n.st_mode,
            "st_nlink": n.st_nlink,
            "st_size": n.st_size,
            "st_ctime": n.st_ctime,
            "st_mtime": n.st_mtime,
            "st_atime": n.st_atime,
            # make it usable by current user (avoid "root-owned" surprises)
            "st_uid": os.getuid(),
            "st_gid": os.getgid(),
        }
        return st

    def readdir(self, path, fh):
        d = self._ensure_dir(path)
        entries = [".", ".."]
        # use stored children for real hierarchy (not scanning all paths)
        entries.extend(sorted(d.children))
        return entries

    def mkdir(self, path, mode):
        parent = _parent(path)
        name = _basename(path)
        pd = self._ensure_dir(parent)
        if path in self.nodes:
            raise FuseOSError(errno.EEXIST)

        self.nodes[path] = Node(st_mode=(S_IFDIR | mode), st_nlink=2)
        pd.children.add(name)
        pd.st_nlink += 1
        self._touch_times(pd, mtime=True)

    def rmdir(self, path):
        if path == "/":
            raise FuseOSError(errno.EPERM)
        d = self._ensure_dir(path)
        if d.children:
            raise FuseOSError(errno.ENOTEMPTY)

        parent = _parent(path)
        name = _basename(path)
        pd = self._ensure_dir(parent)

        pd.children.discard(name)
        pd.st_nlink = max(2, pd.st_nlink - 1)
        self._touch_times(pd, mtime=True)

        self.nodes.pop(path, None)

    def create(self, path, mode, fi=None):
        parent = _parent(path)
        name = _basename(path)
        pd = self._ensure_dir(parent)
        if path in self.nodes:
            raise FuseOSError(errno.EEXIST)

        n = Node(st_mode=(S_IFREG | mode), st_nlink=1)
        # per-file salt (=> per-file key even if same passphrase)
        n.salt = os.urandom(16)
        self.nodes[path] = n
        pd.children.add(name)
        self._touch_times(pd, mtime=True)

        self.fd += 1
        return self.fd

    def open(self, path, flags):
        self._ensure_exists(path)
        self.fd += 1
        return self.fd

    def unlink(self, path):
        if path == "/":
            raise FuseOSError(errno.EPERM)
        n = self._ensure_file(path)

        parent = _parent(path)
        name = _basename(path)
        pd = self._ensure_dir(parent)

        pd.children.discard(name)
        self._touch_times(pd, mtime=True)

        # remove node
        self.nodes.pop(path, None)
        # wipe sensitive material in memory best-effort
        n.key_cached = None
        n.ciphertext = b""

    def truncate(self, path, length, fh=None):
        n = self._ensure_file(path)
        self._require_key(n)

        pt = self._decrypt_from_node(n)
        if length == 0:
            pt2 = b""
        else:
            pt2 = pt[:length].ljust(length, b"\x00")
        self._encrypt_into_node(n, pt2)
        return 0

    def utimens(self, path, times=None):
        n = self._ensure_exists(path)
        now = _now()
        atime, mtime = times if times else (now, now)
        n.st_atime = atime
        n.st_mtime = mtime

    def read(self, path, size, offset, fh):
        n = self._ensure_file(path)
        pt = self._decrypt_from_node(n)
        return pt[offset: offset + size]

    def write(self, path, data, offset, fh):
        n = self._ensure_file(path)
        self._require_key(n)

        pt = self._decrypt_from_node(n)
        if offset > len(pt):
            pt = pt + b"\x00" * (offset - len(pt))
        new_pt = pt[:offset] + data + pt[offset + len(data):]
        self._encrypt_into_node(n, new_pt)
        return len(data)

    # -------- xattr for passphrase --------
    def setxattr(self, path, name, value, options, position=0):
        # setfattr -n user.key -v "mypwd" <file>
        if name != "user.key":
            return 0
        n = self._ensure_file(path)

        if n.salt is None:
            n.salt = os.urandom(16)

        # value from fusepy is bytes
        passphrase = bytes(value)
        n.key_cached = self._derive_key(passphrase, n.salt)
        return 0

    def getxattr(self, path, name, position=0):
        # keep it minimal (avoid leaking anything)
        return b""

    def listxattr(self, path):
        return []

    def removexattr(self, path, name):
        if name == "user.key":
            n = self._ensure_file(path)
            n.key_cached = None
        return 0


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <mountpoint>")
        sys.exit(1)
    mountpoint = sys.argv[1]
    FUSE(EncryptedMemFS(), mountpoint, foreground=True, nothreads=True)


if __name__ == "__main__":
    main()
