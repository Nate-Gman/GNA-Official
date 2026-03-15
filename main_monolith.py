"""Global Network Archive - Single-File Monolith.
All submodules inlined. Runs Start PubLAN.bat upon launch.

Threading Model:
- Main thread: Blocks on infinite loop with 1-second sleeps
- Discovery thread (daemon): Runs every 5 seconds to update peer bookkeeping
- Flask thread (daemon): Runs HTTP server for web UI and peer communication
- Status thread (daemon): Runs every 5 seconds to print live status

Graceful Shutdown:
- KeyboardInterrupt (Ctrl+C) caught, prints warning
- Daemon threads are killed automatically when main exits
- User prompted to press Enter to close window
"""

import asyncio
import hashlib
import hmac as hmac_module
import json
import logging
import logging.handlers
import os
import platform
import random
import re
import shutil
import socket
import string
import struct
import base64
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Dict, Final, List, Optional, Protocol, Tuple

import io as _io
import requests
import socketio

def _find_project_dir() -> Path:
    """Locate the real project directory containing Start PubLAN.bat.

    Search order:
      1. Directory containing this script
      2. 'GNA Official1' subfolder next to this script
      3. Any subfolder next to this script that has Start PubLAN.bat
    Returns the first match, or falls back to the script's own directory.
    """
    script_dir = Path(__file__).parent.resolve()
    # 1. Script lives inside the project folder already
    if (script_dir / 'Start PubLAN.bat').exists():
        return script_dir
    # 2. Well-known subfolder name
    candidate = script_dir / 'GNA Official1'
    if candidate.is_dir() and (candidate / 'Start PubLAN.bat').exists():
        return candidate
    # 3. Scan immediate subdirectories
    try:
        for child in script_dir.iterdir():
            if child.is_dir() and (child / 'Start PubLAN.bat').exists():
                return child
    except OSError:
        pass
    # Fallback — use script dir (original behaviour)
    return script_dir

PROJECT_DIR: Path = _find_project_dir()
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from flask import Flask, Response, request as flask_request, jsonify, abort, redirect, send_from_directory
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener, ServiceInfo, IPVersion

logger = logging.getLogger(__name__)

# ===========================================================================
# config
# ===========================================================================
VERSION: Final[str] = "1.17"
APP_NAME: Final[str] = "Global Network Archive"
SERVICE_TYPE: Final[str] = "_databank._tcp.local."
DATA_DIR: Final[Path] = Path(os.getenv('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))) / APP_NAME
DATA_DIR.mkdir(parents=True, exist_ok=True)
SHARED_PATHS_FILE: Final[Path] = DATA_DIR / "shared_paths.json"
PEERS_FILE: Final[Path] = DATA_DIR / "known_peers.json"
MY_JOIN_TIME_FILE: Final[Path] = DATA_DIR / "my_join_time.txt"
SHARED_DIR: Final[Path] = Path.home()
PORT: Final[int] = 5000
PEER_TIMEOUT_SECONDS: Final[int] = 40
DISCOVERY_INTERVAL_SECONDS: Final[int] = 5
STATUS_PRINT_INTERVAL_SECONDS: Final[int] = 5
SHARED_COUNT_TIMEOUT_SECONDS: Final[float] = 3.0
SHARED_LIST_TIMEOUT_SECONDS: Final[float] = 5.0
PEER_INFO_TIMEOUT_SECONDS: Final[float] = 6.0
SEARCH_TIMEOUT_SECONDS: Final[float] = 4.0
MAX_PREVIEW_ITEMS: Final[int] = 8
MAX_FAILOVER_CHAIN_SIZE: Final[int] = 11
PUBLIC_IP_API_URL: Final[str] = "https://api.ipify.org?format=text"
PUBLIC_IP_TIMEOUT_SECONDS: Final[int] = 5
DNS_PROBE_ADDRESS: Final[str] = "8.8.8.8"
DNS_PROBE_PORT: Final[int] = 80
ABOUT_FILE: Final[Path] = Path("about.txt")

DEFAULT_ABOUT_TEXT: Final[str] = """
<h2>Global Network Archive v1.17</h2>
<p><strong>A decentralized, peer-to-peer file sharing and communication network.</strong></p>
"""

def migrate_legacy_files() -> None:
    install_dir = PROJECT_DIR.parent.absolute()
    migrations = [("shared_paths.json", SHARED_PATHS_FILE), ("known_peers.json", PEERS_FILE), ("my_join_time.txt", MY_JOIN_TIME_FILE)]
    for old_name, new_path in migrations:
        old_path = install_dir / old_name
        if old_path.exists() and not new_path.exists():
            try:
                shutil.copy2(old_path, new_path)
            except Exception:
                pass

def load_about_text() -> str:
    if ABOUT_FILE.exists():
        return ABOUT_FILE.read_text(encoding="utf-8")
    return DEFAULT_ABOUT_TEXT

# ===========================================================================
# domain/exceptions
# ===========================================================================
class GNAException(Exception):
    pass
class PathValidationError(GNAException):
    pass
class PeerDiscoveryError(GNAException):
    pass
class NetworkError(GNAException):
    pass
class StateCorruptionError(GNAException):
    pass
class PersistenceError(GNAException):
    pass

# ===========================================================================
# domain/types
# ===========================================================================
@dataclass(frozen=True)
class PeerId:
    value: str
    def __str__(self) -> str:
        return self.value

@dataclass(frozen=True)
class PeerInfo:
    ip: str
    port: int
    join_time: float
    last_seen: float
    def is_alive(self, current_time: float, timeout_seconds: int) -> bool:
        return self.last_seen > current_time - timeout_seconds

@dataclass(frozen=True)
class SharedItem:
    path: str
    name: str
    size_str: str
    is_folder: bool
    @property
    def download_url_path(self) -> Optional[str]:
        if self.is_folder: return None
        return f"/preview/{self.path.lstrip('/')}?download=1"

@dataclass(frozen=True)
class FailoverNode:
    peer_id: PeerId
    role: str
    ip: str
    port: int

@dataclass(frozen=True)
class SearchResult:
    bank_id: str
    name: str
    size: str
    is_folder: bool
    link: str

@dataclass(frozen=True)
class ExplorerEntry:
    name: str
    path: str
    size: str
    is_dir: bool
    shared: bool
    tags: str = ""

SharedPaths = Dict[str, str]
PeerRegistry = Dict[str, PeerInfo]

class PeerStateProtocol(Protocol):
    def add_discovered_peer(self, peer_id: str, info: PeerInfo) -> None: ...

# ===========================================================================
# domain/peer_logic
# ===========================================================================
def get_live_peers(my_id, my_info, known_peers, discovered_peers, current_time, timeout_seconds):
    live = {my_id.value: my_info}
    for pid, data in list(known_peers.items()) + list(discovered_peers.items()):
        if data.is_alive(current_time, timeout_seconds):
            live[pid] = data
    return sorted(live.items(), key=lambda x: (x[1].join_time, x[0]))

def get_failover_chain(sorted_live, max_size):
    chain = []
    for i, (pid, data) in enumerate(sorted_live[:max_size]):
        role = "Primary" if i == 0 else f"Backup {i}"
        chain.append(FailoverNode(peer_id=PeerId(pid), role=role, ip=data.ip, port=data.port))
    return chain

def get_my_role(my_id, sorted_live):
    if not sorted_live: return "Primary"
    if sorted_live[0][0] == my_id.value: return "Primary"
    for i, (pid, _) in enumerate(sorted_live):
        if pid == my_id.value: return f"Backup {i}"
    return "Unknown"

def is_path_shared(path, shared_paths):
    if path in shared_paths: return True
    for shared_path in shared_paths:
        if shared_path.endswith('/'):
            shared_prefix = shared_path.rstrip('/')
            if path == shared_prefix or path.startswith(shared_prefix + '/'):
                return True
    return False

def filter_visible_paths(all_paths, shared_paths):
    return [p for p in all_paths if is_path_shared(p, shared_paths)]

# ===========================================================================
# infrastructure/crypto
# ===========================================================================
NONCE_SIZE = 12
KEY_SIZE = 32
PUB_KEY_SIZE = 32
SALT_SIZE = 32
FILE_CHUNK_SIZE = 65536
HKDF_INFO = b"PubLAN-v1-secure-channel"
FILE_HKDF_INFO = b"PubLAN-v1-file-encryption"

def generate_file_key():
    return os.urandom(KEY_SIZE)

def derive_key(shared_secret, salt, info=HKDF_INFO):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, info=info, backend=default_backend())
    return hkdf.derive(shared_secret)

def encrypt_data(key, plaintext):
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_data(key, encrypted):
    if len(encrypted) < NONCE_SIZE + 16: raise ValueError("Encrypted data too short")
    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_file_data(key, data):
    salt = os.urandom(SALT_SIZE)
    derived = derive_key(key, salt, FILE_HKDF_INFO)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(derived)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext

def decrypt_file_data(key, encrypted):
    if len(encrypted) < SALT_SIZE + NONCE_SIZE + 16: raise ValueError("Encrypted file data too short")
    salt = encrypted[:SALT_SIZE]
    nonce = encrypted[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted[SALT_SIZE + NONCE_SIZE:]
    derived = derive_key(key, salt, FILE_HKDF_INFO)
    aesgcm = AESGCM(derived)
    return aesgcm.decrypt(nonce, ciphertext, None)

class CryptoIdentity:
    def __init__(self, private_key_bytes=None):
        if private_key_bytes:
            self._private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        else:
            self._private_key = X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
    @property
    def public_key_bytes(self):
        return self._public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    @property
    def private_key_bytes(self):
        return self._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    def encrypt_for_peer(self, peer_public_key_bytes, plaintext):
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        ephemeral_pub_bytes = ephemeral_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        peer_public = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = ephemeral_private.exchange(peer_public)
        salt = os.urandom(SALT_SIZE)
        encryption_key = derive_key(shared_secret, salt)
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return ephemeral_pub_bytes + salt + nonce + ciphertext
    def decrypt_from_peer(self, encrypted):
        min_size = PUB_KEY_SIZE + SALT_SIZE + NONCE_SIZE + 16
        if len(encrypted) < min_size: raise ValueError(f"Encrypted data too short: {len(encrypted)} < {min_size}")
        ephemeral_pub_bytes = encrypted[:PUB_KEY_SIZE]
        salt = encrypted[PUB_KEY_SIZE:PUB_KEY_SIZE + SALT_SIZE]
        nonce = encrypted[PUB_KEY_SIZE + SALT_SIZE:PUB_KEY_SIZE + SALT_SIZE + NONCE_SIZE]
        ciphertext = encrypted[PUB_KEY_SIZE + SALT_SIZE + NONCE_SIZE:]
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        shared_secret = self._private_key.exchange(ephemeral_public)
        encryption_key = derive_key(shared_secret, salt)
        aesgcm = AESGCM(encryption_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    def derive_shared_key(self, peer_public_key_bytes):
        peer_public = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = self._private_key.exchange(peer_public)
        salt = hashlib.sha256(self.public_key_bytes + peer_public_key_bytes).digest()
        return derive_key(shared_secret, salt)

def password_to_key(password, salt=None):
    if salt is None: salt = os.urandom(SALT_SIZE)
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, iterations=600_000, backend=default_backend())
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

def secure_random_token(length=32):
    return os.urandom(length).hex()

# ===========================================================================
# infrastructure/password_policy
# ===========================================================================
@dataclass
class PasswordValidationResult:
    valid: bool
    errors: List[str]
    strength_label: str
    strength_css_class: str

def _count_char_classes(password):
    upper = lower = digit = other = 0
    for ch in password:
        if ch.isupper(): upper += 1
        elif ch.islower(): lower += 1
        elif ch.isdigit(): digit += 1
        else: other += 1
    return upper, lower, digit, other

def get_strength_label(length):
    if length < 40: return "Frail password", "text-danger"
    elif length <= 50: return "Weak password", "text-warning"
    elif length < 75: return "Okay password", "text-info"
    elif length <= 93: return "Reasonable password", "text-primary"
    else: return "Strong password", "text-success"

def validate_vault_password(password):
    errors = []
    length = len(password)
    if length < 15: errors.append(f"Minimum 15 characters required (currently {length})")
    upper, lower, digit, other = _count_char_classes(password)
    if upper < 3: errors.append(f"Minimum 3 uppercase letters required (currently {upper})")
    if lower < 3: errors.append(f"Minimum 3 lowercase letters required (currently {lower})")
    if digit < 3: errors.append(f"Minimum 3 digits required (currently {digit})")
    if other < 1: errors.append(f"Minimum 1 special/other character required (currently {other})")
    strength_label, css_class = get_strength_label(length)
    return PasswordValidationResult(valid=len(errors) == 0, errors=errors, strength_label=strength_label, strength_css_class=css_class)

def format_password_requirements_html():
    return '''<div class="small text-muted mt-2">
        <strong>Password requirements:</strong>
        <ul class="mb-1">
            <li>Minimum 15 characters (no maximum)</li>
            <li>At least 3 uppercase letters</li>
            <li>At least 3 lowercase letters</li>
            <li>At least 3 digits</li>
            <li>At least 1 special character, symbol, Unicode, or emoji</li>
        </ul>
    </div>'''

def password_strength_js():
    return r'''<script>
function checkPasswordStrength(inputId, feedbackId) {
    const input = document.getElementById(inputId);
    const feedback = document.getElementById(feedbackId);
    if (!input || !feedback) return;
    input.addEventListener('input', function() {
        const pw = this.value;
        const len = [...pw].length;
        let upper=0, lower=0, digit=0, other=0;
        for (const ch of pw) {
            if (/\p{Lu}/u.test(ch)) upper++;
            else if (/\p{Ll}/u.test(ch)) lower++;
            else if (/\p{Nd}/u.test(ch)) digit++;
            else other++;
        }
        let errors = [];
        if (len < 15) errors.push('Need ' + (15-len) + ' more chars');
        if (upper < 3) errors.push((3-upper) + ' more uppercase');
        if (lower < 3) errors.push((3-lower) + ' more lowercase');
        if (digit < 3) errors.push((3-digit) + ' more digits');
        if (other < 1) errors.push('1 special/symbol/emoji');
        let strength, cls;
        if (len < 40) { strength='Frail password'; cls='text-danger'; }
        else if (len <= 50) { strength='Weak password'; cls='text-warning'; }
        else if (len < 75) { strength='Okay password'; cls='text-info'; }
        else if (len <= 93) { strength='Reasonable password'; cls='text-primary'; }
        else { strength='Strong password'; cls='text-success'; }
        let html = '<span class="'+cls+' fw-bold">['+strength+']</span>';
        html += ' <span class="text-muted">('+len+' chars)</span>';
        if (errors.length > 0) {
            html += '<br><small class="text-danger">Missing: '+errors.join(' &middot; ')+'</small>';
        } else {
            html += '<br><small class="text-success">All requirements met</small>';
        }
        feedback.innerHTML = html;
    });
}
</script>'''

# ===========================================================================
# infrastructure/vault
# ===========================================================================
VAULT_META_FILE = ".vault_meta"
VAULT_INDEX_FILE = ".vault_index.enc"
VAULT_DOWNLOADS_DIR = "Downloads"
VAULT_VERSION_NUM = 1
ENCRYPTED_EXT = ".vaultenc"

@dataclass
class VaultFileEntry:
    name: str
    encrypted_name: str
    size: int
    added_time: float
    file_hash: str
    is_download: bool = False
    def to_dict(self):
        return {'name': self.name, 'encrypted_name': self.encrypted_name, 'size': self.size, 'added_time': self.added_time, 'file_hash': self.file_hash, 'is_download': self.is_download}
    @staticmethod
    def from_dict(d):
        return VaultFileEntry(name=d['name'], encrypted_name=d['encrypted_name'], size=d['size'], added_time=d['added_time'], file_hash=d['file_hash'], is_download=d.get('is_download', False))

def compute_secret_file_fingerprint(data):
    hmac_key = hashlib.sha3_256(data).digest()
    return {'md5': hashlib.md5(data).hexdigest(), 'sha1': hashlib.sha1(data).hexdigest(), 'sha256': hashlib.sha256(data).hexdigest(), 'sha3_512': hashlib.sha3_512(data).hexdigest(), 'blake2b_512': hashlib.blake2b(data, digest_size=64).hexdigest(), 'hmac_sha256': hmac_module.new(hmac_key, data, hashlib.sha256).hexdigest(), 'size': len(data)}

def verify_secret_file_fingerprint(data, stored):
    current = compute_secret_file_fingerprint(data)
    for key in ('md5', 'sha1', 'sha256', 'sha3_512', 'blake2b_512', 'hmac_sha256', 'size'):
        if current.get(key) != stored.get(key): return False
    return True

class SecureVault:
    def __init__(self, vault_path, password=None, secret_file_data=None):
        self.vault_path = Path(vault_path)
        self.downloads_path = self.vault_path / VAULT_DOWNLOADS_DIR
        self._master_key = None
        self._password_salt = None
        self._password_key = None
        self._index = {}
        self._unlocked = False
        self._requires_secret_file = False
        self._last_validation_errors = []
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.downloads_path.mkdir(parents=True, exist_ok=True)
        meta_path = self.vault_path / VAULT_META_FILE
        if meta_path.exists():
            if password: self._unlock(password, secret_file_data)
        else:
            if password: self._initialize(password, secret_file_data)
    @property
    def last_validation_errors(self): return self._last_validation_errors
    @property
    def requires_secret_file(self): return self._requires_secret_file
    def _initialize(self, password, secret_file_data=None):
        validation = validate_vault_password(password)
        if not validation.valid:
            self._last_validation_errors = validation.errors
            return
        self._last_validation_errors = []
        self._master_key = generate_file_key()
        self._password_key, self._password_salt = password_to_key(password)
        encrypted_master = encrypt_data(self._password_key, self._master_key)
        meta = {'version': VAULT_VERSION_NUM, 'salt': self._password_salt.hex(), 'encrypted_master_key': encrypted_master.hex(), 'created': time.time(), 'requires_secret_file': secret_file_data is not None}
        if secret_file_data is not None:
            meta['secret_file_fingerprint'] = compute_secret_file_fingerprint(secret_file_data)
            self._requires_secret_file = True
        meta_path = self.vault_path / VAULT_META_FILE
        with open(meta_path, 'w') as f: json.dump(meta, f)
        if platform.system() == 'Windows':
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(meta_path), 2)
            except Exception: pass
        self._index = {}
        self._save_index()
        self._unlocked = True
    def _unlock(self, password, secret_file_data=None):
        meta_path = self.vault_path / VAULT_META_FILE
        try:
            with open(meta_path, 'r') as f: meta = json.load(f)
            self._requires_secret_file = meta.get('requires_secret_file', False)
            if self._requires_secret_file:
                stored_fp = meta.get('secret_file_fingerprint')
                if not stored_fp:
                    self._last_validation_errors = ['Vault metadata corrupted']
                    return False
                if secret_file_data is None:
                    self._last_validation_errors = ['This vault requires a secret file to unlock']
                    return False
                if not verify_secret_file_fingerprint(secret_file_data, stored_fp):
                    self._last_validation_errors = ['Secret file does not match']
                    return False
            self._password_salt = bytes.fromhex(meta['salt'])
            encrypted_master = bytes.fromhex(meta['encrypted_master_key'])
            self._password_key, _ = password_to_key(password, self._password_salt)
            self._master_key = decrypt_data(self._password_key, encrypted_master)
            self._load_index()
            self._unlocked = True
            self._last_validation_errors = []
            return True
        except Exception as e:
            self._last_validation_errors = [str(e)]
            self._unlocked = False
            return False
    @property
    def is_unlocked(self): return self._unlocked
    def _save_index(self):
        if not self._master_key: return
        index_data = json.dumps({k: v.to_dict() for k, v in self._index.items()}).encode('utf-8')
        encrypted_index = encrypt_data(self._master_key, index_data)
        with open(self.vault_path / VAULT_INDEX_FILE, 'wb') as f: f.write(encrypted_index)
    def _load_index(self):
        index_path = self.vault_path / VAULT_INDEX_FILE
        if not index_path.exists():
            self._index = {}
            return
        try:
            with open(index_path, 'rb') as f: encrypted_index = f.read()
            index_data = decrypt_data(self._master_key, encrypted_index)
            raw = json.loads(index_data.decode('utf-8'))
            self._index = {k: VaultFileEntry.from_dict(v) for k, v in raw.items()}
        except Exception: self._index = {}
    def add_file(self, name, data, is_download=False):
        if not self._unlocked: return False
        try:
            enc_name = os.urandom(16).hex() + ENCRYPTED_EXT
            store_path = (self.downloads_path if is_download else self.vault_path) / enc_name
            encrypted = encrypt_file_data(self._master_key, data)
            with open(store_path, 'wb') as f: f.write(encrypted)
            self._index[name] = VaultFileEntry(name=name, encrypted_name=enc_name, size=len(data), added_time=time.time(), file_hash=hashlib.sha256(data).hexdigest(), is_download=is_download)
            self._save_index()
            return True
        except Exception: return False
    def read_file(self, name):
        if not self._unlocked: return None
        entry = self._index.get(name)
        if not entry: return None
        try:
            store_path = (self.downloads_path if entry.is_download else self.vault_path) / entry.encrypted_name
            with open(store_path, 'rb') as f: encrypted = f.read()
            return decrypt_file_data(self._master_key, encrypted)
        except Exception: return None
    def open_file(self, name):
        data = self.read_file(name)
        if data is None: return False
        try:
            temp_dir = tempfile.mkdtemp(prefix='publan_vault_')
            temp_path = Path(temp_dir) / name
            with open(temp_path, 'wb') as f: f.write(data)
            if platform.system() == 'Windows': os.startfile(str(temp_path))
            elif platform.system() == 'Darwin': subprocess.Popen(['open', str(temp_path)])
            else: subprocess.Popen(['xdg-open', str(temp_path)])
            def cleanup():
                time.sleep(60)
                shutil.rmtree(temp_dir, ignore_errors=True)
            threading.Thread(target=cleanup, daemon=True).start()
            return True
        except Exception: return False
    def remove_file(self, name):
        if not self._unlocked: return False
        entry = self._index.get(name)
        if not entry: return False
        try:
            store_path = (self.downloads_path if entry.is_download else self.vault_path) / entry.encrypted_name
            if store_path.exists():
                size = store_path.stat().st_size
                with open(store_path, 'wb') as f: f.write(os.urandom(size))
                store_path.unlink()
            del self._index[name]
            self._save_index()
            return True
        except Exception: return False
    def list_files(self):
        if not self._unlocked: return []
        return [{'name': e.name, 'size': e.size, 'added': e.added_time, 'is_download': e.is_download, 'hash': e.file_hash} for e in self._index.values()]

def get_default_vault_path():
    return DATA_DIR / "Vault"

# ===========================================================================
# infrastructure/integrity
# ===========================================================================
MANIFEST_FILE = ".integrity_manifest.json"
VERIFY_EXTENSIONS = {'.py', '.js', '.json', '.bat', '.html', '.css', '.md'}
SKIP_DIRS = {'__pycache__', '.git', 'node_modules', '.mypy_cache', '.pytest_cache', 'venv', 'env'}
SKIP_FILES_SET = {MANIFEST_FILE, '.integrity_manifest.json'}

def _hash_file(filepath):
    h = hashlib.sha3_256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk: break
                h.update(chunk)
        return h.hexdigest()
    except Exception: return ""

def _collect_source_files(project_root):
    files = []
    for root, dirs, filenames in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(filenames):
            if fname in SKIP_FILES_SET: continue
            fpath = Path(root) / fname
            if fpath.suffix.lower() in VERIFY_EXTENSIONS: files.append(fpath)
    return files

def generate_manifest(project_root):
    files = _collect_source_files(project_root)
    manifest = {}
    for fpath in files:
        rel = fpath.relative_to(project_root).as_posix()
        file_hash = _hash_file(fpath)
        if file_hash: manifest[rel] = file_hash
    manifest_path = project_root / MANIFEST_FILE
    try:
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump({'version': 1, 'algorithm': 'sha3-256', 'files': manifest}, f, indent=2)
    except Exception: pass
    return manifest

def verify_integrity(project_root):
    manifest_path = project_root / MANIFEST_FILE
    if not manifest_path.exists():
        generate_manifest(project_root)
        return True, ["Integrity manifest created (first run)"]
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f: data = json.load(f)
        stored = data.get('files', {})
    except Exception as e: return False, [f"Could not read manifest: {e}"]
    issues = []
    current_files = _collect_source_files(project_root)
    current_map = {}
    for fpath in current_files:
        rel = fpath.relative_to(project_root).as_posix()
        current_map[rel] = _hash_file(fpath)
    for rel, expected_hash in stored.items():
        actual = current_map.get(rel)
        if actual is None: issues.append(f"Missing: {rel}")
        elif actual != expected_hash: issues.append(f"Modified: {rel}")
    for rel in current_map:
        if rel not in stored: issues.append(f"New file: {rel}")
    return len(issues) == 0, issues

def run_startup_integrity_check(project_root):
    passed, issues = verify_integrity(project_root)
    if passed:
        if issues and issues[0].startswith("Integrity manifest created"):
            print("[OK] Integrity manifest created for future verification")
        else:
            print("[OK] Software integrity verified")
        return True
    else:
        print()
        print("=" * 60)
        print("  [Unverified modified program]")
        print("=" * 60)
        print(f"  {len(issues)} file(s) differ from the integrity manifest:")
        for issue in issues[:10]: print(f"    - {issue}")
        if len(issues) > 10: print(f"    ... and {len(issues) - 10} more")
        print()
        print("  Execution will continue, but this software may have")
        print("  been modified from its original verified state.")
        print("=" * 60)
        print()
        return False

# ===========================================================================
# infrastructure/filesystem
# ===========================================================================
def normalize_path(path):
    return os.path.normpath(path).replace('\\', '/').lstrip('/')

def is_path_safe(requested_path, base_dir):
    try:
        full_path = (base_dir / requested_path).resolve()
        base_resolved = base_dir.resolve()
        return str(full_path).startswith(str(base_resolved))
    except Exception: return False

def get_file_size_kb(file_path):
    try: return file_path.stat().st_size // 1024
    except OSError: return 0

def list_directory_entries(dir_path, relative_to, shared_paths):
    if not dir_path.is_dir(): return []
    entries = []
    try:
        for name in sorted(os.listdir(dir_path)):
            item_path = dir_path / name
            try: rel_path = item_path.relative_to(relative_to); rel_str = str(rel_path).replace('\\', '/')
            except ValueError: continue
            is_dir = item_path.is_dir()
            if is_dir:
                display_name = name + '/'
                path_key = rel_str + '/'
                size_str = 'Folder'
            else:
                display_name = name
                path_key = rel_str
                size_kb = get_file_size_kb(item_path)
                size_str = f'{size_kb:,} KB'
            shared = is_path_shared(path_key, shared_paths)
            tags = shared_paths.get(path_key, "") if shared else ""
            entries.append(ExplorerEntry(name=display_name, path=path_key, size=size_str, is_dir=is_dir, shared=shared, tags=tags))
    except Exception: pass
    return entries

def get_visible_paths_in_directory(dir_path):
    if not dir_path.is_dir(): return []
    paths = []
    try:
        for name in os.listdir(dir_path):
            item_path = dir_path / name
            rel = normalize_path(name)
            paths.append(rel)
            if item_path.is_dir(): paths.append(rel + '/')
    except Exception: pass
    return paths

# ===========================================================================
# infrastructure/network
# ===========================================================================
def get_local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((DNS_PROBE_ADDRESS, DNS_PROBE_PORT))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception: return "127.0.0.1"

def get_public_ip():
    try:
        response = requests.get(PUBLIC_IP_API_URL, timeout=PUBLIC_IP_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.text.strip()
    except Exception: return "unknown"

def fetch_peer_shared_count(ip, port):
    try:
        response = requests.get(f"http://{ip}:{port}/shared_count", timeout=SHARED_COUNT_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json().get('count')
    except Exception: return None

def fetch_peer_shared_list(ip, port):
    try:
        response = requests.get(f"http://{ip}:{port}/shared_list", timeout=SHARED_LIST_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json().get('items', [])
    except Exception: return None

def fetch_peer_info(ip, port):
    try:
        response = requests.get(f"http://{ip}:{port}/api/info", timeout=PEER_INFO_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()
    except Exception: return None

# ===========================================================================
# infrastructure/id_generator
# ===========================================================================
_used_call_numbers = set()

def generate_random_peer_id():
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return PeerId(f"bank-{suffix}")

def generate_call_number():
    while True:
        part1 = random.randint(100, 999)
        part2 = random.randint(100, 999)
        part3 = random.randint(1000, 9999)
        call_number = f"{part1}-{part2}-{part3}"
        if call_number not in _used_call_numbers:
            _used_call_numbers.add(call_number)
            return call_number

def generate_peer_id_from_ip(ip):
    return PeerId(f"unknown-{ip.replace('.', '-')}")

# ===========================================================================
# infrastructure/discovery
# ===========================================================================
class PeerDiscoveryListener(ServiceListener):
    def __init__(self, state, my_id):
        self.state = state
        self.my_id = my_id
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if not info: return
        properties = dict(info.properties or {})
        peer_id_bytes = properties.get(b'id', b'')
        peer_id_str = peer_id_bytes.decode() if peer_id_bytes else ''
        if not peer_id_str or peer_id_str == self.my_id.value: return
        for addr in info.parsed_addresses(IPVersion.V4Only):
            peer_info = PeerInfo(ip=addr, port=info.port, join_time=time.time(), last_seen=time.time())
            self.state.add_discovered_peer(peer_id_str, peer_info)
    def remove_service(self, zc, type_, name): pass
    def update_service(self, zc, type_, name): pass

def register_service(zc, my_id, local_ip):
    service_name = f"{my_id.value}.{SERVICE_TYPE}"
    info = ServiceInfo(SERVICE_TYPE, service_name, addresses=[socket.inet_aton(local_ip)], port=PORT, properties={b'id': my_id.value.encode()})
    zc.register_service(info)
    return info

def start_discovery(zc, state, my_id):
    listener = PeerDiscoveryListener(state, my_id)
    return ServiceBrowser(zc, SERVICE_TYPE, listener)

# ===========================================================================
# infrastructure/global_discovery
# ===========================================================================
GLOBAL_CONFIG_FILE = PROJECT_DIR / "global_config.json"
DEFAULT_GLOBAL_CONFIG = {"enabled": True, "relay_url": "http://localhost:3000", "network_code": "publan-global-v1", "auto_connect": True}

def load_global_config():
    if GLOBAL_CONFIG_FILE.exists():
        try: return json.loads(GLOBAL_CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception: pass
    return DEFAULT_GLOBAL_CONFIG.copy()

def save_global_config(config):
    try: GLOBAL_CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    except Exception: pass

class GlobalDiscoveryService:
    def __init__(self, my_peer_id, my_call_number, local_ip, local_port, on_peers_updated=None):
        self.my_peer_id = my_peer_id
        self.my_call_number = my_call_number
        self.local_ip = local_ip
        self.local_port = local_port
        self.on_peers_updated = on_peers_updated
        self.config = load_global_config()
        self.sio = None
        self.global_peers = []
        self.running = False
        self._thread = None
        self._loop = None
    @property
    def enabled(self): return bool(self.config.get("enabled") and self.config.get("network_code") and self.config.get("relay_url"))
    @property
    def network_code(self): return self.config.get("network_code", "")
    @property
    def relay_url(self): return self.config.get("relay_url", "http://localhost:3000")
    def start(self):
        if not self.enabled: return
        self.running = True
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="GlobalDiscoveryThread")
        self._thread.start()
    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._connect_and_run())
    async def _connect_and_run(self):
        self.sio = socketio.AsyncClient(reconnection=True, reconnection_attempts=0, reconnection_delay=5, reconnection_delay_max=30)
        @self.sio.event
        async def connect():
            await self._register()
        @self.sio.event
        async def disconnect(): pass
        @self.sio.on("global-peer-list")
        async def on_peer_list(data):
            self.global_peers = [p for p in (data or []) if p.get("peerId") != self.my_peer_id]
            if self.on_peers_updated:
                try: self.on_peers_updated(self.global_peers)
                except Exception: pass
        while self.running:
            try:
                await self.sio.connect(self.relay_url, wait_timeout=10)
                break
            except Exception: await asyncio.sleep(5)
        while self.running:
            for _ in range(10):
                if not self.running: break
                await asyncio.sleep(0.5)
            if not self.running: break
            if self.sio and self.sio.connected:
                try:
                    await self._register()
                    await self.sio.emit("request-global-peers", {"networkCode": self.network_code})
                except Exception: pass
    async def _register(self):
        if not self.sio or not self.sio.connected: return
        await self.sio.emit("register-global-peer", {"networkCode": self.network_code, "peerId": self.my_peer_id, "friendlyName": platform.node(), "ip": self.local_ip, "port": self.local_port, "callNumber": self.my_call_number})
    def stop(self):
        self.running = False
        if self.sio and self._loop and self._loop.is_running():
            try:
                future = asyncio.run_coroutine_threadsafe(self.sio.disconnect(), self._loop)
                future.result(timeout=5)
            except Exception: pass
        if self._thread and self._thread.is_alive(): self._thread.join(timeout=10)
    def get_status(self):
        if not self.enabled: return "DISABLED"
        if self.sio and self.sio.connected: return f"CONNECTED ({len(self.global_peers)} peers)"
        return "CONNECTING..."

# ===========================================================================
# infrastructure/persistence
# ===========================================================================
def load_shared_paths():
    if not SHARED_PATHS_FILE.exists(): return {}
    try:
        with open(SHARED_PATHS_FILE, encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict): return data
            return {}
    except Exception: return {}

def save_shared_paths(paths):
    try:
        SHARED_PATHS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SHARED_PATHS_FILE, 'w', encoding='utf-8') as f: json.dump(paths, f, indent=2, ensure_ascii=False)
    except Exception: pass

def load_known_peers():
    if not PEERS_FILE.exists(): return {}
    try:
        with open(PEERS_FILE, encoding='utf-8') as f:
            raw_data = json.load(f)
            peers = {}
            for pid, data in raw_data.items():
                try: peers[pid] = PeerInfo(ip=data['ip'], port=data['port'], join_time=data.get('join_time', 0.0), last_seen=data.get('last_seen', 0.0))
                except (KeyError, TypeError): pass
            return peers
    except Exception: return {}

def save_known_peers(peers):
    try:
        PEERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        raw_data = {pid: {'ip': info.ip, 'port': info.port, 'join_time': info.join_time, 'last_seen': info.last_seen} for pid, info in peers.items()}
        with open(PEERS_FILE, 'w', encoding='utf-8') as f: json.dump(raw_data, f, indent=2)
    except Exception: pass

def load_join_time():
    if MY_JOIN_TIME_FILE.exists():
        try: return float(MY_JOIN_TIME_FILE.read_text().strip())
        except (ValueError, IOError): pass
    join_time = time.time()
    try:
        MY_JOIN_TIME_FILE.parent.mkdir(parents=True, exist_ok=True)
        MY_JOIN_TIME_FILE.write_text(str(join_time))
    except Exception: pass
    return join_time

# ===========================================================================
# application/state
# ===========================================================================
@dataclass
class ApplicationState:
    my_id: PeerId
    my_join_time: float
    local_ip: str
    public_ip: str
    call_number: str = ""
    shared_paths: SharedPaths = field(default_factory=dict)
    known_peers: PeerRegistry = field(default_factory=dict)
    discovered_peers: PeerRegistry = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)
    def get_my_info(self):
        with self._lock:
            ip = self.public_ip if self.public_ip != "unknown" else self.local_ip
            return PeerInfo(ip=ip, port=PORT, join_time=self.my_join_time, last_seen=time.time())
    def update_shared_paths(self, new_paths):
        with self._lock: self.shared_paths = new_paths
    def get_shared_paths(self):
        with self._lock: return dict(self.shared_paths)
    def add_known_peer(self, peer_id, info):
        with self._lock: self.known_peers[peer_id] = info
    def get_known_peers(self):
        with self._lock: return dict(self.known_peers)
    def add_discovered_peer(self, peer_id, info):
        with self._lock: self.discovered_peers[peer_id] = info
    def get_discovered_peers(self):
        with self._lock: return dict(self.discovered_peers)

# ===========================================================================
# upload transfer system
# ===========================================================================
_pending_uploads = {}
_pending_uploads_lock = threading.Lock()
_upload_counter = 0

def _generate_upload_id():
    global _upload_counter
    _upload_counter += 1
    return f"upload-{int(time.time())}-{_upload_counter}"

def add_pending_upload(sender_id, sender_ip, filename, dest_path, file_data):
    with _pending_uploads_lock:
        upload_id = _generate_upload_id()
        _pending_uploads[upload_id] = {
            'id': upload_id,
            'sender_id': sender_id,
            'sender_ip': sender_ip,
            'filename': filename,
            'dest_path': dest_path,
            'file_data': file_data,
            'file_size': len(file_data),
            'timestamp': time.time(),
            'status': 'pending'
        }
        return upload_id

def get_pending_uploads():
    with _pending_uploads_lock:
        return [
            {k: v for k, v in u.items() if k != 'file_data'}
            for u in _pending_uploads.values()
            if u['status'] == 'pending'
        ]

def accept_upload(upload_id):
    with _pending_uploads_lock:
        upload = _pending_uploads.get(upload_id)
        if not upload or upload['status'] != 'pending':
            return None
        upload['status'] = 'accepted'
        return dict(upload)

def reject_upload(upload_id):
    with _pending_uploads_lock:
        upload = _pending_uploads.get(upload_id)
        if not upload or upload['status'] != 'pending':
            return False
        upload['status'] = 'rejected'
        upload['file_data'] = b''
        return True

def cleanup_old_uploads(max_age=300):
    with _pending_uploads_lock:
        now = time.time()
        expired = [uid for uid, u in _pending_uploads.items()
                   if now - u['timestamp'] > max_age and u['status'] != 'pending']
        for uid in expired:
            _pending_uploads.pop(uid, None)

# ===========================================================================
# folder sync system
# ===========================================================================
_active_syncs = {}
_active_syncs_lock = threading.Lock()
_sync_counter = 0

def _generate_sync_id():
    global _sync_counter
    _sync_counter += 1
    return f"sync-{int(time.time())}-{_sync_counter}"

def add_active_sync(peer_id, local_path, remote_path, peer_ip, peer_port):
    with _active_syncs_lock:
        sync_id = _generate_sync_id()
        _active_syncs[sync_id] = {
            'id': sync_id,
            'peer_id': peer_id,
            'peer_ip': peer_ip,
            'peer_port': peer_port,
            'local_path': local_path,
            'remote_path': remote_path,
            'active': True,
            'last_sync': time.time(),
            'files_synced': 0,
            'stop': False,
        }
        return sync_id

def get_active_syncs():
    with _active_syncs_lock:
        return [
            {k: v for k, v in s.items() if k != 'stop'}
            for s in _active_syncs.values()
            if not s.get('stop', False)
        ]

def stop_sync(sync_id):
    with _active_syncs_lock:
        s = _active_syncs.get(sync_id)
        if s:
            s['stop'] = True
            s['active'] = False
            return True
        return False

def run_sync_job(sync_id, state):
    """Background worker: periodically pull files from peer into local folder."""
    while True:
        with _active_syncs_lock:
            s = _active_syncs.get(sync_id)
            if not s or s.get('stop', False):
                return
            peer_ip = s['peer_ip']
            peer_port = s['peer_port']
            remote_path = s['remote_path']
            local_path = s['local_path']
            s['active'] = True
        try:
            # Fetch remote file list
            url = f"http://{peer_ip}:{peer_port}/shared_list"
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            items = data.get('items', [])
            home = Path.home()
            target_dir = home / local_path.rstrip('/')
            target_dir.mkdir(parents=True, exist_ok=True)
            count = 0
            for item in items:
                if item.get('is_folder', False):
                    continue
                item_path = item.get('path', '')
                if remote_path and not item_path.startswith(remote_path):
                    continue
                # Download the file
                try:
                    dl_url = f"http://{peer_ip}:{peer_port}/preview/{item_path}?download=1"
                    dl_resp = requests.get(dl_url, timeout=30)
                    if dl_resp.status_code == 200:
                        file_name = Path(item_path).name
                        dest_file = target_dir / file_name
                        # Only write if different size or missing
                        if not dest_file.exists() or dest_file.stat().st_size != len(dl_resp.content):
                            with open(dest_file, 'wb') as f:
                                f.write(dl_resp.content)
                            count += 1
                except Exception:
                    pass
            with _active_syncs_lock:
                s2 = _active_syncs.get(sync_id)
                if s2:
                    s2['files_synced'] = count
                    s2['last_sync'] = time.time()
                    s2['active'] = False
        except Exception as e:
            with _active_syncs_lock:
                s3 = _active_syncs.get(sync_id)
                if s3:
                    s3['active'] = False
            print(f"[SYNC] Error syncing {sync_id}: {e}")
        # Wait 30 seconds before next sync cycle
        for _ in range(30):
            time.sleep(1)
            with _active_syncs_lock:
                s4 = _active_syncs.get(sync_id)
                if not s4 or s4.get('stop', False):
                    return

# ===========================================================================
# remote permissions store (controls what remote peers can do to THIS machine)
# ===========================================================================
_remote_permissions_lock = threading.Lock()
_remote_permissions = {
    'remote_exec': False,      # Allow remote command execution
    'clipboard_write': False,  # Allow peers to set our clipboard
    'clipboard_read': False,   # Allow peers to read our clipboard
    'power_control': False,    # Allow peers to shutdown/restart/sleep
    'screenshot': False,       # Allow peers to capture our screen
    'notify': False,           # Allow peers to send us notifications
    'process_manager': False,  # Allow peers to view/kill our processes
    'screen_record': False,    # Allow peers to record our screen
    'remote_audio': False,     # Allow peers to listen to our mic
    'system_audio': False,     # Allow peers to listen to our system/desktop audio
    'input_monitor': False,    # Allow peers to monitor our keystrokes/mouse
}

# Input monitor state
_input_monitor_lock = threading.Lock()
_input_monitor_active = False
_input_monitor_events = []
_input_monitor_thread = None

# Mic audio streaming state
_audio_stream_lock = threading.Lock()
_audio_stream_active = False
_audio_stream_chunks = []  # list of base64 WAV chunks
_audio_stream_thread = None

# System audio streaming state
_sys_audio_lock = threading.Lock()
_sys_audio_active = False
_sys_audio_chunks = []
_sys_audio_thread = None

def get_remote_permissions():
    with _remote_permissions_lock:
        return dict(_remote_permissions)

def set_remote_permission(key, value):
    with _remote_permissions_lock:
        if key in _remote_permissions:
            _remote_permissions[key] = bool(value)
            return True
        return False

def is_local_request():
    addr = flask_request.remote_addr or ''
    return addr in ('127.0.0.1', '::1', 'localhost')

# ===========================================================================
# application/use_cases
# ===========================================================================
def get_sorted_live_peers(state):
    return get_live_peers(my_id=state.my_id, my_info=state.get_my_info(), known_peers=state.get_known_peers(), discovered_peers=state.get_discovered_peers(), current_time=time.time(), timeout_seconds=PEER_TIMEOUT_SECONDS)

def get_current_failover_chain(state):
    return get_failover_chain(get_sorted_live_peers(state), MAX_FAILOVER_CHAIN_SIZE)

def get_current_role(state):
    return get_my_role(state.my_id, get_sorted_live_peers(state))

def get_shared_items_list(state):
    items = []
    for path in state.shared_paths:
        full_item_path = SHARED_DIR / path.rstrip('/')
        is_folder = path.endswith('/')
        if is_folder: size_str = "Folder"
        elif full_item_path.exists(): size_str = f"{get_file_size_kb(full_item_path):,} KB"
        else: size_str = "N/A"
        name = os.path.basename(path.rstrip('/'))
        if is_folder: name += '/'
        items.append(SharedItem(path=path, name=name, size_str=size_str, is_folder=is_folder))
    return items

def get_preview_items(state, max_items=None):
    items = []
    sorted_paths = sorted(state.shared_paths.keys())
    if max_items is not None: sorted_paths = sorted_paths[:max_items]
    for path in sorted_paths:
        full_item_path = SHARED_DIR / path.rstrip('/')
        is_folder = path.endswith('/')
        if is_folder: size_str = "Folder"
        elif full_item_path.exists(): size_str = f"{get_file_size_kb(full_item_path):,} KB"
        else: size_str = "N/A"
        name = os.path.basename(path.rstrip('/'))
        if is_folder: name += '/'
        item = {'name': name, 'size': size_str, 'is_folder': is_folder, 'path': path.lstrip('/')}
        if is_folder: item['download_url'] = f"/preview/{item['path'].rstrip('/')}?download=1"
        elif full_item_path.exists(): item['download_url'] = f"/preview/{item['path']}?download=1"
        else: item['download_url'] = None
        items.append(item)
    return items

def list_explorer_directory(state, requested_path):
    full_path = SHARED_DIR / requested_path if requested_path else SHARED_DIR
    return list_directory_entries(full_path, SHARED_DIR, state.shared_paths)

def update_selection(state, current_path, selected_paths, tags_map=None):
    if tags_map is None: tags_map = {}
    if not isinstance(state.shared_paths, dict): state.shared_paths = {}
    current_norm = normalize_path(current_path) if current_path else ''
    current_prefix = current_norm + '/' if current_norm else ''
    full_path = SHARED_DIR / current_path if current_path else SHARED_DIR
    visible_paths = set(get_visible_paths_in_directory(full_path))
    to_remove = set()
    for p in list(state.shared_paths):
        if p in visible_paths and p not in selected_paths: to_remove.add(p)
        elif current_prefix and p.startswith(current_prefix) and p not in selected_paths: to_remove.add(p)
    for p in to_remove: del state.shared_paths[p]
    for rel_path in selected_paths:
        if not rel_path: continue
        clean_path = normalize_path(rel_path)
        if rel_path.endswith('/') and clean_path and not clean_path.endswith('/'): clean_path += '/'
        if clean_path:
            if rel_path in tags_map: tag_val = tags_map[rel_path]
            elif clean_path in tags_map: tag_val = tags_map[clean_path]
            elif clean_path in state.shared_paths: tag_val = state.shared_paths[clean_path]
            else: tag_val = ""
            state.shared_paths[clean_path] = tag_val
    save_shared_paths(state.shared_paths)

def _matches_query(name, tags, query_terms):
    name_lower = name.lower()
    tags_lower = tags.lower() if tags else ""
    tag_list = [t.strip() for t in tags_lower.split(',') if t.strip()] if tags_lower else []
    for term in query_terms:
        if term in name_lower: continue
        if any(term in t for t in tag_list): continue
        return False
    return True

def search_network(state, query):
    q_raw = query.strip()
    if not q_raw: return []
    query_terms = [t.strip().lower() for t in q_raw.split(',') if t.strip()]
    if not query_terms: return []
    all_results = []
    sorted_live = get_sorted_live_peers(state)
    for pid, data in sorted_live:
        ip, port = data.ip, data.port
        try:
            if pid == state.my_id.value:
                for path, tags in list(state.shared_paths.items()):
                    name = os.path.basename(path.rstrip('/'))
                    if _matches_query(name, tags, query_terms):
                        is_folder = path.endswith('/')
                        full_item_path = SHARED_DIR / path.rstrip('/')
                        if is_folder: size_str = "Folder"
                        elif full_item_path.exists(): size_str = f"{get_file_size_kb(full_item_path):,} KB"
                        else: size_str = "N/A"
                        tag_display = f" [{tags}]" if tags else ""
                        all_results.append(SearchResult(bank_id=pid, name=name + ('/' if is_folder else '') + tag_display, size=size_str, is_folder=is_folder, link=f"/preview/{path.lstrip('/')}"))
            else:
                remote_items = fetch_peer_shared_list(ip, port)
                if remote_items:
                    for item in remote_items:
                        item_tags = item.get('tags', '')
                        if _matches_query(item['name'], item_tags, query_terms):
                            tag_display = f" [{item_tags}]" if item_tags else ""
                            all_results.append(SearchResult(bank_id=pid, name=item['name'] + tag_display, size=item['size'], is_folder=item['is_folder'], link=f"/peer_download/{pid}/{item['path'].lstrip('/')}"))
        except Exception as e:
            print(f"Search failed for peer {pid}: {e}")
    return all_results

def add_manual_peer(state, ip, port):
    peer_id = generate_peer_id_from_ip(ip)
    peer_info_data = fetch_peer_info(ip, port)
    if peer_info_data and 'id' in peer_info_data: peer_id = PeerId(peer_info_data['id'])
    info = PeerInfo(ip=ip, port=port, join_time=time.time(), last_seen=time.time())
    state.add_known_peer(peer_id.value, info)
    save_known_peers(state.known_peers)
    return peer_id

def update_peer_bookkeeping(state):
    now = time.time()
    state.known_peers[state.my_id.value] = PeerInfo(ip=state.public_ip if state.public_ip != "unknown" else state.local_ip, port=PORT, join_time=state.my_join_time, last_seen=now)
    save_known_peers(state.known_peers)

# ===========================================================================
# presentation/templates
# ===========================================================================
def render_homepage(random_id, failover_chain, peers_list, live_count, about_text, call_number=""):
    return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>Global Network Archive</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ background: #0d1117; color: #e6edf3; font-family: 'Inter', system-ui, sans-serif; margin-bottom: 60px; }}
        .card {{ background: #161b22; border: 1px solid #30363d; }}
        .card-header {{ background: #21262d; border-bottom: 1px solid #30363d; color: #58a6ff; }}
        a {{ color: #58a6ff; }}
        a:hover {{ color: #79c0ff; }}
        .btn-primary {{ background: #238636; border-color: #238636; }}
        .btn-primary:hover {{ background: #2ea043; }}
        .btn-outline-light {{ --bs-btn-color: #e6edf3; --bs-btn-border-color: #444d56; }}
        .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }}
        .table-hover tbody tr:hover {{ --bs-table-accent-bg: #21262d; }}
        .warning {{ background: #21262d; border-left: 4px solid #f0883e; color: #f2c46d; }}
        small {{ color: #8b949e; }}
        .preview-modal {{ position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1050; display: none; align-items: center; justify-content: center; }}
        .preview-modal .modal-dialog {{ max-width: 90vw; max-height: 90vh; width: 80vw !important; height: 80vh !important; margin: auto; }}
        .preview-modal .modal-content {{ display: flex !important; flex-direction: column !important; resize: both !important; overflow: hidden !important; height: 100% !important; width: 100% !important; background: #161b22 !important; border: 1px solid #30363d !important; border-radius: 8px !important; padding: 1rem !important; }}
        .preview-modal .preview-body {{ flex: 1; display: flex; flex-direction: column; border: 1px solid #30363d; border-radius: 4px; overflow: hidden; }}
        .preview-modal .preview-search {{ padding: 0.5rem; border-bottom: 1px solid #30363d; }}
        .preview-modal .preview-list {{ flex: 1; overflow-y: auto; padding: 0.5rem; }}
        .preview-modal .list-group {{ margin: 0; }}
        .form-control-lg {{ background: #161b22 !important; border-color: #444d56; color: white; }}
        .version-footer {{ position: fixed; bottom: 10px; left: 20px; font-size: 0.75rem; color: #6c757d; opacity: 0.7; z-index: 1000; }}
        .web-search-bar {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .web-search-bar input {{ background: #0d1117 !important; border-color: #444d56; color: #e6edf3; }}
        .web-search-bar input:focus {{ border-color: #58a6ff; box-shadow: 0 0 0 3px rgba(88,166,255,0.15); }}
        .search-engine-btns .btn {{ font-size: 0.8rem; padding: 4px 12px; margin: 2px; }}
        .search-engine-btns .btn.active {{ background: #238636; border-color: #238636; }}
        .web-result {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 14px 18px; margin-bottom: 10px; transition: border-color 0.2s; }}
        .web-result:hover {{ border-color: #58a6ff; }}
        .web-result-title {{ color: #58a6ff; font-size: 1.05rem; font-weight: 600; text-decoration: none; display: block; margin-bottom: 4px; }}
        .web-result-title:hover {{ color: #79c0ff; text-decoration: underline; }}
        .web-result-url {{ color: #3fb950; font-size: 0.8rem; margin-bottom: 4px; word-break: break-all; }}
        .web-result-snippet {{ color: #8b949e; font-size: 0.9rem; line-height: 1.4; }}
        .web-search-meta {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 15px; }}
        .remote-access-alert {{ background: linear-gradient(135deg, #da3633 0%, #b62324 100%); border: 2px solid #f85149; color: white; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; display: none; align-items: center; justify-content: space-between; animation: pulse-border 2s infinite; }}
        @keyframes pulse-border {{ 0%, 100% {{ border-color: #f85149; box-shadow: 0 0 8px rgba(248,81,73,0.3); }} 50% {{ border-color: #ff7b72; box-shadow: 0 0 16px rgba(248,81,73,0.6); }} }}
        .remote-access-alert .remote-info {{ display: flex; align-items: center; gap: 12px; }}
        .remote-access-alert .remote-icon {{ font-size: 1.5rem; }}
        .upload-modal {{ position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1060; display: none; align-items: center; justify-content: center; }}
        .upload-modal .upload-dialog {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 28px; width: 500px; max-width: 90vw; }}
        .incoming-upload-banner {{ background: linear-gradient(135deg, #1f6feb 0%, #1a4fa0 100%); border: 2px solid #58a6ff; color: white; padding: 15px 20px; border-radius: 8px; margin-bottom: 15px; display: none; align-items: center; justify-content: space-between; animation: pulse-blue 2s infinite; }}
        @keyframes pulse-blue {{ 0%, 100% {{ border-color: #58a6ff; box-shadow: 0 0 8px rgba(88,166,255,0.3); }} 50% {{ border-color: #79c0ff; box-shadow: 0 0 16px rgba(88,166,255,0.6); }} }}
        .gna-modal {{ position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1060; display: none; align-items: center; justify-content: center; }}
        .gna-modal .gna-dialog {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 28px; width: 600px; max-width: 92vw; max-height: 85vh; overflow-y: auto; }}
        .ping-result {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 14px; font-family: monospace; font-size: 0.9rem; }}
        .ping-ok {{ color: #3fb950; }} .ping-warn {{ color: #d29922; }} .ping-fail {{ color: #f85149; }}
        .file-tree-item {{ padding: 6px 12px; border-bottom: 1px solid #21262d; cursor: pointer; transition: background 0.15s; display: flex; align-items: center; justify-content: space-between; }}
        .file-tree-item:hover {{ background: #21262d; }}
        .sync-status {{ font-size: 0.8rem; padding: 3px 8px; border-radius: 4px; }}
        .sync-active {{ background: #238636; color: white; }} .sync-idle {{ background: #30363d; color: #8b949e; }}
        .term-output {{ background: #000; color: #0f0; font-family: 'Consolas', 'Courier New', monospace; font-size: 0.85rem; padding: 12px; border-radius: 6px; max-height: 350px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid #30363d; }}
        .term-input {{ background: #0d1117; color: #0f0; font-family: 'Consolas', monospace; border: 1px solid #30363d; }}
        .term-input:focus {{ border-color: #f85149; box-shadow: 0 0 0 3px rgba(248,81,73,0.2); color: #0f0; background: #0d1117; }}
        .power-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
        .power-grid .btn {{ padding: 16px; font-size: 0.95rem; }}
        .bw-bar {{ background: #21262d; border-radius: 6px; overflow: hidden; height: 24px; }}
        .bw-fill {{ height: 100%; background: linear-gradient(90deg, #238636, #3fb950); transition: width 0.3s; border-radius: 6px; }}
        .screenshot-img {{ max-width: 100%; border-radius: 6px; border: 1px solid #30363d; cursor: pointer; }}
        .sysinfo-grid {{ display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; font-size: 0.88rem; }}
        .sysinfo-grid .si-label {{ color: #8b949e; text-align: right; }} .sysinfo-grid .si-val {{ color: #e6edf3; word-break: break-word; }}
        .proc-table {{ font-size: 0.82rem; }} .proc-table th {{ position: sticky; top: 0; background: #161b22; z-index: 1; }}
        .proc-list-wrap {{ max-height: 400px; overflow-y: auto; border: 1px solid #30363d; border-radius: 6px; }}
        .screenrec-frame {{ max-width: 100%; border-radius: 6px; border: 1px solid #30363d; }}
        .rec-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #f85149; animation: recPulse 1s infinite; margin-right: 6px; }}
        @keyframes recPulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} }}
        .audio-visualizer {{ height: 60px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; display: flex; align-items: flex-end; gap: 2px; padding: 4px 8px; }}
        .audio-bar {{ flex: 1; background: #3fb950; border-radius: 2px 2px 0 0; transition: height 0.15s; min-height: 2px; }}
        .keylog-feed {{ background: #0d1117; color: #e6edf3; font-family: 'Consolas', monospace; font-size: 0.82rem; padding: 12px; border: 1px solid #30363d; border-radius: 6px; max-height: 350px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; min-height: 100px; }}
        .keylog-key {{ color: #58a6ff; }} .keylog-special {{ color: #d29922; }} .keylog-mouse {{ color: #f85149; }} .keylog-time {{ color: #8b949e; font-size: 0.75rem; }}
        .perm-badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px; margin: 1px 2px; font-weight: 600; }}
        .perm-on {{ background: #1a3a1a; color: #3fb950; border: 1px solid #238636; }}
        .perm-off {{ background: #2a1a1a; color: #6e4040; border: 1px solid #3d2020; }}
    </style>
</head>
<body class="p-5">
<div class="container">
    <div id="remote-access-banner" class="remote-access-alert">
        <div class="remote-info">
            <span class="remote-icon">WARNING</span>
            <div>
                <strong>REMOTE ACCESS ACTIVE</strong><br>
                <span id="remote-access-detail">Someone is currently controlling your system.</span>
            </div>
        </div>
        <button class="btn btn-light btn-sm fw-bold" onclick="revokeRemoteAccess()" id="revoke-remote-btn">Revoke Access</button>
    </div>
    <div id="incoming-uploads-container"></div>
    <div class="warning p-3 mb-5 rounded">
        <strong>SELECTIVE SHARING ACTIVE</strong><br>
        Only explicitly selected content is visible to others.
    </div>
    <h1 class="text-center mb-5">Global Network Archive</h1>
    <div class="mb-5 text-center">
        <form action="/search" method="get" class="d-inline-flex w-75">
            <input type="text" name="q" class="form-control form-control-lg me-3 bg-dark text-white border-secondary" placeholder="Search across all live instances..." required autofocus>
            <button type="submit" class="btn btn-primary btn-lg px-5">Search</button>
        </form>
    </div>
    <ul class="nav nav-tabs mb-5 justify-content-center border-bottom-0">
        <li class="nav-item"><a class="nav-link active text-white" data-bs-toggle="tab" href="#dashboard">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link text-white" href="/explorer">My Explorer</a></li>
        <li class="nav-item"><a class="nav-link text-white" href="/vault">Vault</a></li>
        <li class="nav-item"><a class="nav-link text-white" data-bs-toggle="tab" href="#websearch">Web Search</a></li>
        <li class="nav-item"><a class="nav-link text-white" data-bs-toggle="tab" href="#about">About</a></li>
    </ul>
    <div class="tab-content">
        <div class="tab-pane fade show active" id="dashboard">
            <div class="row g-4">
                <div class="col-lg-8">
                    <div class="card mb-4">
                        <div class="card-header">Your Instance</div>
                        <div class="card-body">
                            <p><strong>ID:</strong> {random_id} <small class="text-secondary">(session-based)</small></p>
                            <p><strong>Call Number:</strong> <span class="text-warning">{call_number}</span></p>
                            <p><strong>Role:</strong> Primary</p>
                            <a href="/explorer" class="btn btn-primary btn-lg w-100 mt-3">Manage Shared Content</a>
                        </div>
                    </div>
                </div>
                <div class="col-lg-4">
                    <div class="card mb-4">
                        <div class="card-header">Failover Chain</div>
                        <div class="card-body p-0">
                            <table class="table table-sm mb-0">
                                <thead><tr><th>Role</th><th>ID</th></tr></thead>
                                <tbody>{"".join(f"<tr><td>{c['role']}</td><td>{c['id']}</td></tr>" for c in failover_chain)}</tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card mb-4">
                <div class="card-header">Connect to Remote Instance</div>
                <div class="card-body">
                    <form method="post" action="/add_peer">
                        <input type="text" name="ip_port" class="form-control mb-3 bg-dark text-white border-secondary" placeholder="e.g., 192.168.1.100:5000" required>
                        <button type="submit" class="btn btn-outline-light w-100">Connect</button>
                    </form>
                </div>
            </div>
            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span>Active Instances — {live_count}</span>
                    <button class="btn btn-sm btn-outline-success" id="reconnect-relay-btn" onclick="reconnectRelay()">Reconnect Relay</button>
                </div>
                <div class="card-body p-0">
                    <table class="table table-hover mb-0">
                        <thead><tr><th>ID</th><th>Shared Items</th><th>Actions</th></tr></thead>
                        <tbody>
                        {''.join(
                            f'<tr>'
                            f'<td>{p["id"]}<br><small class="text-muted">Call#: {p.get("call_number", "N/A")}</small></td>'
                            f'<td><span class="shared-count text-secondary" data-peer-id="{p["id"]}">Loading...</span></td>'
                            f'<td>'
                            f' <button class="btn btn-sm btn-outline-info me-1 preview-btn" data-peer-id="{p["id"]}">Preview</button>'
                            f' <button class="btn btn-sm btn-outline-light me-1 connect-btn" data-peer-id="{p["id"]}">Connect</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 view-screen-btn" data-peer-id="{p["id"]}">View Screen</button>'
                            f' <button class="btn btn-sm btn-outline-warning call-btn" data-peer-id="{p["id"]}">Call this PC</button>'
                            f' <button class="btn btn-sm btn-outline-primary me-1 upload-btn" data-peer-id="{p["id"]}">Upload</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 ping-btn" data-peer-id="{p["id"]}">Ping</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 request-file-btn" data-peer-id="{p["id"]}">Request File</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 sync-folder-btn" data-peer-id="{p["id"]}">Sync Folder</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 remote-term-btn" data-peer-id="{p["id"]}">Terminal</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 clipboard-btn" data-peer-id="{p["id"]}">Clipboard</button>'
                            f' <button class="btn btn-sm btn-outline-warning me-1 power-btn" data-peer-id="{p["id"]}">Power</button>'
                            f' <button class="btn btn-sm btn-outline-secondary me-1 bw-test-btn" data-peer-id="{p["id"]}">Speed Test</button>'
                            f' <button class="btn btn-sm btn-outline-light me-1 screenshot-btn" data-peer-id="{p["id"]}">Screenshot</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 sysinfo-btn" data-peer-id="{p["id"]}">Sys Info</button>'
                            f' <button class="btn btn-sm btn-outline-warning me-1 notify-btn" data-peer-id="{p["id"]}">Notify</button>'
                            f' <button class="btn btn-sm btn-outline-danger me-1 procmgr-btn" data-peer-id="{p["id"]}">Processes</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 screenrec-btn" data-peer-id="{p["id"]}">Record</button>'
                            f' <button class="btn btn-sm btn-outline-info me-1 remote-audio-btn" data-peer-id="{p["id"]}">Mic Audio</button>'
                            f' <button class="btn btn-sm btn-outline-success me-1 sys-audio-btn" data-peer-id="{p["id"]}">Sys Audio</button>'
                            f' <button class="btn btn-sm btn-outline-warning me-1 input-monitor-btn" data-peer-id="{p["id"]}">Keylog</button>'
                            f'<div class="mt-1 peer-perms-row" data-peer-id="{p["id"]}" style="font-size:0.7rem;"></div>'
                            f'</td></tr>'
                            for p in peers_list
                        )}
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="card mb-4 mt-3">
                <div class="card-header"><span style="color:#d29922;">Remote Permissions</span> <small class="text-secondary ms-2">— controls what OTHER peers can do to YOUR machine</small></div>
                <div class="card-body">
                    <div class="d-flex flex-wrap gap-3" id="permToggles">
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_remote_exec" onchange="togglePerm('remote_exec', this.checked)">
                            <label class="form-check-label small" for="perm_remote_exec">Remote Terminal</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_clipboard_write" onchange="togglePerm('clipboard_write', this.checked)">
                            <label class="form-check-label small" for="perm_clipboard_write">Clipboard Write</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_clipboard_read" onchange="togglePerm('clipboard_read', this.checked)">
                            <label class="form-check-label small" for="perm_clipboard_read">Clipboard Read</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_power_control" onchange="togglePerm('power_control', this.checked)">
                            <label class="form-check-label small" for="perm_power_control">Power Control</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_screenshot" onchange="togglePerm('screenshot', this.checked)">
                            <label class="form-check-label small" for="perm_screenshot">Screenshot</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_notify" onchange="togglePerm('notify', this.checked)">
                            <label class="form-check-label small" for="perm_notify">Notifications</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_process_manager" onchange="togglePerm('process_manager', this.checked)">
                            <label class="form-check-label small" for="perm_process_manager">Process Manager</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_screen_record" onchange="togglePerm('screen_record', this.checked)">
                            <label class="form-check-label small" for="perm_screen_record">Screen Record</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_remote_audio" onchange="togglePerm('remote_audio', this.checked)">
                            <label class="form-check-label small" for="perm_remote_audio">Mic Audio</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_system_audio" onchange="togglePerm('system_audio', this.checked)">
                            <label class="form-check-label small" for="perm_system_audio">System Audio</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="perm_input_monitor" onchange="togglePerm('input_monitor', this.checked)">
                            <label class="form-check-label small" for="perm_input_monitor">Input Monitor</label>
                        </div>
                    </div>
                    <small class="text-secondary mt-2 d-block">All off by default. Enable only for trusted networks.</small>
                </div>
            </div>
        </div>
        <div class="tab-pane fade" id="websearch">
            <div class="web-search-bar">
                <h5 class="mb-3" style="color:#58a6ff;">Web Search</h5>
                <div class="d-flex">
                    <input type="text" id="webSearchInput" class="form-control form-control-lg me-3" placeholder="Search the web..." autocomplete="off">
                    <button class="btn btn-primary btn-lg px-4" onclick="doWebSearch()">Search</button>
                </div>
                <div class="mt-3 search-engine-btns">
                    <span class="text-secondary me-2" style="font-size:0.85rem;">Also try:</span>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('google')">Google</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('bing')">Bing</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('yahoo')">Yahoo</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('duckduckgo')">DuckDuckGo</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('brave')">Brave</button>
                    <button class="btn btn-sm btn-outline-light" onclick="openEngine('wikipedia')">Wikipedia</button>
                </div>
            </div>
            <div id="webSearchMeta" class="web-search-meta" style="display:none;"></div>
            <div id="webSearchResults"></div>
            <div id="webSearchLoading" style="display:none;" class="text-center py-5">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-3 text-secondary">Searching the web...</p>
            </div>
        </div>
        <div class="tab-pane fade" id="about">
            <div class="card">
                <div class="card-body">
                    {about_text}
                </div>
            </div>
        </div>
    </div>
</div>
<div class="version-footer">v{VERSION}</div>
<div id="previewModal" class="preview-modal">
    <div class="modal-dialog modal-lg">
        <div id="previewContent" class="modal-content"></div>
    </div>
</div>
<div id="uploadModal" class="upload-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="upload-dialog">
        <h5 class="mb-3" style="color:#58a6ff;">Upload File to Peer</h5>
        <p class="text-secondary small mb-3">Select a file and choose where to place it on the remote PC.</p>
        <form id="uploadForm" enctype="multipart/form-data">
            <input type="hidden" id="uploadTargetPeerId" value="">
            <div class="mb-3">
                <label class="form-label small">Target Peer:</label>
                <div id="uploadTargetDisplay" class="text-warning fw-bold"></div>
            </div>
            <div class="mb-3">
                <label class="form-label small">File to send:</label>
                <input type="file" id="uploadFile" name="file" class="form-control bg-dark text-white border-secondary" required>
            </div>
            <div class="mb-3">
                <label class="form-label small">Destination path on remote PC:</label>
                <input type="text" id="uploadDestPath" name="dest_path" class="form-control bg-dark text-white border-secondary" placeholder="e.g. Desktop/received_files/" value="Desktop/">
                <small class="text-muted">Relative to the remote user's home directory</small>
            </div>
            <div id="uploadStatus" class="mb-3" style="display:none;"></div>
            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary flex-fill" id="uploadPlaceBtn">Place</button>
                <button type="button" class="btn btn-outline-light flex-fill" onclick="document.getElementById('uploadModal').style.display='none'">Cancel</button>
            </div>
        </form>
    </div>
</div>
<div id="requestFileModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-3" style="color:#58a6ff;">Request File from Peer</h5>
        <p class="text-secondary small mb-2">Browse the peer's shared files and download what you need.</p>
        <input type="hidden" id="rfTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="rfTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-2">
            <input type="text" id="rfSearchInput" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Filter files..." oninput="filterRequestFiles()">
        </div>
        <div id="rfLoading" class="text-center py-3" style="display:none;"><div class="spinner-border spinner-border-sm text-primary"></div> Loading shared files...</div>
        <div id="rfFileList" style="max-height:350px;overflow-y:auto;border:1px solid #30363d;border-radius:6px;"></div>
        <div id="rfStatus" class="mt-2" style="display:none;"></div>
        <div class="d-flex gap-2 mt-3">
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('requestFileModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="syncFolderModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-3" style="color:#58a6ff;">Sync Folder with Peer</h5>
        <p class="text-secondary small mb-3">Keep a local folder in sync with a peer's shared folder. New or updated files are copied automatically.</p>
        <input type="hidden" id="sfTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="sfTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-3">
            <label class="form-label small">Local folder to sync into:</label>
            <input type="text" id="sfLocalPath" class="form-control bg-dark text-white border-secondary" placeholder="e.g. Desktop/synced/" value="Desktop/synced/">
            <small class="text-muted">Relative to your home directory</small>
        </div>
        <div class="mb-3">
            <label class="form-label small">Remote folder to sync from (leave empty for all shared):</label>
            <input type="text" id="sfRemotePath" class="form-control bg-dark text-white border-secondary" placeholder="/ (root of shared content)" value="">
        </div>
        <div id="sfStatus" class="mb-3" style="display:none;"></div>
        <div id="sfActiveSyncs"></div>
        <div class="d-flex gap-2 mt-3">
            <button class="btn btn-success flex-fill" id="sfStartBtn" onclick="startSync()">Start Sync</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('syncFolderModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="remoteTermModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#f85149;">Remote Terminal</h5>
        <p class="text-secondary small mb-2">Execute commands on the remote peer. <strong class="text-danger">Use responsibly.</strong></p>
        <input type="hidden" id="rtTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="rtTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="rtOutput" class="term-output mb-2">Ready. Type a command below.\n</div>
        <div class="d-flex gap-2">
            <input type="text" id="rtCmdInput" class="form-control term-input flex-fill" placeholder="Enter command..." autocomplete="off">
            <button class="btn btn-danger" id="rtSendBtn" onclick="sendTermCmd()">Run</button>
        </div>
        <div class="d-flex gap-2 mt-3">
            <button class="btn btn-outline-secondary flex-fill" onclick="document.getElementById('rtOutput').textContent='Ready.\\n'">Clear</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('remoteTermModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="clipboardModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#58a6ff;">Clipboard Sync</h5>
        <p class="text-secondary small mb-2">Send your clipboard to the peer, or grab theirs.</p>
        <input type="hidden" id="cbTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="cbTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-3">
            <label class="form-label small">Text to send (or paste here):</label>
            <textarea id="cbTextArea" class="form-control bg-dark text-white border-secondary" rows="4" placeholder="Paste or type text to send..."></textarea>
        </div>
        <div id="cbStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-primary flex-fill" onclick="sendClipboard()">Send to Peer</button>
            <button class="btn btn-outline-info flex-fill" onclick="grabClipboard()">Grab from Peer</button>
        </div>
        <div class="d-flex gap-2 mt-2">
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('clipboardModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="powerModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#d29922;">Power Control</h5>
        <p class="text-secondary small mb-3">Send power commands to the remote peer.</p>
        <input type="hidden" id="pwTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="pwTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="pwStatus" class="mb-3" style="display:none;"></div>
        <div class="power-grid mb-3">
            <button class="btn btn-outline-success" onclick="sendPowerCmd('wake')">Wake (WOL)</button>
            <button class="btn btn-outline-warning" onclick="sendPowerCmd('sleep')">Sleep</button>
            <button class="btn btn-outline-info" onclick="sendPowerCmd('restart')">Restart</button>
            <button class="btn btn-outline-danger" onclick="sendPowerCmd('shutdown')">Shutdown</button>
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('powerModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="bwTestModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#3fb950;">Bandwidth / Speed Test</h5>
        <p class="text-secondary small mb-3">Measure transfer speed between you and a peer.</p>
        <input type="hidden" id="bwTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="bwTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="bwResults" class="mb-3" style="display:none;">
            <div class="mb-2"><small class="text-secondary">Download from peer:</small>
                <div class="bw-bar"><div id="bwDlBar" class="bw-fill" style="width:0%"></div></div>
                <span id="bwDlSpeed" class="text-white small">—</span>
            </div>
            <div class="mb-2"><small class="text-secondary">Upload to peer:</small>
                <div class="bw-bar"><div id="bwUlBar" class="bw-fill" style="width:0%;background:linear-gradient(90deg,#1f6feb,#58a6ff);"></div></div>
                <span id="bwUlSpeed" class="text-white small">—</span>
            </div>
            <div><small class="text-secondary">Latency:</small> <span id="bwLatency" class="text-white small">—</span></div>
        </div>
        <div id="bwStatus" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-success flex-fill" id="bwStartBtn" onclick="runBwTest()">Start Speed Test</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('bwTestModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="screenshotModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#e6edf3;">Screenshot Capture</h5>
        <input type="hidden" id="ssTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="ssTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="ssStatus" class="mb-2" style="display:none;"></div>
        <div id="ssImageContainer" class="text-center mb-3" style="display:none;">
            <img id="ssImage" class="screenshot-img" src="" alt="Screenshot" onclick="window.open(this.src, '_blank')">
            <small class="d-block text-secondary mt-1">Click image to open full size</small>
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-light flex-fill" id="ssCaptureBtn" onclick="captureScreenshot()">Capture Screenshot</button>
            <button class="btn btn-success flex-fill" id="ssSaveBtn" onclick="saveScreenshot()" style="display:none;">Save Screenshot</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('screenshotModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="sysinfoModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:650px;">
        <h5 class="mb-2" style="color:#58a6ff;">System Information</h5>
        <input type="hidden" id="siTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="siTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="siStatus" class="mb-2" style="display:none;"></div>
        <div id="siContent" class="mb-3" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-info flex-fill" id="siRefreshBtn" onclick="fetchSysInfo()">Refresh</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('sysinfoModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="notifyModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog">
        <h5 class="mb-2" style="color:#d29922;">Send Notification</h5>
        <p class="text-secondary small mb-2">Send a pop-up alert to the remote peer's desktop.</p>
        <input type="hidden" id="ntTargetPeerId" value="">
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="ntTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-3">
            <label class="form-label small">Title:</label>
            <input type="text" id="ntTitle" class="form-control bg-dark text-white border-secondary" placeholder="Notification title" value="Message from GNA">
        </div>
        <div class="mb-3">
            <label class="form-label small">Message:</label>
            <textarea id="ntMessage" class="form-control bg-dark text-white border-secondary" rows="3" placeholder="Your message..."></textarea>
        </div>
        <div id="ntStatus" class="mb-2" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-warning flex-fill" onclick="sendNotify()">Send Notification</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('notifyModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="procMgrModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:800px;">
        <h5 class="mb-2" style="color:#f85149;">Process Manager</h5>
        <input type="hidden" id="pmTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="pmTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div class="mb-2 d-flex gap-2">
            <input type="text" id="pmFilter" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Filter processes..." oninput="filterProcs()">
            <button class="btn btn-sm btn-outline-info" id="pmRefreshBtn" onclick="fetchProcesses()">Refresh</button>
        </div>
        <div id="pmStatus" class="mb-2" style="display:none;"></div>
        <div class="proc-list-wrap mb-3">
            <table class="table table-dark table-sm proc-table mb-0">
                <thead><tr><th>PID</th><th>Name</th><th>CPU %</th><th>Memory</th><th></th></tr></thead>
                <tbody id="pmProcList"></tbody>
            </table>
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('procMgrModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="screenRecModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:750px;">
        <h5 class="mb-2" style="color:#3fb950;">Screen Record</h5>
        <input type="hidden" id="srTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="srTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="srRecIndicator" class="mb-2" style="display:none;"><span class="rec-dot"></span><span class="text-danger small fw-bold">Recording</span> <span id="srFrameCount" class="text-secondary small ms-2"></span></div>
        <div id="srStatus" class="mb-2" style="display:none;"></div>
        <div id="srFrameContainer" class="text-center mb-3" style="display:none;">
            <img id="srFrame" class="screenrec-frame" src="" alt="Screen frame">
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-success flex-fill" id="srStartBtn" onclick="startScreenRec()">Start Recording</button>
            <button class="btn btn-danger flex-fill" id="srStopBtn" onclick="stopScreenRec()" style="display:none;">Stop Recording</button>
            <button class="btn btn-info flex-fill" id="srSaveBtn" onclick="saveRecording()" style="display:none;">Save Recording</button>
            <button class="btn btn-outline-light flex-fill" onclick="stopScreenRec(); document.getElementById('screenRecModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="remoteAudioModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:600px;">
        <h5 class="mb-2" style="color:#3fb950;">Mic Audio</h5>
        <p class="text-secondary small mb-2">Listen to the remote peer's microphone — continuous tap.</p>
        <input type="hidden" id="raTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="raTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="raListenIndicator" class="mb-2" style="display:none;"><span class="rec-dot" style="background:#3fb950;"></span><span class="text-success small fw-bold">Listening — continuous mic tap</span></div>
        <div id="raStatus" class="mb-2" style="display:none;"></div>
        <div class="audio-visualizer mb-3" id="raVisualizer" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-success flex-fill" id="raStartBtn" onclick="startRemoteAudio()">Start Listening</button>
            <button class="btn btn-danger flex-fill" id="raStopBtn" onclick="stopRemoteAudio()" style="display:none;">Stop Listening</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('remoteAudioModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="sysAudioModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:600px;">
        <h5 class="mb-2" style="color:#58a6ff;">System Audio</h5>
        <p class="text-secondary small mb-2">Listen to what's playing on the remote peer's desktop (YouTube, Spotify, games, etc.).</p>
        <input type="hidden" id="saTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="saTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="saListenIndicator" class="mb-2" style="display:none;"><span class="rec-dot" style="background:#58a6ff;"></span><span class="text-info small fw-bold">Listening — system audio</span></div>
        <div id="saStatus" class="mb-2" style="display:none;"></div>
        <div class="audio-visualizer mb-3" id="saVisualizer" style="display:none;"></div>
        <div class="d-flex gap-2">
            <button class="btn btn-primary flex-fill" id="saStartBtn" onclick="startSysAudio()">Start Listening</button>
            <button class="btn btn-danger flex-fill" id="saStopBtn" onclick="stopSysAudio()" style="display:none;">Stop Listening</button>
            <button class="btn btn-outline-light flex-fill" onclick="document.getElementById('sysAudioModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<div id="inputMonitorModal" class="gna-modal" onclick="if(event.target===this)this.style.display='none'">
    <div class="gna-dialog" style="width:700px;">
        <h5 class="mb-2" style="color:#d29922;">Input Monitor</h5>
        <p class="text-secondary small mb-2">Monitor keystrokes and mouse activity on the remote peer.</p>
        <input type="hidden" id="imTargetPeerId" value="">
        <div class="mb-2 d-flex align-items-center gap-2">
            <span class="text-secondary small">Peer:</span>
            <span id="imTargetDisplay" class="text-warning fw-bold"></span>
        </div>
        <div id="imRecIndicator" class="mb-2" style="display:none;"><span class="rec-dot"></span><span class="text-danger small fw-bold">Monitoring</span> <span id="imEventCount" class="text-secondary small ms-2"></span></div>
        <div id="imStatus" class="mb-2" style="display:none;"></div>
        <div class="keylog-feed mb-3" id="imFeed" style="display:none;"><span class="text-secondary">Waiting for input events...</span></div>
        <div class="d-flex gap-2">
            <button class="btn btn-warning flex-fill" id="imStartBtn" onclick="startInputMonitor()">Start Monitoring</button>
            <button class="btn btn-danger flex-fill" id="imStopBtn" onclick="stopInputMonitor()" style="display:none;">Stop Monitoring</button>
            <button class="btn btn-outline-secondary flex-fill" id="imClearBtn" onclick="document.getElementById('imFeed').innerHTML=''" style="display:none;">Clear</button>
            <button class="btn btn-outline-light flex-fill" onclick="stopInputMonitor(); document.getElementById('inputMonitorModal').style.display='none'">Close</button>
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<script>
let _liveSocket = null;
try {{
    _liveSocket = io('http://localhost:3000', {{ transports: ['websocket', 'polling'] }});
    _liveSocket.on('connect', function() {{ _liveSocket.emit('dashboard-join', {{ peerId: '{random_id}' }}); }});
    _liveSocket.on('share-updated', function(data) {{ refreshSharedCounts(); setTimeout(function() {{ window.location.reload(); }}, 2000); }});
}} catch(e) {{ console.warn('Socket.IO live session unavailable:', e); }}
function refreshSharedCounts() {{
    document.querySelectorAll('.shared-count').forEach(function(span) {{
        const peerId = span.getAttribute('data-peer-id');
        fetch('/peer_shared_count/' + peerId).then(function(r) {{ return r.json(); }}).then(function(data) {{ span.textContent = data.count + ' items'; span.classList.remove('text-secondary'); span.classList.add('text-white'); }}).catch(function() {{ span.textContent = 'N/A'; }});
    }});
}}
refreshSharedCounts();
setInterval(function() {{ fetch('/api/peers').then(function(r) {{ return r.json(); }}).then(function(peers) {{ refreshSharedCounts(); }}).catch(function() {{}}); }}, 5000);
let _activeRemoteSessions = [];
function checkRemoteAccessStatus() {{ fetch('http://localhost:3000/api/remote-access-status').then(r => r.json()).then(data => {{ _activeRemoteSessions = data.sessions || []; updateRemoteBanner(); }}).catch(() => {{}}); }}
function updateRemoteBanner() {{
    const banner = document.getElementById('remote-access-banner');
    const detail = document.getElementById('remote-access-detail');
    const myId = '{random_id}';
    const mySessions = _activeRemoteSessions.filter(s => s.sessionId === myId);
    if (mySessions.length > 0) {{ const s = mySessions[0]; const name = s.remoteName || s.remotePeerId || 'Unknown'; detail.textContent = name + ' is currently controlling your system.'; banner.style.display = 'flex'; banner.setAttribute('data-session-id', s.sessionId); }} else {{ banner.style.display = 'none'; }}
}}
function revokeRemoteAccess() {{
    const banner = document.getElementById('remote-access-banner');
    const sessionId = banner.getAttribute('data-session-id');
    if (!sessionId) return;
    const btn = document.getElementById('revoke-remote-btn');
    btn.textContent = 'Revoking...'; btn.disabled = true;
    fetch('http://localhost:3000/api/remote-access-revoke', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ sessionId: sessionId }}) }}).then(r => r.json()).then(data => {{ banner.style.display = 'none'; btn.textContent = 'Revoke Access'; btn.disabled = false; }}).catch(() => {{ btn.textContent = 'Revoke Access'; btn.disabled = false; }});
}}
if (_liveSocket) {{
    _liveSocket.on('remote-access-status', function(data) {{
        if (data.active) {{ const idx = _activeRemoteSessions.findIndex(s => s.sessionId === data.sessionId); if (idx >= 0) {{ _activeRemoteSessions[idx] = data; }} else {{ _activeRemoteSessions.push(data); }} }} else {{ _activeRemoteSessions = _activeRemoteSessions.filter(s => s.sessionId !== data.sessionId); }}
        updateRemoteBanner();
    }});
}}
checkRemoteAccessStatus();
setInterval(checkRemoteAccessStatus, 10000);
function reconnectRelay() {{
    const btn = document.getElementById('reconnect-relay-btn');
    btn.textContent = 'Reconnecting...'; btn.disabled = true;
    fetch('/api/global-reconnect', {{ method: 'POST' }}).then(r => r.json()).then(data => {{ btn.textContent = data.status === 'ok' ? 'Relay Connected' : 'Reconnect Relay'; btn.disabled = false; setTimeout(() => {{ btn.textContent = 'Reconnect Relay'; }}, 3000); }}).catch(() => {{ btn.textContent = 'Reconnect Relay'; btn.disabled = false; }});
}}
document.querySelectorAll('.preview-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const modal = document.getElementById('previewModal');
        const content = document.getElementById('previewContent');
        content.innerHTML = '<div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div><p class="mt-3">Loading preview...</p></div>';
        modal.style.display = 'flex';
        fetch('/peer_preview/' + peerId).then(r => {{ if (!r.ok) throw new Error(r.status + ' ' + r.statusText); return r.text(); }}).then(html => {{ content.innerHTML = html; }}).catch(err => {{ content.innerHTML = '<div class="alert alert-warning m-4">Could not load preview<br><small>' + (err.message || err) + '</small><br><br><small>(Remote peers need port 5000 open & forwarded.)</small></div>'; }});
    }});
}});
document.querySelectorAll('.connect-btn').forEach(btn => {{ btn.addEventListener('click', function() {{ window.location.href = '/peer_connect/' + this.getAttribute('data-peer-id'); }}); }});
document.querySelectorAll('.view-screen-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        fetch('/launch_screen_viewer/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{ if (data.success) {{ alert('Screen viewer launched for ' + peerId); }} else {{ alert('Failed to launch viewer: ' + (data.error || 'Unknown error')); }} }}).catch(err => {{ alert('Error launching viewer: ' + err.message); }});
    }});
}});
document.querySelectorAll('.call-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const self = this;
        fetch('/launch_call/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{ if (data.success) {{ self.textContent = 'Calling...'; self.disabled = true; setTimeout(() => {{ self.textContent = 'Call this PC'; self.disabled = false; }}, 10000); }} else {{ alert('Failed to start call: ' + (data.error || 'Unknown error')); }} }}).catch(err => {{ alert('Error starting call: ' + err.message); }});
    }});
}});
document.getElementById('previewModal').addEventListener('click', function(e) {{ if (e.target === this) {{ this.style.display = 'none'; }} }});
document.querySelectorAll('.upload-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('uploadTargetPeerId').value = peerId;
        document.getElementById('uploadTargetDisplay').textContent = peerId;
        document.getElementById('uploadFile').value = '';
        document.getElementById('uploadDestPath').value = 'Desktop/';
        document.getElementById('uploadStatus').style.display = 'none';
        document.getElementById('uploadPlaceBtn').disabled = false;
        document.getElementById('uploadPlaceBtn').textContent = 'Place';
        document.getElementById('uploadModal').style.display = 'flex';
    }});
}});
document.getElementById('uploadForm').addEventListener('submit', function(e) {{
    e.preventDefault();
    const peerId = document.getElementById('uploadTargetPeerId').value;
    const fileInput = document.getElementById('uploadFile');
    const destPath = document.getElementById('uploadDestPath').value.trim();
    const statusDiv = document.getElementById('uploadStatus');
    const placeBtn = document.getElementById('uploadPlaceBtn');
    if (!fileInput.files.length) {{ statusDiv.innerHTML = '<div class="alert alert-warning py-2">Please select a file.</div>'; statusDiv.style.display = 'block'; return; }}
    if (!destPath) {{ statusDiv.innerHTML = '<div class="alert alert-warning py-2">Please enter a destination path.</div>'; statusDiv.style.display = 'block'; return; }}
    placeBtn.disabled = true; placeBtn.textContent = 'Sending...';
    statusDiv.innerHTML = '<div class="text-info small">Uploading file to peer...</div>'; statusDiv.style.display = 'block';
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('dest_path', destPath);
    fetch('/upload_to_peer/' + peerId, {{ method: 'POST', body: formData }}).then(r => r.json()).then(data => {{
        if (data.success) {{
            statusDiv.innerHTML = '<div class="alert alert-success py-2">File sent! Waiting for ' + peerId + ' to accept.</div>';
            placeBtn.textContent = 'Sent';
            setTimeout(() => {{ document.getElementById('uploadModal').style.display = 'none'; }}, 3000);
        }} else {{
            statusDiv.innerHTML = '<div class="alert alert-danger py-2">Failed: ' + (data.error || 'Unknown error') + '</div>';
            placeBtn.disabled = false; placeBtn.textContent = 'Place';
        }}
    }}).catch(err => {{
        statusDiv.innerHTML = '<div class="alert alert-danger py-2">Error: ' + err.message + '</div>';
        placeBtn.disabled = false; placeBtn.textContent = 'Place';
    }});
}});
function checkIncomingUploads() {{
    fetch('/api/pending-uploads').then(r => r.json()).then(data => {{
        const container = document.getElementById('incoming-uploads-container');
        const uploads = data.uploads || [];
        if (uploads.length === 0) {{ container.innerHTML = ''; return; }}
        let html = '';
        uploads.forEach(function(u) {{
            const sizeStr = u.file_size > 1048576 ? (u.file_size / 1048576).toFixed(1) + ' MB' : u.file_size > 1024 ? (u.file_size / 1024).toFixed(1) + ' KB' : u.file_size + ' bytes';
            html += '<div class="incoming-upload-banner" style="display:flex;" id="upload-banner-' + u.id + '">'
                + '<div style="flex:1;">'
                + '<strong>INCOMING FILE</strong><br>'
                + '<span>' + escapeHtml(u.sender_id) + ' wants to send you <strong>' + escapeHtml(u.filename) + '</strong> (' + sizeStr + ')</span><br>'
                + '<small class="opacity-75">Destination: ~/' + escapeHtml(u.dest_path) + '</small>'
                + '</div>'
                + '<div class="d-flex gap-2 ms-3">'
                + '<button class="btn btn-success btn-sm fw-bold accept-upload-btn" data-upload-id="' + u.id + '">Yes, Accept</button>'
                + '<button class="btn btn-outline-light btn-sm fw-bold reject-upload-btn" data-upload-id="' + u.id + '">No, Reject</button>'
                + '</div></div>';
        }});
        container.innerHTML = html;
    }}).catch(() => {{}});
}}
function respondUpload(uploadId, accept) {{
    const banner = document.getElementById('upload-banner-' + uploadId);
    if (banner) {{
        const btns = banner.querySelectorAll('button');
        btns.forEach(b => {{ b.disabled = true; }});
    }}
    const endpoint = accept ? '/api/accept-upload/' : '/api/reject-upload/';
    fetch(endpoint + uploadId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (banner) {{
            if (accept && data.success) {{
                banner.style.background = 'linear-gradient(135deg, #238636 0%, #196c2e 100%)';
                banner.style.borderColor = '#3fb950';
                banner.querySelector('div').innerHTML = '<strong>FILE ACCEPTED</strong><br><span>Saved to ~/' + escapeHtml(data.saved_to || '') + '</span>';
            }} else if (!accept) {{
                banner.style.background = 'linear-gradient(135deg, #6e4000 0%, #4d2d00 100%)';
                banner.style.borderColor = '#d29922';
                banner.querySelector('div').innerHTML = '<strong>FILE REJECTED</strong>';
            }} else {{
                banner.querySelector('div').innerHTML = '<strong>Error:</strong> ' + (data.error || 'Unknown error');
            }}
            setTimeout(() => {{ banner.style.display = 'none'; }}, 4000);
        }}
    }}).catch(err => {{ if (banner) banner.querySelector('div').innerHTML = '<strong>Error:</strong> ' + err.message; }});
}}
checkIncomingUploads();
setInterval(checkIncomingUploads, 3000);
document.addEventListener('click', function(e) {{
    if (e.target.classList.contains('accept-upload-btn')) {{
        respondUpload(e.target.getAttribute('data-upload-id'), true);
    }}
    if (e.target.classList.contains('reject-upload-btn')) {{
        respondUpload(e.target.getAttribute('data-upload-id'), false);
    }}
}});
document.querySelectorAll('.ping-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        const self = this;
        self.textContent = 'Pinging...'; self.disabled = true;
        fetch('/api/ping/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
            self.disabled = false;
            if (data.success) {{
                const ms = data.latency_ms;
                const cls = ms < 100 ? 'ping-ok' : ms < 500 ? 'ping-warn' : 'ping-fail';
                const label = ms < 100 ? 'Excellent' : ms < 300 ? 'Good' : ms < 500 ? 'Fair' : 'Poor';
                self.innerHTML = '<span class="' + cls + '">' + ms + 'ms</span>';
                setTimeout(() => {{ self.textContent = 'Ping'; }}, 5000);
            }} else {{
                self.innerHTML = '<span class="ping-fail">Failed</span>';
                setTimeout(() => {{ self.textContent = 'Ping'; }}, 3000);
            }}
        }}).catch(() => {{ self.innerHTML = '<span class="ping-fail">Error</span>'; self.disabled = false; setTimeout(() => {{ self.textContent = 'Ping'; }}, 3000); }});
    }});
}});
let _rfAllItems = [];
document.querySelectorAll('.request-file-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('rfTargetPeerId').value = peerId;
        document.getElementById('rfTargetDisplay').textContent = peerId;
        document.getElementById('rfFileList').innerHTML = '';
        document.getElementById('rfSearchInput').value = '';
        document.getElementById('rfStatus').style.display = 'none';
        document.getElementById('rfLoading').style.display = 'block';
        _rfAllItems = [];
        document.getElementById('requestFileModal').style.display = 'flex';
        fetch('/api/request-file-list/' + peerId).then(r => r.json()).then(data => {{
            document.getElementById('rfLoading').style.display = 'none';
            if (data.error) {{ document.getElementById('rfFileList').innerHTML = '<div class="p-3 text-danger">' + data.error + '</div>'; return; }}
            _rfAllItems = data.items || [];
            renderRequestFiles(_rfAllItems);
        }}).catch(err => {{
            document.getElementById('rfLoading').style.display = 'none';
            document.getElementById('rfFileList').innerHTML = '<div class="p-3 text-danger">Could not load files: ' + err.message + '</div>';
        }});
    }});
}});
function renderRequestFiles(items) {{
    const list = document.getElementById('rfFileList');
    if (items.length === 0) {{ list.innerHTML = '<div class="p-3 text-secondary">No shared files found.</div>'; return; }}
    const peerId = document.getElementById('rfTargetPeerId').value;
    let html = '';
    items.forEach(function(item) {{
        const icon = item.is_folder ? 'Folder ' : 'File ';
        const sizeStr = item.is_folder ? '' : ' (' + item.size + ')';
        const cleanPath = item.is_folder ? item.path.replace(/\\/+$/g, '') : item.path;
        const dlBtn = '<button class="btn btn-sm btn-outline-success request-dl-btn" data-peer-id="' + peerId + '" data-path="' + cleanPath + '" data-is-folder="' + (item.is_folder ? '1' : '0') + '">Download</button>';
        html += '<div class="file-tree-item"><span>' + icon + escapeHtml(item.name) + sizeStr + '</span>' + dlBtn + '</div>';
    }});
    list.innerHTML = html;
}}
function filterRequestFiles() {{
    const q = (document.getElementById('rfSearchInput').value || '').toLowerCase();
    const filtered = q ? _rfAllItems.filter(function(i) {{ return i.name.toLowerCase().indexOf(q) >= 0; }}) : _rfAllItems;
    renderRequestFiles(filtered);
}}
document.addEventListener('click', function(e) {{
    if (e.target.classList.contains('request-dl-btn')) {{
        const peerId = e.target.getAttribute('data-peer-id');
        const path = e.target.getAttribute('data-path');
        const btn = e.target;
        btn.textContent = 'Downloading...'; btn.disabled = true;
        fetch('/api/request-file-download/' + peerId + '/' + path, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
            if (data.success) {{
                btn.textContent = 'Saved';
                btn.classList.remove('btn-outline-success'); btn.classList.add('btn-success');
                const st = document.getElementById('rfStatus');
                st.innerHTML = '<div class="alert alert-success py-2 small">Saved to ~/' + escapeHtml(data.saved_to || '') + '</div>';
                st.style.display = 'block';
            }} else {{
                btn.textContent = 'Failed';
                const st = document.getElementById('rfStatus');
                st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Download failed') + '</div>';
                st.style.display = 'block';
            }}
            setTimeout(() => {{ btn.textContent = 'Download'; btn.disabled = false; btn.classList.remove('btn-success'); btn.classList.add('btn-outline-success'); }}, 4000);
        }}).catch(err => {{ btn.textContent = 'Error'; btn.disabled = false; }});
    }}
}});
document.querySelectorAll('.sync-folder-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('sfTargetPeerId').value = peerId;
        document.getElementById('sfTargetDisplay').textContent = peerId;
        document.getElementById('sfLocalPath').value = 'Desktop/synced/';
        document.getElementById('sfRemotePath').value = '';
        document.getElementById('sfStatus').style.display = 'none';
        document.getElementById('sfStartBtn').disabled = false;
        document.getElementById('sfStartBtn').textContent = 'Start Sync';
        document.getElementById('syncFolderModal').style.display = 'flex';
        refreshActiveSyncs();
    }});
}});
function startSync() {{
    const peerId = document.getElementById('sfTargetPeerId').value;
    const localPath = document.getElementById('sfLocalPath').value.trim();
    const remotePath = document.getElementById('sfRemotePath').value.trim();
    const btn = document.getElementById('sfStartBtn');
    const st = document.getElementById('sfStatus');
    if (!localPath) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter a local folder path.</div>'; st.style.display = 'block'; return; }}
    btn.disabled = true; btn.textContent = 'Starting...';
    st.innerHTML = '<div class="text-info small">Initiating sync...</div>'; st.style.display = 'block';
    fetch('/api/sync-folder', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ peer_id: peerId, local_path: localPath, remote_path: remotePath }}) }}).then(r => r.json()).then(data => {{
        if (data.success) {{
            st.innerHTML = '<div class="alert alert-success py-2 small">Sync started! ' + (data.files_synced || 0) + ' files synced. Next auto-sync in 30s.</div>';
            btn.textContent = 'Sync Running';
            refreshActiveSyncs();
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Sync failed') + '</div>';
            btn.disabled = false; btn.textContent = 'Start Sync';
        }}
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; btn.disabled = false; btn.textContent = 'Start Sync'; }});
}}
function refreshActiveSyncs() {{
    fetch('/api/active-syncs').then(r => r.json()).then(data => {{
        const container = document.getElementById('sfActiveSyncs');
        const syncs = data.syncs || [];
        if (syncs.length === 0) {{ container.innerHTML = '<p class="text-secondary small">No active syncs.</p>'; return; }}
        let html = '<h6 class="small text-secondary mt-3 mb-2">Active Syncs:</h6>';
        syncs.forEach(function(s) {{
            html += '<div class="d-flex justify-content-between align-items-center mb-2 p-2" style="background:#0d1117;border-radius:6px;border:1px solid #30363d;">'
                + '<div><small class="text-white">' + escapeHtml(s.peer_id) + '</small><br><small class="text-muted">~/' + escapeHtml(s.local_path) + '</small></div>'
                + '<div class="d-flex align-items-center gap-2"><span class="sync-status ' + (s.active ? 'sync-active' : 'sync-idle') + '">' + (s.active ? 'Syncing' : 'Idle') + '</span>'
                + '<button class="btn btn-sm btn-outline-danger stop-sync-btn" data-sync-id="' + s.id + '">Stop</button></div></div>';
        }});
        container.innerHTML = html;
    }}).catch(() => {{}});
}}
document.addEventListener('click', function(e) {{
    if (e.target.classList.contains('stop-sync-btn')) {{
        const syncId = e.target.getAttribute('data-sync-id');
        e.target.disabled = true; e.target.textContent = '...';
        fetch('/api/stop-sync/' + syncId, {{ method: 'POST' }}).then(r => r.json()).then(() => {{ refreshActiveSyncs(); }}).catch(() => {{ e.target.disabled = false; e.target.textContent = 'Stop'; }});
    }}
}});
document.querySelectorAll('.remote-term-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('rtTargetPeerId').value = peerId;
        document.getElementById('rtTargetDisplay').textContent = peerId;
        document.getElementById('rtOutput').textContent = 'Connected to ' + peerId + '. Type a command below.\\n';
        document.getElementById('rtCmdInput').value = '';
        document.getElementById('remoteTermModal').style.display = 'flex';
        document.getElementById('rtCmdInput').focus();
    }});
}});
document.getElementById('rtCmdInput').addEventListener('keydown', function(e) {{
    if (e.key === 'Enter') sendTermCmd();
}});
function sendTermCmd() {{
    const peerId = document.getElementById('rtTargetPeerId').value;
    const cmd = document.getElementById('rtCmdInput').value.trim();
    if (!cmd) return;
    const out = document.getElementById('rtOutput');
    out.textContent += '> ' + cmd + '\\n';
    document.getElementById('rtCmdInput').value = '';
    document.getElementById('rtSendBtn').disabled = true;
    document.getElementById('rtSendBtn').textContent = '...';
    fetch('/api/remote-exec/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ command: cmd }}) }}).then(r => r.json()).then(data => {{
        if (data.output) out.textContent += data.output + '\\n';
        if (data.error) out.textContent += 'ERROR: ' + data.error + '\\n';
        out.scrollTop = out.scrollHeight;
        document.getElementById('rtSendBtn').disabled = false;
        document.getElementById('rtSendBtn').textContent = 'Run';
    }}).catch(err => {{
        out.textContent += 'NETWORK ERROR: ' + err.message + '\\n';
        document.getElementById('rtSendBtn').disabled = false;
        document.getElementById('rtSendBtn').textContent = 'Run';
    }});
}}
document.querySelectorAll('.clipboard-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('cbTargetPeerId').value = peerId;
        document.getElementById('cbTargetDisplay').textContent = peerId;
        document.getElementById('cbTextArea').value = '';
        document.getElementById('cbStatus').style.display = 'none';
        document.getElementById('clipboardModal').style.display = 'flex';
    }});
}});
function sendClipboard() {{
    const peerId = document.getElementById('cbTargetPeerId').value;
    const text = document.getElementById('cbTextArea').value;
    const st = document.getElementById('cbStatus');
    if (!text) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Nothing to send.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Sending...</div>'; st.style.display = 'block';
    fetch('/api/clipboard-send/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ text: text }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">Clipboard sent to peer!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
function grabClipboard() {{
    const peerId = document.getElementById('cbTargetPeerId').value;
    const st = document.getElementById('cbStatus');
    st.innerHTML = '<div class="text-info small">Fetching clipboard...</div>'; st.style.display = 'block';
    fetch('/api/clipboard-grab/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (data.success) {{
            document.getElementById('cbTextArea').value = data.text || '';
            st.innerHTML = '<div class="alert alert-success py-2 small">Clipboard grabbed! Text is in the box above.</div>';
        }} else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
document.querySelectorAll('.power-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('pwTargetPeerId').value = peerId;
        document.getElementById('pwTargetDisplay').textContent = peerId;
        document.getElementById('pwStatus').style.display = 'none';
        document.getElementById('powerModal').style.display = 'flex';
    }});
}});
function sendPowerCmd(action) {{
    const peerId = document.getElementById('pwTargetPeerId').value;
    const st = document.getElementById('pwStatus');
    const warnings = {{ shutdown: 'SHUTDOWN the remote machine', restart: 'RESTART the remote machine', sleep: 'put the remote machine to SLEEP', wake: 'send a Wake-on-LAN packet' }};
    if (!confirm('Are you sure you want to ' + (warnings[action] || action) + ' (' + peerId + ')?')) return;
    st.innerHTML = '<div class="text-info small">Sending ' + action + ' command...</div>'; st.style.display = 'block';
    fetch('/api/power/' + peerId + '/' + action, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">' + (data.message || action + ' command sent!') + '</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
document.querySelectorAll('.bw-test-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('bwTargetPeerId').value = peerId;
        document.getElementById('bwTargetDisplay').textContent = peerId;
        document.getElementById('bwResults').style.display = 'none';
        document.getElementById('bwStatus').style.display = 'none';
        document.getElementById('bwStartBtn').disabled = false;
        document.getElementById('bwStartBtn').textContent = 'Start Speed Test';
        document.getElementById('bwTestModal').style.display = 'flex';
    }});
}});
function runBwTest() {{
    const peerId = document.getElementById('bwTargetPeerId').value;
    const btn = document.getElementById('bwStartBtn');
    const st = document.getElementById('bwStatus');
    const res = document.getElementById('bwResults');
    btn.disabled = true; btn.textContent = 'Testing...';
    st.innerHTML = '<div class="text-info small">Running speed test...</div>'; st.style.display = 'block';
    res.style.display = 'none';
    document.getElementById('bwDlBar').style.width = '0%';
    document.getElementById('bwUlBar').style.width = '0%';
    document.getElementById('bwDlSpeed').textContent = '—';
    document.getElementById('bwUlSpeed').textContent = '—';
    document.getElementById('bwLatency').textContent = '—';
    fetch('/api/bandwidth-test/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Start Speed Test';
        if (data.success) {{
            res.style.display = 'block';
            st.style.display = 'none';
            const dlMbps = data.download_mbps || 0;
            const ulMbps = data.upload_mbps || 0;
            const maxMbps = 1000;
            document.getElementById('bwDlBar').style.width = Math.min(dlMbps / maxMbps * 100, 100) + '%';
            document.getElementById('bwUlBar').style.width = Math.min(ulMbps / maxMbps * 100, 100) + '%';
            document.getElementById('bwDlSpeed').textContent = dlMbps.toFixed(2) + ' Mbps (' + (dlMbps / 8).toFixed(2) + ' MB/s)';
            document.getElementById('bwUlSpeed').textContent = ulMbps.toFixed(2) + ' Mbps (' + (ulMbps / 8).toFixed(2) + ' MB/s)';
            document.getElementById('bwLatency').textContent = (data.latency_ms || 0) + ' ms';
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Test failed') + '</div>';
            st.style.display = 'block';
        }}
    }}).catch(err => {{
        btn.disabled = false; btn.textContent = 'Start Speed Test';
        st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block';
    }});
}}
document.querySelectorAll('.screenshot-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('ssTargetPeerId').value = peerId;
        document.getElementById('ssTargetDisplay').textContent = peerId;
        document.getElementById('ssStatus').style.display = 'none';
        document.getElementById('ssImageContainer').style.display = 'none';
        document.getElementById('ssCaptureBtn').disabled = false;
        document.getElementById('ssCaptureBtn').textContent = 'Capture Screenshot';
        document.getElementById('screenshotModal').style.display = 'flex';
    }});
}});
function captureScreenshot() {{
    const peerId = document.getElementById('ssTargetPeerId').value;
    const btn = document.getElementById('ssCaptureBtn');
    const st = document.getElementById('ssStatus');
    const imgC = document.getElementById('ssImageContainer');
    btn.disabled = true; btn.textContent = 'Capturing...';
    st.innerHTML = '<div class="text-info small">Requesting screenshot...</div>'; st.style.display = 'block';
    imgC.style.display = 'none';
    fetch('/api/screenshot/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Capture Again';
        if (data.success) {{
            st.style.display = 'none';
            document.getElementById('ssImage').src = 'data:image/png;base64,' + data.image;
            imgC.style.display = 'block';
            document.getElementById('ssSaveBtn').style.display = '';
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
            st.style.display = 'block';
        }}
    }}).catch(err => {{
        btn.disabled = false; btn.textContent = 'Capture Screenshot';
        st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block';
    }});
}}
document.querySelectorAll('.sysinfo-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('siTargetPeerId').value = peerId;
        document.getElementById('siTargetDisplay').textContent = peerId;
        document.getElementById('siStatus').style.display = 'none';
        document.getElementById('siContent').style.display = 'none';
        document.getElementById('sysinfoModal').style.display = 'flex';
        fetchSysInfo();
    }});
}});
function fetchSysInfo() {{
    const peerId = document.getElementById('siTargetPeerId').value;
    const st = document.getElementById('siStatus');
    const content = document.getElementById('siContent');
    const btn = document.getElementById('siRefreshBtn');
    btn.disabled = true; btn.textContent = 'Loading...';
    st.innerHTML = '<div class="text-info small">Fetching system info...</div>'; st.style.display = 'block';
    content.style.display = 'none';
    fetch('/api/sysinfo/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{
            st.style.display = 'none';
            const info = data.info;
            let html = '<div class="sysinfo-grid">';
            const fields = [
                ['OS', info.os], ['Hostname', info.hostname], ['CPU', info.cpu],
                ['CPU Cores', info.cpu_cores], ['RAM Total', info.ram_total],
                ['RAM Used', info.ram_used], ['RAM %', info.ram_percent + '%'],
                ['Disk Total', info.disk_total], ['Disk Used', info.disk_used],
                ['Disk Free', info.disk_free], ['Disk %', info.disk_percent + '%'],
                ['Uptime', info.uptime], ['GPU', info.gpu],
                ['Python', info.python_version],
                ['Architecture', info.architecture], ['IP Addresses', (info.ip_addresses || []).join(', ')]
            ];
            fields.forEach(function(f) {{
                html += '<div class="si-label">' + f[0] + ':</div><div class="si-val">' + (f[1] || 'N/A') + '</div>';
            }});
            html += '</div>';
            content.innerHTML = html;
            content.style.display = 'block';
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
            st.style.display = 'block';
        }}
    }}).catch(err => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block';
    }});
}}
document.querySelectorAll('.notify-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('ntTargetPeerId').value = peerId;
        document.getElementById('ntTargetDisplay').textContent = peerId;
        document.getElementById('ntMessage').value = '';
        document.getElementById('ntStatus').style.display = 'none';
        document.getElementById('notifyModal').style.display = 'flex';
    }});
}});
function sendNotify() {{
    const peerId = document.getElementById('ntTargetPeerId').value;
    const title = document.getElementById('ntTitle').value.trim();
    const msg = document.getElementById('ntMessage').value.trim();
    const st = document.getElementById('ntStatus');
    if (!msg) {{ st.innerHTML = '<div class="alert alert-warning py-2 small">Enter a message.</div>'; st.style.display = 'block'; return; }}
    st.innerHTML = '<div class="text-info small">Sending notification...</div>'; st.style.display = 'block';
    fetch('/api/notify/' + peerId, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ title: title, message: msg }}) }}).then(r => r.json()).then(data => {{
        if (data.success) st.innerHTML = '<div class="alert alert-success py-2 small">Notification sent!</div>';
        else st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
        st.style.display = 'block';
    }}).catch(err => {{ st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block'; }});
}}
let _pmAllProcs = [];
document.querySelectorAll('.procmgr-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('pmTargetPeerId').value = peerId;
        document.getElementById('pmTargetDisplay').textContent = peerId;
        document.getElementById('pmStatus').style.display = 'none';
        document.getElementById('pmProcList').innerHTML = '';
        document.getElementById('pmFilter').value = '';
        _pmAllProcs = [];
        document.getElementById('procMgrModal').style.display = 'flex';
        fetchProcesses();
    }});
}});
function fetchProcesses() {{
    const peerId = document.getElementById('pmTargetPeerId').value;
    const st = document.getElementById('pmStatus');
    const btn = document.getElementById('pmRefreshBtn');
    btn.disabled = true; btn.textContent = '...';
    st.innerHTML = '<div class="text-info small">Loading processes...</div>'; st.style.display = 'block';
    fetch('/api/processes/' + peerId).then(r => r.json()).then(data => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        if (data.success) {{
            st.style.display = 'none';
            _pmAllProcs = data.processes || [];
            renderProcs(_pmAllProcs);
        }} else {{
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
            st.style.display = 'block';
        }}
    }}).catch(err => {{
        btn.disabled = false; btn.textContent = 'Refresh';
        st.innerHTML = '<div class="alert alert-danger py-2 small">Error: ' + err.message + '</div>'; st.style.display = 'block';
    }});
}}
function renderProcs(procs) {{
    const list = document.getElementById('pmProcList');
    if (procs.length === 0) {{ list.innerHTML = '<tr><td colspan="5" class="text-secondary text-center">No processes.</td></tr>'; return; }}
    const peerId = document.getElementById('pmTargetPeerId').value;
    list.innerHTML = procs.map(function(p) {{
        return '<tr><td>' + p.pid + '</td><td>' + p.name + '</td><td>' + (p.cpu || '0') + '</td><td>' + (p.memory || '—') + '</td>'
            + '<td><button class="btn btn-sm btn-outline-danger py-0 px-1 kill-proc-btn" data-pid="' + p.pid + '" data-name="' + p.name + '">Kill</button></td></tr>';
    }}).join('');
}}
function filterProcs() {{
    const f = (document.getElementById('pmFilter').value || '').toLowerCase();
    if (!f) {{ renderProcs(_pmAllProcs); return; }}
    renderProcs(_pmAllProcs.filter(function(p) {{ return (p.name || '').toLowerCase().includes(f) || String(p.pid).includes(f); }}));
}}
document.addEventListener('click', function(e) {{
    if (e.target.classList.contains('kill-proc-btn')) {{
        const pid = e.target.getAttribute('data-pid');
        const name = e.target.getAttribute('data-name');
        if (!confirm('Kill process "' + name + '" (PID ' + pid + ')?')) return;
        const peerId = document.getElementById('pmTargetPeerId').value;
        e.target.disabled = true; e.target.textContent = '...';
        fetch('/api/kill-process/' + peerId + '/' + pid, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
            if (data.success) {{ fetchProcesses(); }}
            else {{ alert('Failed to kill: ' + (data.error || 'Unknown error')); e.target.disabled = false; e.target.textContent = 'Kill'; }}
        }}).catch(err => {{ alert('Error: ' + err.message); e.target.disabled = false; e.target.textContent = 'Kill'; }});
    }}
}});
let _srInterval = null;
let _srFrameNum = 0;
let _srFrames = [];
document.querySelectorAll('.screenrec-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('srTargetPeerId').value = peerId;
        document.getElementById('srTargetDisplay').textContent = peerId;
        document.getElementById('srStatus').style.display = 'none';
        document.getElementById('srFrameContainer').style.display = 'none';
        document.getElementById('srRecIndicator').style.display = 'none';
        document.getElementById('srStartBtn').style.display = '';
        document.getElementById('srStopBtn').style.display = 'none';
        document.getElementById('srSaveBtn').style.display = 'none';
        _srFrameNum = 0;
        _srFrames = [];
        document.getElementById('screenRecModal').style.display = 'flex';
    }});
}});
function startScreenRec() {{
    const peerId = document.getElementById('srTargetPeerId').value;
    document.getElementById('srStartBtn').style.display = 'none';
    document.getElementById('srStopBtn').style.display = '';
    document.getElementById('srRecIndicator').style.display = 'block';
    document.getElementById('srFrameContainer').style.display = 'block';
    document.getElementById('srStatus').style.display = 'none';
    _srFrameNum = 0;
    _srFrames = [];
    document.getElementById('srFrameCount').textContent = 'Frame: 0';
    fetchScreenFrame();
    _srInterval = setInterval(fetchScreenFrame, 2000);
}}
function stopScreenRec() {{
    if (_srInterval) {{ clearInterval(_srInterval); _srInterval = null; }}
    document.getElementById('srStartBtn').style.display = '';
    document.getElementById('srStopBtn').style.display = 'none';
    document.getElementById('srRecIndicator').style.display = 'none';
    if (_srFrames.length > 0) document.getElementById('srSaveBtn').style.display = '';
}}
function saveScreenshot() {{
    const img = document.getElementById('ssImage');
    if (!img.src || !img.src.startsWith('data:')) return;
    const a = document.createElement('a');
    a.href = img.src;
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    a.download = 'screenshot_' + ts + '.png';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
}}
function saveRecording() {{
    if (_srFrames.length === 0) return;
    // Save all frames as individual PNG files in a zip-like download, or save the last frame
    // For simplicity: save each frame as separate download, or create a single animated approach
    // Best approach: download all frames as numbered PNGs
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    if (_srFrames.length === 1) {{
        const a = document.createElement('a');
        a.href = 'data:image/png;base64,' + _srFrames[0];
        a.download = 'recording_' + ts + '_001.png';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        return;
    }}
    // Multiple frames: trigger downloads sequentially
    const st = document.getElementById('srStatus');
    st.innerHTML = '<div class="text-info small">Saving ' + _srFrames.length + ' frames...</div>'; st.style.display = 'block';
    let idx = 0;
    function dlNext() {{
        if (idx >= _srFrames.length) {{
            st.innerHTML = '<div class="alert alert-success py-2 small">Saved ' + _srFrames.length + ' frames!</div>';
            return;
        }}
        const a = document.createElement('a');
        a.href = 'data:image/png;base64,' + _srFrames[idx];
        a.download = 'recording_' + ts + '_' + String(idx + 1).padStart(3, '0') + '.png';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        idx++;
        setTimeout(dlNext, 300);
    }}
    dlNext();
}}
function fetchScreenFrame() {{
    const peerId = document.getElementById('srTargetPeerId').value;
    fetch('/api/screenshot/' + peerId, {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (data.success && data.image) {{
            _srFrameNum++;
            _srFrames.push(data.image);
            document.getElementById('srFrame').src = 'data:image/png;base64,' + data.image;
            document.getElementById('srFrameCount').textContent = 'Frame: ' + _srFrameNum;
            document.getElementById('srFrameContainer').style.display = 'block';
        }} else if (data.error) {{
            const st = document.getElementById('srStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>';
            st.style.display = 'block';
            stopScreenRec();
        }}
    }}).catch(function(err) {{
        const st = document.getElementById('srStatus');
        st.innerHTML = '<div class="alert alert-danger py-2 small">Frame error: ' + err.message + '</div>';
        st.style.display = 'block';
        stopScreenRec();
    }});
}}
let _raInterval = null;
let _raAudioCtx = null;
let _raPlaying = false;
document.querySelectorAll('.remote-audio-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('raTargetPeerId').value = peerId;
        document.getElementById('raTargetDisplay').textContent = peerId;
        document.getElementById('raStatus').style.display = 'none';
        if (_raPlaying) {{
            document.getElementById('raListenIndicator').style.display = 'block';
            document.getElementById('raVisualizer').style.display = 'flex';
            document.getElementById('raStartBtn').style.display = 'none';
            document.getElementById('raStopBtn').style.display = '';
        }} else {{
            document.getElementById('raListenIndicator').style.display = 'none';
            document.getElementById('raVisualizer').style.display = 'none';
            document.getElementById('raStartBtn').style.display = '';
            document.getElementById('raStopBtn').style.display = 'none';
        }}
        document.getElementById('remoteAudioModal').style.display = 'flex';
    }});
}});
function startRemoteAudio() {{
    const peerId = document.getElementById('raTargetPeerId').value;
    document.getElementById('raStartBtn').style.display = 'none';
    document.getElementById('raStopBtn').style.display = '';
    document.getElementById('raStatus').style.display = 'none';
    document.getElementById('raListenIndicator').style.display = 'block';
    const vis = document.getElementById('raVisualizer');
    vis.innerHTML = '';
    for (let i = 0; i < 32; i++) {{
        const bar = document.createElement('div');
        bar.className = 'audio-bar';
        bar.style.height = '2px';
        vis.appendChild(bar);
    }}
    vis.style.display = 'flex';
    if (!_raAudioCtx) _raAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    _raPlaying = true;
    // Tell remote to start streaming
    fetch('/api/audio-stream/' + peerId + '/start', {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (!data.success) {{
            const st = document.getElementById('raStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed to start') + '</div>';
            st.style.display = 'block';
            stopRemoteAudio();
            return;
        }}
        // Start polling for chunks
        _raInterval = setInterval(fetchAudioChunk, 1500);
    }}).catch(function(err) {{
        const st = document.getElementById('raStatus');
        st.innerHTML = '<div class="alert alert-danger py-2 small">' + err.message + '</div>';
        st.style.display = 'block';
        stopRemoteAudio();
    }});
}}
function stopRemoteAudio() {{
    _raPlaying = false;
    if (_raInterval) {{ clearInterval(_raInterval); _raInterval = null; }}
    const peerId = document.getElementById('raTargetPeerId').value;
    fetch('/api/audio-stream/' + peerId + '/stop', {{ method: 'POST' }}).catch(function() {{}});
    document.getElementById('raStartBtn').style.display = '';
    document.getElementById('raStopBtn').style.display = 'none';
    document.getElementById('raListenIndicator').style.display = 'none';
}}
function fetchAudioChunk() {{
    if (!_raPlaying) return;
    const peerId = document.getElementById('raTargetPeerId').value;
    fetch('/api/audio-stream/' + peerId + '/chunk').then(r => r.json()).then(data => {{
        if (data.success && data.audio) {{
            const raw = atob(data.audio);
            const buf = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
            _raAudioCtx.decodeAudioData(buf.buffer.slice(0), function(audioBuffer) {{
                const src = _raAudioCtx.createBufferSource();
                src.buffer = audioBuffer;
                src.connect(_raAudioCtx.destination);
                src.start(0);
                const bars = document.querySelectorAll('#raVisualizer .audio-bar');
                const cd = audioBuffer.getChannelData(0);
                const step = Math.floor(cd.length / bars.length);
                bars.forEach(function(bar, i) {{
                    let sum = 0;
                    for (let j = i * step; j < (i + 1) * step && j < cd.length; j++) sum += Math.abs(cd[j]);
                    const avg = sum / step;
                    bar.style.height = Math.max(2, avg * 200) + 'px';
                }});
            }}, function() {{ }});
        }} else if (data.error) {{
            const st = document.getElementById('raStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>';
            st.style.display = 'block';
            stopRemoteAudio();
        }}
    }}).catch(function() {{}});
}}
let _saInterval = null;
let _saAudioCtx = null;
let _saPlaying = false;
document.querySelectorAll('.sys-audio-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('saTargetPeerId').value = peerId;
        document.getElementById('saTargetDisplay').textContent = peerId;
        document.getElementById('saStatus').style.display = 'none';
        if (_saPlaying) {{
            document.getElementById('saListenIndicator').style.display = 'block';
            document.getElementById('saVisualizer').style.display = 'flex';
            document.getElementById('saStartBtn').style.display = 'none';
            document.getElementById('saStopBtn').style.display = '';
        }} else {{
            document.getElementById('saListenIndicator').style.display = 'none';
            document.getElementById('saVisualizer').style.display = 'none';
            document.getElementById('saStartBtn').style.display = '';
            document.getElementById('saStopBtn').style.display = 'none';
        }}
        document.getElementById('sysAudioModal').style.display = 'flex';
    }});
}});
function startSysAudio() {{
    const peerId = document.getElementById('saTargetPeerId').value;
    document.getElementById('saStartBtn').style.display = 'none';
    document.getElementById('saStopBtn').style.display = '';
    document.getElementById('saStatus').style.display = 'none';
    document.getElementById('saListenIndicator').style.display = 'block';
    const vis = document.getElementById('saVisualizer');
    vis.innerHTML = '';
    for (let i = 0; i < 32; i++) {{
        const bar = document.createElement('div');
        bar.className = 'audio-bar';
        bar.style.height = '2px';
        bar.style.background = '#58a6ff';
        vis.appendChild(bar);
    }}
    vis.style.display = 'flex';
    if (!_saAudioCtx) _saAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    _saPlaying = true;
    fetch('/api/sys-audio-stream/' + peerId + '/start', {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (!data.success) {{
            const st = document.getElementById('saStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed to start') + '</div>';
            st.style.display = 'block';
            stopSysAudio();
            return;
        }}
        _saInterval = setInterval(fetchSysAudioChunk, 1500);
    }}).catch(function(err) {{
        const st = document.getElementById('saStatus');
        st.innerHTML = '<div class="alert alert-danger py-2 small">' + err.message + '</div>';
        st.style.display = 'block';
        stopSysAudio();
    }});
}}
function stopSysAudio() {{
    _saPlaying = false;
    if (_saInterval) {{ clearInterval(_saInterval); _saInterval = null; }}
    const peerId = document.getElementById('saTargetPeerId').value;
    fetch('/api/sys-audio-stream/' + peerId + '/stop', {{ method: 'POST' }}).catch(function() {{}});
    document.getElementById('saStartBtn').style.display = '';
    document.getElementById('saStopBtn').style.display = 'none';
    document.getElementById('saListenIndicator').style.display = 'none';
}}
function fetchSysAudioChunk() {{
    if (!_saPlaying) return;
    const peerId = document.getElementById('saTargetPeerId').value;
    fetch('/api/sys-audio-stream/' + peerId + '/chunk').then(r => r.json()).then(data => {{
        if (data.success && data.audio) {{
            const raw = atob(data.audio);
            const buf = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
            _saAudioCtx.decodeAudioData(buf.buffer.slice(0), function(audioBuffer) {{
                const src = _saAudioCtx.createBufferSource();
                src.buffer = audioBuffer;
                src.connect(_saAudioCtx.destination);
                src.start(0);
                const bars = document.querySelectorAll('#saVisualizer .audio-bar');
                const cd = audioBuffer.getChannelData(0);
                const step = Math.floor(cd.length / bars.length);
                bars.forEach(function(bar, i) {{
                    let sum = 0;
                    for (let j = i * step; j < (i + 1) * step && j < cd.length; j++) sum += Math.abs(cd[j]);
                    const avg = sum / step;
                    bar.style.height = Math.max(2, avg * 200) + 'px';
                }});
            }}, function() {{ }});
        }} else if (data.error) {{
            const st = document.getElementById('saStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>';
            st.style.display = 'block';
            stopSysAudio();
        }}
    }}).catch(function() {{}});
}}
let _imInterval = null;
let _imEventTotal = 0;
document.querySelectorAll('.input-monitor-btn').forEach(btn => {{
    btn.addEventListener('click', function() {{
        const peerId = this.getAttribute('data-peer-id');
        document.getElementById('imTargetPeerId').value = peerId;
        document.getElementById('imTargetDisplay').textContent = peerId;
        document.getElementById('imStatus').style.display = 'none';
        document.getElementById('imFeed').style.display = 'none';
        document.getElementById('imRecIndicator').style.display = 'none';
        document.getElementById('imStartBtn').style.display = '';
        document.getElementById('imStopBtn').style.display = 'none';
        document.getElementById('imClearBtn').style.display = 'none';
        _imEventTotal = 0;
        document.getElementById('inputMonitorModal').style.display = 'flex';
    }});
}});
function startInputMonitor() {{
    const peerId = document.getElementById('imTargetPeerId').value;
    document.getElementById('imStartBtn').style.display = 'none';
    document.getElementById('imStopBtn').style.display = '';
    document.getElementById('imClearBtn').style.display = '';
    document.getElementById('imRecIndicator').style.display = 'block';
    document.getElementById('imFeed').style.display = 'block';
    document.getElementById('imFeed').innerHTML = '<span class="text-secondary">Waiting for input events...</span>';
    document.getElementById('imStatus').style.display = 'none';
    _imEventTotal = 0;
    // Start monitoring on remote
    fetch('/api/input-monitor/' + peerId + '/start', {{ method: 'POST' }}).then(r => r.json()).then(data => {{
        if (!data.success) {{
            const st = document.getElementById('imStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + (data.error || 'Failed') + '</div>';
            st.style.display = 'block';
            stopInputMonitor();
            return;
        }}
        _imInterval = setInterval(pollInputEvents, 1000);
    }}).catch(function(err) {{
        const st = document.getElementById('imStatus');
        st.innerHTML = '<div class="alert alert-danger py-2 small">' + err.message + '</div>';
        st.style.display = 'block';
        stopInputMonitor();
    }});
}}
function stopInputMonitor() {{
    if (_imInterval) {{ clearInterval(_imInterval); _imInterval = null; }}
    const peerId = document.getElementById('imTargetPeerId').value;
    fetch('/api/input-monitor/' + peerId + '/stop', {{ method: 'POST' }}).catch(function() {{}});
    document.getElementById('imStartBtn').style.display = '';
    document.getElementById('imStopBtn').style.display = 'none';
    document.getElementById('imRecIndicator').style.display = 'none';
}}
function pollInputEvents() {{
    const peerId = document.getElementById('imTargetPeerId').value;
    fetch('/api/input-monitor/' + peerId + '/events').then(r => r.json()).then(data => {{
        if (data.success && data.events && data.events.length > 0) {{
            const feed = document.getElementById('imFeed');
            if (_imEventTotal === 0) feed.innerHTML = '';
            data.events.forEach(function(ev) {{
                _imEventTotal++;
                let html = '<span class="keylog-time">[' + (ev.time || '') + '] </span>';
                if (ev.type === 'key') {{
                    if (ev.key && ev.key.length === 1) html += '<span class="keylog-key">' + ev.key + '</span>';
                    else html += '<span class="keylog-special">[' + (ev.key || '?') + ']</span>';
                }} else if (ev.type === 'mouse') {{
                    html += '<span class="keylog-mouse">[Click ' + (ev.button || '') + ' @ ' + (ev.x || 0) + ',' + (ev.y || 0) + ']</span>';
                }}
                feed.innerHTML += html;
            }});
            document.getElementById('imEventCount').textContent = 'Events: ' + _imEventTotal;
            feed.scrollTop = feed.scrollHeight;
        }} else if (data.error) {{
            const st = document.getElementById('imStatus');
            st.innerHTML = '<div class="alert alert-danger py-2 small">' + data.error + '</div>';
            st.style.display = 'block';
            stopInputMonitor();
        }}
    }}).catch(function() {{}});
}}
function togglePerm(key, val) {{
    fetch('/api/permissions', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ key: key, value: val }}) }}).then(r => r.json()).then(data => {{
        if (!data.success) alert('Failed to update permission: ' + (data.error || ''));
    }}).catch(err => alert('Error: ' + err.message));
}}
function loadPerms() {{
    fetch('/api/permissions').then(r => r.json()).then(data => {{
        const perms = data.permissions || {{}};
        Object.keys(perms).forEach(function(k) {{
            const el = document.getElementById('perm_' + k);
            if (el) el.checked = perms[k];
        }});
    }}).catch(() => {{}});
}}
loadPerms();
const PERM_LABELS = {{
    'remote_exec': 'Terminal', 'clipboard_write': 'Clip Write', 'clipboard_read': 'Clip Read',
    'power_control': 'Power', 'screenshot': 'Screenshot', 'notify': 'Notify',
    'process_manager': 'Processes', 'screen_record': 'Record', 'remote_audio': 'Mic Audio',
    'system_audio': 'Sys Audio', 'input_monitor': 'Keylog'
}};
const PERM_BTN_MAP = {{
    'remote_exec': '.remote-term-btn', 'clipboard_write': '.clipboard-btn', 'clipboard_read': '.clipboard-btn',
    'power_control': '.power-btn', 'screenshot': '.screenshot-btn', 'notify': '.notify-btn',
    'process_manager': '.procmgr-btn', 'screen_record': '.screenrec-btn', 'remote_audio': '.remote-audio-btn',
    'system_audio': '.sys-audio-btn', 'input_monitor': '.input-monitor-btn'
}};
function loadPeerPerms() {{
    document.querySelectorAll('.peer-perms-row').forEach(function(row) {{
        const peerId = row.getAttribute('data-peer-id');
        fetch('/api/peer-permissions/' + peerId).then(r => r.json()).then(data => {{
            if (!data.success) {{ row.innerHTML = '<span class="text-secondary">Permissions unavailable</span>'; return; }}
            const perms = data.permissions || {{}};
            let html = '';
            Object.keys(PERM_LABELS).forEach(function(k) {{
                const on = !!perms[k];
                html += '<span class="perm-badge ' + (on ? 'perm-on' : 'perm-off') + '">' + PERM_LABELS[k] + '</span>';
                // Dim buttons whose permission is off on the remote peer
                if (!on && PERM_BTN_MAP[k]) {{
                    const btn = row.closest('tr').querySelector(PERM_BTN_MAP[k] + '[data-peer-id="' + peerId + '"]');
                    if (btn) {{ btn.style.opacity = '0.35'; btn.title = PERM_LABELS[k] + ' is disabled on this peer'; }}
                }}
            }});
            row.innerHTML = html;
        }}).catch(function() {{ row.innerHTML = '<span class="text-secondary">Permissions unavailable</span>'; }});
    }});
}}
loadPeerPerms();
setInterval(loadPeerPerms, 30000);
function filterPreview() {{
    const filter = (document.getElementById('previewSearch')?.value || '').toLowerCase();
    document.querySelectorAll('#previewList li').forEach(li => {{ if (!filter) {{ li.style.display = ''; }} else {{ const text = li.textContent.toLowerCase(); li.style.display = text.includes(filter) ? '' : 'none'; }} }});
}}
let _lastWebQuery = '';
document.getElementById('webSearchInput').addEventListener('keydown', function(e) {{ if (e.key === 'Enter') doWebSearch(); }});
function doWebSearch() {{
    const q = document.getElementById('webSearchInput').value.trim();
    if (!q) return;
    _lastWebQuery = q;
    const results = document.getElementById('webSearchResults');
    const loading = document.getElementById('webSearchLoading');
    const meta = document.getElementById('webSearchMeta');
    results.innerHTML = ''; meta.style.display = 'none'; loading.style.display = 'block';
    fetch('/api/web-search?q=' + encodeURIComponent(q)).then(r => r.json()).then(data => {{
        loading.style.display = 'none';
        if (data.error) {{ results.innerHTML = '<div class="alert alert-warning">' + data.error + '</div>'; return; }}
        const items = data.results || [];
        meta.style.display = 'block';
        meta.textContent = 'Found ' + items.length + ' results for "' + q + '" via ' + (data.engine || 'web search');
        if (items.length === 0) {{ results.innerHTML = '<div class="text-center py-4 text-secondary">No results found. Try a different query or use the engine buttons above.</div>'; return; }}
        let html = '';
        items.forEach(function(item) {{ const title = item.title || 'Untitled'; const url = item.url || '#'; const snippet = item.snippet || ''; const displayUrl = url.length > 80 ? url.substring(0, 80) + '...' : url; html += '<div class="web-result"><a href="' + url + '" target="_blank" rel="noopener" class="web-result-title">' + escapeHtml(title) + '</a><div class="web-result-url">' + escapeHtml(displayUrl) + '</div><div class="web-result-snippet">' + escapeHtml(snippet) + '</div></div>'; }});
        results.innerHTML = html;
    }}).catch(err => {{ loading.style.display = 'none'; results.innerHTML = '<div class="alert alert-danger">Search failed: ' + err.message + '</div>'; }});
}}
function escapeHtml(text) {{ const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }}
function openEngine(engine) {{
    const q = document.getElementById('webSearchInput').value.trim() || _lastWebQuery;
    if (!q) {{ alert('Enter a search query first.'); return; }}
    const urls = {{ google: 'https://www.google.com/search?q=', bing: 'https://www.bing.com/search?q=', yahoo: 'https://search.yahoo.com/search?p=', duckduckgo: 'https://duckduckgo.com/?q=', brave: 'https://search.brave.com/search?q=', wikipedia: 'https://en.wikipedia.org/w/index.php?search=' }};
    const base = urls[engine];
    if (base) window.open(base + encodeURIComponent(q), '_blank');
}}
</script>
</body>
</html>"""


def render_search_results(results, query):
    rows = []
    for r in results:
        actions = f'<a href="{r["link"]}" class="btn btn-sm btn-outline-light">Open</a>'
        dl_link = f'{r["link"]}?download=1' if '?' not in r["link"] else f'{r["link"]}&download=1'
        actions += f' <a href="{dl_link}" class="btn btn-sm btn-light ms-2">Download</a>'
        actions += f' <a href="/peer_connect/{r["bank_id"]}" class="btn btn-sm btn-outline-light ms-2">Connect</a>'
        rows.append(f'<tr><td><small class="text-secondary">{r["bank_id"]}</small><br><strong>{r["name"]}</strong></td><td>{r["size"]}</td><td>{actions}</td></tr>')
    return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Search Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>body {{ font-family: 'Inter', system-ui, sans-serif; background: #0d1117; color: #e6edf3; }} a {{ color: #58a6ff; }} a:hover {{ color: #79c0ff; }} .btn-outline-light {{ --bs-btn-color: #e6edf3; --bs-btn-border-color: #444d56; }} .btn-outline-light:hover {{ background: #30363d; color: white; }} .btn-light {{ --bs-btn-bg: #e6edf3; --bs-btn-color: #0d1117; }} .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }} .table-hover tbody tr:hover {{ --bs-table-accent-bg: #21262d; }} small {{ color: #8b949e; }}</style>
</head>
<body class="p-5">
    <div class="container">
        <h1 class="mb-4 text-center">Network Search Results</h1>
        <p class="text-center mb-5 text-secondary">Found {len(results)} matching items across live instances</p>
        <a href="/" class="btn btn-outline-light mb-4">← Dashboard</a>
        <div class="table-responsive">
            <table class="table table-hover">
                <thead><tr><th>Instance / Name</th><th>Size/Type</th><th>Actions</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""


def render_explorer(entries, req_path):
    def _entry_row(e, idx):
        checked = 'checked' if e['shared'] else ''
        tag_display = 'block' if e['shared'] else 'none'
        tag_val = e.get('tags', '') or ''
        tag_val_safe = tag_val.replace('"', '&quot;')
        icon = 'Folder ' if e['is_dir'] else 'File '
        return (f'<tr><td><input type="checkbox" name="path" value="{e["path"]}" {checked} class="form-check-input" id="cb_{idx}" onchange="toggleTag({idx})"></td><td>{icon}<a href="/explorer/{e["path"]}" class="text-decoration-none">{e["name"]}</a></td><td>{e["size"]}</td><td><input type="text" name="tags_{e["path"]}" id="tag_{idx}" value="{tag_val_safe}" placeholder="Tags (comma separated)" class="form-control form-control-sm bg-dark text-white border-secondary tag-input" style="display:{tag_display};width:200px;font-size:0.8rem;"></td></tr>')
    rows = "".join(_entry_row(e, i) for i, e in enumerate(entries))
    return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Content Selection</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>body {{ background:#0d1117; color:#e6edf3; font-family:'Inter',system-ui,sans-serif; }} .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }} .table-hover tbody tr:hover {{ --bs-table-accent-bg: #21262d; }} .form-check-input:checked {{ background-color: #238636; border-color: #238636; }} a {{ color: #58a6ff; }} a:hover {{ color: #79c0ff; }} .tag-input::placeholder {{ color: #6e7681; }}</style>
</head>
<body class="p-5">
    <div class="container">
        <h1 class="mb-4">Content Selection</h1>
        <p class="text-secondary mb-4">Current location: /{req_path or 'Root'}</p>
        <p class="text-secondary small">Check a file to share it. Add comma-separated tags to make it searchable by genre/category.</p>
        <a href="/" class="btn btn-outline-light mb-4">← Dashboard</a>
        <form method="post" action="/save_selection">
            <input type="hidden" name="current_path" value="{req_path}">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead><tr><th width="50">Select</th><th>Name</th><th>Size/Type</th><th>Tags</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            <button type="submit" class="btn btn-success btn-lg w-100 mt-4">Save Selection</button>
        </form>
    </div>
<script>
function toggleTag(idx) {{ var cb = document.getElementById('cb_' + idx); var tag = document.getElementById('tag_' + idx); if (cb.checked) {{ tag.style.display = 'block'; }} else {{ tag.style.display = 'none'; tag.value = ''; }} }}
</script>
</body>
</html>"""


def render_preview(entries, req_path):
    def _preview_row(e):
        entry_type = "Folder " if e["is_dir"] else "File "
        download_btn = f'<a href="/preview/{e["path"].rstrip("/")}?download=1" class="btn btn-sm btn-outline-light">Download</a>'
        return f'<tr><td>{entry_type} <a href="/preview/{e["path"]}" class="text-decoration-none">{e["name"]}</a></td><td>{e["size"]}</td><td>{download_btn}</td></tr>'
    rows = "".join(_preview_row(e) for e in entries)
    return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Shared Content Preview</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>body {{ background:#0d1117; color:#e6edf3; font-family:'Inter',system-ui,sans-serif; }} .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }} .table-hover tbody tr:hover {{ --bs-table-accent-bg: #21262d; }} a {{ color: #58a6ff; }} a:hover {{ color: #79c0ff; }}</style>
</head>
<body class="p-5">
    <div class="container">
        <h1 class="mb-4">Shared Content Preview</h1>
        <p class="text-secondary mb-4">Current location: /{req_path or 'Root'}</p>
        <a href="/" class="btn btn-outline-light mb-4">← Dashboard</a>
        <div class="table-responsive">
            <table class="table table-hover">
                <thead><tr><th>Name</th><th>Size</th><th>Action</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>
</body>
</html>"""


# ===========================================================================
# presentation/routes
# ===========================================================================
def create_routes(app, state):
    @app.route('/shared_count')
    def shared_count():
        return jsonify({'count': len(state.shared_paths)})

    @app.route('/shared_list')
    def shared_list():
        items = get_shared_items_list(state)
        return jsonify({'items': [{'path': item.path, 'name': item.name, 'size': item.size_str, 'is_folder': item.is_folder, 'tags': state.shared_paths.get(item.path, '')} for item in items]})

    @app.route('/my_preview')
    def my_preview():
        count = len(state.shared_paths)
        items = get_preview_items(state)
        html = f"""
        <div class="modal-content bg-dark text-light p-4 rounded">
            <h5 class="mb-3">Peer Preview — Your Instance ({state.my_id})</h5>
            <p class="text-muted small">Click off display to close or use the button below</p>
            <p><strong>Shared items:</strong> {count}</p>
            <hr class="bg-secondary">
            <h6>Top shared content:</h6>
            <div class="preview-body">
                <ul id="previewList" class="list-group list-group-flush small preview-list">
                    {''.join(
                        '<li class="list-group-item bg-dark text-light border-secondary py-2 d-flex justify-content-between align-items-center">'
                        + ("F " if i["is_folder"] else "f ") + i["name"]
                        + '<div class="d-flex align-items-center">'
                        + f'<small class="text-muted me-3">{i["size"]}</small>'
                        + (f'<a href="{i["download_url"]}" class="btn btn-sm btn-outline-light">Download</a>' if i["download_url"] else '')
                        + '</div></li>'
                        for i in items
                    ) or '<li class="list-group-item bg-dark text-muted border-secondary">No items shared yet</li>'}
                </ul>
            </div>
            <div class="mt-4 text-end">
                <button type="button" class="btn btn-sm btn-outline-light me-2" onclick="document.getElementById('previewModal').style.display='none'">Close</button>
                <a href="/" class="btn btn-sm btn-primary">Open Full Dashboard</a>
            </div>
        </div>
        """
        return html

    @app.route('/peer_shared_count/<peer_id>')
    def peer_shared_count_route(peer_id):
        if peer_id == str(state.my_id):
            return jsonify({'count': len(state.shared_paths)})
        peer_info = state.known_peers.get(peer_id)
        if not peer_info:
            return jsonify({'count': 0})
        count = fetch_peer_shared_count(peer_info.ip, peer_info.port)
        return jsonify({'count': count if count is not None else 0})

    @app.route('/peer_preview/<peer_id>')
    def peer_preview(peer_id):
        try:
            if peer_id == str(state.my_id):
                return my_preview()
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return '<div class="alert alert-warning m-4"><strong>Peer not found</strong></div>'
            count = "N/A"
            items = []
            count_val = fetch_peer_shared_count(peer_info.ip, peer_info.port)
            if count_val is not None: count = count_val
            remote_items = fetch_peer_shared_list(peer_info.ip, peer_info.port)
            if remote_items:
                count = len(remote_items)
                for item in remote_items:
                    path_clean = item.get('path', '').lstrip('/')
                    if path_clean:
                        download_url = f"/peer_download/{peer_id}/{path_clean.rstrip('/')}"
                    else:
                        download_url = None
                    items.append({'name': item.get('name', '—'), 'size': item.get('size', '—'), 'is_folder': item.get('is_folder', False), 'download_url': download_url})
            html = f"""
            <div class="modal-content bg-dark text-light p-4 rounded">
                <h5 class="mb-3">Peer Preview — {peer_id}</h5>
                <p class="text-muted small">Click off display to close or use the button below</p>
                <p><strong>Shared items:</strong> {count}</p>
                <hr class="bg-secondary">
                <div class="preview-body">
                    <div class="preview-search">
                        <input id="previewSearch" type="text" class="form-control" placeholder="Filter items..." oninput="filterPreview()">
                    </div>
                    <ul id="previewList" class="list-group list-group-flush small">
                        {''.join(
                            '<li class="list-group-item bg-dark text-light border-secondary py-2 d-flex justify-content-between align-items-center">'
                            + ("F " if i["is_folder"] else "f ") + i["name"]
                            + '<div class="d-flex align-items-center">'
                            + f'<small class="text-muted me-3">{i["size"]}</small>'
                            + (f'<a href="{i["download_url"]}" class="btn btn-sm btn-outline-light">Download</a>' if i.get("download_url") else '')
                            + '</div></li>'
                            for i in items
                        ) or '<li class="list-group-item bg-dark text-muted border-secondary">No items visible or reachable</li>'}
                    </ul>
                </div>
                <div class="mt-4 text-end">
                    <button type="button" class="btn btn-sm btn-outline-light me-2" onclick="document.getElementById('previewModal').style.display='none'">Close</button>
                </div>
            </div>
            """
            return html
        except requests.exceptions.ConnectionError:
            return '<div class="alert alert-warning m-4"><strong>Connection refused</strong><br>The peer is not reachable.</div>'
        except requests.exceptions.Timeout:
            return '<div class="alert alert-warning m-4"><strong>Request timed out</strong></div>'
        except Exception as e:
            return f'<div class="alert alert-danger m-4">Could not load preview<br><small>{str(e)}</small></div>'

    @app.route('/peer_connect/<peer_id>')
    def peer_connect(peer_id):
        if peer_id == str(state.my_id): return redirect('/')
        peer_info = state.known_peers.get(peer_id)
        if not peer_info: abort(404)
        return redirect(f"http://{peer_info.ip}:{peer_info.port}")

    @app.route('/peer_download/<peer_id>/<path:file_path>')
    def peer_download(peer_id, file_path):
        if peer_id == str(state.my_id): return redirect(f"/preview/{file_path}?download=1")
        peer_info = state.known_peers.get(peer_id)
        if not peer_info: abort(404)
        return redirect(f"http://{peer_info.ip}:{peer_info.port}/preview/{file_path}?download=1")

    @app.route('/search', methods=['GET'])
    def search():
        q = flask_request.args.get('q', '').strip()
        if not q: return redirect('/')
        results = search_network(state, q)
        results_dicts = [{'bank_id': r.bank_id, 'name': r.name, 'size': r.size, 'is_folder': r.is_folder, 'link': r.link} for r in results]
        return render_search_results(results_dicts, q)

    @app.route('/api/peers', methods=['GET'])
    def api_peers():
        sorted_live = get_sorted_live_peers(state)
        peers = [{'id': pid, 'shared_count': 0} for pid, data in sorted_live]
        return jsonify({'peers': peers, 'count': len(peers)})

    @app.route('/add_peer', methods=['POST'])
    def add_peer_route():
        ip_port = flask_request.form.get('ip_port', '').strip()
        if ip_port:
            if ':' in ip_port:
                parts = ip_port.rsplit(':', 1)
                ip = parts[0]
                try: port = int(parts[1])
                except ValueError: port = PORT
            else:
                ip = ip_port
                port = PORT
            add_manual_peer(state, ip, port)
        return redirect('/')

    @app.route('/api/global-config', methods=['GET'])
    def get_global_config_route():
        return jsonify(load_global_config())

    @app.route('/api/global-config', methods=['POST'])
    def set_global_config_route():
        data = flask_request.get_json(force=True)
        cfg = load_global_config()
        cfg.update({'enabled': bool(data.get('enabled', cfg.get('enabled'))), 'relay_url': data.get('relay_url', cfg.get('relay_url', '')).strip(), 'network_code': data.get('network_code', cfg.get('network_code', '')).strip(), 'auto_connect': bool(data.get('auto_connect', cfg.get('auto_connect', True)))})
        save_global_config(cfg)
        old_svc = getattr(state, '_global_discovery', None)
        if old_svc: old_svc.stop()
        new_svc = GlobalDiscoveryService(my_peer_id=str(state.my_id), my_call_number=state.call_number, local_ip=state.local_ip, local_port=PORT, on_peers_updated=getattr(old_svc, 'on_peers_updated', None) if old_svc else None)
        state._global_discovery = new_svc
        new_svc.start()
        return jsonify({'status': 'ok', 'enabled': new_svc.enabled})

    @app.route('/api/global-reconnect', methods=['POST'])
    def global_reconnect():
        old_svc = getattr(state, '_global_discovery', None)
        if not old_svc: return jsonify({'status': 'error', 'message': 'No global discovery service'})
        old_svc.stop()
        new_svc = GlobalDiscoveryService(my_peer_id=str(state.my_id), my_call_number=state.call_number, local_ip=state.local_ip, local_port=PORT, on_peers_updated=getattr(old_svc, 'on_peers_updated', None))
        state._global_discovery = new_svc
        new_svc.start()
        return jsonify({'status': 'ok', 'enabled': new_svc.enabled})

    @app.route('/api/global-status')
    def get_global_status():
        svc = getattr(state, '_global_discovery', None)
        if not svc: return jsonify({'status': 'N/A', 'peers': []})
        return jsonify({'status': svc.get_status(), 'peers': svc.global_peers, 'enabled': svc.enabled, 'network_code': svc.network_code, 'relay_url': svc.relay_url})

    @app.route('/')
    def homepage():
        failover_chain = get_current_failover_chain(state)
        sorted_live = get_sorted_live_peers(state)
        live_count = len(sorted_live)
        failover_dicts = [{'role': node.role, 'id': str(node.peer_id)} for node in failover_chain]
        global_cn = getattr(state, '_global_call_numbers', {})
        peers_list = [{'id': pid, 'call_number': state.call_number if pid == str(state.my_id) else global_cn.get(pid, 'N/A')} for pid, data in sorted_live]
        about_text = load_about_text()
        return render_homepage(random_id=str(state.my_id), failover_chain=failover_dicts, peers_list=peers_list, live_count=live_count, about_text=about_text, call_number=state.call_number)

    @app.route('/explorer', defaults={'req_path': ''}, strict_slashes=False)
    @app.route('/explorer/<path:req_path>', strict_slashes=False)
    def explorer(req_path):
        full_path = SHARED_DIR / req_path if req_path else SHARED_DIR
        if not is_path_safe(req_path, SHARED_DIR): abort(403)
        if full_path.is_file():
            if flask_request.args.get('download') == '1': return send_from_directory(SHARED_DIR, req_path, as_attachment=True)
            return send_from_directory(SHARED_DIR, req_path)
        if full_path.is_dir() and flask_request.args.get('download') == '1':
            import zipfile
            from flask import send_file
            zip_buf = _io.BytesIO()
            folder_name = full_path.name or 'shared'
            with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                for fp in full_path.rglob('*'):
                    if fp.is_file():
                        zf.write(fp, str(fp.relative_to(full_path)))
            zip_buf.seek(0)
            return send_file(zip_buf, mimetype='application/zip', as_attachment=True, download_name=f'{folder_name}.zip')
        if not full_path.is_dir(): abort(404)
        entries = list_explorer_directory(state, req_path)
        entries_dicts = [{'name': e.name, 'path': e.path, 'size': e.size, 'is_dir': e.is_dir, 'shared': e.shared, 'tags': e.tags} for e in entries]
        return render_explorer(entries_dicts, req_path)

    @app.route('/save_selection', methods=['POST'])
    def save_selection():
        current_path = flask_request.form.get('current_path', '').strip()
        selected = flask_request.form.getlist('path') or []
        tags_map = {}
        for p in selected:
            tag_val = flask_request.form.get(f'tags_{p}', '').strip()
            tags_map[p] = tag_val
        try:
            update_selection(state, current_path, selected, tags_map=tags_map)
            try:
                requests.post('http://localhost:3000/api/share-update', json={'peerId': str(state.my_id)}, timeout=1)
            except Exception: pass
            redirect_to = f'/explorer/{current_path}' if current_path else '/explorer'
            return redirect(redirect_to)
        except Exception as e:
            print("\n" + "="*80)
            print("ERROR in save_selection:")
            traceback.print_exc()
            print("="*80 + "\n")
            redirect_to = f'/explorer/{current_path}' if current_path else '/explorer'
            return redirect(redirect_to)

    @app.route('/preview', defaults={'req_path': ''}, strict_slashes=False)
    @app.route('/preview/<path:req_path>', strict_slashes=False)
    def preview(req_path):
        full_path = SHARED_DIR / req_path if req_path else SHARED_DIR
        if not is_path_safe(req_path, SHARED_DIR): abort(403)
        if full_path.is_file():
            if flask_request.args.get('download') == '1': return send_from_directory(SHARED_DIR, req_path, as_attachment=True)
            return send_from_directory(SHARED_DIR, req_path)
        if full_path.is_dir() and flask_request.args.get('download') == '1':
            import zipfile
            from flask import send_file
            zip_buf = _io.BytesIO()
            folder_name = full_path.name or 'shared'
            with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                for fp in full_path.rglob('*'):
                    if fp.is_file():
                        zf.write(fp, str(fp.relative_to(full_path)))
            zip_buf.seek(0)
            return send_file(zip_buf, mimetype='application/zip', as_attachment=True, download_name=f'{folder_name}.zip')
        if not full_path.is_dir(): abort(404)
        all_entries = list_directory_entries(full_path, SHARED_DIR, state.shared_paths)
        visible_entries = [e for e in all_entries if is_path_shared(e.path, state.shared_paths)]
        entries_dicts = [{'name': e.name, 'path': e.path, 'size': e.size, 'is_dir': e.is_dir} for e in visible_entries]
        return render_preview(entries_dicts, req_path)

    # ========== VAULT ROUTES ==========
    _vault_instance = [None]
    _vault_errors = [[]]

    def _get_vault(password=None, secret_file_data=None):
        if _vault_instance[0] and _vault_instance[0].is_unlocked: return _vault_instance[0]
        if password:
            vault_path = get_default_vault_path()
            v = SecureVault(str(vault_path), password=password, secret_file_data=secret_file_data)
            _vault_instance[0] = v
            if not v.is_unlocked and v.last_validation_errors: _vault_errors[0] = v.last_validation_errors
            else: _vault_errors[0] = []
            return v
        return None

    def _vault_needs_secret_file():
        meta_path = get_default_vault_path() / VAULT_META_FILE
        if meta_path.exists():
            try:
                with open(meta_path, 'r') as f: meta = json.load(f)
                return meta.get('requires_secret_file', False)
            except Exception: pass
        return False

    @app.route('/vault', methods=['GET'])
    def vault_page():
        vault = _get_vault()
        unlocked = vault is not None and vault.is_unlocked
        files = vault.list_files() if unlocked else []
        needs_secret = _vault_needs_secret_file()
        errors = _vault_errors[0]
        files_html = ""
        for f in files:
            size_str = f"{f['size']:,} bytes"
            if f['size'] > 1048576: size_str = f"{f['size']/1048576:.1f} MB"
            elif f['size'] > 1024: size_str = f"{f['size']/1024:.1f} KB"
            loc = "Downloads" if f['is_download'] else "Vault"
            files_html += (f'<tr><td>{f["name"]}</td><td>{size_str}</td><td>{loc}</td><td><form method="post" action="/vault/open" style="display:inline"><input type="hidden" name="filename" value="{f["name"]}"><button class="btn btn-sm btn-outline-light me-1" type="submit">Open</button></form><form method="post" action="/vault/remove" style="display:inline"><input type="hidden" name="filename" value="{f["name"]}"><button class="btn btn-sm btn-outline-danger" type="submit">Remove</button></form></td></tr>')
        error_html = ""
        if errors:
            items = "".join(f"<li>{e}</li>" for e in errors)
            error_html = f'<div class="alert alert-danger"><strong>Error:</strong><ul class="mb-0">{items}</ul></div>'
        secret_file_field = ""
        if needs_secret:
            secret_file_field = '<label class="form-label small text-warning mt-2">Secret file required:</label><input type="file" name="secret_file" class="form-control bg-dark text-white border-secondary mb-3" required>'
        if not unlocked:
            req_html = format_password_requirements_html()
            strength_js = password_strength_js()
            body = f'''
            <div class="card">
                <div class="card-header">Unlock Vault</div>
                <div class="card-body">
                    {error_html}
                    <form method="post" action="/vault/unlock" enctype="multipart/form-data">
                        <input type="password" id="vaultPw" name="password" class="form-control mb-1 bg-dark text-white border-secondary" placeholder="Vault password" required>
                        <div id="pwStrength" class="mb-3 small"></div>
                        {secret_file_field}
                        <div class="form-check mb-3">
                            <input class="form-check-input" type="checkbox" name="setup_secret_file" id="setupSecretFile" value="1">
                            <label class="form-check-label small text-muted" for="setupSecretFile">Set up a secret file (optional, in addition to password)</label>
                        </div>
                        <div id="newSecretFileDiv" style="display:none" class="mb-3">
                            <label class="form-label small">Choose your secret file:</label>
                            <input type="file" name="new_secret_file" class="form-control bg-dark text-white border-secondary">
                            <small class="text-muted">This exact file will be required every time you unlock the vault.</small>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Unlock / Create Vault</button>
                    </form>
                    {req_html}
                    <p class="text-muted small mt-2">The vault is optional. It is never the default save location.</p>
                </div>
            </div>
            {strength_js}
            <script>
            checkPasswordStrength('vaultPw', 'pwStrength');
            document.getElementById('setupSecretFile').addEventListener('change', function() {{
                document.getElementById('newSecretFileDiv').style.display = this.checked ? 'block' : 'none';
            }});
            </script>'''
        else:
            body = f'''
            <div class="card mb-4">
                <div class="card-header">Vault — Encrypted Storage (Optional)</div>
                <div class="card-body">
                    <p class="text-success">Vault is unlocked</p>
                    <form method="post" action="/vault/add" enctype="multipart/form-data" class="mb-3">
                        <div class="input-group">
                            <input type="file" name="file" class="form-control bg-dark text-white border-secondary" required>
                            <select name="location" class="form-select bg-dark text-white border-secondary" style="max-width:150px">
                                <option value="vault">Vault</option>
                                <option value="downloads">Downloads</option>
                            </select>
                            <button type="submit" class="btn btn-primary">Add File</button>
                        </div>
                    </form>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead><tr><th>Name</th><th>Size</th><th>Location</th><th>Actions</th></tr></thead>
                            <tbody>{files_html or '<tr><td colspan="4" class="text-muted">No files in vault</td></tr>'}</tbody>
                        </table>
                    </div>
                    <form method="post" action="/vault/lock" class="mt-3">
                        <button type="submit" class="btn btn-outline-warning w-100">Lock Vault</button>
                    </form>
                </div>
            </div>'''
        return f'''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Vault — Global Network Archive</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>body {{ background:#0d1117; color:#e6edf3; font-family:'Inter',system-ui,sans-serif; }} .table {{ --bs-table-bg: #161b22; --bs-table-color: #e6edf3; }} .card {{ background: #161b22; border: 1px solid #30363d; }} .card-header {{ background: #21262d; border-bottom: 1px solid #30363d; color: #58a6ff; }} a {{ color: #58a6ff; }}</style>
</head>
<body class="p-5">
<div class="container">
    <h1 class="mb-4">Encrypted Vault</h1>
    <a href="/" class="btn btn-outline-light mb-4">&larr; Dashboard</a>
    {body}
</div>
</body></html>'''

    @app.route('/vault/unlock', methods=['POST'])
    def vault_unlock():
        password = flask_request.form.get('password', '')
        if not password: return redirect('/vault')
        secret_data = None
        sf = flask_request.files.get('secret_file')
        if sf and sf.filename: secret_data = sf.read()
        nsf = flask_request.files.get('new_secret_file')
        if nsf and nsf.filename and flask_request.form.get('setup_secret_file') == '1': secret_data = nsf.read()
        _get_vault(password, secret_data)
        return redirect('/vault')

    @app.route('/vault/lock', methods=['POST'])
    def vault_lock():
        _vault_instance[0] = None
        _vault_errors[0] = []
        return redirect('/vault')

    @app.route('/vault/add', methods=['POST'])
    def vault_add():
        vault = _get_vault()
        if not vault or not vault.is_unlocked: return redirect('/vault')
        file = flask_request.files.get('file')
        if not file: return redirect('/vault')
        location = flask_request.form.get('location', 'vault')
        is_download = location == 'downloads'
        data = file.read()
        vault.add_file(file.filename, data, is_download=is_download)
        return redirect('/vault')

    @app.route('/vault/open', methods=['POST'])
    def vault_open():
        vault = _get_vault()
        if not vault or not vault.is_unlocked: return redirect('/vault')
        filename = flask_request.form.get('filename', '')
        if filename: vault.open_file(filename)
        return redirect('/vault')

    @app.route('/vault/remove', methods=['POST'])
    def vault_remove():
        vault = _get_vault()
        if not vault or not vault.is_unlocked: return redirect('/vault')
        filename = flask_request.form.get('filename', '')
        if filename: vault.remove_file(filename)
        return redirect('/vault')

    @app.route('/api/web-search')
    def web_search():
        query = flask_request.args.get('q', '').strip()
        if not query: return jsonify({'error': 'No query provided', 'results': []})
        if len(query) > 500: return jsonify({'error': 'Query too long', 'results': []})
        results = []
        engine = 'DuckDuckGo'
        try:
            from bs4 import BeautifulSoup
            resp = requests.post('https://lite.duckduckgo.com/lite/', data={'q': query}, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, timeout=10)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link_tag in soup.find_all('a', class_='result-link'):
                title = link_tag.get_text(strip=True)
                url = link_tag.get('href', '')
                snippet_tag = link_tag.find_parent('tr')
                snippet = ''
                if snippet_tag:
                    next_tr = snippet_tag.find_next_sibling('tr')
                    if next_tr:
                        snippet_td = next_tr.find('td', class_='result-snippet')
                        if snippet_td: snippet = snippet_td.get_text(strip=True)
                if url and title: results.append({'title': title, 'url': url, 'snippet': snippet})
                if len(results) >= 20: break
        except ImportError:
            try:
                resp = requests.post('https://lite.duckduckgo.com/lite/', data={'q': query}, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, timeout=10)
                resp.raise_for_status()
                html = resp.text
                link_pattern = re.compile(r'<a[^>]+class="result-link"[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', re.IGNORECASE)
                snippet_pattern = re.compile(r'<td[^>]+class="result-snippet"[^>]*>(.*?)</td>', re.IGNORECASE | re.DOTALL)
                links = link_pattern.findall(html)
                snippets = snippet_pattern.findall(html)
                for i, (url, title) in enumerate(links):
                    snippet = ''
                    if i < len(snippets): snippet = re.sub(r'<[^>]+>', '', snippets[i]).strip()
                    results.append({'title': title.strip(), 'url': url.strip(), 'snippet': snippet})
                    if len(results) >= 20: break
            except Exception: pass
        except Exception as e:
            return jsonify({'error': f'Search failed: {str(e)}', 'results': []})
        return jsonify({'results': results, 'engine': engine, 'query': query})

    @app.route('/launch_call/<peer_id>', methods=['POST'])
    def launch_call(peer_id):
        try:
            base_path = PROJECT_DIR
            caller_path = base_path / 'caller.py'
            if not caller_path.exists(): return jsonify({'success': False, 'error': 'caller.py not found'})
            my_id = str(state.my_id)
            my_call_num = state.call_number
            subprocess.Popen([sys.executable, str(caller_path), my_id, my_call_num, peer_id], creationflags=0)
            return jsonify({'success': True, 'peer_id': peer_id})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/launch_screen_viewer/<peer_id>', methods=['POST'])
    def launch_screen_viewer(peer_id):
        try:
            base_path = PROJECT_DIR
            receiver_path = base_path / 'receiver.py'
            sender_path = base_path / 'sender.py'
            if not receiver_path.exists(): return jsonify({'success': False, 'error': 'receiver.py not found'})
            my_id = str(state.my_id)
            if peer_id == my_id:
                if not sender_path.exists(): return jsonify({'success': False, 'error': 'sender.py not found'})
                session_id_file = base_path / 'sender_session_id.txt'
                with open(session_id_file, 'w') as f: f.write(my_id)
                subprocess.Popen([sys.executable, str(sender_path)], creationflags=0)
                time.sleep(2)
            subprocess.Popen([sys.executable, str(receiver_path), peer_id], creationflags=0)
            return jsonify({'success': True, 'peer_id': peer_id, 'sender_started': peer_id == my_id})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/upload_to_peer/<peer_id>', methods=['POST'])
    def upload_to_peer(peer_id):
        try:
            file = flask_request.files.get('file')
            if not file or not file.filename:
                return jsonify({'success': False, 'error': 'No file selected'})
            dest_path = flask_request.form.get('dest_path', 'Desktop/').strip()
            file_data = file.read()
            if len(file_data) > 100 * 1024 * 1024:
                return jsonify({'success': False, 'error': 'File too large (max 100 MB)'})
            # If uploading to self, add directly to pending
            if peer_id == str(state.my_id):
                upload_id = add_pending_upload(
                    sender_id=str(state.my_id),
                    sender_ip=state.local_ip,
                    filename=file.filename,
                    dest_path=dest_path,
                    file_data=file_data
                )
                return jsonify({'success': True, 'upload_id': upload_id, 'message': 'Upload queued locally'})
            # Find peer and forward
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': f'Peer {peer_id} not found'})
            try:
                resp = requests.post(
                    f"http://{peer_info.ip}:{peer_info.port}/api/incoming-upload",
                    files={'file': (file.filename, _io.BytesIO(file_data), 'application/octet-stream')},
                    data={'sender_id': str(state.my_id), 'sender_ip': state.local_ip, 'dest_path': dest_path},
                    timeout=30
                )
                resp.raise_for_status()
                result = resp.json()
                return jsonify({'success': result.get('success', False), 'upload_id': result.get('upload_id', ''),
                                'message': result.get('message', 'Sent to peer')})
            except requests.exceptions.ConnectionError:
                return jsonify({'success': False, 'error': f'Could not connect to {peer_id} — peer unreachable'})
            except requests.exceptions.Timeout:
                return jsonify({'success': False, 'error': 'Upload timed out'})
            except Exception as e:
                return jsonify({'success': False, 'error': f'Transfer failed: {str(e)}'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/incoming-upload', methods=['POST'])
    def incoming_upload():
        try:
            file = flask_request.files.get('file')
            if not file or not file.filename:
                return jsonify({'success': False, 'error': 'No file in request'})
            sender_id = flask_request.form.get('sender_id', 'unknown')
            sender_ip = flask_request.form.get('sender_ip', flask_request.remote_addr or 'unknown')
            dest_path = flask_request.form.get('dest_path', 'Desktop/')
            file_data = file.read()
            upload_id = add_pending_upload(
                sender_id=sender_id,
                sender_ip=sender_ip,
                filename=file.filename,
                dest_path=dest_path,
                file_data=file_data
            )
            print(f"[UPLOAD] Incoming file '{file.filename}' from {sender_id} — awaiting approval (id: {upload_id})")
            return jsonify({'success': True, 'upload_id': upload_id, 'message': 'Upload pending approval'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/pending-uploads', methods=['GET'])
    def pending_uploads_route():
        cleanup_old_uploads()
        return jsonify({'uploads': get_pending_uploads()})

    @app.route('/api/accept-upload/<upload_id>', methods=['POST'])
    def accept_upload_route(upload_id):
        try:
            upload = accept_upload(upload_id)
            if not upload:
                return jsonify({'success': False, 'error': 'Upload not found or already handled'})
            dest_path = upload.get('dest_path', 'Desktop/')
            filename = upload.get('filename', 'unnamed_file')
            file_data = upload.get('file_data', b'')
            # Resolve destination: relative to user's home directory
            home = Path.home()
            target_dir = home / dest_path.rstrip('/')
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / filename
            # Avoid overwriting — add suffix if file exists
            if target_file.exists():
                stem = target_file.stem
                suffix = target_file.suffix
                counter = 1
                while target_file.exists():
                    target_file = target_dir / f"{stem}_{counter}{suffix}"
                    counter += 1
            with open(target_file, 'wb') as f:
                f.write(file_data)
            saved_to = str(target_file.relative_to(home))
            print(f"[UPLOAD] Accepted '{filename}' from {upload.get('sender_id')} — saved to ~/{saved_to}")
            return jsonify({'success': True, 'saved_to': saved_to, 'filename': filename})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/reject-upload/<upload_id>', methods=['POST'])
    def reject_upload_route(upload_id):
        try:
            result = reject_upload(upload_id)
            if result:
                print(f"[UPLOAD] Rejected upload {upload_id}")
                return jsonify({'success': True})
            return jsonify({'success': False, 'error': 'Upload not found or already handled'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/ping/<peer_id>', methods=['POST'])
    def ping_peer(peer_id):
        try:
            if peer_id == str(state.my_id):
                return jsonify({'success': True, 'latency_ms': 0, 'status': 'self'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            start = time.time()
            try:
                resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/api/info", timeout=5)
                latency = round((time.time() - start) * 1000)
                if resp.status_code == 200:
                    return jsonify({'success': True, 'latency_ms': latency, 'status': 'reachable',
                                    'peer_version': resp.json().get('version', '?')})
                return jsonify({'success': True, 'latency_ms': latency, 'status': f'http_{resp.status_code}'})
            except requests.exceptions.ConnectionError:
                return jsonify({'success': False, 'error': 'Unreachable', 'latency_ms': -1})
            except requests.exceptions.Timeout:
                return jsonify({'success': False, 'error': 'Timeout (>5s)', 'latency_ms': -1})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/request-file-list/<peer_id>')
    def request_file_list(peer_id):
        try:
            if peer_id == str(state.my_id):
                items = get_shared_items_list(state)
                return jsonify({'items': [{'path': i.path, 'name': i.name, 'size': i.size_str,
                                           'is_folder': i.is_folder} for i in items]})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'error': f'Peer {peer_id} not found', 'items': []})
            resp = requests.get(f"http://{peer_info.ip}:{peer_info.port}/shared_list", timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return jsonify({'items': data.get('items', [])})
        except requests.exceptions.ConnectionError:
            return jsonify({'error': 'Peer unreachable', 'items': []})
        except Exception as e:
            return jsonify({'error': str(e), 'items': []})

    @app.route('/api/request-file-download/<peer_id>/<path:file_path>', methods=['POST'])
    def request_file_download(peer_id, file_path):
        try:
            home = Path.home()
            downloads_dir = home / 'Desktop' / 'GNA_Downloads'
            downloads_dir.mkdir(parents=True, exist_ok=True)
            if peer_id == str(state.my_id):
                # Local file or folder — copy from shared dir
                source = SHARED_DIR / file_path
                if not source.exists():
                    return jsonify({'success': False, 'error': 'Path not found locally'})
                if source.is_dir():
                    import zipfile
                    folder_name = source.name or 'folder'
                    dest = downloads_dir / f"{folder_name}.zip"
                    if dest.exists():
                        c = 1
                        while dest.exists():
                            dest = downloads_dir / f"{folder_name}_{c}.zip"
                            c += 1
                    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for fp in source.rglob('*'):
                            if fp.is_file():
                                zf.write(fp, str(fp.relative_to(source)))
                    return jsonify({'success': True, 'saved_to': str(dest.relative_to(home))})
                dest = downloads_dir / source.name
                if dest.exists():
                    stem, suffix = dest.stem, dest.suffix
                    c = 1
                    while dest.exists():
                        dest = downloads_dir / f"{stem}_{c}{suffix}"
                        c += 1
                shutil.copy2(str(source), str(dest))
                return jsonify({'success': True, 'saved_to': str(dest.relative_to(home))})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            dl_url = f"http://{peer_info.ip}:{peer_info.port}/preview/{file_path}?download=1"
            resp = requests.get(dl_url, timeout=60, stream=True)
            if resp.status_code != 200:
                return jsonify({'success': False, 'error': f'Remote returned {resp.status_code}'})
            content = resp.content
            file_name = Path(file_path).name
            # Detect zip response (folder download)
            ct = resp.headers.get('Content-Type', '')
            if 'zip' in ct and not file_name.endswith('.zip'):
                file_name = file_name + '.zip'
            dest = downloads_dir / file_name
            if dest.exists():
                stem, suffix = dest.stem, dest.suffix
                c = 1
                while dest.exists():
                    dest = downloads_dir / f"{stem}_{c}{suffix}"
                    c += 1
            with open(dest, 'wb') as f:
                f.write(resp.content)
            saved_to = str(dest.relative_to(home))
            print(f"[REQUEST] Downloaded '{file_name}' from {peer_id} — saved to ~/{saved_to}")
            return jsonify({'success': True, 'saved_to': saved_to, 'filename': file_name})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sync-folder', methods=['POST'])
    def sync_folder_route():
        try:
            data = flask_request.get_json(force=True)
            peer_id = data.get('peer_id', '')
            local_path = data.get('local_path', 'Desktop/synced/').strip()
            remote_path = data.get('remote_path', '').strip()
            if not peer_id:
                return jsonify({'success': False, 'error': 'No peer specified'})
            if not local_path:
                return jsonify({'success': False, 'error': 'No local path specified'})
            # Find peer info
            if peer_id == str(state.my_id):
                peer_ip = '127.0.0.1'
                peer_port = PORT
            else:
                peer_info = state.known_peers.get(peer_id)
                if not peer_info:
                    return jsonify({'success': False, 'error': f'Peer {peer_id} not found'})
                peer_ip = peer_info.ip
                peer_port = peer_info.port
            # Do an initial sync right now
            sync_id = add_active_sync(peer_id, local_path, remote_path, peer_ip, peer_port)
            # Run initial sync inline
            try:
                resp = requests.get(f"http://{peer_ip}:{peer_port}/shared_list", timeout=10)
                resp.raise_for_status()
                items = resp.json().get('items', [])
                home = Path.home()
                target_dir = home / local_path.rstrip('/')
                target_dir.mkdir(parents=True, exist_ok=True)
                count = 0
                for item in items:
                    if item.get('is_folder', False):
                        continue
                    item_path = item.get('path', '')
                    if remote_path and not item_path.startswith(remote_path):
                        continue
                    try:
                        dl_url = f"http://{peer_ip}:{peer_port}/preview/{item_path}?download=1"
                        dl_resp = requests.get(dl_url, timeout=30)
                        if dl_resp.status_code == 200:
                            file_name = Path(item_path).name
                            dest_file = target_dir / file_name
                            if not dest_file.exists() or dest_file.stat().st_size != len(dl_resp.content):
                                with open(dest_file, 'wb') as f:
                                    f.write(dl_resp.content)
                                count += 1
                    except Exception:
                        pass
                with _active_syncs_lock:
                    s = _active_syncs.get(sync_id)
                    if s:
                        s['files_synced'] = count
                        s['last_sync'] = time.time()
                        s['active'] = False
            except Exception as e:
                print(f"[SYNC] Initial sync failed for {sync_id}: {e}")
            # Start background sync thread
            threading.Thread(target=run_sync_job, args=(sync_id, state), daemon=True,
                             name=f"SyncThread-{sync_id}").start()
            print(f"[SYNC] Started sync {sync_id}: {peer_id} -> ~/{local_path}")
            with _active_syncs_lock:
                files_synced = _active_syncs.get(sync_id, {}).get('files_synced', 0)
            return jsonify({'success': True, 'sync_id': sync_id, 'files_synced': files_synced})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/active-syncs')
    def active_syncs_route():
        return jsonify({'syncs': get_active_syncs()})

    @app.route('/api/stop-sync/<sync_id>', methods=['POST'])
    def stop_sync_route(sync_id):
        result = stop_sync(sync_id)
        if result:
            print(f"[SYNC] Stopped sync {sync_id}")
        return jsonify({'success': result})

    @app.route('/api/permissions', methods=['GET', 'POST'])
    def permissions_route():
        if flask_request.method == 'GET':
            return jsonify({'permissions': get_remote_permissions()})
        data = flask_request.get_json(force=True)
        key = data.get('key', '')
        value = data.get('value', False)
        ok = set_remote_permission(key, value)
        action = 'enabled' if value else 'disabled'
        if ok:
            print(f"[PERMS] {key} {action}")
        return jsonify({'success': ok})

    @app.route('/api/peer-permissions/<peer_id>')
    def peer_permissions_route(peer_id):
        try:
            if peer_id == str(state.my_id):
                return jsonify({'success': True, 'peer_id': peer_id, 'permissions': get_remote_permissions()})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/peer-permissions/{peer_id}",
                timeout=5
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/remote-exec/<peer_id>', methods=['POST'])
    def remote_exec(peer_id):
        try:
            data = flask_request.get_json(force=True)
            cmd = data.get('command', '').strip()
            if not cmd:
                return jsonify({'error': 'No command provided'})
            if peer_id == str(state.my_id):
                # Permission check: block remote requests if not allowed
                if not is_local_request() and not get_remote_permissions().get('remote_exec'):
                    return jsonify({'error': 'Remote terminal is disabled on this peer. Ask the owner to enable it.'})
                try:
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True, timeout=30,
                        cwd=str(Path.home())
                    )
                    output = result.stdout
                    if result.stderr:
                        output += result.stderr
                    return jsonify({'output': output or '(no output)', 'exit_code': result.returncode})
                except subprocess.TimeoutExpired:
                    return jsonify({'error': 'Command timed out (30s limit)'})
                except Exception as e:
                    return jsonify({'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'error': f'Peer {peer_id} not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/remote-exec/{peer_id}",
                json={'command': cmd}, timeout=35
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'error': str(e)})

    @app.route('/api/clipboard-send/<peer_id>', methods=['POST'])
    def clipboard_send(peer_id):
        try:
            data = flask_request.get_json(force=True)
            text = data.get('text', '')
            if not text:
                return jsonify({'success': False, 'error': 'No text provided'})
            if peer_id == str(state.my_id):
                # Permission check: block remote clipboard writes
                if not is_local_request() and not get_remote_permissions().get('clipboard_write'):
                    return jsonify({'success': False, 'error': 'Clipboard write is disabled on this peer. Ask the owner to enable it.'})
                try:
                    import tempfile
                    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
                    tmp.write(text)
                    tmp.close()
                    tmp_path = tmp.name
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    subprocess.run(
                        ['powershell', '-Command', f'Get-Content -Raw -Path "{tmp_path}" | Set-Clipboard'],
                        capture_output=True, timeout=10, creationflags=cflags
                    )
                    os.unlink(tmp_path)
                    return jsonify({'success': True})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': f'Peer {peer_id} not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/clipboard-send/{peer_id}",
                json={'text': text}, timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/clipboard-grab/<peer_id>', methods=['POST'])
    def clipboard_grab(peer_id):
        try:
            if peer_id == str(state.my_id):
                # Permission check: block remote clipboard reads
                if not is_local_request() and not get_remote_permissions().get('clipboard_read'):
                    return jsonify({'success': False, 'error': 'Clipboard read is disabled on this peer. Ask the owner to enable it.'})
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', 'Get-Clipboard'],
                        capture_output=True, text=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    )
                    return jsonify({'success': True, 'text': result.stdout.strip()})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': f'Peer {peer_id} not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/clipboard-grab/{peer_id}",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/power/<peer_id>/<action>', methods=['POST'])
    def power_control(peer_id, action):
        try:
            valid_actions = {'wake', 'sleep', 'restart', 'shutdown'}
            if action not in valid_actions:
                return jsonify({'success': False, 'error': f'Invalid action: {action}'})
            if action == 'wake':
                # Wake-on-LAN — need the peer's MAC address or IP
                peer_info = state.known_peers.get(peer_id)
                if not peer_info:
                    return jsonify({'success': False, 'error': 'Peer not found'})
                # Try to get MAC from ARP table
                try:
                    arp_result = subprocess.run(
                        ['arp', '-a', peer_info.ip],
                        capture_output=True, text=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    )
                    mac = None
                    for line in arp_result.stdout.splitlines():
                        if peer_info.ip in line:
                            parts = line.split()
                            for p in parts:
                                if len(p) == 17 and (p.count('-') == 5 or p.count(':') == 5):
                                    mac = p.replace('-', ':')
                                    break
                            if mac: break
                    if not mac:
                        return jsonify({'success': False, 'error': f'Could not find MAC address for {peer_info.ip}. Try pinging the peer first.'})
                    # Send WOL magic packet
                    mac_bytes = bytes.fromhex(mac.replace(':', ''))
                    magic = b'\xff' * 6 + mac_bytes * 16
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    sock.sendto(magic, ('255.255.255.255', 9))
                    sock.sendto(magic, ('255.255.255.255', 7))
                    sock.close()
                    return jsonify({'success': True, 'message': f'Wake-on-LAN packet sent to {mac}'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            # For sleep/restart/shutdown — execute on peer
            if peer_id == str(state.my_id):
                # Permission check: block remote power commands
                if not is_local_request() and not get_remote_permissions().get('power_control'):
                    return jsonify({'success': False, 'error': 'Power control is disabled on this peer. Ask the owner to enable it.'})
                cmds = {
                    'shutdown': 'shutdown /s /t 5 /c "Remote shutdown via GNA"',
                    'restart': 'shutdown /r /t 5 /c "Remote restart via GNA"',
                    'sleep': 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0',
                }
                cmd = cmds.get(action)
                try:
                    subprocess.Popen(cmd, shell=True,
                                     creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
                    return jsonify({'success': True, 'message': f'{action.title()} command executed locally'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/power/{peer_id}/{action}",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/bandwidth-test/<peer_id>', methods=['POST'])
    def bandwidth_test(peer_id):
        try:
            if peer_id == str(state.my_id):
                # Self-test: benchmark against own Flask via loopback
                base_url = f"http://127.0.0.1:{PORT}"
                lat_start = time.time()
                try:
                    requests.get(f"{base_url}/api/info", timeout=5)
                except Exception:
                    return jsonify({'success': False, 'error': 'Loopback unreachable'})
                latency_ms = round((time.time() - lat_start) * 1000)
                test_size = 2 * 1024 * 1024
                dl_start = time.time()
                try:
                    dl_resp = requests.get(f"{base_url}/api/bw-test-payload?size={test_size}", timeout=30)
                    dl_time = time.time() - dl_start
                    dl_mbps = (len(dl_resp.content) * 8) / (dl_time * 1_000_000) if dl_time > 0 else 0
                except Exception:
                    dl_mbps = 0
                payload = os.urandom(test_size)
                ul_start = time.time()
                try:
                    requests.post(f"{base_url}/api/bw-test-receive", data=payload, timeout=30,
                                  headers={'Content-Type': 'application/octet-stream'})
                    ul_time = time.time() - ul_start
                    ul_mbps = (len(payload) * 8) / (ul_time * 1_000_000) if ul_time > 0 else 0
                except Exception:
                    ul_mbps = 0
                return jsonify({'success': True, 'download_mbps': round(dl_mbps, 2),
                                'upload_mbps': round(ul_mbps, 2), 'latency_ms': latency_ms})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            base_url = f"http://{peer_info.ip}:{peer_info.port}"
            # Latency test
            lat_start = time.time()
            try:
                requests.get(f"{base_url}/api/info", timeout=5)
            except Exception:
                return jsonify({'success': False, 'error': 'Peer unreachable'})
            latency_ms = round((time.time() - lat_start) * 1000)
            # Download test: fetch the test payload from peer
            test_size = 2 * 1024 * 1024  # 2 MB payload
            dl_start = time.time()
            try:
                dl_resp = requests.get(f"{base_url}/api/bw-test-payload?size={test_size}", timeout=30)
                dl_bytes = len(dl_resp.content)
                dl_time = time.time() - dl_start
                dl_mbps = (dl_bytes * 8) / (dl_time * 1_000_000) if dl_time > 0 else 0
            except Exception:
                dl_mbps = 0
                dl_bytes = 0
                dl_time = 0
            # Upload test: send a test payload to peer
            payload = os.urandom(test_size)
            ul_start = time.time()
            try:
                requests.post(f"{base_url}/api/bw-test-receive", data=payload, timeout=30,
                              headers={'Content-Type': 'application/octet-stream'})
                ul_time = time.time() - ul_start
                ul_mbps = (len(payload) * 8) / (ul_time * 1_000_000) if ul_time > 0 else 0
            except Exception:
                ul_mbps = 0
            return jsonify({
                'success': True,
                'download_mbps': round(dl_mbps, 2),
                'upload_mbps': round(ul_mbps, 2),
                'latency_ms': latency_ms,
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/bw-test-payload')
    def bw_test_payload():
        size = min(int(flask_request.args.get('size', 2097152)), 10 * 1024 * 1024)  # Max 10 MB
        data = os.urandom(size)
        return Response(data, mimetype='application/octet-stream')

    @app.route('/api/bw-test-receive', methods=['POST'])
    def bw_test_receive():
        _ = flask_request.get_data()
        return jsonify({'success': True, 'bytes_received': len(_)})

    @app.route('/api/screenshot/<peer_id>', methods=['POST'])
    def screenshot_capture(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('screenshot'):
                    return jsonify({'success': False, 'error': 'Screenshot is disabled on this peer. Ask the owner to enable it.'})
                try:
                    import mss
                    import base64
                    with mss.mss() as sct:
                        monitor = sct.monitors[0]
                        img = sct.grab(monitor)
                        png_bytes = mss.tools.to_png(img.rgb, img.size)
                    encoded = base64.b64encode(png_bytes).decode('ascii')
                    return jsonify({'success': True, 'image': encoded})
                except ImportError:
                    # Fallback: use PowerShell screenshot
                    try:
                        import base64
                        ps_script = (
                            "Add-Type -AssemblyName System.Windows.Forms;"
                            "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
                            "$bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height);"
                            "$g=[System.Drawing.Graphics]::FromImage($bmp);"
                            "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
                            "$ms=New-Object System.IO.MemoryStream;"
                            "$bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png);"
                            "[Convert]::ToBase64String($ms.ToArray())"
                        )
                        result = subprocess.run(
                            ['powershell', '-Command', ps_script],
                            capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            return jsonify({'success': True, 'image': result.stdout.strip()})
                        return jsonify({'success': False, 'error': 'Screenshot failed: ' + (result.stderr or 'no output')})
                    except Exception as e:
                        return jsonify({'success': False, 'error': f'Screenshot unavailable: {e}'})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/screenshot/{peer_id}",
                timeout=20
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sysinfo/<peer_id>')
    def sysinfo_route(peer_id):
        try:
            if peer_id == str(state.my_id):
                import platform
                info = {
                    'os': f"{platform.system()} {platform.release()} ({platform.version()})",
                    'hostname': platform.node(),
                    'cpu': platform.processor() or 'N/A',
                    'cpu_cores': str(os.cpu_count() or 'N/A'),
                    'architecture': platform.machine(),
                    'python_version': platform.python_version(),
                }
                # RAM info
                try:
                    import psutil
                    vm = psutil.virtual_memory()
                    info['ram_total'] = f"{vm.total / (1024**3):.1f} GB"
                    info['ram_used'] = f"{vm.used / (1024**3):.1f} GB"
                    info['ram_percent'] = str(vm.percent)
                    du = psutil.disk_usage('/')
                    info['disk_total'] = f"{du.total / (1024**3):.1f} GB"
                    info['disk_used'] = f"{du.used / (1024**3):.1f} GB"
                    info['disk_free'] = f"{du.free / (1024**3):.1f} GB"
                    info['disk_percent'] = str(du.percent)
                    boot = psutil.boot_time()
                    uptime_sec = time.time() - boot
                    days = int(uptime_sec // 86400)
                    hours = int((uptime_sec % 86400) // 3600)
                    mins = int((uptime_sec % 3600) // 60)
                    info['uptime'] = f"{days}d {hours}h {mins}m"
                except ImportError:
                    # Fallback without psutil: use WMIC / PowerShell
                    cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    # RAM via WMIC
                    try:
                        ram_r = subprocess.run(['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory', '/value'],
                                               capture_output=True, text=True, timeout=10, creationflags=cflags)
                        vals = {}
                        for line in ram_r.stdout.splitlines():
                            if '=' in line:
                                k, v = line.strip().split('=', 1)
                                vals[k.strip()] = int(v.strip()) if v.strip().isdigit() else 0
                        total_kb = vals.get('TotalVisibleMemorySize', 0)
                        free_kb = vals.get('FreePhysicalMemory', 0)
                        used_kb = total_kb - free_kb
                        info['ram_total'] = f"{total_kb / (1024*1024):.1f} GB"
                        info['ram_used'] = f"{used_kb / (1024*1024):.1f} GB"
                        info['ram_percent'] = str(round(used_kb / total_kb * 100)) if total_kb else '0'
                    except Exception:
                        info['ram_total'] = 'N/A'
                        info['ram_used'] = 'N/A'
                        info['ram_percent'] = '0'
                    # Disk via WMIC
                    try:
                        disk_r = subprocess.run(['wmic', 'logicaldisk', 'where', 'DeviceID="C:"', 'get', 'Size,FreeSpace', '/value'],
                                                capture_output=True, text=True, timeout=10, creationflags=cflags)
                        vals = {}
                        for line in disk_r.stdout.splitlines():
                            if '=' in line:
                                k, v = line.strip().split('=', 1)
                                vals[k.strip()] = int(v.strip()) if v.strip().isdigit() else 0
                        d_total = vals.get('Size', 0)
                        d_free = vals.get('FreeSpace', 0)
                        d_used = d_total - d_free
                        info['disk_total'] = f"{d_total / (1024**3):.1f} GB"
                        info['disk_used'] = f"{d_used / (1024**3):.1f} GB"
                        info['disk_free'] = f"{d_free / (1024**3):.1f} GB"
                        info['disk_percent'] = str(round(d_used / d_total * 100)) if d_total else '0'
                    except Exception:
                        info['disk_total'] = 'N/A'
                        info['disk_used'] = 'N/A'
                        info['disk_free'] = 'N/A'
                        info['disk_percent'] = '0'
                    # Uptime via WMIC
                    try:
                        up_r = subprocess.run(['wmic', 'os', 'get', 'LastBootUpTime', '/value'],
                                              capture_output=True, text=True, timeout=10, creationflags=cflags)
                        for line in up_r.stdout.splitlines():
                            if 'LastBootUpTime=' in line:
                                boot_str = line.split('=', 1)[1].strip().split('.')[0]
                                from datetime import datetime
                                boot_time = datetime.strptime(boot_str, '%Y%m%d%H%M%S')
                                delta = datetime.now() - boot_time
                                days = delta.days
                                hours = delta.seconds // 3600
                                mins = (delta.seconds % 3600) // 60
                                info['uptime'] = f"{days}d {hours}h {mins}m"
                                break
                        else:
                            info['uptime'] = 'N/A'
                    except Exception:
                        info['uptime'] = 'N/A'
                    # GPU via WMIC
                    try:
                        gpu_r = subprocess.run(['wmic', 'path', 'win32_videocontroller', 'get', 'Name', '/value'],
                                               capture_output=True, text=True, timeout=10, creationflags=cflags)
                        gpus = []
                        for line in gpu_r.stdout.splitlines():
                            if 'Name=' in line:
                                gpus.append(line.split('=', 1)[1].strip())
                        info['gpu'] = ', '.join(gpus) if gpus else 'N/A'
                    except Exception:
                        info['gpu'] = 'N/A'
                # IP addresses
                try:
                    ips = []
                    try:
                        import psutil as _pu
                        for iface_name, addrs in _pu.net_if_addrs().items():
                            for addr in addrs:
                                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                                    ips.append(f"{addr.address} ({iface_name})")
                    except ImportError:
                        hostname = socket.gethostname()
                        for ip in socket.getaddrinfo(hostname, None, socket.AF_INET):
                            addr = ip[4][0]
                            if not addr.startswith('127.'):
                                ips.append(addr)
                    info['ip_addresses'] = ips or [socket.gethostbyname(socket.gethostname())]
                except Exception:
                    try:
                        info['ip_addresses'] = [socket.gethostbyname(socket.gethostname())]
                    except Exception:
                        info['ip_addresses'] = ['N/A']
                return jsonify({'success': True, 'info': info})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/sysinfo/{peer_id}",
                timeout=15
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/notify/<peer_id>', methods=['POST'])
    def notify_route(peer_id):
        try:
            data = flask_request.get_json(force=True)
            title = data.get('title', 'GNA Notification')
            message = data.get('message', '')
            if not message:
                return jsonify({'success': False, 'error': 'No message provided'})
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('notify'):
                    return jsonify({'success': False, 'error': 'Notifications are disabled on this peer. Ask the owner to enable it.'})
                # Write title+message to temp files to avoid any injection
                import tempfile
                tmp_t = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
                tmp_t.write(title); tmp_t.close()
                tmp_m = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
                tmp_m.write(message); tmp_m.close()
                try:
                    # Windows Forms MessageBox — do NOT use CREATE_NO_WINDOW or the popup is invisible
                    ps_script = (
                        f'Add-Type -AssemblyName System.Windows.Forms;'
                        f'$t = Get-Content -Raw -Path "{tmp_t.name}";'
                        f'$m = Get-Content -Raw -Path "{tmp_m.name}";'
                        f'[System.Windows.Forms.MessageBox]::Show($m, $t, "OK", "Information") | Out-Null'
                    )
                    subprocess.Popen(
                        ['powershell', '-WindowStyle', 'Hidden', '-Command', ps_script]
                    )
                    # Clean up temp files after a short delay in a thread
                    def _cleanup():
                        time.sleep(60)
                        try: os.unlink(tmp_t.name)
                        except: pass
                        try: os.unlink(tmp_m.name)
                        except: pass
                    threading.Thread(target=_cleanup, daemon=True).start()
                    return jsonify({'success': True})
                except Exception as e:
                    try: os.unlink(tmp_t.name)
                    except: pass
                    try: os.unlink(tmp_m.name)
                    except: pass
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/notify/{peer_id}",
                json={'title': title, 'message': message}, timeout=15
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/processes/<peer_id>')
    def list_processes(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('process_manager'):
                    return jsonify({'success': False, 'error': 'Process manager is disabled on this peer. Ask the owner to enable it.'})
                try:
                    import psutil
                    procs = []
                    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                        try:
                            info = p.info
                            mem = info.get('memory_info')
                            mem_str = f"{mem.rss / (1024*1024):.1f} MB" if mem else '—'
                            procs.append({
                                'pid': info['pid'],
                                'name': info.get('name', '?'),
                                'cpu': str(info.get('cpu_percent', 0)),
                                'memory': mem_str,
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    procs.sort(key=lambda x: x['name'].lower())
                    return jsonify({'success': True, 'processes': procs})
                except ImportError:
                    # Fallback without psutil: use tasklist
                    try:
                        result = subprocess.run(
                            ['tasklist', '/FO', 'CSV', '/NH'],
                            capture_output=True, text=True, timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        )
                        procs = []
                        for line in result.stdout.strip().splitlines():
                            parts = [p.strip('"') for p in line.split('","')]
                            if len(parts) >= 5:
                                procs.append({
                                    'pid': parts[1],
                                    'name': parts[0],
                                    'cpu': '—',
                                    'memory': parts[4],
                                })
                        procs.sort(key=lambda x: x['name'].lower())
                        return jsonify({'success': True, 'processes': procs})
                    except Exception as e:
                        return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/processes/{peer_id}",
                timeout=15
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/kill-process/<peer_id>/<int:pid>', methods=['POST'])
    def kill_process(peer_id, pid):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('process_manager'):
                    return jsonify({'success': False, 'error': 'Process manager is disabled on this peer.'})
                try:
                    import psutil
                    proc = psutil.Process(pid)
                    proc.terminate()
                    proc.wait(timeout=5)
                    return jsonify({'success': True, 'message': f'Process {pid} terminated'})
                except ImportError:
                    # Fallback: taskkill
                    try:
                        result = subprocess.run(
                            ['taskkill', '/PID', str(pid), '/F'],
                            capture_output=True, text=True, timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        )
                        if result.returncode == 0:
                            return jsonify({'success': True, 'message': f'Process {pid} killed'})
                        return jsonify({'success': False, 'error': result.stderr or result.stdout or 'Failed'})
                    except Exception as e:
                        return jsonify({'success': False, 'error': str(e)})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/kill-process/{peer_id}/{pid}",
                timeout=15
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/audio-stream/<peer_id>/start', methods=['POST'])
    def audio_stream_start(peer_id):
        global _audio_stream_active, _audio_stream_chunks, _audio_stream_thread
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('remote_audio'):
                    return jsonify({'success': False, 'error': 'Remote audio is disabled on this peer. Ask the owner to enable it.'})
                with _audio_stream_lock:
                    if _audio_stream_active:
                        return jsonify({'success': True, 'message': 'Already streaming'})
                    _audio_stream_active = True
                    _audio_stream_chunks.clear()
                def _audio_thread():
                    global _audio_stream_active
                    import wave, struct
                    sample_rate = 16000
                    channels = 1
                    chunk_seconds = 2
                    chunk_samples = sample_rate * chunk_seconds
                    # Find a working audio capture method
                    use_sd = False
                    sd_device = None
                    try:
                        import sounddevice as sd
                        # Try default input device first
                        default_in = sd.default.device[0]
                        candidates = []
                        if default_in is not None and default_in >= 0:
                            candidates.append(default_in)
                        # Then add all other input-capable devices
                        devices = sd.query_devices()
                        for i, d in enumerate(devices):
                            if d.get('max_input_channels', 0) > 0 and i not in candidates:
                                candidates.append(i)
                        # Test each candidate with a tiny recording
                        for dev_id in candidates:
                            try:
                                test = sd.rec(1600, samplerate=16000, channels=1, dtype='int16', device=dev_id)
                                sd.wait()
                                sd_device = dev_id
                                print(f"[AUDIO] Using device {dev_id}: {devices[dev_id]['name']}")
                                break
                            except Exception:
                                continue
                        if sd_device is not None:
                            use_sd = True
                    except ImportError:
                        pass
                    except Exception:
                        pass
                    if use_sd:
                        import sounddevice as sd
                        while _audio_stream_active:
                            try:
                                recording = sd.rec(chunk_samples, samplerate=sample_rate,
                                                   channels=channels, dtype='int16', device=sd_device)
                                sd.wait()
                                samples = recording.flatten()
                                wav_buf = _io.BytesIO()
                                with wave.open(wav_buf, 'wb') as wf:
                                    wf.setnchannels(channels)
                                    wf.setsampwidth(2)
                                    wf.setframerate(sample_rate)
                                    wf.writeframes(samples.tobytes())
                                wav_buf.seek(0)
                                b64 = base64.b64encode(wav_buf.read()).decode('ascii')
                                with _audio_stream_lock:
                                    _audio_stream_chunks.append(b64)
                                    if len(_audio_stream_chunks) > 20:
                                        _audio_stream_chunks.pop(0)
                            except Exception as e:
                                print(f"[AUDIO] sounddevice error: {e}")
                                time.sleep(1)
                    else:
                        # Fallback: PowerShell to record via Windows audio APIs
                        cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        while _audio_stream_active:
                            try:
                                import tempfile
                                tmp = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
                                tmp.close()
                                ps = (
                                    f'Add-Type -AssemblyName System.Speech;'
                                    f'$r = New-Object System.Speech.Recognition.SpeechRecognitionEngine;'
                                    f'$r.SetInputToDefaultAudioDevice();'
                                    f'# Fallback: use ffmpeg or cmdlet'
                                    f'powershell -Command "'
                                    f'Add-Type -TypeDefinition @\\\"'
                                    f'using System;using System.Runtime.InteropServices;'
                                    f'public class WinMM{{'
                                    f'[DllImport(\\\"winmm.dll\\\")] public static extern int mciSendString(string c,System.Text.StringBuilder r,int l,IntPtr h);'
                                    f'}}'
                                    f'\\\"@;'
                                    f'[WinMM]::mciSendString(\\\"open new Type waveaudio Alias cap\\\",\\$null,0,0);'
                                    f'[WinMM]::mciSendString(\\\"record cap\\\",\\$null,0,0);'
                                    f'Start-Sleep -Seconds {chunk_seconds};'
                                    f'[WinMM]::mciSendString(\\\"save cap {tmp.name}\\\",\\$null,0,0);'
                                    f'[WinMM]::mciSendString(\\\"close cap\\\",\\$null,0,0);'
                                    f'"'
                                )
                                # Simpler approach: use ffmpeg if available
                                try:
                                    subprocess.run(
                                        ['ffmpeg', '-y', '-f', 'dshow', '-i', 'audio=default',
                                         '-t', str(chunk_seconds), '-ar', str(sample_rate),
                                         '-ac', '1', '-acodec', 'pcm_s16le', tmp.name],
                                        capture_output=True, timeout=chunk_seconds + 5, creationflags=cflags
                                    )
                                except FileNotFoundError:
                                    # No ffmpeg, try SoX
                                    try:
                                        subprocess.run(
                                            ['sox', '-d', '-r', str(sample_rate), '-c', '1', '-b', '16', tmp.name,
                                             'trim', '0', str(chunk_seconds)],
                                            capture_output=True, timeout=chunk_seconds + 5, creationflags=cflags
                                        )
                                    except FileNotFoundError:
                                        os.unlink(tmp.name)
                                        with _audio_stream_lock:
                                            _audio_stream_active = False
                                        return
                                if os.path.exists(tmp.name) and os.path.getsize(tmp.name) > 44:
                                    with open(tmp.name, 'rb') as f:
                                        b64 = base64.b64encode(f.read()).decode('ascii')
                                    with _audio_stream_lock:
                                        _audio_stream_chunks.append(b64)
                                        if len(_audio_stream_chunks) > 20:
                                            _audio_stream_chunks.pop(0)
                                os.unlink(tmp.name)
                            except Exception as e:
                                print(f"[AUDIO] fallback error: {e}")
                                time.sleep(1)
                _audio_stream_thread = threading.Thread(target=_audio_thread, daemon=True)
                _audio_stream_thread.start()
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/audio-stream/{peer_id}/start",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/audio-stream/<peer_id>/stop', methods=['POST'])
    def audio_stream_stop(peer_id):
        global _audio_stream_active
        try:
            if peer_id == str(state.my_id):
                with _audio_stream_lock:
                    _audio_stream_active = False
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/audio-stream/{peer_id}/stop",
                timeout=10
            )
            return jsonify(resp.json())
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/audio-stream/<peer_id>/chunk')
    def audio_stream_chunk(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('remote_audio'):
                    return jsonify({'success': False, 'error': 'Remote audio disabled.'})
                with _audio_stream_lock:
                    if _audio_stream_chunks:
                        chunk = _audio_stream_chunks.pop(0)
                        return jsonify({'success': True, 'audio': chunk, 'remaining': len(_audio_stream_chunks)})
                    return jsonify({'success': True, 'audio': None, 'remaining': 0})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/audio-stream/{peer_id}/chunk",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sys-audio-stream/<peer_id>/start', methods=['POST'])
    def sys_audio_stream_start(peer_id):
        global _sys_audio_active, _sys_audio_chunks, _sys_audio_thread
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('system_audio'):
                    return jsonify({'success': False, 'error': 'System audio is disabled on this peer. Ask the owner to enable it.'})
                with _sys_audio_lock:
                    if _sys_audio_active:
                        return jsonify({'success': True, 'message': 'Already streaming'})
                    _sys_audio_active = True
                    _sys_audio_chunks.clear()
                def _sys_audio_thread_fn():
                    global _sys_audio_active
                    import wave
                    sample_rate = 44100
                    channels = 2
                    chunk_seconds = 2
                    # Method 1: sounddevice WASAPI loopback
                    use_sd = False
                    sd_device = None
                    try:
                        import sounddevice as sd
                        devices = sd.query_devices()
                        # Find a WASAPI output device to use as loopback
                        for i, d in enumerate(devices):
                            name = d.get('name', '').lower()
                            hostapi = sd.query_hostapis(d['hostapi'])['name'] if 'hostapi' in d else ''
                            if 'wasapi' in hostapi.lower() and d.get('max_output_channels', 0) > 0:
                                # Test if loopback works on this device
                                try:
                                    test_frames = int(sample_rate * 0.1)
                                    test = sd.rec(test_frames, samplerate=sample_rate, channels=channels,
                                                  dtype='int16', device=i,
                                                  extra_settings=sd.WasapiSettings(exclusive=False))
                                    sd.wait()
                                    sd_device = i
                                    print(f"[SYS-AUDIO] Using WASAPI loopback device {i}: {d['name']}")
                                    break
                                except Exception:
                                    continue
                        # If no WASAPI loopback, try default output as loopback
                        if sd_device is None:
                            default_out = sd.default.device[1]
                            if default_out is not None and default_out >= 0:
                                try:
                                    test = sd.rec(int(sample_rate * 0.1), samplerate=sample_rate,
                                                  channels=channels, dtype='int16', device=default_out)
                                    sd.wait()
                                    sd_device = default_out
                                    print(f"[SYS-AUDIO] Using default output device {default_out} as loopback")
                                except Exception:
                                    pass
                        if sd_device is not None:
                            use_sd = True
                    except ImportError:
                        pass
                    except Exception:
                        pass
                    if use_sd:
                        import sounddevice as sd
                        chunk_samples = sample_rate * chunk_seconds
                        while _sys_audio_active:
                            try:
                                recording = sd.rec(chunk_samples, samplerate=sample_rate,
                                                   channels=channels, dtype='int16', device=sd_device)
                                sd.wait()
                                samples = recording.flatten()
                                wav_buf = _io.BytesIO()
                                with wave.open(wav_buf, 'wb') as wf:
                                    wf.setnchannels(channels)
                                    wf.setsampwidth(2)
                                    wf.setframerate(sample_rate)
                                    wf.writeframes(samples.tobytes())
                                wav_buf.seek(0)
                                b64 = base64.b64encode(wav_buf.read()).decode('ascii')
                                with _sys_audio_lock:
                                    _sys_audio_chunks.append(b64)
                                    if len(_sys_audio_chunks) > 20:
                                        _sys_audio_chunks.pop(0)
                            except Exception as e:
                                print(f"[SYS-AUDIO] error: {e}")
                                time.sleep(1)
                    else:
                        # Fallback: use ffmpeg to capture system audio via dshow
                        cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        while _sys_audio_active:
                            try:
                                tmp = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
                                tmp.close()
                                # Try ffmpeg with virtual-audio-capturer or stereo mix
                                try:
                                    subprocess.run(
                                        ['ffmpeg', '-y', '-f', 'dshow',
                                         '-i', 'audio=Stereo Mix (Realtek(R) Audio)',
                                         '-t', str(chunk_seconds), '-ar', str(sample_rate),
                                         '-ac', '2', '-acodec', 'pcm_s16le', tmp.name],
                                        capture_output=True, timeout=chunk_seconds + 5, creationflags=cflags
                                    )
                                except FileNotFoundError:
                                    try: os.unlink(tmp.name)
                                    except: pass
                                    with _sys_audio_lock:
                                        _sys_audio_active = False
                                    return
                                if os.path.exists(tmp.name) and os.path.getsize(tmp.name) > 44:
                                    with open(tmp.name, 'rb') as f:
                                        b64 = base64.b64encode(f.read()).decode('ascii')
                                    with _sys_audio_lock:
                                        _sys_audio_chunks.append(b64)
                                        if len(_sys_audio_chunks) > 20:
                                            _sys_audio_chunks.pop(0)
                                try: os.unlink(tmp.name)
                                except: pass
                            except Exception as e:
                                print(f"[SYS-AUDIO] fallback error: {e}")
                                time.sleep(1)
                _sys_audio_thread = threading.Thread(target=_sys_audio_thread_fn, daemon=True)
                _sys_audio_thread.start()
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/sys-audio-stream/{peer_id}/start",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sys-audio-stream/<peer_id>/stop', methods=['POST'])
    def sys_audio_stream_stop(peer_id):
        global _sys_audio_active
        try:
            if peer_id == str(state.my_id):
                with _sys_audio_lock:
                    _sys_audio_active = False
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/sys-audio-stream/{peer_id}/stop",
                timeout=10
            )
            return jsonify(resp.json())
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/sys-audio-stream/<peer_id>/chunk')
    def sys_audio_stream_chunk(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('system_audio'):
                    return jsonify({'success': False, 'error': 'System audio disabled.'})
                with _sys_audio_lock:
                    if _sys_audio_chunks:
                        chunk = _sys_audio_chunks.pop(0)
                        return jsonify({'success': True, 'audio': chunk, 'remaining': len(_sys_audio_chunks)})
                    return jsonify({'success': True, 'audio': None, 'remaining': 0})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/sys-audio-stream/{peer_id}/chunk",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/input-monitor/<peer_id>/start', methods=['POST'])
    def input_monitor_start(peer_id):
        global _input_monitor_active, _input_monitor_events, _input_monitor_thread
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('input_monitor'):
                    return jsonify({'success': False, 'error': 'Input monitoring is disabled on this peer. Ask the owner to enable it.'})
                with _input_monitor_lock:
                    if _input_monitor_active:
                        return jsonify({'success': True, 'message': 'Already monitoring'})
                    _input_monitor_active = True
                    _input_monitor_events = []
                def _monitor_thread():
                    global _input_monitor_active
                    try:
                        from pynput import keyboard, mouse
                        def on_key_press(key):
                            if not _input_monitor_active:
                                return False
                            ts = time.strftime('%H:%M:%S')
                            try:
                                key_str = key.char if key.char else str(key)
                            except AttributeError:
                                key_str = str(key).replace('Key.', '')
                            with _input_monitor_lock:
                                _input_monitor_events.append({'type': 'key', 'key': key_str, 'time': ts})
                                if len(_input_monitor_events) > 5000:
                                    _input_monitor_events.pop(0)
                        def on_click(x, y, button, pressed):
                            if not _input_monitor_active:
                                return False
                            if pressed:
                                ts = time.strftime('%H:%M:%S')
                                btn = str(button).replace('Button.', '')
                                with _input_monitor_lock:
                                    _input_monitor_events.append({'type': 'mouse', 'button': btn, 'x': int(x), 'y': int(y), 'time': ts})
                                    if len(_input_monitor_events) > 5000:
                                        _input_monitor_events.pop(0)
                        kl = keyboard.Listener(on_press=on_key_press)
                        ml = mouse.Listener(on_click=on_click)
                        kl.start()
                        ml.start()
                        while _input_monitor_active:
                            time.sleep(0.5)
                        kl.stop()
                        ml.stop()
                    except ImportError:
                        # Fallback: use ctypes to call GetAsyncKeyState directly (fast, no subprocess)
                        import ctypes
                        import ctypes.wintypes
                        user32 = ctypes.windll.user32
                        # VK code to readable name map for special keys
                        VK_NAMES = {
                            8: 'Backspace', 9: 'Tab', 13: 'Enter', 16: 'Shift', 17: 'Ctrl', 18: 'Alt',
                            20: 'CapsLock', 27: 'Escape', 32: ' ', 37: 'Left', 38: 'Up', 39: 'Right', 40: 'Down',
                            46: 'Delete', 91: 'Win', 160: 'LShift', 161: 'RShift', 162: 'LCtrl', 163: 'RCtrl',
                            164: 'LAlt', 165: 'RAlt', 186: ';', 187: '=', 188: ',', 189: '-', 190: '.', 191: '/',
                            219: '[', 220: '\\', 221: ']', 222: "'",
                        }
                        SKIP_VKS = {16, 17, 18, 160, 161, 162, 163, 164, 165}  # modifier-only keys
                        # Mouse button VK codes
                        VK_LBUTTON, VK_RBUTTON, VK_MBUTTON = 1, 2, 4
                        class POINT(ctypes.Structure):
                            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
                        while _input_monitor_active:
                            ts = time.strftime('%H:%M:%S')
                            # Check mouse clicks
                            for vk_btn, btn_name in [(VK_LBUTTON, 'left'), (VK_RBUTTON, 'right'), (VK_MBUTTON, 'middle')]:
                                if user32.GetAsyncKeyState(vk_btn) & 1:
                                    pt = POINT()
                                    user32.GetCursorPos(ctypes.byref(pt))
                                    with _input_monitor_lock:
                                        _input_monitor_events.append({'type': 'mouse', 'button': btn_name, 'x': pt.x, 'y': pt.y, 'time': ts})
                                        if len(_input_monitor_events) > 5000:
                                            _input_monitor_events.pop(0)
                            # Check keyboard keys (VK 8-222)
                            for vk in range(8, 223):
                                if vk in SKIP_VKS:
                                    continue
                                if user32.GetAsyncKeyState(vk) & 1:
                                    if vk in VK_NAMES:
                                        key_str = VK_NAMES[vk]
                                    elif 65 <= vk <= 90:
                                        key_str = chr(vk).lower()
                                    elif 48 <= vk <= 57:
                                        key_str = chr(vk)
                                    elif 96 <= vk <= 105:
                                        key_str = str(vk - 96)
                                    else:
                                        key_str = f'VK_{vk}'
                                    with _input_monitor_lock:
                                        _input_monitor_events.append({'type': 'key', 'key': key_str, 'time': ts})
                                        if len(_input_monitor_events) > 5000:
                                            _input_monitor_events.pop(0)
                            time.sleep(0.02)
                    except Exception:
                        pass
                _input_monitor_thread = threading.Thread(target=_monitor_thread, daemon=True)
                _input_monitor_thread.start()
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/input-monitor/{peer_id}/start",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/input-monitor/<peer_id>/stop', methods=['POST'])
    def input_monitor_stop(peer_id):
        global _input_monitor_active
        try:
            if peer_id == str(state.my_id):
                with _input_monitor_lock:
                    _input_monitor_active = False
                return jsonify({'success': True})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.post(
                f"http://{peer_info.ip}:{peer_info.port}/api/input-monitor/{peer_id}/stop",
                timeout=10
            )
            return jsonify(resp.json())
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/input-monitor/<peer_id>/events')
    def input_monitor_events(peer_id):
        try:
            if peer_id == str(state.my_id):
                if not is_local_request() and not get_remote_permissions().get('input_monitor'):
                    return jsonify({'success': False, 'error': 'Input monitoring is disabled on this peer.'})
                with _input_monitor_lock:
                    events = list(_input_monitor_events)
                    _input_monitor_events.clear()
                return jsonify({'success': True, 'events': events})
            peer_info = state.known_peers.get(peer_id)
            if not peer_info:
                return jsonify({'success': False, 'error': 'Peer not found'})
            resp = requests.get(
                f"http://{peer_info.ip}:{peer_info.port}/api/input-monitor/{peer_id}/events",
                timeout=10
            )
            return jsonify(resp.json())
        except requests.exceptions.ConnectionError:
            return jsonify({'success': False, 'error': 'Peer unreachable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/api/info')
    def api_info():
        return jsonify({'id': str(state.my_id), 'version': VERSION, 'call_number': state.call_number})


# ===========================================================================
# main entry point (from main.py + launcher.py)
# ===========================================================================

def setup_logging():
    log_file = DATA_DIR / "gna.log"
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    file_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    logging.getLogger('flask').setLevel(logging.ERROR)
    logging.getLogger('zeroconf').setLevel(logging.WARNING)

def print_startup_banner():
    print(f">> {APP_NAME} v{VERSION} -- Starting (console will stay open forever)")
    print(f"   Project directory: {PROJECT_DIR}")

_sender_cache = {"status": "UNKNOWN", "ts": 0}
_signaling_cache = {"status": "UNKNOWN", "ts": 0}
_STATUS_CACHE_TTL = 15
_sender_pid = None  # PID of the sender.py subprocess we launched

def check_sender_status():
    global _sender_pid
    now = time.time()
    if now - _sender_cache["ts"] < _STATUS_CACHE_TTL: return _sender_cache["status"]
    result_status = "NOT DETECTED"
    # Method 1: check our own launched sender PID
    if _sender_pid is not None:
        try:
            os.kill(_sender_pid, 0)  # signal 0 = just check if alive
            result_status = "RUNNING"
        except (OSError, ProcessLookupError):
            _sender_pid = None  # process died
    # Method 2: check by window title (if launched via bat file)
    if result_status == "NOT DETECTED":
        try:
            result = subprocess.run(['tasklist', '/FI', 'WINDOWTITLE eq PubLAN Sender'], capture_output=True, text=True, timeout=5)
            if 'python' in result.stdout.lower(): result_status = "RUNNING"
        except Exception: pass
    # Method 3: check by command line containing sender.py
    if result_status == "NOT DETECTED":
        try:
            cflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            result = subprocess.run(
                ['wmic', 'process', 'where', "commandline like '%sender.py%'", 'get', 'processid'],
                capture_output=True, text=True, timeout=5, creationflags=cflags
            )
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line.isdigit():
                    result_status = "RUNNING"
                    break
        except Exception: pass
    _sender_cache["status"] = result_status
    _sender_cache["ts"] = now
    return result_status

def check_signaling_server_status():
    now = time.time()
    if now - _signaling_cache["ts"] < _STATUS_CACHE_TTL: return _signaling_cache["status"]
    result_status = "NOT REACHABLE"
    try:
        resp = requests.get("http://localhost:3000/health", timeout=2)
        if resp.status_code == 200: result_status = "RUNNING"
        else: result_status = f"RESPONDING ({resp.status_code})"
    except Exception: pass
    _signaling_cache["status"] = result_status
    _signaling_cache["ts"] = now
    return result_status

def print_live_status(state):
    sorted_live = get_sorted_live_peers(state)
    my_role = get_current_role(state)
    sender_status = check_sender_status()
    signaling_status = check_signaling_server_status()
    global_svc = getattr(state, '_global_discovery', None)
    if global_svc and global_svc.enabled:
        relay_connected = global_svc.sio and global_svc.sio.connected
        relay_status = "LIVE" if relay_connected else "OFFLINE"
        relay_url = global_svc.relay_url if relay_connected else "(disconnected)"
        relay_peers = len(global_svc.global_peers)
    else:
        relay_status = "DISABLED"
        relay_url = ""
        relay_peers = 0
    print(f"\n{'='*80}")
    print(f"{APP_NAME} v{VERSION} LIVE STATUS — {time.strftime('%H:%M:%S')}")
    print(f"ID : {state.my_id}")
    print(f"Call Number : {state.call_number}")
    print(f"Role : {my_role}")
    print(f"Public IP : {state.public_ip}")
    print(f"Local IP:Port : {state.local_ip}:{PORT}")
    print(f"Live Peers : {len(sorted_live)}")
    print(f"Shared Items : {len(state.shared_paths)}")
    print(f"Sender.py : {sender_status}")
    print(f"Signal Server : {signaling_status}")
    if relay_status == "LIVE":
        print(f"Global Relay : {relay_status} — {relay_url} ({relay_peers} peers)")
    elif relay_status == "OFFLINE":
        print(f"Global Relay : {relay_status} — attempting {global_svc.relay_url}...")
    else:
        print(f"Global Relay : {relay_status}")
    print(f"Status : Active")
    print(f"{'='*80}")

def discovery_thread_fn(state):
    try:
        while True:
            update_peer_bookkeeping(state)
            time.sleep(DISCOVERY_INTERVAL_SECONDS)
    except Exception: pass

def status_thread_fn(state):
    try:
        while True:
            print_live_status(state)
            time.sleep(STATUS_PRINT_INTERVAL_SECONDS)
    except Exception: pass

def flask_thread_fn(app):
    try:
        app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)
    except Exception: pass

def launch_bat_file():
    """Run Start PubLAN.bat in the project directory (from launcher.py)."""
    try:
        exe_dir = PROJECT_DIR
        bat_path = exe_dir / "Start PubLAN.bat"
        if bat_path.exists():
            print(f"[OK] Launching Start PubLAN.bat from {exe_dir}")
            subprocess.Popen(
                ['cmd.exe', '/c', str(bat_path)],
                cwd=str(exe_dir),
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            print(f"[WARNING] Start PubLAN.bat not found at {bat_path}")
    except Exception as e:
        print(f"[WARNING] Could not launch Start PubLAN.bat: {e}")

def main():
    setup_logging()
    print_startup_banner()

    # NOTE: Start PubLAN.bat is no longer launched here because the monolith
    # now directly starts the signaling server, sender.py, and caller.py.
    # The bat file would launch databank_explorer.py which creates a duplicate
    # Flask instance and a duplicate browser tab.

    try:
        # Self-verification check
        run_startup_integrity_check(PROJECT_DIR)

        migrate_legacy_files()

        my_id = generate_random_peer_id()
        my_call_number = generate_call_number()
        print(f"New random Bank ID this session: {my_id}")
        print(f"Call Number this session: {my_call_number}")

        my_join_time = load_join_time()
        local_ip = get_local_ip()
        public_ip = get_public_ip()

        state = ApplicationState(
            my_id=my_id, my_join_time=my_join_time,
            local_ip=local_ip, public_ip=public_ip,
            call_number=my_call_number,
            shared_paths=load_shared_paths(),
            known_peers=load_known_peers(),
        )

        shared_count = len(state.shared_paths)
        print(f"Loaded {shared_count} public paths")

        app = Flask(__name__)
        app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB upload limit
        app.logger.disabled = True
        create_routes(app, state)

        zc = Zeroconf()
        register_service(zc, my_id, local_ip)
        start_discovery(zc, state, my_id)

        # Start global discovery service
        state._global_call_numbers = {}

        def on_global_peers_updated(peers):
            for p in peers:
                pid = p.get('peerId', '')
                if not pid or pid == str(my_id): continue
                info = PeerInfo(ip=p.get('ip', ''), port=int(p.get('port', PORT)), join_time=time.time(), last_seen=time.time())
                state.add_known_peer(pid, info)
                cn = p.get('callNumber', '')
                if cn: state._global_call_numbers[pid] = cn

        global_svc = GlobalDiscoveryService(my_peer_id=str(my_id), my_call_number=my_call_number, local_ip=local_ip, local_port=PORT, on_peers_updated=on_global_peers_updated)
        state._global_discovery = global_svc
        global_svc.start()
        if global_svc.enabled:
            print(f"[OK] Global discovery enabled: network='{global_svc.network_code}'")
        else:
            print("[INFO] Global discovery disabled (configure global_config.json to enable)")

        # Spawn daemon threads
        threading.Thread(target=discovery_thread_fn, args=(state,), daemon=True, name="DiscoveryThread").start()
        threading.Thread(target=flask_thread_fn, args=(app,), daemon=True, name="FlaskThread").start()
        threading.Thread(target=status_thread_fn, args=(state,), daemon=True, name="StatusThread").start()

        # Start Node.js signaling server (if not already running)
        try:
            sig_running = False
            try:
                r = requests.get("http://localhost:3000/health", timeout=2)
                if r.status_code == 200:
                    sig_running = True
            except Exception:
                pass
            if not sig_running:
                server_js = PROJECT_DIR / 'server.js'
                if server_js.exists():
                    # npm install first if node_modules missing
                    pkg_json = PROJECT_DIR / 'package.json'
                    node_modules = PROJECT_DIR / 'node_modules'
                    if pkg_json.exists() and not node_modules.exists():
                        try:
                            subprocess.run(['npm', 'install', '--silent'], cwd=str(PROJECT_DIR),
                                           capture_output=True, timeout=60)
                        except Exception:
                            pass
                    subprocess.Popen(['node', str(server_js)], cwd=str(PROJECT_DIR),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
                    time.sleep(2)
                    print("[OK] Signaling server (server.js) started in background")
                else:
                    print("[INFO] server.js not found — signaling server not started")
            else:
                print("[OK] Signaling server already running on port 3000")
        except Exception as e:
            print(f"[WARNING] Could not start signaling server: {e}")

        # Start sender.py in background (screen sharing)
        try:
            sender_path = PROJECT_DIR / 'sender.py'
            if sender_path.exists():
                # Write sender_session_id.txt (same as bat file does)
                session_id_file = PROJECT_DIR / 'sender_session_id.txt'
                sender_session_id = hashlib.md5(platform.node().encode()).hexdigest()
                try:
                    with open(session_id_file, 'w') as f:
                        f.write(sender_session_id)
                except Exception:
                    pass
                sender_proc = subprocess.Popen(
                    [sys.executable, str(sender_path)],
                    cwd=str(PROJECT_DIR),
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                global _sender_pid
                _sender_pid = sender_proc.pid
                time.sleep(2)
                print(f"[OK] Sender.py started in background (PID {_sender_pid})")
            else:
                print("[INFO] sender.py not found — screen sharing not started")
        except Exception as e:
            print(f"[WARNING] Could not start sender.py: {e}")

        # Start caller listener in background
        try:
            caller_path = PROJECT_DIR / 'caller.py'
            if caller_path.exists():
                subprocess.Popen([sys.executable, str(caller_path), str(my_id), my_call_number], creationflags=0)
                print("[OK] Call listener started in background")
        except Exception as e:
            print(f"[WARNING] Could not start call listener: {e}")

        # Open browser
        try:
            webbrowser.open(f"http://127.0.0.1:{PORT}")
            print("[OK] Browser opened to Dashboard!")
        except Exception as e:
            print(f"[WARNING] Could not open browser: {e}")
            print(f"         Navigate manually to http://127.0.0.1:{PORT}")

        # Main thread blocks here forever
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[WARNING] Shutting down...")
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__} - {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        print("\nConsole will stay open until you press Enter...")
        input("Press Enter to close this window...")


if __name__ == '__main__':
    main()
