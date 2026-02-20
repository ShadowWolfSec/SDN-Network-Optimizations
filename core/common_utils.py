"""
core/common_utils.py
Common utility functions: type parsing, IP/MAC validation,
token handling, and cross-platform file locking.
"""

import ipaddress
import os
import re
import sys
import time
from typing import Any, Dict, Optional, Tuple, Union


# Type and Parsing Utilities

def parse_bool(val: Any) -> bool:
    """Safely parse input value into boolean.
    Truthy values: True, 1, '1', 'true', 'yes', 'y', 'on' (case-insensitive).
    Falsy: everything else. Never raises exceptions.
    """
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.strip().lower() in ('1', 'true', 'yes', 'y', 'on')
    return bool(val)


def parse_int(val: Any, default: int = 0) -> int:
    """Safely parse input value into int with fallback."""
    if isinstance(val, (int, float)):
        return int(val)
    try:
        s = str(val).strip()
        return int(s)
    except (ValueError, TypeError):
        return default


def parse_float(val: Any, default: float = 0.0) -> float:
    """Safely parse input value into float with fallback."""
    if isinstance(val, (int, float)):
        return float(val)
    try:
        s = str(val).strip()
        return float(s)
    except (ValueError, TypeError):
        return default


def parse_str(val: Any, default: str = "") -> str:
    """Safely parse input value into stripped string."""
    if val is None:
        return default
    return str(val).strip()


# Network Address Validators

def validate_ipv4(value: Any) -> Optional[str]:
    """Return normalized IPv4 string or None if invalid. Rejects IPv6.
    
    Args:
        value: Input value to validate
        
    Returns:
        Normalized IPv4 string or None if invalid
    """
    if value is None or not isinstance(value, str):
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        addr = ipaddress.ip_address(s)
        if not isinstance(addr, ipaddress.IPv4Address):
            return None
        return str(addr)
    except ValueError:
        return None


def validate_mac(value: Any) -> Optional[str]:
    """Return normalized MAC (lowercase, colon-separated) or None if invalid.
    
    Args:
        value: Input value to validate
        
    Returns:
        Normalized MAC address or None if invalid
    """
    if value is None or not isinstance(value, str):
        return None
    s = str(value).strip().lower().replace('-', ':')
    if re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', s):
        return s
    return None


# Path Security Utilities

def safe_resolve_path(base_dir: str, rel_path: str) -> str:
    """Strictly validates relative path and enforces directory containment.
    Prevents lexical path traversal (e.g. '../').
    
    Note on TOCTOU:
        This check eliminates lexical/canonical path traversal. In POSIX environments
        with untrusted local actors, opening files should be guarded with O_NOFOLLOW
        if symlink swapping race conditions are a concern.
    """
    if not rel_path or not isinstance(rel_path, str):
        raise ValueError("invalid_path")
    bn = os.path.basename(rel_path.strip())
    if bn != rel_path or '..' in rel_path or '/' in rel_path or '\\' in rel_path:
        raise ValueError("path_traversal_attempt")
    real_dir = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_dir, bn))
    if not (target.startswith(real_dir + os.sep) and os.path.dirname(target) == real_dir):
        raise ValueError("path_outside_base_dir")
    return target


def resolve_safe_pcap_path(pcap_dir: str, name: str) -> str:
    """Strictly validates pcap filename and enforces directory containment.
    Prevents path traversal, symlink escapes, and non-pcap extensions.
    """
    if not name or not isinstance(name, str):
        raise ValueError("invalid_pcap_name")
    bn = os.path.basename(name.strip())
    if bn != name or '..' in name or '/' in name or '\\' in name:
        raise ValueError("path_traversal_attempt")
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:pcap|pcapng|cap)', bn):
        raise ValueError("invalid_pcap_extension")
    real_dir = os.path.realpath(pcap_dir)
    target = os.path.realpath(os.path.join(pcap_dir, bn))
    if not (target.startswith(real_dir + os.sep) and os.path.dirname(target) == real_dir):
        raise ValueError("path_outside_pcap_dir")
    return target


# Security Token Resolution

def load_internal_token(token_file: Optional[str] = None) -> str:
    """Loads internal service token from environment or token file.
    Order of precedence:
    1. SDN_INTERNAL_TOKEN environment variable.
    2. Explicit token_file path (if provided and exists).
    3. .run/internal.token relative to project root / current working dir.
    """
    tok = (os.getenv('SDN_INTERNAL_TOKEN') or '').strip()
    if tok:
        return tok
    candidates = []
    if token_file:
        candidates.append(token_file)
    candidates.extend([
        os.path.join('.run', 'internal.token'),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.run', 'internal.token'),
    ])
    for cp in candidates:
        try:
            if os.path.isfile(cp):
                with open(cp, 'r', encoding='utf-8') as f:
                    val = f.read().strip()
                    if val:
                        return val
        except Exception:
            continue
    return ''


# Cross-Process File Lock

class CrossProcessFileLock:
    """Advisory file lock manager across multiple OS worker processes (POSIX & Windows).
    Uses time.monotonic() to eliminate wall-clock/NTP drift issues.
    Implements full Context Manager protocol (__enter__ and __exit__).
    """
    def __init__(self, lock_file_path: str, timeout_sec: float = 5.0, poll_interval: float = 0.05):
        self.lock_file_path = str(lock_file_path)
        self.timeout_sec = float(timeout_sec)
        self.poll_interval = float(poll_interval)
        self.fd: Optional[int] = None

    def __enter__(self) -> "CrossProcessFileLock":
        os.makedirs(os.path.dirname(os.path.abspath(self.lock_file_path)), exist_ok=True)
        self.fd = os.open(self.lock_file_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.fstat(self.fd).st_size == 0:
                os.write(self.fd, b'\0')
        except OSError:
            pass

        deadline = time.monotonic() + self.timeout_sec
        while True:
            try:
                if os.name != 'nt':
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    import msvcrt
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                return self
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    self.release()
                    raise TimeoutError(f"Timed out waiting for file lock on {self.lock_file_path}")
                time.sleep(self.poll_interval)

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()

    def release(self) -> None:
        if self.fd is not None:
            try:
                if os.name != 'nt':
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                else:
                    import msvcrt
                    try:
                        os.lseek(self.fd, 0, os.SEEK_SET)
                        msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
            finally:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None
