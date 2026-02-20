"""
SDN DoS/DDoS Guard - Helper Functions & Environment Parsers
============================================================
Encapsulates:
- Environment variable parsers with safe fallbacks (delegating to core.common_utils)
- Internal token loading and header generation (delegating to core.common_utils)
- IPv4 and MAC address normalization and validation (delegating to core.common_utils)
- Greenlet/Thread-safe semaphore creation for whitelist concurrency
"""

import os
import threading
from typing import Any, Dict, List, Optional

from core.common_utils import (
    load_internal_token as _core_load_internal_token,
    parse_bool as _core_parse_bool,
    parse_int as _core_parse_int,
    parse_float as _core_parse_float,
    validate_ipv4 as _core_validate_ipv4,
    validate_mac as _core_validate_mac,
)


def _create_whitelist_semaphore():
    """Create greenlet-aware semaphore for mutual exclusion across Ryu greenlets."""
    try:
        import eventlet.semaphore
        return eventlet.semaphore.Semaphore(1)
    except Exception:
        try:
            from ryu.lib import hub
            if hasattr(hub, 'Semaphore'):
                return hub.Semaphore(1)
        except Exception:
            pass
        return threading.Lock()


def _load_internal_token() -> str:
    """Load internal shared secret token from env or disk (delegates to core.common_utils)."""
    return _core_load_internal_token()


def _internal_headers() -> Dict[str, str]:
    """Generate HTTP headers containing internal service token."""
    tok = _load_internal_token()
    return {'X-Internal-Token': tok} if tok else {}


def _env_bool(name: str, default: bool) -> bool:
    """Parse boolean from environment variable with default (delegates to core.common_utils)."""
    v = os.getenv(name)
    if v is None:
        return bool(default)
    return _core_parse_bool(v)


def _env_int(name: str, default: int) -> int:
    """Parse integer from environment variable with fallback (delegates to core.common_utils)."""
    v = os.getenv(name)
    if v is None:
        return int(default)
    return _core_parse_int(v, default=default)


def _env_float(name: str, default: float) -> float:
    """Parse float from environment variable with fallback (delegates to core.common_utils)."""
    v = os.getenv(name)
    if v is None:
        return float(default)
    return _core_parse_float(v, default=default)


def _env_csv_ints(name: str, default_csv: str) -> List[int]:
    """Parse comma-separated integers from environment variable."""
    v = os.getenv(name)
    raw = default_csv if (v is None or str(v).strip() == '') else str(v)
    out = []
    for part in str(raw).split(','):
        part = str(part).strip()
        if not part:
            continue
        try:
            out.append(int(part))
        except Exception:
            continue
    return out


def _validate_ipv4(value: Any) -> Optional[str]:
    """Return normalized IPv4 string or None if invalid (delegates to core.common_utils)."""
    return _core_validate_ipv4(value)


def _validate_mac(value: Any) -> Optional[str]:
    """Return normalized MAC or None if invalid (delegates to core.common_utils)."""
    return _core_validate_mac(value)
