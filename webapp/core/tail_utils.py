"""Log tailing and sanitization utilities for the SDN web application.

Extracts log text using bounded reverse seeking (avoiding reading large files into memory),
redacts sensitive credentials (passwords, tokens, bearer headers), collapses tracebacks,
and masks internal system paths and URLs before presenting logs to web clients.
"""

import os
import re
import sys
from typing import Any

from core.sdn_config import get_config_manager

_SECRET_KV_RX = re.compile(
    r'(?i)\b(password|passwd|pwd|secret|secret_key|flask_secret_key|token|csrf_token|'
    r'sdn_internal_token|api_key|authorization|x-internal-token|x-csrf-token)\b'
    r'(\s*[:=]\s*)(?:(?:Bearer|Basic|Token)\s+)?(?:\[redacted\]|"[^"]*"|\'[^\']*\'|[^\s,;\]\}"\']+)'
)
_BEARER_RX = re.compile(r'(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]{6,}')
_URL_RX = re.compile(r'https?://[^\s\'"<>\)\]]+', re.IGNORECASE)
_PATH_RX = re.compile(r'(?:[A-Za-z]:\\[^\s\'"<>\)\]]+|/(?:home|root|mnt|etc|var|opt|usr|tmp)/[^\s\'"<>\)\]]*)')
_TB_START_RX = re.compile(r'^Traceback \(most recent call last\):')


def _redact_secrets(text: Any) -> str:
    """Redact sensitive credentials, tokens, and authorization headers from text."""
    s = str(text or '')
    s = _BEARER_RX.sub(r'\1 [redacted]', s)
    s = _SECRET_KV_RX.sub(lambda m: f'{m.group(1)}{m.group(2)}[redacted]', s)
    return s


def _sanitize_log_text(raw_text: str, max_lines: int = 40, max_chars: int = 4096) -> str:
    """Collapse tracebacks and redact secrets, internal URLs, and sensitive paths before returning logs."""
    if not raw_text:
        return ''
    lines = str(raw_text).splitlines()
    cleaned = []
    in_traceback = False
    for line in lines:
        if _TB_START_RX.match(line.strip()):
            in_traceback = True
            cleaned.append('[traceback redacted]')
            continue
        if in_traceback:
            # Skip indented stack frames and final Exception: detail line inside traceback block
            if line.startswith((' ', '\t')):
                continue
            in_traceback = False
            if line.strip():
                cleaned.append('[error detail redacted]')
            continue
        s = _URL_RX.sub('[internal-url]', line)
        s = _redact_secrets(s)
        s = _PATH_RX.sub('[path]', s)
        if len(s) > 220:
            s = s[:217] + '...'
        cleaned.append(s)

    if max_lines > 0 and len(cleaned) > max_lines:
        cleaned = cleaned[-max_lines:]
    out = '\n'.join(cleaned)
    if max_chars > 0 and len(out) > max_chars:
        out = out[-max_chars:]
    return out


def _tail_file(path: str, max_lines: int = 40, max_chars: int = 4096) -> str:
    """Reads the last max_lines (up to max_chars) from path using bounded reverse seek.
    Memory consumption is strictly bounded by MAX_TAIL_BYTES (default 256 KB)
    regardless of whether the file size is 100 MB or 10 GB.
    """
    try:
        if not path or not os.path.isfile(path):
            return ''
        try:
            st_size = os.path.getsize(path)
        except OSError:
            return ''
        if st_size <= 0:
            return ''

        # Hard safety ceiling on bytes read from disk (default 256 KB)
        max_tail_bytes = 256 * 1024
        try:
            mgr = get_config_manager()
            cfg_limit = mgr.get_effective('log_tail_max_bytes')
            if cfg_limit and isinstance(cfg_limit, int) and cfg_limit > 0:
                max_tail_bytes = cfg_limit
        except Exception:
            pass

        needed_newlines = max(1, int(max_lines)) + 1
        chunk_size = 8192
        curr_pos = st_size
        bytes_read = 0
        chunks = []

        with open(path, 'rb') as f:
            while curr_pos > 0 and bytes_read < max_tail_bytes:
                read_len = min(chunk_size, curr_pos, max_tail_bytes - bytes_read)
                curr_pos -= read_len
                f.seek(curr_pos, os.SEEK_SET)
                chunk = f.read(read_len)
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_read += len(chunk)

                # Count newlines in accumulated chunks
                nl_count = sum(c.count(b'\n') for c in chunks)
                if nl_count >= needed_newlines:
                    break

                # Exponential chunk growth up to 64KB
                chunk_size = min(chunk_size * 2, 65536)

        if not chunks:
            return ''

        # Combine chunks in correct chronological order
        raw_bytes = b''.join(reversed(chunks))
        text = raw_bytes.decode('utf-8', errors='replace')
        lines = text.splitlines(keepends=True)

        # If we didn't read from the beginning of the file (curr_pos > 0)
        # and we have more lines than max_lines, drop the first (potentially partial) line
        if curr_pos > 0 and len(lines) > max_lines:
            lines = lines[1:]

        tail_text = ''.join(lines[-max_lines:])
        return _sanitize_log_text(tail_text, max_lines=max_lines, max_chars=max_chars)
    except Exception:
        return ''
