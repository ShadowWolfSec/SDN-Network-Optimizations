"""Security infrastructure, authentication, session validation, CSRF, rate limiting,
trusted proxy handling, and sanitization for the SDN web application.
"""

import os
import sys
import subprocess
import time
import json
import re
import hmac
import hashlib
import secrets
import ipaddress
import logging
import threading
import uuid
import datetime
from datetime import timedelta
import urllib.parse
from typing import Optional, Dict, Any, Tuple, Set, List

from flask import Flask, Response, g, jsonify, request, render_template, redirect, session, current_app
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

from core.common_utils import CrossProcessFileLock
from webapp.core.tail_utils import (
    _redact_secrets,
    _sanitize_log_text,
    _PATH_RX,
    _URL_RX,
    _TB_START_RX,
    _SECRET_KV_RX,
    _BEARER_RX,
)


class SecurityError(Exception):
    """Raised when security boundaries (e.g. symlink attack or path traversal) are violated."""
    pass


_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_WEBAPP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RUN_DIR = os.path.join(_PROJECT_ROOT, '.run')
USERS_FILE = os.path.join(_WEBAPP_DIR, 'users.json')

_DEFAULT_SECRET_KEY = 'sdn_demo_secret_key_change_me'
_SERVER_BOOT_ID = (os.getenv('WEB_BOOT_ID') or '').strip() or secrets.token_urlsafe(16)


def get_server_boot_id() -> str:
    """Retrieve the active server boot ID dynamically, allowing module patching in tests."""
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_SERVER_BOOT_ID'):
        return getattr(m, '_SERVER_BOOT_ID')
    return _SERVER_BOOT_ID


def _get_logger():
    """Retrieve the active Flask app logger if available, otherwise a module-level logger."""
    try:
        if current_app:
            return current_app.logger
    except Exception:
        pass
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, 'app') and hasattr(getattr(m, 'app'), 'logger'):
        return getattr(m, 'app').logger
    return logging.getLogger('webapp.server')


_TRUSTED_PROXY_NETS = []
for _cidr in (os.getenv('TRUSTED_PROXY_CIDRS', '127.0.0.1/32,::1/128')).split(','):
    _cidr = _cidr.strip()
    if _cidr:
        try:
            _TRUSTED_PROXY_NETS.append(ipaddress.ip_network(_cidr, strict=False))
        except Exception:
            pass


def _is_trusted_proxy_peer(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address((ip_str or '').strip())
        return any(addr in net for net in _TRUSTED_PROXY_NETS)
    except Exception:
        return False


class _TrustedProxyMiddleware:
    """Apply ProxyFix only when the direct TCP peer is a trusted proxy."""
    def __init__(self, raw_wsgi_app, proxied_wsgi_app):
        self.raw_wsgi_app = raw_wsgi_app
        self.proxied_wsgi_app = proxied_wsgi_app

    def __call__(self, environ, start_response):
        peer = environ.get('REMOTE_ADDR', '')
        if _is_trusted_proxy_peer(peer):
            environ['SDN_TRUSTED_PROXY'] = '1'
            return self.proxied_wsgi_app(environ, start_response)
        environ['SDN_TRUSTED_PROXY'] = '0'
        return self.raw_wsgi_app(environ, start_response)


_rate_lock = threading.Lock()
_rate_state: Dict[str, Any] = {}

# Memory cache for users.json (performance + security)
_users_cache: Dict[str, Any] = {}
_users_cache_lock = threading.Lock()
_users_cache_mtime: float = 0.0
USERS_CACHE_TTL: float = 30.0  # Reload users.json every 30 seconds


def current_users_file() -> str:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, 'USERS_FILE'):
        return getattr(m, 'USERS_FILE')
    return USERS_FILE


_ALLOWED_RUNNER_ERROR_CODES = {
    'unauthorized',
    'busy',
    'network_not_built',
    'network_not_running',
    'controller_changed_rebuild_required',
    'too_many_nodes_max_100',
    'tcpdump_not_installed',
    'iperf_not_installed',
    'hping3_not_installed',
    'ha_need_two_hosts',
    'ha_backup_missing',
    'ha_service_error',
    'ha_test_failed',
    'ha_config_error',
    'active_must_be_primary_or_backup',
    'no_hosts',
    'no_linked_hosts',
    'need_hosts',
    'missing_endpoints',
    'link_not_found',
    'link_update_failed',
    'unknown_scenario',
    'unknown_command_type',
    'missing_src_or_dst',
    'src_not_found',
    'missing_client_or_server',
    'client_must_differ_from_server',
    'client_or_server_not_found',
    'switch_not_found',
    'missing_switch',
    'attack_already_running',
    'victim_not_found',
    'victim_not_linked',
    'victim_in_attackers',
    'no_attackers_available',
    'attacker_not_found',
    'attacker_reserved_role',
    'attacker_not_linked',
    'attacker_blocked',
    'insufficient_attackers',
    'ovs_dump_failed',
    'cmd_failed',
    'ping_failed',
    'invalid_pcap_name',
    'invalid_ip',
    'invalid_mac',
    'invalid_request',
    'bad_request',
    'not_found',
    'method_not_allowed',
    'conflict',
    'unprocessable_entity',
    'runner_http_error',
    'runner_internal_error',
    'lab_job_failed',
}

_ALLOWED_RUNNER_DETAIL_KEYS = {
    'victim',
    'attacker',
    'ip',
    'required',
    'available',
    'available_hosts',
    'excluded_ha',
    'ha',
    'active',
    'service_running',
    'busy',
    'is_busy',
    'current_state',
    'task_id',
    'op',
    'message',
}

_ALLOWED_RYU_400_ERRORS = {
    'invalid_ip',
    'cannot_block_vip',
    'cannot_block_whitelisted_ip',
    'cannot_block_protected_ip',
    'invalid_mac',
    'invalid_json',
    'json_object_required',
    'invalid_config',
    'invalid_request',
    'bad_request',
}


def _current_request_id() -> str:
    try:
        rid = getattr(g, 'request_id', '') or ''
        return str(rid)
    except Exception:
        return ''


def _assign_request_id():
    g.request_id = secrets.token_hex(6)


def _log_backend_exception(op: str, exc: Optional[Exception] = None, level: str = 'warning', **ctx) -> None:
    rid = _current_request_id() or '-'
    safe_ctx = {k: _redact_secrets(v) for k, v in ctx.items()}
    logger = _get_logger()
    if exc is not None:
        detail = _redact_secrets(str(exc))
        if level == 'exception':
            logger.exception('[req=%s] %s failed (%s) ctx=%s', rid, op, type(exc).__name__, safe_ctx)
        else:
            logger.warning('[req=%s] %s failed (%s: %s) ctx=%s', rid, op, type(exc).__name__, detail[:300], safe_ctx)
    else:
        logger.warning('[req=%s] %s ctx=%s', rid, op, safe_ctx)


def _classify_backend_exception(exc: Exception, upstream: str = 'backend') -> Tuple[str, int, str]:
    """Map raw exceptions to stable public error codes and HTTP status codes."""
    if isinstance(exc, (requests.exceptions.Timeout, TimeoutError)):
        return 'timeout', 502, 'Backend service timed out.'
    if isinstance(exc, (requests.exceptions.ConnectionError, ConnectionError)):
        return 'service_unavailable', 502, 'Backend service is unavailable.'
    if isinstance(exc, requests.exceptions.SSLError):
        return 'upstream_tls_error', 502, 'Backend TLS connection failed.'
    if isinstance(exc, requests.exceptions.HTTPError):
        resp = getattr(exc, 'response', None)
        sc = int(getattr(resp, 'status_code', 0) or 0)
        code = f'{upstream}_http_{sc}' if sc else f'{upstream}_http_error'
        return code, 502, 'Backend service returned an error.'
    if isinstance(exc, requests.exceptions.RequestException):
        return f'{upstream}_request_error', 502, 'Backend request failed.'
    if isinstance(exc, (ValueError, KeyError, TypeError)):
        if upstream != 'local':
            return 'invalid_upstream_response', 502, 'Invalid response from backend service.'
        return 'internal_error', 500, 'Internal server error.'
    if isinstance(exc, (OSError, subprocess.SubprocessError) if 'subprocess' in sys.modules else OSError):
        return f'{upstream}_process_error' if upstream != 'local' else 'internal_error', 500, 'Backend process operation failed.'
    return ('internal_error' if upstream == 'local' else f'{upstream}_error'), (500 if upstream == 'local' else 502), 'Operation failed due to an internal error.'


def _error_json(
    error_code: str,
    message: Optional[str] = None,
    status: int = 500,
    *,
    extra: Optional[Dict[str, Any]] = None,
):
    body: Dict[str, Any] = {'ok': False, 'error': str(error_code or 'internal_error')}
    if message:
        body['message'] = str(message)
    rid = _current_request_id()
    if rid:
        body['request_id'] = rid
    if isinstance(extra, dict):
        body.update(extra)
    return jsonify(body), int(status)


def _handle_backend_exception(
    op: str,
    exc: Exception,
    *,
    upstream: str = 'backend',
    status_override: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
):
    code, status, msg = _classify_backend_exception(exc, upstream=upstream)
    final_status = int(status_override) if status_override is not None else status
    lvl = 'warning' if isinstance(exc, (requests.exceptions.RequestException, ConnectionError, TimeoutError)) else 'exception'
    _log_backend_exception(op, exc, level=lvl, error_code=code, upstream=upstream)
    return _error_json(code, msg, status=final_status, extra=extra)


def _is_safe_detail_str(val: str) -> bool:
    s = str(val or '').strip()
    if not s or len(s) > 64:
        return False
    lower = s.lower()
    if any(
        bad in lower
        for bad in (
            'http://',
            'https://',
            'traceback',
            'file "',
            '\n',
            '\r',
            '\\',
            '/home/',
            '/etc/',
            '/var/',
            '/root/',
            '/mnt/',
            '/opt/',
            '/usr/',
            '/tmp/',
            'exception',
        )
    ):
        return False
    if _PATH_RX.search(s):
        return False
    return True


def _sanitize_runner_detail_value(val: Any) -> Any:
    if isinstance(val, bool) or val is None:
        return val
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, str):
        return val.strip() if _is_safe_detail_str(val) else None
    if isinstance(val, list):
        cleaned = []
        for item in val[:32]:
            if isinstance(item, str) and _is_safe_detail_str(item):
                cleaned.append(item.strip())
            elif isinstance(item, (int, float, bool)):
                cleaned.append(item)
        return cleaned
    if isinstance(val, dict):
        cleaned_dict = {}
        for k, v in list(val.items())[:16]:
            if isinstance(k, str) and k in {'vip_ip', 'primary', 'backup', 'active', 'service_port'}:
                sv = _sanitize_runner_detail_value(v)
                if sv is not None:
                    cleaned_dict[k] = sv
        return cleaned_dict
    return None


def _sanitize_runner_error_payload(data: Dict[str, Any], status_code: int, op: str) -> Tuple[str, int, Dict[str, Any]]:
    raw_err = str(data.get('error') or '').strip()
    default_code = 'invalid_request' if 400 <= status_code < 500 else 'runner_internal_error'
    if raw_err in _ALLOWED_RUNNER_ERROR_CODES:
        safe_err = raw_err
    else:
        _log_backend_exception(op, level='warning', suppressed_runner_error=raw_err[:200], upstream_status=status_code)
        safe_err = default_code

    safe_extra: Dict[str, Any] = {}
    for k in _ALLOWED_RUNNER_DETAIL_KEYS:
        if k in data:
            sv = _sanitize_runner_detail_value(data[k])
            if sv is not None:
                safe_extra[k] = sv

    out_status = int(status_code) if 400 <= int(status_code) < 500 else 502
    return safe_err, out_status, safe_extra


def _forward_runner_response(r, op: str = 'runner'):
    raw_sc = getattr(r, 'status_code', None)
    status_int = int(raw_sc) if isinstance(raw_sc, int) else 200
    if r.ok:
        try:
            data = r.json()
        except Exception as e:
            return _handle_backend_exception(op, e, upstream='runner')
        return jsonify(data), status_int

    err_sc = int(raw_sc) if isinstance(raw_sc, int) else 502
    try:
        parsed = r.json()
    except Exception:
        parsed = None

    if isinstance(parsed, dict):
        safe_err, out_status, safe_extra = _sanitize_runner_error_payload(parsed, err_sc, op)
        return _error_json(safe_err, status=out_status, extra=safe_extra)

    _log_backend_exception(
        op,
        level='warning',
        runner_http_status=err_sc,
        snippet=_redact_secrets((r.text or '').strip()[:250]),
    )
    out_status = err_sc if 400 <= err_sc < 500 else 502
    msg = 'Lab runner rejected the request.' if out_status < 500 else 'Lab runner returned an error.'
    return _error_json('runner_http_error', msg, status=out_status, extra={'status': err_sc})


def _ryu_post(path: str, json_data: Optional[Dict] = None, timeout: float = 2.0) -> requests.Response:
    m = sys.modules.get('webapp.server')
    req_mod = m.requests if (m and hasattr(m, 'requests')) else requests
    ryu_base = getattr(m, 'RYU_API_BASE', None) if m else None
    if not ryu_base:
        ryu_base = os.getenv('RYU_API_BASE', 'http://127.0.0.1:8080')
    return req_mod.post(f"{ryu_base}{path}", json=json_data, headers=_internal_headers() or None, timeout=timeout)


def _call_ryu_post(path: str, json_data: Optional[Dict] = None, timeout: float = 2.0) -> requests.Response:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_ryu_post'):
        return getattr(m, '_ryu_post')(path, json_data=json_data, timeout=timeout)
    return _ryu_post(path, json_data=json_data, timeout=timeout)


def _proxy_ryu_post(
    ryu_path: str,
    *,
    json_data: Optional[Dict[str, Any]] = None,
    timeout: float = 2.0,
    forward_400: bool = False,
    op: str = 'ryu_post',
):
    try:
        r = _call_ryu_post(ryu_path, json_data=json_data, timeout=timeout)
        if forward_400 and getattr(r, 'status_code', None) == 400:
            try:
                err_data = r.json()
            except Exception:
                err_data = None
            if not isinstance(err_data, dict):
                return _error_json('invalid_request', 'Controller rejected request.', status=400)
            raw_err = str(err_data.get('error') or '').strip()
            if raw_err in _ALLOWED_RYU_400_ERRORS:
                safe_err = raw_err
                raw_msg = str(err_data.get('message') or '').strip()
                safe_msg = _sanitize_log_text(raw_msg, max_lines=1, max_chars=180) if raw_msg else None
            else:
                _log_backend_exception(op, level='warning', suppressed_ryu_400_error=raw_err[:200])
                safe_err = 'invalid_request'
                safe_msg = 'Controller rejected request.'
            extra: Dict[str, Any] = {}
            raw_errs = err_data.get('errors')
            if isinstance(raw_errs, dict):
                extra['errors'] = {
                    str(k)[:40]: _sanitize_log_text(str(v), max_lines=1, max_chars=160)
                    for k, v in list(raw_errs.items())[:20]
                }
            elif isinstance(raw_errs, list):
                extra['errors'] = [
                    _sanitize_log_text(str(item), max_lines=1, max_chars=160)
                    for item in raw_errs[:20]
                ]
            if isinstance(err_data.get('changed'), dict):
                extra['changed'] = {
                    str(k)[:40]: (_sanitize_log_text(v, max_lines=1, max_chars=80) if isinstance(v, str) else v)
                    for k, v in err_data['changed'].items()
                    if isinstance(v, (bool, int, float, str))
                }
            return _error_json(safe_err, safe_msg, status=400, extra=extra or None)
        r.raise_for_status()
        return jsonify(r.json())
    except Exception as e:
        return _handle_backend_exception(op, e, upstream='ryu')


def _handle_http_exception(exc: HTTPException):
    sc = int(exc.code or 500)
    code_map = {
        400: 'bad_request',
        401: 'unauthorized',
        403: 'forbidden',
        404: 'not_found',
        405: 'method_not_allowed',
        409: 'conflict',
        413: 'payload_too_large',
        422: 'unprocessable_entity',
        429: 'rate_limited',
    }
    code = code_map.get(sc, 'http_error' if sc < 500 else 'internal_error')
    if (request.path or '').startswith('/api/'):
        return _error_json(code, status=sc)
    return Response(code.replace('_', ' ').title(), status=sc, mimetype='text/plain')


def _handle_unhandled_exception(exc: Exception):
    _log_backend_exception('unhandled_exception', exc, level='exception', path=request.path or '')
    if (request.path or '').startswith('/api/'):
        return _error_json('internal_error', 'An internal server error occurred.', status=500)
    return Response('Internal Server Error', status=500, mimetype='text/plain')


def _load_internal_token() -> str:
    tok = (os.getenv('SDN_INTERNAL_TOKEN') or '').strip()
    if tok:
        return tok
    try:
        tok_path = os.path.join(RUN_DIR, 'internal.token')
        if os.path.isfile(tok_path):
            with open(tok_path, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except Exception:
        pass
    return ''


def _internal_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    tok = _load_internal_token()
    if tok:
        headers['X-Internal-Token'] = tok
    rid = _current_request_id()
    if rid:
        headers['X-Request-ID'] = rid
    return headers


def _to_int(v, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return int(default)


def _rate_ip() -> str:
    trust = (os.getenv('TRUST_PROXY_HEADERS', '0').strip().lower() in ('1', 'true', 'yes', 'y', 'on'))
    if trust and request.environ.get('SDN_TRUSTED_PROXY') == '1':
        cf = (request.headers.get('CF-Connecting-IP') or '').strip()
        if cf:
            return cf
        xff = (request.headers.get('X-Forwarded-For') or '').strip()
        if xff:
            return xff.split(',')[0].strip()
        xrip = (request.headers.get('X-Real-IP') or '').strip()
        if xrip:
            return xrip
    return (request.remote_addr or 'unknown').strip()


def _rate_check(bucket: str, limit: int, window_s: int) -> bool:
    now = float(time.time())
    key = f"{bucket}:{_rate_ip()}"
    with _rate_lock:
        item = _rate_state.get(key)
        if not isinstance(item, dict):
            item = {'ts': now, 'count': 0}
            _rate_state[key] = item
        ts = float(item.get('ts') or 0.0)
        if now - ts >= float(window_s):
            item['ts'] = now
            item['count'] = 0
        item['count'] = int(item.get('count') or 0) + 1
        if int(item['count']) > int(limit):
            return False
        if len(_rate_state) > 5000:
            cutoff = now - float(max(window_s, 120))
            for k, v in list(_rate_state.items()):
                try:
                    if float(v.get('ts') or 0.0) < cutoff:
                        _rate_state.pop(k, None)
                except Exception:
                    _rate_state.pop(k, None)
        return True


def _access_allowed() -> bool:
    allow = (os.getenv('WEB_ALLOW_CIDRS') or '').strip()
    if not allow:
        return True
    ip_s = (_rate_ip() or '').strip()
    try:
        ip = ipaddress.ip_address(ip_s)
    except Exception:
        return False
    for part in allow.split(','):
        part = (part or '').strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
            if ip in net:
                return True
        except Exception:
            try:
                if ip == ipaddress.ip_address(part):
                    return True
            except Exception:
                continue
    return False


def _validate_ipv4_api(value) -> Optional[str]:
    """Return normalized IPv4 string or None if invalid. Rejects IPv6."""
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


def _validate_mac_api(value) -> Optional[str]:
    """Return normalized MAC (lowercase, colon-separated) or None if invalid."""
    if value is None or not isinstance(value, str):
        return None
    s = str(value).strip().lower().replace('-', ':')
    if re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', s):
        return s
    return None


def _validate_service_url(raw_url: Any) -> Optional[str]:
    """Validate backend base URL strictly to prevent SSRF."""
    if not isinstance(raw_url, str):
        return None
    s = raw_url.strip()
    if not s:
        return None
    try:
        parsed = urllib.parse.urlparse(s)
    except Exception:
        return None
    if parsed.scheme not in ('http', 'https'):
        return None
    if not parsed.netloc or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if parsed.query or parsed.fragment:
        return None
    if parsed.path not in ('', '/'):
        return None
    try:
        port = parsed.port
        if port is not None and (port < 1 or port > 65535):
            return None
    except Exception:
        return None
    allow_remote = os.getenv('ALLOW_REMOTE_RYU_URL', '0').strip().lower() in ('1', 'true', 'yes', 'y', 'on')
    if not allow_remote:
        host = parsed.hostname.lower()
        if host != 'localhost':
            try:
                if not ipaddress.ip_address(host).is_loopback:
                    return None
            except Exception:
                return None
    return s.rstrip('/')


def _is_password_hash(value: str) -> bool:
    """True if value looks like a Werkzeug/Flask password hash (pbkdf2, scrypt, etc.)."""
    if not value or not isinstance(value, str):
        return False
    s = value.strip()
    return s.startswith('pbkdf2:') or s.startswith('scrypt:') or s.startswith('argon2:')


def _verify_password(stored: str, password: str) -> bool:
    """Verify password against stored value strictly via hash; rejects plaintext passwords."""
    if not stored or not password:
        return False
    if _is_password_hash(stored):
        return check_password_hash(stored, password)
    return False


def _load_users() -> Dict[str, Any]:
    """Load users from disk with memory caching for performance and dual-schema support."""
    global _users_cache, _users_cache_mtime
    users_path = current_users_file()

    try:
        stat = os.stat(users_path)
        current_mtime = stat.st_mtime
    except Exception:
        current_mtime = 0.0

    now = time.time()
    with _users_cache_lock:
        if _users_cache and (now - _users_cache_mtime < USERS_CACHE_TTL) and current_mtime == _users_cache_mtime:
            return dict(_users_cache)

        try:
            if os.path.isfile(users_path):
                with open(users_path, 'r', encoding='utf-8') as f:
                    v = json.load(f)
                data = v if isinstance(v, dict) else {}
                normalized: Dict[str, Any] = {}
                for uname, uobj in data.items():
                    if isinstance(uobj, dict):
                        pw = str(uobj.get('password') or uobj.get('password_hash') or '')
                        role = str(uobj.get('role') or 'user').strip().lower()
                        if pw and not _is_password_hash(pw):
                            print(
                                f"SECURITY WARNING: User '{uname}' uses a plaintext password in users.json; hash it with 'python -m webapp.hash_password'.",
                                file=sys.stderr,
                            )
                        normalized[uname] = {'password': pw, 'role': role}
                    elif isinstance(uobj, str):
                        pw = uobj.strip()
                        if pw and not _is_password_hash(pw):
                            print(
                                f"SECURITY WARNING: User '{uname}' uses a plaintext password in users.json; hash it with 'python -m webapp.hash_password'.",
                                file=sys.stderr,
                            )
                        normalized[uname] = {'password': pw, 'role': 'user'}
                _users_cache = normalized
                _users_cache_mtime = current_mtime
                return dict(_users_cache)
        except Exception:
            _users_cache = {}
            _users_cache_mtime = current_mtime
    return {}


def _is_logged_in() -> bool:
    return bool(session.get('user'))


def _get_csrf_token() -> str:
    tok = session.get('csrf_token')
    if not tok or not isinstance(tok, str):
        tok = secrets.token_urlsafe(32)
        session['csrf_token'] = tok
    return tok


def _inject_csrf_token():
    return {'csrf_token': _get_csrf_token()}


def _login_fail_allowed(ip: str, limit: int = 8, window_s: int = 300) -> bool:
    now = float(time.time())
    key = f"login_fail:{ip}"
    with _rate_lock:
        item = _rate_state.get(key)
        if not isinstance(item, dict):
            return True
        ts = float(item.get('ts') or 0.0)
        if now - ts >= float(window_s):
            _rate_state.pop(key, None)
            return True
        return int(item.get('count') or 0) < int(limit)


def _login_fail_record(ip: str, window_s: int = 300) -> None:
    now = float(time.time())
    key = f"login_fail:{ip}"
    with _rate_lock:
        item = _rate_state.get(key)
        if not isinstance(item, dict) or (now - float(item.get('ts') or 0.0) >= float(window_s)):
            _rate_state[key] = {'ts': now, 'count': 1}
        else:
            item['count'] = int(item.get('count') or 0) + 1


def _login_fail_clear(ip: str) -> None:
    with _rate_lock:
        _rate_state.pop(f"login_fail:{ip}", None)


def _rate_limit_guard():
    if not (os.getenv('RATE_LIMIT_ENABLE', '1').strip().lower() in ('1', 'true', 'yes', 'y', 'on')):
        return None

    path = request.path or ''
    if path.startswith('/static/'):
        return None

    window_s = _to_int(os.getenv('RATE_LIMIT_WINDOW_S', '60'), 60)
    api_limit = _to_int(os.getenv('RATE_LIMIT_API_PER_WINDOW', '180'), 180)
    ui_limit = _to_int(os.getenv('RATE_LIMIT_UI_PER_WINDOW', '120'), 120)
    heavy_limit = _to_int(os.getenv('RATE_LIMIT_HEAVY_PER_WINDOW', '30'), 30)
    poll_limit = _to_int(os.getenv('RATE_LIMIT_POLL_PER_WINDOW', '1200'), 1200)

    bucket = 'ui'
    limit = ui_limit
    if path.startswith('/api/'):
        bucket = 'api'
        limit = api_limit

    if path in (
        '/api/lab/status',
        '/api/metrics',
        '/api/flows',
        '/api/alerts',
        '/api/history',
        '/api/vm/metrics',
        '/api/vm/proc',
        '/api/lab/ha/status',
        '/api/lab/ha/failover/status',
        '/api/lab/attack/status',
        '/api/lab/pcap/list',
        '/api/lab/ovs/flows',
    ):
        bucket = 'poll'
        limit = poll_limit

    if path in (
        '/api/lab/build',
        '/api/lab/topology/apply',
        '/api/lab/stop',
        '/api/lab/scenario',
        '/api/lab/attack/run',
        '/api/lab/attack/stop',
        '/api/controller/start',
        '/api/controller/stop',
    ):
        bucket = f"heavy:{path}"
        limit = heavy_limit

    if not _rate_check(bucket=bucket, limit=limit, window_s=window_s):
        if path.startswith('/api/'):
            return _error_json('rate_limited', status=429, extra={'limit': limit, 'window_s': window_s})
        return Response('Too Many Requests', status=429, mimetype='text/plain')
    return None


def _access_guard():
    if not (os.getenv('WEB_ALLOWLIST_ENABLE', '0').strip().lower() in ('1', 'true', 'yes', 'y', 'on')):
        return None
    path = request.path or ''
    if path.startswith('/static/'):
        return None
    if not _access_allowed():
        if path.startswith('/api/'):
            return _error_json('forbidden', status=403)
        return Response('Forbidden', status=403, mimetype='text/plain')
    return None


def _auth_guard():
    """Enhanced authentication guard with session timeout check."""
    path = request.path or ''
    if path.startswith('/static/'):
        return None
    if path in ('/health', '/login'):
        return None
    if path == '/logout':
        return None

    if not _is_logged_in():
        if path.startswith('/api/'):
            return _error_json('unauthorized', status=401)
        return redirect('/login')

    boot_id = session.get('boot_id')
    server_boot_id = get_server_boot_id()
    if not boot_id or not isinstance(boot_id, str) or not hmac.compare_digest(boot_id, server_boot_id):
        session.clear()
        if path.startswith('/api/'):
            return _error_json('session_invalidated', status=401)
        return redirect('/login')

    # Check session age (8 hour timeout)
    login_ts = session.get('login_ts')
    if login_ts:
        session_age = time.time() - int(login_ts)
        if session_age > 28800:  # 8 hours in seconds
            session.clear()
            if path.startswith('/api/'):
                return _error_json('session_expired', status=401)
            return redirect('/login')

    return None


def _csrf_guard():
    """Validate per-session CSRF token on state-changing requests."""
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None
    path = request.path or ''
    expected = session.get('csrf_token')
    provided = (request.headers.get('X-CSRF-Token') or request.form.get('csrf_token') or '').strip()
    if not expected or not isinstance(expected, str) or not provided or not hmac.compare_digest(provided, expected):
        if path.startswith('/api/'):
            return _error_json('csrf_invalid', status=403)
        if path == '/login':
            return render_template('login.html', error='Session expired or invalid CSRF token. Please try again.'), 403
        return Response('Invalid CSRF token', status=403, mimetype='text/plain')
    return None


def _security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    resp.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    resp.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    path = request.path or ''
    if path.startswith('/api/') or path == '/login':
        resp.headers['Cache-Control'] = 'no-store'
    rid = _current_request_id()
    if rid:
        resp.headers.setdefault('X-Request-ID', rid)
    return resp


def _require_admin_role():
    """Verify authenticated session holds administrative privileges."""
    user = session.get('user')
    if not user:
        return _error_json('unauthorized', 'Authentication required', status=401)
    users_db = _load_users()
    user_record = users_db.get(user)
    if user_record is not None:
        if isinstance(user_record, dict):
            role = user_record.get('role', 'user')
        else:
            role = 'user'
    else:
        role = session.get('role', 'user')

    if role != 'admin':
        return _error_json('forbidden', 'Administrative privileges required', status=403)
    return None


def require_admin(f):
    """Decorator for route handlers that require administrative privileges."""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        err = _require_admin_role()
        if err is not None:
            return err
        return f(*args, **kwargs)

    return decorated_function



def _audit_log_whitelist(event_type: str, user: str, count: int, ips_list: List[str], req_id: str):
    """Log structured whitelist audit event with sha256 fingerprint; fail-secure fallback to stderr."""
    sorted_ips = sorted(list(ips_list))
    fingerprint = hashlib.sha256(",".join(sorted_ips).encode('utf-8')).hexdigest()[:16] if sorted_ips else "empty"
    payload = {
        "event": event_type,
        "user": str(user),
        "count": int(count),
        "sha256_prefix": fingerprint,
        "request_id": str(req_id),
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    logger = _get_logger()
    try:
        logger.info("[AUDIT] %s", json.dumps(payload, sort_keys=True))
    except Exception:
        try:
            sys.stderr.write(f"[EMERGENCY-AUDIT-FALLBACK] {json.dumps(payload)}\n")
            sys.stderr.flush()
        except Exception:
            pass
