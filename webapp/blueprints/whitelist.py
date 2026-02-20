"""Persistent Whitelist Blueprint (F-20).

Handles persistent IP whitelist saving, restoration, status checking,
and deletion with cross-process locking, schema validation, and atomic writes.
Routes (4 total):
- POST   /api/whitelist/save -> api_whitelist_save()
- POST   /api/whitelist/restore -> api_whitelist_restore()
- GET    /api/whitelist/status -> api_whitelist_status()
- DELETE /api/whitelist/persistent -> api_whitelist_delete_persistent()
"""

import datetime
import hashlib
import ipaddress
import json
import os
import re
import sys
import uuid
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Blueprint, current_app, jsonify, session

from core.common_utils import CrossProcessFileLock
from webapp.core import (
    SecurityError,
    CONFIGS_DIR,
    RYU_API_BASE,
    WHITELIST_LOCK_PATH,
    WHITELIST_STORAGE_PATH,
)
from webapp.core.security import (
    _audit_log_whitelist,
    _auth_guard,
    _error_json,
    _internal_headers,
    _require_admin_role,
    _validate_ipv4_api,
    require_admin,
)

whitelist_bp = Blueprint('whitelist', __name__)


def _get_configs_dir() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'CONFIGS_DIR'):
        return srv.CONFIGS_DIR
    return CONFIGS_DIR


def _get_whitelist_storage_path() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'WHITELIST_STORAGE_PATH'):
        return srv.WHITELIST_STORAGE_PATH
    return WHITELIST_STORAGE_PATH


def _get_whitelist_lock_path() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'WHITELIST_LOCK_PATH'):
        return srv.WHITELIST_LOCK_PATH
    return WHITELIST_LOCK_PATH


def _validate_whitelist_json_payload(raw_content: bytes) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Validate JSON schema, strict UTF-8, types, and invariants of persistent whitelist."""
    if len(raw_content) > 65536:
        return None, "File size exceeds maximum allowed 64KB limit"
    if raw_content.startswith(b'\xef\xbb\xbf'):
        return None, "Invalid encoding: UTF-8 BOM is strictly prohibited"
    try:
        text = raw_content.decode('utf-8')
        data = json.loads(text)
    except UnicodeDecodeError:
        return None, "Invalid encoding: strict UTF-8 required"
    except json.JSONDecodeError as err:
        return None, f"Malformed JSON: {err}"

    if not isinstance(data, dict):
        return None, "Root element must be a JSON object"

    required_keys = {"schema_version", "updated_at", "updated_by", "count", "whitelist_ips"}
    allowed_keys = required_keys | {"description"}
    missing = required_keys - set(data.keys())
    if missing:
        return None, f"Missing required fields: {sorted(list(missing))}"
    extra = set(data.keys()) - allowed_keys
    if extra:
        return None, f"Unexpected fields found: {sorted(list(extra))}"

    if data.get("schema_version") != "1.0":
        return None, f"Unsupported schema_version '{data.get('schema_version')}'; expected '1.0'"

    updated_by = data.get("updated_by")
    if not isinstance(updated_by, str) or not re.match(r"^[a-zA-Z0-9_.\-]{1,64}$", updated_by):
        return None, "Field 'updated_by' must match pattern '^[a-zA-Z0-9_.-]{1,64}$'"

    count = data.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0 or count > 256:
        return None, "Field 'count' must be an integer between 0 and 256"

    raw_ips = data.get("whitelist_ips")
    if not isinstance(raw_ips, list):
        return None, "Field 'whitelist_ips' must be a list"

    if len(raw_ips) != count:
        return None, f"Count mismatch: field 'count' is {count} but list contains {len(raw_ips)} items"

    if len(raw_ips) != len(set(raw_ips)):
        return None, "Duplicate IP addresses detected in whitelist_ips"

    for item in raw_ips:
        if not isinstance(item, str):
            return None, f"All items in whitelist_ips must be strings; got {type(item).__name__}"
        item_s = item.strip()
        if '/' in item_s or ':' in item_s:
            return None, f"CIDR notation and IPv6 are not allowed: {item_s}"
        try:
            parsed = ipaddress.IPv4Address(item_s)
        except ValueError:
            return None, f"Invalid IPv4 address: {item_s}"
        if parsed.is_loopback:
            return None, f"Loopback address not permitted in whitelist: {item_s}"
        if parsed.is_multicast:
            return None, f"Multicast address not permitted in whitelist: {item_s}"
        if item_s in ("0.0.0.0", "255.255.255.255"):
            return None, f"Reserved broadcast/wildcard address not permitted: {item_s}"

    return data, None


@whitelist_bp.post('/api/whitelist/save')
@require_admin
def api_whitelist_save():
    admin_err = _require_admin_role()
    if admin_err:
        return admin_err

    user = session.get('user', 'admin')
    req_id = str(uuid.uuid4())

    headers = _internal_headers()
    try:
        ryu_resp = requests.get(f"{RYU_API_BASE.rstrip('/')}/dos/whitelist", headers=headers, timeout=3.0)
    except Exception as ex:
        try:
            current_app.logger.warning('[req=%s] whitelist_save failed to reach Ryu (%s)', req_id, ex)
        except Exception:
            pass
        return _error_json('ryu_unreachable', f"Failed to fetch whitelist from controller: {ex}", status=502)

    if ryu_resp.status_code != 200:
        return _error_json('ryu_error', f"Ryu returned HTTP {ryu_resp.status_code}", status=502)

    try:
        ryu_data = ryu_resp.json()
    except Exception as ex:
        return _error_json('invalid_upstream_response', f"Ryu returned invalid JSON: {ex}", status=502)

    raw_ips = ryu_data.get('whitelist_ips', [])
    if not isinstance(raw_ips, list):
        return _error_json('invalid_upstream_data', "Ryu whitelist_ips is not a list", status=502)

    if len(raw_ips) > 256:
        return _error_json('limit_exceeded', "Whitelist exceeds maximum allowed 256 IPs", status=422)

    validated_ips = []
    for raw_ip in raw_ips:
        clean_ip = _validate_ipv4_api(raw_ip)
        if not clean_ip:
            return _error_json('invalid_ip_in_whitelist', f"Upstream contained invalid IPv4: {raw_ip}", status=502)
        validated_ips.append(clean_ip)
    validated_ips.sort()

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload_dict = {
        "schema_version": "1.0",
        "updated_at": now_iso,
        "updated_by": str(user),
        "description": "SDN DoS Guard Whitelist Persistent Configuration",
        "count": len(validated_ips),
        "whitelist_ips": validated_ips
    }

    configs_dir = _get_configs_dir()
    storage_path = _get_whitelist_storage_path()
    lock_path = _get_whitelist_lock_path()

    try:
        with CrossProcessFileLock(lock_path, timeout_sec=5.0):
            if os.path.islink(configs_dir) or os.path.islink(storage_path):
                raise SecurityError("Symlink detected in configuration path; operation strictly prohibited.")

            real_target = os.path.realpath(storage_path)
            if os.path.commonpath([real_target, configs_dir]) != configs_dir:
                raise SecurityError("Path traversal detected.")

            tmp_filename = f"sdn_whitelist.json.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
            tmp_path = os.path.join(configs_dir, tmp_filename)

            fd = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                content_bytes = json.dumps(payload_dict, indent=2).encode('utf-8')
                with open(fd, 'wb', closefd=True) as f:
                    f.write(content_bytes)
                    f.flush()
                    os.fsync(f.fileno())

                os.replace(tmp_path, storage_path)

                if os.name != 'nt':
                    try:
                        dir_fd = os.open(configs_dir, os.O_RDONLY)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                    except OSError:
                        pass
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
    except TimeoutError:
        return _error_json('lock_timeout', "Timed out waiting for file lock", status=503)
    except SecurityError as sec_err:
        try:
            current_app.logger.error('[req=%s] Security violation in whitelist_save: %s', req_id, sec_err)
        except Exception:
            pass
        return _error_json('security_violation', str(sec_err), status=400)
    except Exception as ex:
        try:
            current_app.logger.exception('[req=%s] Failed to save whitelist file: %s', req_id, ex)
        except Exception:
            pass
        return _error_json('io_error', f"Failed to persist whitelist: {ex}", status=500)

    _audit_log_whitelist("WHITELIST_SAVE", user, len(validated_ips), validated_ips, req_id)

    fingerprint = hashlib.sha256(",".join(validated_ips).encode('utf-8')).hexdigest() if validated_ips else "empty"
    return jsonify({
        'ok': True,
        'message': 'Whitelist successfully saved to disk',
        'file_metadata': {
            'schema_version': '1.0',
            'updated_at': now_iso,
            'updated_by': user,
            'count': len(validated_ips),
            'sha256': fingerprint
        }
    })


@whitelist_bp.post('/api/whitelist/restore')
@require_admin
def api_whitelist_restore():
    admin_err = _require_admin_role()
    if admin_err:
        return admin_err

    user = session.get('user', 'admin')
    req_id = str(uuid.uuid4())

    configs_dir = _get_configs_dir()
    storage_path = _get_whitelist_storage_path()
    lock_path = _get_whitelist_lock_path()

    try:
        with CrossProcessFileLock(lock_path, timeout_sec=5.0):
            if os.path.islink(configs_dir) or os.path.islink(storage_path):
                raise SecurityError("Symlink detected in configuration path; operation strictly prohibited.")
            if not os.path.isfile(storage_path):
                return _error_json('file_not_found', "No persistent whitelist file found on disk", status=404)
            with open(storage_path, 'rb') as f:
                raw_bytes = f.read()
    except TimeoutError:
        return _error_json('lock_timeout', "Timed out waiting for file lock", status=503)
    except SecurityError as sec_err:
        return _error_json('security_violation', str(sec_err), status=400)
    except Exception as ex:
        return _error_json('io_error', f"Failed to read whitelist file: {ex}", status=500)

    parsed_data, val_err = _validate_whitelist_json_payload(raw_bytes)
    if val_err or not parsed_data:
        return _error_json('schema_validation_error', f"Invalid whitelist file: {val_err}", status=422)

    target_ips = parsed_data.get('whitelist_ips', [])

    headers = _internal_headers()
    headers['Content-Type'] = 'application/json'
    replace_payload = {
        'request_id': req_id,
        'whitelist_ips': target_ips
    }

    timed_out = False
    ryu_resp = None
    try:
        ryu_resp = requests.post(
            f"{RYU_API_BASE.rstrip('/')}/dos/whitelist/replace",
            json=replace_payload,
            headers=headers,
            timeout=5.0
        )
    except requests.exceptions.Timeout:
        timed_out = True
    except Exception as ex:
        try:
            current_app.logger.warning('[req=%s] whitelist_restore failed to reach Ryu (%s)', req_id, ex)
        except Exception:
            pass
        return _error_json('ryu_unreachable', f"Failed to connect to controller: {ex}", status=502)

    reconciled = False
    remediation_warnings = []
    restored_version = None

    if timed_out:
        try:
            current_app.logger.warning('[req=%s] Timeout communicating with Ryu during restore; initiating reconciliation', req_id)
        except Exception:
            pass
        try:
            recon_resp = requests.get(f"{RYU_API_BASE.rstrip('/')}/dos/whitelist", headers=headers, timeout=2.0)
            if recon_resp.status_code == 200:
                recon_data = recon_resp.json()
                history = recon_data.get('recent_history', [])
                matched_in_history = any(h.get('request_id') == req_id for h in history)
                if matched_in_history or recon_data.get('last_request_id') == req_id:
                    reconciled = True
                    restored_version = recon_data.get('state_version')
                    try:
                        current_app.logger.info('[req=%s] Successfully reconciled whitelist restore after timeout', req_id)
                    except Exception:
                        pass
        except Exception as recon_ex:
            try:
                current_app.logger.error('[req=%s] Reconciliation check failed: %s', req_id, recon_ex)
            except Exception:
                pass

        if not reconciled:
            return _error_json('gateway_timeout', "Controller did not respond in time and state reconciliation could not confirm application", status=504)
    else:
        if ryu_resp.status_code != 200:
            return _error_json('ryu_error', f"Controller rejected replace: HTTP {ryu_resp.status_code} ({ryu_resp.text[:200]})", status=502)
        try:
            resp_json = ryu_resp.json()
            restored_version = resp_json.get('state_version')
            remediation_warnings = resp_json.get('remediation_warnings', [])
        except Exception:
            pass

    _audit_log_whitelist("WHITELIST_RESTORE", user, len(target_ips), target_ips, req_id)

    return jsonify({
        'ok': True,
        'message': 'Whitelist successfully restored from disk',
        'restored_count': len(target_ips),
        'state_version': restored_version,
        'reconciled': reconciled,
        'remediation_warnings': remediation_warnings
    })


@whitelist_bp.get('/api/whitelist/status')
def api_whitelist_status():
    auth_err = _auth_guard()
    if auth_err:
        return auth_err

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    headers = _internal_headers()
    in_memory_info = {'count': 0, 'whitelist_ips': [], 'state_version': 0}
    ryu_ok = False
    try:
        ryu_resp = requests.get(f"{RYU_API_BASE.rstrip('/')}/dos/whitelist", headers=headers, timeout=2.0)
        if ryu_resp.status_code == 200:
            ryu_data = ryu_resp.json()
            in_memory_info = {
                'count': ryu_data.get('count', 0),
                'whitelist_ips': ryu_data.get('whitelist_ips', []),
                'state_version': ryu_data.get('state_version', 0)
            }
            ryu_ok = True
    except Exception:
        pass

    storage_path = _get_whitelist_storage_path()
    lock_path = _get_whitelist_lock_path()

    file_info = {'exists': False}
    file_ips = None
    file_valid = False
    try:
        with CrossProcessFileLock(lock_path, timeout_sec=2.0):
            if os.path.isfile(storage_path) and not os.path.islink(storage_path):
                with open(storage_path, 'rb') as f:
                    content = f.read()
                data, err = _validate_whitelist_json_payload(content)
                if data and not err:
                    file_ips = data.get('whitelist_ips', [])
                    sorted_ips = sorted(file_ips)
                    fp = hashlib.sha256(",".join(sorted_ips).encode('utf-8')).hexdigest() if sorted_ips else "empty"
                    file_info = {
                        'exists': True,
                        'updated_at': data.get('updated_at'),
                        'updated_by': data.get('updated_by'),
                        'count': len(file_ips),
                        'sha256': fp
                    }
                    file_valid = True
                else:
                    file_info = {'exists': True, 'corrupt': True, 'error': err}
    except Exception:
        pass

    if not ryu_ok:
        sync_status = "unknown"
    elif not file_info.get('exists'):
        sync_status = "no_file"
    elif file_info.get('corrupt'):
        sync_status = "file_unreadable"
    elif file_valid and sorted(in_memory_info['whitelist_ips']) == sorted(file_ips):
        sync_status = "synced"
    else:
        sync_status = "memory_dirty"

    return jsonify({
        'ok': True,
        'checked_at': now_iso,
        'sync_status': sync_status,
        'in_memory': in_memory_info,
        'persistent_file': file_info
    })


@whitelist_bp.delete('/api/whitelist/persistent')
@require_admin
def api_whitelist_delete_persistent():
    admin_err = _require_admin_role()
    if admin_err:
        return admin_err

    user = session.get('user', 'admin')
    req_id = str(uuid.uuid4())

    configs_dir = _get_configs_dir()
    storage_path = _get_whitelist_storage_path()
    lock_path = _get_whitelist_lock_path()

    try:
        with CrossProcessFileLock(lock_path, timeout_sec=5.0):
            if os.path.islink(configs_dir) or os.path.islink(storage_path):
                raise SecurityError("Symlink detected in configuration path; operation strictly prohibited.")
            if os.path.exists(storage_path):
                os.unlink(storage_path)
                deleted = True
            else:
                deleted = False
    except TimeoutError:
        return _error_json('lock_timeout', "Timed out waiting for file lock", status=503)
    except SecurityError as sec_err:
        return _error_json('security_violation', str(sec_err), status=400)
    except Exception as ex:
        try:
            current_app.logger.exception('[req=%s] Failed to delete persistent whitelist file: %s', req_id, ex)
        except Exception:
            pass
        return _error_json('io_error', f"Failed to delete whitelist file: {ex}", status=500)

    _audit_log_whitelist("WHITELIST_DELETE", user, 0, [], req_id)
    return jsonify({'ok': True, 'message': 'Persistent whitelist file successfully deleted', 'deleted': deleted})
