"""Ryu Controller Mitigation Proxy Blueprint.

Handles all DoS mitigation, IP/MAC blocking, whitelisting, OpenFlow rules,
and dynamic controller configuration routes proxied to Ryu REST (Port 8080).
Routes (14 total):
- POST /api/whitelist/clear -> api_whitelist_clear()
- POST /api/unblock/all -> api_unblock_all()
- POST /api/alerts/clear -> api_alerts_clear()
- POST /api/block/ip -> api_block_ip()
- POST /api/unblock/ip -> api_unblock_ip()
- GET  /api/config -> api_get_config()
- POST /api/config -> api_update_config()
- GET  /api/flows -> api_flows()
- POST /api/flows/clear -> api_flows_clear()
- POST /api/block/mac -> api_block_mac()
- POST /api/unblock/mac -> api_unblock_mac()
- POST /api/unblock/mac/all -> api_unblock_mac_all()
- POST /api/whitelist/ip -> api_whitelist_ip()
- POST /api/unwhitelist/ip -> api_unwhitelist_ip()
"""

import re
import sys
import time
from typing import Any, Dict

from flask import Blueprint, jsonify, request

from core.sdn_config import get_config_manager
from webapp.core import RYU_API_BASE
from webapp.core.security import (
    _error_json,
    _log_backend_exception,
    _validate_ipv4_api,
    _validate_mac_api,
    _proxy_ryu_post,
    require_admin,
)
from webapp.core.alerts_sync import (
    _safe_request,
    _get_service_health,
    _alerts_snapshot,
    _snapshot_lock,
)

mitigation_bp = Blueprint('mitigation', __name__)


def _parse_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val != 0
    if isinstance(val, str):
        return val.strip().lower() in ('true', '1', 'yes', 'on')
    return False


def _get_ryu_api_base() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'RYU_API_BASE'):
        return str(srv.RYU_API_BASE or '')
    return str(RYU_API_BASE or '')


def _call_safe_request(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_safe_request'):
        return srv._safe_request(*args, **kwargs)
    return _safe_request(*args, **kwargs)


def _call_proxy_ryu_post(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_proxy_ryu_post'):
        return srv._proxy_ryu_post(*args, **kwargs)
    return _proxy_ryu_post(*args, **kwargs)


@mitigation_bp.post('/api/whitelist/clear')
@require_admin
def api_whitelist_clear():
    return _call_proxy_ryu_post('/dos/whitelist/clear', timeout=2, op='whitelist_clear')


@mitigation_bp.post('/api/unblock/all')
@require_admin
def api_unblock_all():
    return _call_proxy_ryu_post('/dos/unblock/all', timeout=2, op='unblock_all')


@mitigation_bp.post('/api/alerts/clear')
@require_admin
def api_alerts_clear():
    resp = _call_proxy_ryu_post('/dos/alerts/clear', timeout=2, op='alerts_clear')
    if (isinstance(resp, tuple) and len(resp) >= 2 and resp[1] == 200) or (hasattr(resp, 'status_code') and resp.status_code == 200):
        with _snapshot_lock:
            _alerts_snapshot['alerts'] = []
            _alerts_snapshot['ts'] = time.time()
    return resp


@mitigation_bp.post('/api/block/ip')
@require_admin
def api_block_ip():
    data = request.get_json(silent=True) or {}
    ip_val = _validate_ipv4_api(data.get('ip'))
    if not ip_val:
        return _error_json('invalid_ip', 'Valid IPv4 address required', status=400)
    return _call_proxy_ryu_post(f"/dos/block/ip/{ip_val}", timeout=2, forward_400=True, op='block_ip')


@mitigation_bp.post('/api/unblock/ip')
@require_admin
def api_unblock_ip():
    data = request.get_json(silent=True) or {}
    ip_val = _validate_ipv4_api(data.get('ip'))
    if not ip_val:
        return _error_json('invalid_ip', 'Valid IPv4 address required', status=400)
    return _call_proxy_ryu_post(f"/dos/unblock/ip/{ip_val}", timeout=2, op='unblock_ip')


@mitigation_bp.get('/api/config')
def api_get_config():
    mgr = get_config_manager()
    return jsonify({
        'ok': True,
        'effective': mgr.get_all_effective(),
        'metadata': mgr.get_metadata(),
    })


@mitigation_bp.post('/api/config')
@mitigation_bp.post('/api/config/update')
@require_admin
def api_update_config():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return _error_json('invalid_json_object', status=400)

    persist = _parse_bool(payload.get('persist', False))
    clean_updates = {k: v for k, v in payload.items() if k != 'persist'}

    mgr = get_config_manager()
    changed: Dict[str, Any] = {}
    if persist:
        changed, errors, _ = mgr.apply_runtime_override(clean_updates, persist=True)
        if errors:
            return jsonify({'ok': False, 'error': 'validation_failed', 'errors': errors}), 400

    resp = _call_proxy_ryu_post('/dos/config', json_data=clean_updates, timeout=2, forward_400=True, op='update_config')
    ryu_ok = (isinstance(resp, tuple) and resp[1] == 200) or (hasattr(resp, 'status_code') and resp.status_code == 200)

    if not ryu_ok:
        return resp

    persisted = False
    if persist:
        if not changed:
            changed, _, _ = mgr.apply_runtime_override(clean_updates, persist=True)
        if changed:
            persisted = mgr._atomic_persist_to_file(changed)
            if not persisted:
                return jsonify({
                    'ok': False,
                    'error': 'live_applied_but_disk_persistence_failed',
                    'changed': changed,
                    'persisted': False,
                }), 500
    else:
        mgr.apply_runtime_override(clean_updates, persist=False)

    return jsonify({
        'ok': True,
        'changed': changed or clean_updates,
        'durability': 'permanent' if (persist and persisted) else 'ephemeral',
        'persisted': persisted,
        'note': 'Configuration saved to sdn_config.json' if persisted else 'Configuration active in memory only (lost on restart)',
    })


@mitigation_bp.get('/api/flows')
def api_flows():
    ryu_base = _get_ryu_api_base()
    r = _call_safe_request(f"{ryu_base}/dos/flows", method='GET', timeout=2.0, service_name='ryu')
    if r and r.ok:
        try:
            return jsonify(r.json())
        except Exception as e:
            _log_backend_exception('flows', e, level='warning')
    health = _get_service_health('ryu')
    err_code = str(health.get('error') or 'service_unavailable').strip()
    if not re.fullmatch(r'[a-z0-9_]{2,40}', err_code):
        err_code = 'service_unavailable'
    return _error_json(err_code, status=502, extra={'service_unhealthy': True})


@mitigation_bp.post('/api/flows/clear')
@require_admin
def api_flows_clear():
    return _call_proxy_ryu_post('/dos/flows/clear', timeout=2, op='flows_clear')


@mitigation_bp.post('/api/block/mac')
@require_admin
def api_block_mac():
    data = request.get_json(silent=True) or {}
    mac_val = _validate_mac_api(data.get('mac'))
    if not mac_val:
        return _error_json('invalid_mac', 'Valid MAC required (e.g. aa:bb:cc:dd:ee:ff)', status=400)
    return _call_proxy_ryu_post(f"/dos/block/mac/{mac_val}", timeout=2, op='block_mac')


@mitigation_bp.post('/api/unblock/mac')
@require_admin
def api_unblock_mac():
    data = request.get_json(silent=True) or {}
    mac_val = _validate_mac_api(data.get('mac'))
    if not mac_val:
        return _error_json('invalid_mac', 'Valid MAC required (e.g. aa:bb:cc:dd:ee:ff)', status=400)
    return _call_proxy_ryu_post(f"/dos/unblock/mac/{mac_val}", timeout=2, op='unblock_mac')


@mitigation_bp.post('/api/unblock/mac/all')
@require_admin
def api_unblock_mac_all():
    return _call_proxy_ryu_post('/dos/unblock/mac/all', timeout=2, op='unblock_mac_all')


@mitigation_bp.post('/api/whitelist/ip')
@require_admin
def api_whitelist_ip():
    data = request.get_json(silent=True) or {}
    ip_val = _validate_ipv4_api(data.get('ip'))
    if not ip_val:
        return _error_json('invalid_ip', 'Valid IPv4 address required', status=400)
    return _call_proxy_ryu_post(f"/dos/whitelist/ip/{ip_val}", timeout=2, op='whitelist_ip')


@mitigation_bp.post('/api/unwhitelist/ip')
@require_admin
def api_unwhitelist_ip():
    data = request.get_json(silent=True) or {}
    ip_val = _validate_ipv4_api(data.get('ip'))
    if not ip_val:
        return _error_json('invalid_ip', 'Valid IPv4 address required', status=400)
    return _call_proxy_ryu_post(f"/dos/unwhitelist/ip/{ip_val}", timeout=2, op='unwhitelist_ip')
