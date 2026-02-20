"""Mininet Runner Proxy Blueprint.

Handles all lab network lifecycle, topology, attack management, PCAP operations,
and High Availability (HA) endpoints proxied to Mininet Runner (Port 9090).
Routes (24 total):
- GET    /api/lab/status -> api_lab_status()
- POST   /api/lab/build -> api_lab_build()
- POST   /api/lab/topology/apply -> api_lab_topology_apply()
- POST   /api/lab/stop -> api_lab_stop()
- POST   /api/lab/link/update -> api_lab_link_update()
- POST   /api/lab/scenario -> api_lab_scenario()
- GET    /api/lab/ovs/flows -> api_lab_ovs_flows()
- GET    /api/lab/attack/status -> api_lab_attack_status()
- POST   /api/lab/attack/run -> api_lab_attack_run()
- POST   /api/lab/attack/stop -> api_lab_attack_stop()
- GET    /api/lab/pcap/list -> api_lab_pcap_list()
- GET    /api/lab/pcap/download/<name> -> api_lab_pcap_download()
- POST   /api/lab/pcap/pin/<name> -> api_lab_pcap_pin()
- POST   /api/lab/pcap/unpin/<name> -> api_lab_pcap_unpin()
- DELETE /api/lab/pcap/delete/<name> -> api_lab_pcap_delete()
- GET    /api/lab/pcap/storage -> api_lab_pcap_storage()
- GET    /api/lab/ha/status -> api_lab_ha_status()
- POST   /api/lab/ha/config -> api_lab_ha_config()
- POST   /api/lab/ha/active -> api_lab_ha_active()
- POST   /api/lab/ha/service/start -> api_lab_ha_service_start()
- POST   /api/lab/ha/service/stop -> api_lab_ha_service_stop()
- GET    /api/lab/ha/test -> api_lab_ha_test()
- GET    /api/lab/ha/failover/status -> api_lab_ha_failover_status()
- POST   /api/lab/cmd/run -> api_lab_cmd_run()
"""

import re
import sys
from typing import Any, Dict, Optional

import requests
from flask import Blueprint, Response, jsonify, request, session

from webapp.core import (
    MININET_RUNNER_BASE,
    RYU_API_BASE,
)
from webapp.core.security import (
    _internal_headers,
    _error_json,
    _handle_backend_exception,
    _log_backend_exception,
    _forward_runner_response,
    require_admin,
)
from webapp.core.alerts_sync import (
    _safe_request,
    _get_service_health,
    _append_event,
    _failover_states_lock,
    _failover_execution_lock,
    _failover_states,
    _failover_history,
    VALID_HA_TARGETS,
)

lab_proxy_bp = Blueprint('lab_proxy', __name__)


def _get_requests_module():
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'requests'):
        return srv.requests
    return requests


def _call_safe_request(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_safe_request'):
        return srv._safe_request(*args, **kwargs)
    return _safe_request(*args, **kwargs)


def _call_append_event(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_append_event'):
        return srv._append_event(*args, **kwargs)
    return _append_event(*args, **kwargs)


def _runner_get(path: str, timeout: float = 5.0, stream: bool = False) -> requests.Response:
    srv = sys.modules.get('webapp.server')
    base = getattr(srv, 'MININET_RUNNER_BASE', MININET_RUNNER_BASE) if srv else MININET_RUNNER_BASE
    req_mod = _get_requests_module()
    return req_mod.get(f"{base}{path}", headers=_internal_headers() or None, timeout=timeout, stream=stream)


def _runner_post(path: str, json_data: Optional[Dict] = None, timeout: float = 5.0) -> requests.Response:
    srv = sys.modules.get('webapp.server')
    base = getattr(srv, 'MININET_RUNNER_BASE', MININET_RUNNER_BASE) if srv else MININET_RUNNER_BASE
    req_mod = _get_requests_module()
    return req_mod.post(f"{base}{path}", json=json_data, headers=_internal_headers() or None, timeout=timeout)


def _runner_delete(path: str, timeout: float = 5.0) -> requests.Response:
    srv = sys.modules.get('webapp.server')
    base = getattr(srv, 'MININET_RUNNER_BASE', MININET_RUNNER_BASE) if srv else MININET_RUNNER_BASE
    req_mod = _get_requests_module()
    return req_mod.delete(f"{base}{path}", headers=_internal_headers() or None, timeout=timeout)


def _ryu_post(path: str, json_data: Optional[Dict] = None, timeout: float = 2.0) -> requests.Response:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_ryu_post'):
        return srv._ryu_post(path, json_data=json_data, timeout=timeout)
    base = getattr(srv, 'RYU_API_BASE', RYU_API_BASE) if srv else RYU_API_BASE
    req_mod = _get_requests_module()
    return req_mod.post(f"{base}{path}", json=json_data, headers=_internal_headers() or None, timeout=timeout)


def _call_runner_get(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_runner_get'):
        return srv._runner_get(*args, **kwargs)
    return _runner_get(*args, **kwargs)


def _call_runner_post(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_runner_post'):
        return srv._runner_post(*args, **kwargs)
    return _runner_post(*args, **kwargs)


def _call_runner_delete(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_runner_delete'):
        return srv._runner_delete(*args, **kwargs)
    return _runner_delete(*args, **kwargs)


def _call_proxy_runner(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_proxy_runner'):
        return srv._proxy_runner(*args, **kwargs)
    return _proxy_runner(*args, **kwargs)


def _forward_runner_error(r) -> Any:
    return _forward_runner_response(r, op='runner')


def _proxy_runner(
    method: str,
    path: str,
    *,
    json_data: Optional[Dict[str, Any]] = None,
    timeout: float = 5.0,
    op: str = 'runner',
    on_success=None,
):
    try:
        if method == 'GET':
            r = _call_runner_get(path, timeout=timeout)
        elif method == 'DELETE':
            r = _call_runner_delete(path, timeout=timeout)
        else:
            r = _call_runner_post(path, json_data=json_data, timeout=timeout)
        if r.ok:
            data = r.json()
            if on_success is not None:
                try:
                    on_success(data)
                except Exception:
                    pass
            raw_sc = getattr(r, 'status_code', None)
            status_int = int(raw_sc) if isinstance(raw_sc, int) else 200
            return jsonify(data), status_int
        return _forward_runner_response(r, op=op)
    except Exception as e:
        return _handle_backend_exception(op, e, upstream='runner')


def _inject_ryu_preflight(payload: Any) -> Dict[str, Any]:
    out = dict(payload) if isinstance(payload, dict) else {}
    pf: Dict[str, Any] = {'blocked_ips': [], 'ddos_source_threshold': 4, 'ryu_running': False}
    try:
        srv = sys.modules.get('webapp.server')
        base = getattr(srv, 'RYU_API_BASE', RYU_API_BASE) if srv else RYU_API_BASE
        r = _call_safe_request(f"{base}/dos/metrics", method='GET', timeout=1.5, service_name='ryu')
        if r and r.ok:
            d = r.json() or {}
            cfg = d.get('config') if isinstance(d.get('config'), dict) else {}
            pf['blocked_ips'] = list(d.get('blocked_ips') or [])
            try:
                pf['ddos_source_threshold'] = max(1, int(cfg.get('ddos_source_threshold') or 4))
            except Exception:
                pf['ddos_source_threshold'] = 4
            pf['ryu_running'] = True
    except Exception:
        pass
    out['_preflight'] = pf
    return out


@lab_proxy_bp.get('/api/lab/status')
def api_lab_status():
    srv = sys.modules.get('webapp.server')
    base = getattr(srv, 'MININET_RUNNER_BASE', MININET_RUNNER_BASE) if srv else MININET_RUNNER_BASE
    r = _call_safe_request(f"{base}/status", method='GET', timeout=15.0, service_name='runner')
    if r is not None and (r.ok or getattr(r, 'status_code', None) == 409):
        try:
            return jsonify(r.json()), 200
        except Exception as e:
            _log_backend_exception('lab_status', e, level='warning')
    health = _get_service_health('runner')
    err_code = str(health.get('error') or 'service_unavailable').strip()
    if not re.fullmatch(r'[a-z0-9_]{2,40}', err_code):
        err_code = 'service_unavailable'
    return _error_json(err_code, status=502, extra={'service_unhealthy': True})


@lab_proxy_bp.post('/api/lab/build')
@require_admin
def api_lab_build():
    payload = request.get_json(silent=True) or {}

    def _log_build(data):
        nodes = payload.get('nodes') if isinstance(payload, dict) else None
        links = payload.get('links') if isinstance(payload, dict) else None
        extra = {
            'accepted': bool(data.get('accepted') or data.get('queued') or data.get('ok')),
            'busy': bool(data.get('busy')),
            'nodes': len(nodes) if isinstance(nodes, list) else None,
            'links': len(links) if isinstance(links, list) else None,
        }
        _call_append_event('lab_build', src=str(session.get('user') or ''), extra=extra)

    return _call_proxy_runner('POST', '/build', json_data=payload, timeout=60, op='lab_build', on_success=_log_build)


@lab_proxy_bp.post('/api/lab/topology/apply')
@require_admin
def api_lab_topology_apply():
    payload = request.get_json(silent=True) or {}

    def _log_apply(data):
        nodes = payload.get('nodes') if isinstance(payload, dict) else None
        links = payload.get('links') if isinstance(payload, dict) else None
        extra = {
            'accepted': bool(data.get('accepted') or data.get('queued') or data.get('ok')),
            'busy': bool(data.get('busy')),
            'nodes': len(nodes) if isinstance(nodes, list) else None,
            'links': len(links) if isinstance(links, list) else None,
        }
        _call_append_event('lab_apply', src=str(session.get('user') or ''), extra=extra)

    return _call_proxy_runner('POST', '/topology/apply', json_data=payload, timeout=60, op='lab_topology_apply', on_success=_log_apply)


@lab_proxy_bp.post('/api/lab/stop')
@require_admin
def api_lab_stop():
    def _log_stop(data):
        _call_append_event(
            'lab_stop',
            src=str(session.get('user') or ''),
            extra={'accepted': bool(data.get('accepted') or data.get('queued') or data.get('ok')), 'busy': bool(data.get('busy'))},
        )

    return _call_proxy_runner('POST', '/stop', timeout=20, op='lab_stop', on_success=_log_stop)


@lab_proxy_bp.post('/api/lab/link/update')
@require_admin
def api_lab_link_update():
    payload = request.get_json(silent=True) or {}
    return _call_proxy_runner('POST', '/link/update', json_data=payload, timeout=5, op='lab_link_update')


@lab_proxy_bp.post('/api/lab/scenario')
@require_admin
def api_lab_scenario():
    raw_payload = request.get_json(silent=True) or {}
    payload = _inject_ryu_preflight(raw_payload)

    def _log_scenario(_data):
        extra = {
            'name': raw_payload.get('name') if isinstance(raw_payload, dict) else None,
            'proto': raw_payload.get('proto') if isinstance(raw_payload, dict) else None,
            'duration': raw_payload.get('duration') if isinstance(raw_payload, dict) else None,
            'capture': bool(raw_payload.get('capture')) if isinstance(raw_payload, dict) else None,
            'attackers': raw_payload.get('attackers') if isinstance(raw_payload, dict) else None,
            'victim': raw_payload.get('victim') if isinstance(raw_payload, dict) else None,
        }
        _call_append_event('scenario', src=str(session.get('user') or ''), extra=extra)

    return _call_proxy_runner('POST', '/scenario', json_data=payload, timeout=35, op='lab_scenario', on_success=_log_scenario)


@lab_proxy_bp.get('/api/lab/ovs/flows')
def api_lab_ovs_flows():
    return _call_proxy_runner('GET', '/ovs/flows', timeout=5, op='lab_ovs_flows')


@lab_proxy_bp.get('/api/lab/attack/status')
def api_lab_attack_status():
    return _call_proxy_runner('GET', '/attack/status', timeout=15, op='lab_attack_status')


@lab_proxy_bp.post('/api/lab/attack/run')
@require_admin
def api_lab_attack_run():
    raw_payload = request.get_json(silent=True) or {}
    payload = _inject_ryu_preflight(raw_payload)

    def _log_attack_run(_data):
        extra = {
            'kind': raw_payload.get('kind') if isinstance(raw_payload, dict) else None,
            'profile': raw_payload.get('profile') if isinstance(raw_payload, dict) else None,
            'proto': raw_payload.get('proto') if isinstance(raw_payload, dict) else None,
            'duration': raw_payload.get('duration') if isinstance(raw_payload, dict) else None,
            'mixed': bool(raw_payload.get('mixed')) if isinstance(raw_payload, dict) else None,
            'capture': bool(raw_payload.get('capture')) if isinstance(raw_payload, dict) else None,
        }
        _call_append_event('attack_run', src=str(session.get('user') or ''), extra=extra)

    return _call_proxy_runner('POST', '/attack/run', json_data=payload, timeout=25, op='lab_attack_run', on_success=_log_attack_run)


@lab_proxy_bp.post('/api/lab/attack/stop')
@require_admin
def api_lab_attack_stop():
    def _after_stop(data):
        try:
            _call_ryu_post('/dos/reset', timeout=2)
        except Exception as e_reset:
            _log_backend_exception('attack_stop_dos_reset', e_reset, level='warning')
        _call_append_event(
            'attack_stop',
            src=str(session.get('user') or ''),
            extra={'ok': bool(data.get('ok')), 'running': bool(data.get('running'))},
        )

    return _call_proxy_runner('POST', '/attack/stop', timeout=15, op='lab_attack_stop', on_success=_after_stop)


@lab_proxy_bp.get('/api/lab/pcap/list')
def api_lab_pcap_list():
    return _call_proxy_runner('GET', '/pcap/list', timeout=10, op='lab_pcap_list')


@lab_proxy_bp.get('/api/lab/pcap/download/<name>')
def api_lab_pcap_download(name: str):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:pcap|pcapng|cap)', name or '') or '..' in name:
        return _error_json('invalid_pcap_name', status=400)
    try:
        r = _call_runner_get(f"/pcap/download/{name}", timeout=10, stream=True)
        if r.status_code != 200:
            return _forward_runner_response(r, op='lab_pcap_download')
        headers = {}
        ct = r.headers.get('content-type') or 'application/octet-stream'
        cd = r.headers.get('content-disposition')
        if cd:
            headers['Content-Disposition'] = cd
        return Response(r.iter_content(chunk_size=8192), content_type=ct, headers=headers)
    except Exception as e:
        return _handle_backend_exception('lab_pcap_download', e, upstream='runner')


@lab_proxy_bp.post('/api/lab/pcap/pin/<name>')
@require_admin
def api_lab_pcap_pin(name: str):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:pcap|pcapng|cap)', name or '') or '..' in name:
        return _error_json('invalid_pcap_name', status=400)
    return _call_proxy_runner('POST', f'/pcap/pin/{name}', timeout=5, op='lab_pcap_pin')


@lab_proxy_bp.post('/api/lab/pcap/unpin/<name>')
@require_admin
def api_lab_pcap_unpin(name: str):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:pcap|pcapng|cap)', name or '') or '..' in name:
        return _error_json('invalid_pcap_name', status=400)
    return _call_proxy_runner('POST', f'/pcap/unpin/{name}', timeout=5, op='lab_pcap_unpin')


@lab_proxy_bp.delete('/api/lab/pcap/delete/<name>')
@require_admin
def api_lab_pcap_delete(name: str):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:pcap|pcapng|cap)', name or '') or '..' in name:
        return _error_json('invalid_pcap_name', status=400)
    return _call_proxy_runner('DELETE', f'/pcap/delete/{name}', timeout=5, op='lab_pcap_delete')


@lab_proxy_bp.get('/api/lab/pcap/storage')
def api_lab_pcap_storage():
    return _call_proxy_runner('GET', '/pcap/storage', timeout=5, op='lab_pcap_storage')


@lab_proxy_bp.get('/api/lab/ha/status')
def api_lab_ha_status():
    return _call_proxy_runner('GET', '/ha/status', timeout=10, op='lab_ha_status')


@lab_proxy_bp.post('/api/lab/ha/config')
@require_admin
def api_lab_ha_config():
    payload = request.get_json(silent=True) or {}
    return _call_proxy_runner('POST', '/ha/config', json_data=payload, timeout=5, op='lab_ha_config')


@lab_proxy_bp.post('/api/lab/ha/active')
@require_admin
def api_lab_ha_active():
    payload = request.get_json(silent=True) or {}
    active_val = str(payload.get('active') or '').strip().lower() if isinstance(payload, dict) else ''
    if active_val not in VALID_HA_TARGETS:
        return _error_json('active_must_be_primary_or_backup', status=400)

    def _log_ha_active(_data):
        _call_append_event(
            'ha_active',
            src=str(session.get('user') or 'manual'),
            reason='manual_ui',
            extra={'active': active_val, 'source': 'manual_ui'},
        )

    with _failover_execution_lock:
        return _call_proxy_runner('POST', '/ha/active', json_data=payload, timeout=15, op='lab_ha_active', on_success=_log_ha_active)


@lab_proxy_bp.post('/api/lab/ha/service/start')
@require_admin
def api_lab_ha_service_start():
    def _log_ha_start(data):
        _call_append_event('ha_service_start', src=str(session.get('user') or ''), extra={'ok': bool(data.get('ok'))})

    return _call_proxy_runner('POST', '/ha/service/start', timeout=10, op='lab_ha_service_start', on_success=_log_ha_start)


@lab_proxy_bp.post('/api/lab/ha/service/stop')
@require_admin
def api_lab_ha_service_stop():
    def _log_ha_stop(data):
        _call_append_event('ha_service_stop', src=str(session.get('user') or ''), extra={'ok': bool(data.get('ok'))})

    return _call_proxy_runner('POST', '/ha/service/stop', timeout=10, op='lab_ha_service_stop', on_success=_log_ha_stop)


@lab_proxy_bp.get('/api/lab/ha/test')
def api_lab_ha_test():
    return _call_proxy_runner('GET', '/ha/test', timeout=10, op='lab_ha_test')


@lab_proxy_bp.get('/api/lab/ha/failover/status')
def api_lab_ha_failover_status():
    with _failover_states_lock:
        history_list = [dict(r) for r in _failover_history]
        active_states = {k: dict(v) for k, v in _failover_states.items() if v.get('state') in ('received', 'pending', 'retrying')}
        last_fo = history_list[-1] if history_list else None
    return jsonify({
        'ok': True,
        'active_in_flight': len(active_states),
        'last_failover': last_fo,
        'history': history_list[-20:],
    })


@lab_proxy_bp.post('/api/lab/cmd/run')
@require_admin
def api_lab_cmd_run():
    payload = request.get_json(silent=True) or {}
    return _call_proxy_runner('POST', '/cmd/run', json_data=payload, timeout=15, op='lab_cmd_run')
