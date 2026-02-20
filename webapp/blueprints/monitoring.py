"""Monitoring and Metrics Blueprint.

Handles metrics, settings, VM system stats via Glances with circuit breaker, and alerts snapshot.
Routes:
- GET  /api/settings -> api_get_settings()
- POST /api/settings -> api_set_settings()
- GET  /api/metrics -> api_metrics()
- GET  /api/vm/metrics -> api_vm_metrics()
- GET  /api/vm/proc -> api_vm_proc()
- GET  /api/alerts -> api_alerts()
"""

import copy
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Blueprint, jsonify, request

from webapp.core import (
    GLANCES_API_BASE,
    GLANCES_CACHE_TTL_SEC,
    GLANCES_TIMEOUT_SEC,
    GLANCES_CB_FAIL_THRESHOLD,
    GLANCES_CB_COOLDOWN_SEC,
    RYU_API_BASE,
)
from webapp.core.security import (
    _error_json,
    _validate_service_url,
    _current_request_id,
    _classify_backend_exception,
    _log_backend_exception,
    require_admin,
)
from webapp.core.alerts_sync import (
    _safe_request,
    _get_service_health,
    _alerts_snapshot,
    _snapshot_lock,
    _health_lock,
    _service_health,
)

monitoring_bp = Blueprint('monitoring', __name__)

_GLANCES_EXECUTOR = ThreadPoolExecutor(max_workers=4)

_glances_cb_lock = threading.Lock()
_glances_cb_state: str = 'closed'
_glances_cb_fail_count: int = 0
_glances_cb_open_until: float = 0.0
_glances_cb_half_open_probe: bool = False
_glances_cb_last_error: Optional[str] = None
_glances_cb_last_check: float = 0.0


def _new_glances_cache_entry() -> Dict[str, Any]:
    return {
        'data': None,
        'ts': 0.0,
        'base': '',
        'refreshing': False,
        'gen': 0,
        'last_attempt_ok': False,
        'last_attempt_err': None,
        'last_attempt_base': '',
        'cond': threading.Condition(),
    }


_glances_caches: Dict[str, Dict[str, Any]] = {
    'vm_metrics': _new_glances_cache_entry(),
    'vm_proc': _new_glances_cache_entry(),
}


def _get_glances_api_base() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'GLANCES_API_BASE'):
        return str(srv.GLANCES_API_BASE or '')
    return str(GLANCES_API_BASE or '')


def _get_ryu_api_base() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'RYU_API_BASE'):
        return str(srv.RYU_API_BASE or '')
    return str(RYU_API_BASE or '')


def _set_ryu_api_base(new_val: str) -> None:
    srv = sys.modules.get('webapp.server')
    if srv:
        srv.RYU_API_BASE = new_val


def _call_safe_request(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_safe_request'):
        return srv._safe_request(*args, **kwargs)
    return _safe_request(*args, **kwargs)


def _get_glances_cache_ttl_sec() -> float:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'GLANCES_CACHE_TTL_SEC'):
        try:
            return max(0.0, float(srv.GLANCES_CACHE_TTL_SEC))
        except Exception:
            pass
    return max(0.0, float(GLANCES_CACHE_TTL_SEC))


def _get_glances_timeout_sec() -> float:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'GLANCES_TIMEOUT_SEC'):
        try:
            return max(0.2, float(srv.GLANCES_TIMEOUT_SEC))
        except Exception:
            pass
    return max(0.2, float(GLANCES_TIMEOUT_SEC))


def _get_glances_cb_fail_threshold() -> int:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'GLANCES_CB_FAIL_THRESHOLD'):
        try:
            return max(1, int(srv.GLANCES_CB_FAIL_THRESHOLD))
        except Exception:
            pass
    return max(1, int(GLANCES_CB_FAIL_THRESHOLD))


def _get_glances_cb_cooldown_sec() -> float:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'GLANCES_CB_COOLDOWN_SEC'):
        try:
            return max(0.05, float(srv.GLANCES_CB_COOLDOWN_SEC))
        except Exception:
            pass
    return max(0.05, float(GLANCES_CB_COOLDOWN_SEC))


def _get_glances_cb_open_until() -> float:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_glances_cb_open_until'):
        try:
            return float(srv._glances_cb_open_until)
        except Exception:
            pass
    return float(_glances_cb_open_until)


def _set_glances_cb_open_until(val: float) -> None:
    global _glances_cb_open_until
    _glances_cb_open_until = float(val)
    srv = sys.modules.get('webapp.server')
    if srv:
        srv._glances_cb_open_until = float(val)


def _glances_cb_snapshot_unlocked(now: Optional[float] = None) -> Dict[str, Any]:
    cur = time.time() if now is None else float(now)
    rem = 0.0
    effective_state = _glances_cb_state
    open_until = _get_glances_cb_open_until()
    if _glances_cb_state == 'open':
        if cur >= open_until:
            effective_state = 'half_open'
        else:
            rem = max(0.0, open_until - cur)
    return {
        'state': effective_state,
        'fail_count': int(_glances_cb_fail_count),
        'cooldown_remaining_sec': round(rem, 3),
        'last_error': _glances_cb_last_error,
        'last_check': float(_glances_cb_last_check),
    }


def _glances_cb_snapshot() -> Dict[str, Any]:
    with _glances_cb_lock:
        return _glances_cb_snapshot_unlocked()


def _sync_glances_service_health(cb_snap: Dict[str, Any]) -> None:
    st = str(cb_snap.get('state') or 'closed')
    healthy = (st == 'closed') and (cb_snap.get('last_error') is None)
    with _health_lock:
        _service_health['glances'] = {
            'healthy': healthy,
            'last_check': float(cb_snap.get('last_check') or time.time()),
            'error': cb_snap.get('last_error'),
            'state': st,
            'fail_count': int(cb_snap.get('fail_count') or 0),
            'cooldown_remaining_sec': float(cb_snap.get('cooldown_remaining_sec') or 0.0),
        }


def _glances_cb_acquire():
    global _glances_cb_state, _glances_cb_half_open_probe
    with _glances_cb_lock:
        now = time.time()
        if _glances_cb_state == 'closed':
            return True, False, _glances_cb_snapshot_unlocked(now)
        if _glances_cb_state == 'open':
            if now < _get_glances_cb_open_until():
                return False, False, _glances_cb_snapshot_unlocked(now)
            _glances_cb_state = 'half_open'
            _glances_cb_half_open_probe = True
            return True, True, _glances_cb_snapshot_unlocked(now)
        if not _glances_cb_half_open_probe:
            _glances_cb_half_open_probe = True
            return True, True, _glances_cb_snapshot_unlocked(now)
        return False, False, _glances_cb_snapshot_unlocked(now)


def _glances_cb_release(ok: bool, err_code: Optional[str], is_probe: bool) -> Dict[str, Any]:
    global _glances_cb_state, _glances_cb_fail_count, _glances_cb_half_open_probe, _glances_cb_last_error, _glances_cb_last_check
    with _glances_cb_lock:
        now = time.time()
        _glances_cb_last_check = now
        if ok:
            _glances_cb_state = 'closed'
            _glances_cb_fail_count = 0
            _set_glances_cb_open_until(0.0)
            _glances_cb_half_open_probe = False
            _glances_cb_last_error = None
        else:
            _glances_cb_last_error = str(err_code or 'glances_error')
            if is_probe:
                _glances_cb_state = 'open'
                _set_glances_cb_open_until(now + _get_glances_cb_cooldown_sec())
                _glances_cb_half_open_probe = False
            else:
                _glances_cb_fail_count += 1
                if _glances_cb_fail_count >= _get_glances_cb_fail_threshold():
                    _glances_cb_state = 'open'
                    _set_glances_cb_open_until(now + _get_glances_cb_cooldown_sec())
        snap = _glances_cb_snapshot_unlocked(now)
    _sync_glances_service_health(snap)
    return snap


def _reset_glances_state_for_tests() -> None:
    global _glances_cb_state, _glances_cb_fail_count, _glances_cb_half_open_probe, _glances_cb_last_error, _glances_cb_last_check
    with _glances_cb_lock:
        _glances_cb_state = 'closed'
        _glances_cb_fail_count = 0
        _set_glances_cb_open_until(0.0)
        _glances_cb_half_open_probe = False
        _glances_cb_last_error = None
        _glances_cb_last_check = 0.0
    for key in list(_glances_caches.keys()):
        ent = _glances_caches[key]
        with ent['cond']:
            ent['data'] = None
            ent['ts'] = 0.0
            ent['base'] = ''
            ent['refreshing'] = False
            ent['gen'] = 0
            ent['last_attempt_ok'] = False
            ent['last_attempt_err'] = None
            ent['last_attempt_base'] = ''
            ent['cond'].notify_all()
    with _health_lock:
        _service_health['glances'] = {
            'healthy': True,
            'last_check': 0.0,
            'error': None,
            'state': 'closed',
            'fail_count': 0,
            'cooldown_remaining_sec': 0.0,
        }


def _glances_fresh_payload(data: Dict[str, Any], ts_val: float, cb_state: str, cached: bool) -> Dict[str, Any]:
    out = copy.deepcopy(data)
    age = max(0.0, time.time() - float(ts_val))
    out['cached'] = bool(cached)
    out['stale'] = False
    out['fetched_at'] = float(ts_val)
    out['age_sec'] = round(age, 3)
    out['service_state'] = str(cb_state or 'closed')
    return out


def _glances_error_payload(entry: Dict[str, Any], base: str, err_code: str, cb_snap: Dict[str, Any]) -> Dict[str, Any]:
    cb_state = str(cb_snap.get('state') or 'closed')
    resp: Dict[str, Any] = {
        'ok': False,
        'error': str(err_code or 'glances_error'),
        'service_unhealthy': True,
        'service_state': cb_state,
        'circuit_open': (cb_state == 'open'),
        'cooldown_remaining_sec': float(cb_snap.get('cooldown_remaining_sec') or 0.0),
        'stale': False,
        'stale_available': False,
    }
    rid = _current_request_id()
    if rid:
        resp['request_id'] = rid
    if entry.get('data') is not None and entry.get('base') == base:
        last_ts = float(entry.get('ts') or 0.0)
        age = max(0.0, time.time() - last_ts) if last_ts > 0.0 else None
        resp.update({
            'stale_available': True,
            'last_good_ts': last_ts,
            'age_sec': round(age, 3) if age is not None else None,
            'last_good': copy.deepcopy(entry['data']),
        })
    return resp


def _fetch_glances_cached(cache_key: str, base: str, fetcher_fn):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_fetch_glances_cached') and srv._fetch_glances_cached != _fetch_glances_cached:
        return srv._fetch_glances_cached(cache_key, base, fetcher_fn)

    entry = _glances_caches[cache_key]
    cond = entry['cond']
    ttl = _get_glances_cache_ttl_sec()
    timeout = _get_glances_timeout_sec()
    now = time.time()

    with cond:
        if (
            entry['data'] is not None
            and entry['base'] == base
            and ttl > 0.0
            and (now - float(entry['ts'])) < ttl
        ):
            snap_cb = _glances_cb_snapshot()
            return 200, _glances_fresh_payload(entry['data'], entry['ts'], snap_cb['state'], cached=True)

        if entry['refreshing']:
            my_gen = int(entry['gen'])
            cond.wait(timeout=timeout + 1.0)
            if int(entry['gen']) != my_gen:
                if entry['last_attempt_ok'] and entry['data'] is not None and entry['base'] == base:
                    snap_cb = _glances_cb_snapshot()
                    return 200, _glances_fresh_payload(entry['data'], entry['ts'], snap_cb['state'], cached=True)
                if not entry['last_attempt_ok'] and entry['last_attempt_base'] == base:
                    snap_cb = _glances_cb_snapshot()
                    return 502, _glances_error_payload(entry, base, entry['last_attempt_err'] or 'glances_error', snap_cb)
            if entry['refreshing']:
                snap_cb = _glances_cb_snapshot()
                return 502, _glances_error_payload(entry, base, 'refresh_timeout', snap_cb)

        now2 = time.time()
        if (
            entry['data'] is not None
            and entry['base'] == base
            and ttl > 0.0
            and (now2 - float(entry['ts'])) < ttl
        ):
            snap_cb = _glances_cb_snapshot()
            return 200, _glances_fresh_payload(entry['data'], entry['ts'], snap_cb['state'], cached=True)

        entry['refreshing'] = True

    ok = False
    err_code = 'glances_error'
    fresh_data = None
    allowed = False
    is_probe = False
    probe_settled = False
    try:
        allowed, is_probe, cb_snap = _glances_cb_acquire()
        if not allowed:
            err_code = 'circuit_open' if cb_snap.get('state') == 'open' else 'half_open_probe_busy'
            _sync_glances_service_health(cb_snap)
            with cond:
                entry['last_attempt_ok'] = False
                entry['last_attempt_err'] = err_code
                entry['last_attempt_base'] = base
                err_resp = _glances_error_payload(entry, base, err_code, cb_snap)
            return 502, err_resp

        try:
            fresh_data = fetcher_fn(timeout)
            ok = True
        except requests.exceptions.Timeout:
            err_code = 'timeout'
        except requests.exceptions.ConnectionError:
            err_code = 'connection_refused'
        except requests.exceptions.HTTPError as e:
            err_code = 'upstream_http_error'
            _log_backend_exception('glances_fetch', e, level='warning', error_code=err_code)
        except Exception as e:
            err_code, _, _ = _classify_backend_exception(e, upstream='glances')
            _log_backend_exception('glances_fetch', e, level='warning', error_code=err_code)

        cb_snap = _glances_cb_release(ok, None if ok else err_code, is_probe)
        probe_settled = True
        now_done = time.time()
        with cond:
            if ok and isinstance(fresh_data, dict):
                entry['data'] = fresh_data
                entry['ts'] = now_done
                entry['base'] = base
                entry['last_attempt_ok'] = True
                entry['last_attempt_err'] = None
                entry['last_attempt_base'] = base
                payload = _glances_fresh_payload(fresh_data, now_done, cb_snap['state'], cached=False)
                return 200, payload
            entry['last_attempt_ok'] = False
            entry['last_attempt_err'] = err_code
            entry['last_attempt_base'] = base
            err_resp = _glances_error_payload(entry, base, err_code, cb_snap)
            return 502, err_resp
    finally:
        if allowed and is_probe and not probe_settled:
            _glances_cb_release(False, 'internal_error', True)
        with cond:
            entry['refreshing'] = False
            entry['gen'] = int(entry['gen']) + 1
            cond.notify_all()


def _first_or_self(v):
    if isinstance(v, list):
        return v[0] if v else {}
    return v if isinstance(v, dict) else {}


def _glances_get_json(url: str, timeout: float):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _fetch_vm_metrics_live(base: str, timeout: float) -> Dict[str, Any]:
    t_lim = max(0.2, float(timeout))
    deadline = time.monotonic() + t_lim
    f_quick = _GLANCES_EXECUTOR.submit(_glances_get_json, f"{base}/api/3/quicklook", t_lim)
    f_load = _GLANCES_EXECUTOR.submit(_glances_get_json, f"{base}/api/3/load", t_lim)
    f_fs = _GLANCES_EXECUTOR.submit(_glances_get_json, f"{base}/api/3/fs", t_lim)
    f_net = _GLANCES_EXECUTOR.submit(_glances_get_json, f"{base}/api/3/network", t_lim)

    try:
        quick_raw = f_quick.result(timeout=max(0.2, deadline - time.monotonic()))
        quick = _first_or_self(quick_raw)
    except Exception:
        for fut in (f_load, f_fs, f_net):
            fut.cancel()
        raise

    load = {}
    try:
        load_raw = f_load.result(timeout=max(0.05, deadline - time.monotonic()))
        load = _first_or_self(load_raw)
    except Exception:
        load = {}

    fs = []
    try:
        fs_raw = f_fs.result(timeout=max(0.05, deadline - time.monotonic()))
        fs = fs_raw if isinstance(fs_raw, list) else []
    except Exception:
        fs = []

    net = []
    try:
        net_raw = f_net.result(timeout=max(0.05, deadline - time.monotonic()))
        net = net_raw if isinstance(net_raw, list) else []
    except Exception:
        net = []

    total_disk = 0.0
    used_disk = 0.0
    for it in (fs or []):
        try:
            total_disk += float(it.get('size', 0) or 0)
            used_disk += float(it.get('used', 0) or 0)
        except Exception:
            pass

    rx_rate = 0.0
    tx_rate = 0.0
    rx_total = 0.0
    tx_total = 0.0
    for it in (net or []):
        try:
            rx_total += float(it.get('rx', 0) or 0)
            tx_total += float(it.get('tx', 0) or 0)
        except Exception:
            pass
        try:
            rx_rate += float(it.get('rx_rate', 0) or 0)
            tx_rate += float(it.get('tx_rate', 0) or 0)
        except Exception:
            pass

    cpu = quick.get('cpu')
    mem = quick.get('mem')
    return {
        'ok': True,
        'cpu_percent': cpu,
        'mem_percent': mem,
        'load': {
            'min1': load.get('min1') or load.get('load1') or load.get('cpuload') or load.get('1') or None,
            'min5': load.get('min5') or load.get('load5') or load.get('5') or None,
            'min15': load.get('min15') or load.get('load15') or load.get('15') or None,
        },
        'disk': {
            'total': total_disk,
            'used': used_disk,
            'percent': (used_disk * 100.0 / total_disk) if total_disk else None,
        },
        'network': {
            'rx_total': rx_total,
            'tx_total': tx_total,
            'rx_rate': rx_rate,
            'tx_rate': tx_rate,
        },
    }


def _proc_mem_mb(p: dict) -> float:
    if not isinstance(p, dict):
        return 0.0
    mi = p.get('memory_info')
    if isinstance(mi, dict):
        try:
            rss = float(mi.get('rss') or 0)
            return rss / (1024.0 * 1024.0)
        except Exception:
            return 0.0
    if isinstance(mi, (list, tuple)) and mi:
        try:
            rss = float(mi[0] or 0)
            return rss / (1024.0 * 1024.0)
        except Exception:
            return 0.0
    try:
        return float(p.get('memory_mb') or 0.0)
    except Exception:
        return 0.0


def _proc_cpu(p: dict) -> float:
    if not isinstance(p, dict):
        return 0.0
    for k in ('cpu_percent', 'cpu', 'cpu%'):
        if k in p:
            try:
                return float(p.get(k) or 0.0)
            except Exception:
                return 0.0
    return 0.0


def _proc_threads(p: dict) -> int:
    if not isinstance(p, dict):
        return 0
    for k in ('num_threads', 'threads'):
        if k in p:
            try:
                return int(p.get(k) or 0)
            except Exception:
                return 0
    return 0


def _fetch_vm_proc_live(base: str, timeout: float) -> Dict[str, Any]:
    r = requests.get(f"{base}/api/3/processlist", timeout=timeout)
    r.raise_for_status()
    pl = r.json()

    items = []
    if isinstance(pl, dict):
        v = pl.get('processlist')
        if isinstance(v, list):
            items = v
        elif isinstance(v, dict):
            for vv in v.values():
                if isinstance(vv, list):
                    items.extend(vv)
        else:
            items = []
    elif isinstance(pl, list):
        items = pl

    def _name(p: dict) -> str:
        if not isinstance(p, dict):
            return ''
        return str(p.get('name') or p.get('cmdline') or p.get('command') or '').lower()

    ryu_procs = [p for p in items if 'ryu' in _name(p) or 'ryu-manager' in _name(p)]
    ovs_procs = [p for p in items if 'ovs-vswitchd' in _name(p) or 'ovsdb-server' in _name(p) or (_name(p).startswith('ovs') and 'ovs' in _name(p))]

    def _agg(ps: list) -> dict:
        cpu = 0.0
        mem = 0.0
        th = 0
        for p in ps:
            cpu += _proc_cpu(p)
            mem += _proc_mem_mb(p)
            th += _proc_threads(p)
        return {'count': len(ps), 'cpu_percent': round(cpu, 2), 'mem_mb': round(mem, 2), 'threads': th}

    return {
        'ok': True,
        'ryu': _agg(ryu_procs),
        'ovs': _agg(ovs_procs),
    }


@monitoring_bp.get('/api/settings')
def api_get_settings():
    return jsonify({'ryu_api_base': _get_ryu_api_base()})


@monitoring_bp.post('/api/settings')
@require_admin
def api_set_settings():
    data = request.get_json(silent=True) or {}
    validated = _validate_service_url(data.get('ryu_api_base'))
    if not validated:
        return jsonify({'ok': False, 'error': 'invalid_ryu_api_base'}), 400
    _set_ryu_api_base(validated)
    return jsonify({'ok': True, 'ryu_api_base': _get_ryu_api_base()})


@monitoring_bp.get('/api/metrics')
def api_metrics():
    ryu_base = _get_ryu_api_base()
    r = _call_safe_request(f"{ryu_base}/dos/metrics", method='GET', timeout=2.0, service_name='ryu')
    if r and r.ok:
        try:
            return jsonify(r.json())
        except Exception:
            pass
    health = _get_service_health('ryu')
    return _error_json(
        health.get('error') or 'service_unavailable',
        'Controller metrics service is unavailable.',
        status=502,
        extra={'service_unhealthy': True},
    )


@monitoring_bp.get('/api/vm/metrics')
def api_vm_metrics():
    base = (_get_glances_api_base() or '').rstrip('/')
    if not base:
        return jsonify({'ok': False, 'error': 'glances_api_base_empty'}), 500

    srv = sys.modules.get('webapp.server')
    fetch_live = srv._fetch_vm_metrics_live if (srv and hasattr(srv, '_fetch_vm_metrics_live')) else _fetch_vm_metrics_live
    status, body = _fetch_glances_cached(
        'vm_metrics',
        base,
        lambda t: fetch_live(base, t),
    )
    return jsonify(body), status


@monitoring_bp.get('/api/vm/proc')
def api_vm_proc():
    base = (_get_glances_api_base() or '').rstrip('/')
    if not base:
        return jsonify({'ok': False, 'error': 'glances_api_base_empty'}), 500

    srv = sys.modules.get('webapp.server')
    fetch_live = srv._fetch_vm_proc_live if (srv and hasattr(srv, '_fetch_vm_proc_live')) else _fetch_vm_proc_live
    status, body = _fetch_glances_cached(
        'vm_proc',
        base,
        lambda t: fetch_live(base, t),
    )
    return jsonify(body), status


@monitoring_bp.get('/api/alerts')
def api_alerts():
    with _snapshot_lock:
        alerts_list = list(_alerts_snapshot.get('alerts') or [])
        snapshot_ts = float(_alerts_snapshot.get('ts') or 0.0)
        status_str = str(_alerts_snapshot.get('status') or 'initializing')
        boot_id = _alerts_snapshot.get('boot_id')
        last_seq = _alerts_snapshot.get('last_seq')
        failures = int(_alerts_snapshot.get('consecutive_failures') or 0)

    if not alerts_list and status_str != 'ok':
        health = _get_service_health('ryu')
        return _error_json(
            health.get('error') or 'service_unavailable',
            'Controller alerts service is unavailable.',
            status=502,
            extra={'service_unhealthy': True},
        )

    resp = jsonify(alerts_list)
    resp.headers['X-Snapshot-Status'] = status_str
    resp.headers['X-Snapshot-Age'] = f"{max(0.0, time.time() - snapshot_ts):.3f}"
    if boot_id:
        resp.headers['X-Ryu-Boot-ID'] = str(boot_id)
    if last_seq is not None:
        resp.headers['X-Ryu-Last-Seq'] = str(last_seq)
    if failures > 0:
        resp.headers['X-Snapshot-Failures'] = str(failures)
    return resp
