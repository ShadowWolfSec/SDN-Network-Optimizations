"""Alerts background worker, in-memory snapshot, CSV archiving, failover coordination,
and OS flock-based leader election across multiple WSGI workers.
"""

import os
import sys
import time
import json
import csv
import re
import random
import logging
import threading
from collections import deque
from typing import Optional, Dict, Any, Tuple, Set, List

from flask import current_app
import requests

from webapp.core.security import _to_int, _internal_headers

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
RUN_DIR = os.path.join(_PROJECT_ROOT, '.run')
LOG_DIR = os.path.join(_PROJECT_ROOT, 'logs')
EVENTS_LOG_FILE = os.path.join(LOG_DIR, 'events.csv')
os.makedirs(RUN_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


def current_log_dir() -> str:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, 'LOG_DIR'):
        return getattr(m, 'LOG_DIR')
    return LOG_DIR


def current_events_log_file() -> str:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, 'EVENTS_LOG_FILE'):
        return getattr(m, 'EVENTS_LOG_FILE')
    return EVENTS_LOG_FILE


def current_run_dir() -> str:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, 'RUN_DIR'):
        return getattr(m, 'RUN_DIR')
    return RUN_DIR


def current_ryu_api_base() -> str:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, 'RYU_API_BASE'):
        return getattr(m, 'RYU_API_BASE')
    return os.getenv('RYU_API_BASE', 'http://127.0.0.1:8080')


def current_runner_base() -> str:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, 'MININET_RUNNER_BASE'):
        return getattr(m, 'MININET_RUNNER_BASE')
    return os.getenv('MININET_RUNNER_BASE', 'http://127.0.0.1:9090')


def _get_logger():
    try:
        if current_app:
            return current_app.logger
    except Exception:
        pass
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, 'app') and hasattr(getattr(m, 'app'), 'logger'):
        return getattr(m, 'app').logger
    return logging.getLogger('webapp.alerts_sync')


# Event tracking state
_events_last_ts = 0.0
_events_ts_initialized = False
_events_lock = threading.Lock()
_events_last_cleanup_day = ''

# F-19: Snapshot state for pure-read GET /api/alerts
_alerts_snapshot: Dict[str, Any] = {
    'alerts': [],
    'ts': 0.0,
    'status': 'initializing',  # 'initializing', 'ok', 'degraded', 'stale'
    'boot_id': None,
    'last_seq': None,
    'consecutive_failures': 0,
    'last_error': None,
}
_snapshot_lock = threading.Lock()

# F-19: Deduplication and sequence tracking state
_seen_alert_ids_set: Set[str] = set()
_seen_alert_ids_deque: deque = deque(maxlen=2000)
_seen_ids_lock = threading.Lock()
_last_seen_boot_id: Optional[str] = None
_last_seen_seq: Optional[int] = None

# F-19: Worker lifecycle controls
ALERTS_SYNC_INTERVAL_SEC = float(os.getenv('SDN_ALERTS_SYNC_INTERVAL', '2.0') or 2.0)
_alerts_sync_thread: Optional[threading.Thread] = None
_alerts_sync_stop_event = threading.Event()
_alerts_sync_started = False
_alerts_sync_lifecycle_lock = threading.Lock()
_leader_lock_fd: Optional[int] = None
_is_sync_leader = False


def _get_last_seen_boot_id() -> Optional[str]:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_last_seen_boot_id'):
        return getattr(m, '_last_seen_boot_id')
    return _last_seen_boot_id


def _set_last_seen_boot_id(val: Optional[str]):
    global _last_seen_boot_id
    _last_seen_boot_id = val
    m = sys.modules.get('webapp.server')
    if m is not None:
        setattr(m, '_last_seen_boot_id', val)


def _get_last_seen_seq() -> Optional[int]:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_last_seen_seq'):
        return getattr(m, '_last_seen_seq')
    return _last_seen_seq


def _set_last_seen_seq(val: Optional[int]):
    global _last_seen_seq
    _last_seen_seq = val
    m = sys.modules.get('webapp.server')
    if m is not None:
        setattr(m, '_last_seen_seq', val)


def _get_alerts_sync_started() -> bool:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_alerts_sync_started'):
        return getattr(m, '_alerts_sync_started')
    return _alerts_sync_started


def _set_alerts_sync_started(val: bool):
    global _alerts_sync_started
    _alerts_sync_started = val
    m = sys.modules.get('webapp.server')
    if m is not None:
        setattr(m, '_alerts_sync_started', val)


def _get_alerts_sync_thread() -> Optional[threading.Thread]:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_alerts_sync_thread'):
        return getattr(m, '_alerts_sync_thread')
    return _alerts_sync_thread


def _set_alerts_sync_thread(val: Optional[threading.Thread]):
    global _alerts_sync_thread
    _alerts_sync_thread = val
    m = sys.modules.get('webapp.server')
    if m is not None:
        setattr(m, '_alerts_sync_thread', val)


def _get_events_last_ts() -> float:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_events_last_ts'):
        return getattr(m, '_events_last_ts')
    return _events_last_ts


def _set_events_last_ts(val: float):
    global _events_last_ts
    _events_last_ts = val
    m = sys.modules.get('webapp.server')
    if m is not None:
        setattr(m, '_events_last_ts', val)


def _get_events_ts_initialized() -> bool:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_events_ts_initialized'):
        return getattr(m, '_events_ts_initialized')
    return _events_ts_initialized


def _set_events_ts_initialized(val: bool):
    global _events_ts_initialized
    _events_ts_initialized = val
    m = sys.modules.get('webapp.server')
    if m is not None:
        setattr(m, '_events_ts_initialized', val)


def _get_events_last_cleanup_day() -> str:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_events_last_cleanup_day'):
        return getattr(m, '_events_last_cleanup_day')
    return _events_last_cleanup_day


def _set_events_last_cleanup_day(val: str):
    global _events_last_cleanup_day
    _events_last_cleanup_day = val
    m = sys.modules.get('webapp.server')
    if m is not None:
        setattr(m, '_events_last_cleanup_day', val)


def _call_safe_request(*args, **kwargs) -> Optional[requests.Response]:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_safe_request'):
        return getattr(m, '_safe_request')(*args, **kwargs)
    return _safe_request(*args, **kwargs)


def _call_append_event(*args, **kwargs) -> bool:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_append_event'):
        return getattr(m, '_append_event')(*args, **kwargs)
    return _append_event(*args, **kwargs)

# F-17: Failover Coordinator state machine, locks, and history
VALID_HA_TARGETS = {'primary', 'backup'}
_failover_states: Dict[str, Dict[str, Any]] = {}
_failover_states_lock = threading.Lock()
_failover_execution_lock = threading.Lock()
_failover_history: deque = deque(maxlen=100)

# Service health tracking
_service_health: Dict[str, Dict[str, Any]] = {
    'ryu': {'healthy': True, 'last_check': 0.0, 'error': None},
    'runner': {'healthy': True, 'last_check': 0.0, 'error': None},
    'glances': {'healthy': True, 'last_check': 0.0, 'error': None, 'state': 'closed', 'fail_count': 0, 'cooldown_remaining_sec': 0.0},
}
_health_lock = threading.Lock()
HEALTH_CHECK_INTERVAL: float = 5.0


def _update_service_health(service: str, healthy: bool, error: Optional[str] = None) -> None:
    with _health_lock:
        _service_health[service] = {
            'healthy': healthy,
            'last_check': time.time(),
            'error': error,
        }


def _get_service_health(service: str) -> Dict[str, Any]:
    with _health_lock:
        return dict(_service_health.get(service, {'healthy': False, 'last_check': 0.0, 'error': 'unknown'}))


def _safe_request(
    url: str,
    method: str = 'GET',
    timeout: Any = 2.0,
    json_data: Optional[Dict] = None,
    service_name: str = 'unknown',
) -> Optional[requests.Response]:
    from webapp.core.security import _internal_headers, _classify_backend_exception, _log_backend_exception
    headers = _internal_headers() if service_name in ('ryu', 'runner') else {}
    try:
        m = method.upper()
        if m == 'GET':
            r = requests.get(url, headers=headers or None, timeout=timeout)
        elif m == 'POST':
            r = requests.post(url, json=json_data, headers=headers or None, timeout=timeout)
        else:
            return None

        _update_service_health(service_name, healthy=True)
        return r
    except requests.exceptions.Timeout:
        _update_service_health(service_name, healthy=False, error='timeout')
        return None
    except requests.exceptions.ConnectionError:
        _update_service_health(service_name, healthy=False, error='connection_refused')
        return None
    except Exception as e:
        code, _, _ = _classify_backend_exception(e, upstream=service_name)
        _log_backend_exception(f'safe_request:{service_name}', e, level='warning', error_code=code)
        _update_service_health(service_name, healthy=False, error=code)
        return None


def _reset_alerts_state_for_tests():
    with _snapshot_lock:
        _alerts_snapshot.clear()
        _alerts_snapshot.update({
            'alerts': [],
            'ts': 0.0,
            'status': 'initializing',
            'boot_id': None,
            'last_seq': None,
            'consecutive_failures': 0,
            'last_error': None,
        })
    with _seen_ids_lock:
        _seen_alert_ids_set.clear()
        _seen_alert_ids_deque.clear()
        _set_last_seen_boot_id(None)
        _set_last_seen_seq(None)
    with _failover_states_lock:
        _failover_states.clear()
        _failover_history.clear()
    _set_events_last_ts(0.0)
    _set_events_ts_initialized(False)

    # Mirror to webapp.server if imported
    m = sys.modules.get('webapp.server')
    if m is not None:
        if hasattr(m, '_last_seen_boot_id'):
            setattr(m, '_last_seen_boot_id', None)
        if hasattr(m, '_last_seen_seq'):
            setattr(m, '_last_seen_seq', None)
        if hasattr(m, '_events_last_ts'):
            setattr(m, '_events_last_ts', 0.0)
        if hasattr(m, '_events_ts_initialized'):
            setattr(m, '_events_ts_initialized', False)


def _events_max_bytes() -> int:
    raw_bytes = _to_int(os.getenv('EVENTS_MAX_BYTES', '0'), 0)
    if raw_bytes > 0:
        return max(256, raw_bytes)
    mb = max(1, _to_int(os.getenv('EVENTS_MAX_FILE_MB', '10'), 10))
    return mb * 1024 * 1024


def _events_retention_days() -> int:
    return max(1, _to_int(os.getenv('EVENTS_RETENTION_DAYS', '14'), 14))


def _events_max_parts() -> int:
    return max(1, _to_int(os.getenv('EVENTS_MAX_PARTS_PER_DAY', '10'), 10))


def _events_date_str(ts_val: Optional[float] = None) -> str:
    ts = float(ts_val) if ts_val is not None else float(time.time())
    return time.strftime('%Y-%m-%d', time.localtime(ts))


def _events_file_for_date(date_str: str) -> str:
    return os.path.join(current_log_dir(), f"events-{date_str}.csv")


def _list_event_files() -> List[str]:
    """Return event CSV paths sorted chronologically oldest -> newest."""
    items = []
    ev_file = current_events_log_file()
    ldir = current_log_dir()
    if os.path.isfile(ev_file):
        items.append((('0000-00-00', 0), ev_file))
    if not os.path.isdir(ldir):
        return [p for _, p in items]
    pat = re.compile(r'^events-(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.csv$')
    try:
        for fname in os.listdir(ldir):
            m = pat.match(fname)
            if not m:
                continue
            dstr = m.group(1)
            part = int(m.group(2)) if m.group(2) else 10**9
            fpath = os.path.join(ldir, fname)
            if os.path.isfile(fpath):
                items.append(((dstr, part), fpath))
    except Exception:
        pass
    items.sort(key=lambda x: x[0])
    return [p for _, p in items]


def _cleanup_old_event_files(retention_days: int) -> None:
    ldir = current_log_dir()
    if not os.path.isdir(ldir):
        return
    cutoff = time.strftime('%Y-%m-%d', time.localtime(time.time() - (retention_days * 86400)))
    pat = re.compile(r'^events-(\d{4}-\d{2}-\d{2})(?:\.\d+)?\.csv$')
    try:
        for fname in os.listdir(ldir):
            m = pat.match(fname)
            if not m:
                continue
            if m.group(1) < cutoff:
                try:
                    os.remove(os.path.join(ldir, fname))
                except Exception:
                    pass
    except Exception:
        pass


def _rotate_daily_event_file_if_needed(path: str, date_str: str) -> None:
    max_bytes = _events_max_bytes()
    if not os.path.isfile(path):
        return
    try:
        if os.path.getsize(path) < max_bytes:
            return
    except Exception:
        return

    ldir = current_log_dir()
    pat = re.compile(rf'^events-{re.escape(date_str)}\.(\d+)\.csv$')
    parts = []
    try:
        for fname in os.listdir(ldir):
            m = pat.match(fname)
            if m:
                parts.append((int(m.group(1)), os.path.join(ldir, fname)))
    except Exception:
        pass
    parts.sort(key=lambda x: x[0])
    next_part = (parts[-1][0] + 1) if parts else 1
    rotated_path = os.path.join(ldir, f"events-{date_str}.{next_part}.csv")
    try:
        os.replace(path, rotated_path)
        parts.append((next_part, rotated_path))
    except Exception:
        return

    max_parts = _events_max_parts()
    while len(parts) > max_parts:
        _, old_part = parts.pop(0)
        try:
            os.remove(old_part)
        except Exception:
            pass


def _ensure_events_last_ts() -> float:
    if _get_events_ts_initialized():
        return _get_events_last_ts()
    max_ts = float(_get_events_last_ts() or 0.0)
    with _events_lock:
        if _get_events_ts_initialized():
            return _get_events_last_ts()
        files = _list_event_files()
        for fpath in files[-2:]:
            try:
                with open(fpath, 'r', encoding='utf-8', newline='') as f:
                    for row in csv.DictReader(f):
                        try:
                            val = float(row.get('ts') or 0.0)
                            if val > max_ts:
                                max_ts = val
                        except Exception:
                            continue
            except Exception:
                continue
        _set_events_last_ts(max_ts)
        _set_events_ts_initialized(True)
        return _get_events_last_ts()


def _append_event(event_type: str, src: str = '', reason: str = '', extra: dict = None, ts_val: Optional[float] = None) -> bool:
    global _events_last_cleanup_day
    ldir = current_log_dir()
    with _events_lock:
        try:
            os.makedirs(ldir, exist_ok=True)
            row_ts = float(ts_val) if ts_val is not None else float(time.time())
            today_str = _events_date_str(row_ts)
            if _get_events_last_cleanup_day() != today_str:
                _cleanup_old_event_files(_events_retention_days())
                _set_events_last_cleanup_day(today_str)
            target = _events_file_for_date(today_str)
            _rotate_daily_event_file_if_needed(target, today_str)
            exists = os.path.isfile(target) and os.path.getsize(target) > 0
            with open(target, 'a', encoding='utf-8', newline='') as f:
                w = csv.writer(f)
                if not exists:
                    w.writerow(['ts', 'type', 'src', 'reason', 'extra_json'])
                w.writerow([
                    row_ts,
                    str(event_type or ''),
                    str(src or ''),
                    str(reason or ''),
                    json.dumps(extra or {}, ensure_ascii=False),
                ])
                f.flush()
            if row_ts > _get_events_last_ts():
                _set_events_last_ts(row_ts)
            _set_events_ts_initialized(True)
            return True
        except Exception:
            return False


def _bootstrap_seen_alerts_from_csv(target_alert_count: int = 200) -> int:
    """Scan event CSV files backwards (newest to oldest) to recover at least
    target_alert_count alert IDs and seed sequence state for deduplication and gap detection.
    """
    global _last_seen_boot_id, _last_seen_seq
    recovered_ids: List[str] = []
    latest_boot_id: Optional[str] = None
    latest_seq: Optional[int] = None

    with _events_lock:
        files = _list_event_files()
        for fpath in reversed(files):
            try:
                with open(fpath, 'r', encoding='utf-8', newline='') as f:
                    rows = list(csv.DictReader(f))
            except Exception:
                continue
            if not rows:
                continue

            for row in reversed(rows):
                extra_raw = row.get('extra_json') or ''
                if not extra_raw:
                    continue
                try:
                    extra = json.loads(extra_raw)
                except Exception:
                    continue
                if not isinstance(extra, dict):
                    continue

                aid = extra.get('id') or extra.get('alert_id')
                boot = extra.get('boot_id')
                seq_val = extra.get('seq')

                # Identify if row represents an alert
                is_alert = bool(aid or (boot and seq_val is not None) or
                                (row.get('type') or '').startswith('alert') or
                                row.get('type') in (
                                    'vip_rl_on', 'vip_rl_off', 'spoof_flood', 'failsafe_on',
                                    'failsafe_off', 'quarantine', 'block', 'detect', 'ddos',
                                    'ddos_block', 'auto_unblock', 'auto_unquarantine', 'failover',
                                    'failover_error', 'failover_requested', 'ha_active', 'manual_block',
                                    'manual_unblock', 'manual_unblock_all', 'manual_block_mac',
                                    'manual_unblock_mac', 'manual_unblock_mac_all', 'flows_cleared'
                                ))

                # Restore historical failover state if present
                if row.get('type') == 'ha_active' and extra.get('alert_id'):
                    fo_id = str(extra.get('alert_id'))
                    with _failover_states_lock:
                        if fo_id not in _failover_states:
                            _failover_states[fo_id] = {
                                'alert_id': fo_id,
                                'state': 'succeeded',
                                'target': str(extra.get('target') or 'backup'),
                                'reason': str(row.get('reason') or ''),
                                'attempts': int(extra.get('attempts') or 1),
                                'max_retries': 3,
                                'last_error': None,
                                'created_at': float(row.get('ts') or 0.0),
                                'completed_at': float(row.get('ts') or 0.0),
                            }
                elif row.get('type') == 'failover_error' and extra.get('alert_id'):
                    fo_id = str(extra.get('alert_id'))
                    with _failover_states_lock:
                        if fo_id not in _failover_states:
                            _failover_states[fo_id] = {
                                'alert_id': fo_id,
                                'state': 'failed',
                                'target': str(extra.get('target') or 'backup'),
                                'reason': str(row.get('reason') or ''),
                                'attempts': int(extra.get('attempts') or 1),
                                'max_retries': 3,
                                'last_error': str(extra.get('error') or row.get('reason') or 'failed'),
                                'created_at': float(row.get('ts') or 0.0),
                                'completed_at': float(row.get('ts') or 0.0),
                            }

                if not is_alert:
                    continue

                if not aid:
                    if boot and seq_val is not None:
                        aid = f"{boot}-{seq_val}"
                    else:
                        aid = f"legacy:{row.get('ts')}:{row.get('type')}:{row.get('src')}:{row.get('reason')}"

                if aid and aid not in recovered_ids:
                    recovered_ids.append(aid)

                # Seed the latest boot_id and seq from the newest alert in history
                if latest_boot_id is None and boot and seq_val is not None:
                    try:
                        latest_boot_id = str(boot)
                        latest_seq = int(seq_val)
                    except Exception:
                        pass

                if len(recovered_ids) >= target_alert_count:
                    break
            if len(recovered_ids) >= target_alert_count:
                break

    with _seen_ids_lock:
        for aid in reversed(recovered_ids):
            if aid not in _seen_alert_ids_set:
                if len(_seen_alert_ids_deque) >= _seen_alert_ids_deque.maxlen:
                    evicted = _seen_alert_ids_deque.popleft()
                    _seen_alert_ids_set.discard(evicted)
                _seen_alert_ids_deque.append(aid)
                _seen_alert_ids_set.add(aid)

        if _get_last_seen_boot_id() is None and latest_boot_id is not None:
            _set_last_seen_boot_id(latest_boot_id)
            _set_last_seen_seq(latest_seq)

    logger = _get_logger()
    logger.info("Bootstrapped %d alert IDs from CSV (last_boot=%s, last_seq=%s)",
                len(recovered_ids), _get_last_seen_boot_id(), _get_last_seen_seq())
    return len(recovered_ids)


def _call_runner_get(path: str, timeout: float = 5.0) -> requests.Response:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_runner_get'):
        return getattr(m, '_runner_get')(path, timeout=timeout)
    runner_base = current_runner_base()
    return requests.get(f"{runner_base}{path}", headers=_internal_headers() or None, timeout=timeout)


def _call_runner_post(path: str, json_data: Optional[Dict] = None, timeout: float = 5.0) -> requests.Response:
    m = sys.modules.get('webapp.server')
    if m is not None and hasattr(m, '_runner_post'):
        return getattr(m, '_runner_post')(path, json_data=json_data, timeout=timeout)
    runner_base = current_runner_base()
    return requests.post(f"{runner_base}{path}", json=json_data, headers=_internal_headers() or None, timeout=timeout)


def _coordinate_failover_request(
    alert: dict,
    *,
    max_retries: int = 3,
    backoff_base: float = 0.5,
) -> Tuple[bool, str]:
    """Execute HA failover coordination with state machine, locking, and retries.
    States: received -> pending -> retrying -> succeeded | failed
    """
    logger = _get_logger()
    aid = alert.get('id')
    if not aid:
        boot = alert.get('boot_id')
        seq = alert.get('seq')
        if boot and seq is not None:
            aid = f"{boot}-{seq}"
        else:
            aid = f"alert_{time.time()}"
    alert_id = str(aid)

    raw_target = str(alert.get('target') or 'backup').strip().lower()
    reason = str(alert.get('reason') or '')
    now = time.time()

    # 1. Target validation
    if raw_target not in VALID_HA_TARGETS:
        with _failover_states_lock:
            state_rec = {
                'alert_id': alert_id,
                'state': 'failed',
                'target': raw_target,
                'reason': reason,
                'attempts': 0,
                'max_retries': max_retries,
                'last_error': 'invalid_target',
                'created_at': now,
                'completed_at': now,
            }
            _failover_states[alert_id] = state_rec
            _failover_history.append(dict(state_rec))
        _append_event(
            'failover_error',
            src='failover_coordinator',
            reason='invalid_target',
            extra={'alert_id': alert_id, 'target': raw_target, 'error': 'invalid_target', 'attempts': 0},
            ts_val=now,
        )
        logger.warning("Failover request %s rejected: invalid target '%s'", alert_id, raw_target)
        return False, 'invalid_target'

    target = raw_target

    # 2. Idempotency check against prior completions or in-flight operations
    with _failover_states_lock:
        existing = _failover_states.get(alert_id)
        if existing:
            st = existing.get('state')
            if st in ('succeeded', 'failed'):
                logger.info("Failover request %s already reached state %s; skipping", alert_id, st)
                return (st == 'succeeded'), f"already_{st}"
            if st in ('pending', 'retrying'):
                logger.info("Failover request %s already in progress (%s); skipping duplicate", alert_id, st)
                return True, 'in_progress'

        state_rec = {
            'alert_id': alert_id,
            'state': 'received',
            'target': target,
            'reason': reason,
            'attempts': 0,
            'max_retries': max_retries,
            'last_attempt_ts': None,
            'last_error': None,
            'created_at': now,
            'completed_at': None,
        }
        _failover_states[alert_id] = state_rec
        _failover_history.append(state_rec)

    # 3. Acquire execution lock for serialized execution
    with _failover_execution_lock:
        with _failover_states_lock:
            state_rec['state'] = 'pending'

        # Check Runner current status for coalescing
        try:
            st_resp = _call_runner_get('/ha/status', timeout=2.0)
            if st_resp.ok:
                st_data = st_resp.json() if st_resp.text else {}
                curr_active = str(st_data.get('ha', {}).get('active') or '').strip().lower()
                if curr_active == target:
                    fin_now = time.time()
                    with _failover_states_lock:
                        state_rec['state'] = 'succeeded'
                        state_rec['completed_at'] = fin_now
                        state_rec['note'] = 'coalesced_already_active'
                    _append_event(
                        'ha_active',
                        src='failover_coordinator',
                        reason=reason,
                        extra={
                            'alert_id': alert_id,
                            'target': target,
                            'applied': True,
                            'coalesced': True,
                            'attempts': 0,
                        },
                        ts_val=fin_now,
                    )
                    logger.info("Failover request %s target %s is already active in Runner; coalesced", alert_id, target)
                    return True, 'already_active'
        except Exception as ex:
            logger.debug("Runner /ha/status check before failover skipped/failed: %s", ex)

        # 4. Dispatch with bounded retries
        last_err: Optional[str] = None
        for attempt in range(max_retries + 1):
            with _failover_states_lock:
                state_rec['attempts'] = attempt + 1
                state_rec['last_attempt_ts'] = time.time()
                if attempt > 0:
                    state_rec['state'] = 'retrying'

            try:
                resp = _call_runner_post('/ha/active', json_data={'active': target}, timeout=3.0)
                if resp.ok:
                    resp_data = resp.json() if resp.text else {}
                    fin_now = time.time()
                    with _failover_states_lock:
                        state_rec['state'] = 'succeeded'
                        state_rec['completed_at'] = fin_now
                        state_rec['applied'] = resp_data.get('applied')
                    _append_event(
                        'ha_active',
                        src='failover_coordinator',
                        reason=reason,
                        extra={
                            'alert_id': alert_id,
                            'target': target,
                            'applied': True,
                            'attempts': attempt + 1,
                        },
                        ts_val=fin_now,
                    )
                    logger.info("Failover request %s successfully applied to Runner on attempt %d", alert_id, attempt + 1)
                    return True, 'succeeded'

                sc = resp.status_code
                err_code = f"http_{sc}"
                try:
                    err_json = resp.json()
                    if isinstance(err_json, dict) and err_json.get('error'):
                        err_code = str(err_json['error'])
                except Exception:
                    pass
                last_err = err_code

                # Terminal check: 400 or 404
                if sc in (400, 404):
                    logger.warning("Failover request %s terminal error from Runner (%s)", alert_id, err_code)
                    break
                else:
                    logger.warning("Failover request %s transient HTTP %d (%s), attempt %d/%d",
                                   alert_id, sc, err_code, attempt + 1, max_retries + 1)

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as req_err:
                err_name = 'timeout' if isinstance(req_err, requests.exceptions.Timeout) else 'connection_refused'
                last_err = err_name
                logger.warning("Failover request %s network error (%s), attempt %d/%d",
                               alert_id, err_name, attempt + 1, max_retries + 1)
            except Exception as req_ex:
                last_err = type(req_ex).__name__
                logger.warning("Failover request %s unexpected exception (%s), attempt %d/%d",
                               alert_id, last_err, attempt + 1, max_retries + 1)

            # Backoff before retry
            if attempt < max_retries:
                sleep_dur = backoff_base * (2 ** attempt) + random.uniform(0.02, 0.08)
                time.sleep(sleep_dur)

        # 5. Retries exhausted or terminal error
        fin_now = time.time()
        with _failover_states_lock:
            state_rec['state'] = 'failed'
            state_rec['completed_at'] = fin_now
            state_rec['last_error'] = last_err

        _append_event(
            'failover_error',
            src='failover_coordinator',
            reason=str(last_err or 'failed'),
            extra={
                'alert_id': alert_id,
                'target': target,
                'error': str(last_err or 'failed'),
                'attempts': state_rec['attempts'],
            },
            ts_val=fin_now,
        )
        logger.error("Failover request %s failed permanently after %d attempts: %s",
                     alert_id, state_rec['attempts'], last_err)
        return False, str(last_err or 'failed')


def _process_and_archive_alerts(alerts_data: list) -> Tuple[int, int]:
    """Process a batch of alerts fetched from Ryu:
    1. Detect gaps (confirmed sequence gaps vs indeterminate controller session resets).
    2. Deduplicate against in-memory seen alert IDs.
    3. Write new alerts to CSV under _events_lock with atomic write-before-commit order.
    4. Update the pure-read in-memory snapshot.
    5. Coordinate any failover_requested alerts via Failover Coordinator.
    Returns (committed_alert_count, gaps_detected_count).
    """
    global _last_seen_boot_id, _last_seen_seq
    logger = _get_logger()
    if not isinstance(alerts_data, list):
        return 0, 0

    valid_alerts = [a for a in alerts_data if isinstance(a, dict)]

    def _sort_key(item: dict):
        b = str(item.get('boot_id') or '')
        s = item.get('seq')
        seq_int = int(s) if isinstance(s, int) else (int(s) if str(s).isdigit() else -1)
        try:
            ts = float(item.get('ts') or 0.0)
        except Exception:
            ts = 0.0
        return (b, seq_int, ts)

    valid_alerts.sort(key=_sort_key)

    gaps_detected = 0

    # 1. Gap detection pass
    for a in valid_alerts:
        boot_id = a.get('boot_id')
        seq_val = a.get('seq')
        if not boot_id or seq_val is None:
            continue
        try:
            seq = int(seq_val)
        except Exception:
            continue

        last_boot = _get_last_seen_boot_id()
        last_s = _get_last_seen_seq()

        if last_boot is None:
            _set_last_seen_boot_id(str(boot_id))
            _set_last_seen_seq(seq)
        elif str(boot_id) != last_boot:
            # Controller session changed (reboot or failover) -> Indeterminate gap
            logger.info("Alerts session boot_id changed from %s to %s (seq=%d)",
                        last_boot, boot_id, seq)
            _append_event('ryu_session_changed', src='server',
                          reason='boot_id_changed',
                          extra={'old_boot_id': last_boot,
                                 'new_boot_id': str(boot_id),
                                 'new_seq': seq})
            _set_last_seen_boot_id(str(boot_id))
            _set_last_seen_seq(seq)
        else:
            # Same boot_id
            if last_s is not None:
                if seq > last_s + 1:
                    # Confirmed gap!
                    dropped_count = seq - last_s - 1
                    gaps_detected += 1
                    logger.warning("Confirmed alert gap: missed %d alerts between seq %d and %d (boot=%s)",
                                   dropped_count, last_s, seq, boot_id)
                    _append_event('alert_gap_detected', src='ryu',
                                  reason=f"missed_{dropped_count}_alerts",
                                  extra={'dropped_count': dropped_count,
                                         'expected_seq': last_s + 1,
                                         'received_seq': seq,
                                         'boot_id': str(boot_id)})
                if seq > last_s:
                    _set_last_seen_seq(seq)
            else:
                _set_last_seen_seq(seq)

    # 2. Candidate collection & deduplication
    new_candidates: List[Tuple[str, dict]] = []
    with _seen_ids_lock:
        for a in valid_alerts:
            aid = a.get('id')
            if not aid:
                boot = a.get('boot_id')
                s = a.get('seq')
                if boot and s is not None:
                    aid = f"{boot}-{s}"
                else:
                    aid = f"legacy:{a.get('ts')}:{a.get('type')}:{a.get('src')}:{a.get('reason')}"
            if aid not in _seen_alert_ids_set:
                new_candidates.append((aid, a))

    # 3. Write-before-commit: write new candidates to CSV
    committed_ids: List[str] = []
    committed_alerts: List[dict] = []
    for aid, a in new_candidates:
        ats = float(a.get('ts') or time.time())
        extra_payload = dict(a)
        extra_payload['id'] = aid
        ok = _call_append_event(
            a.get('type') or 'alert',
            src=str(a.get('src') or ''),
            reason=str(a.get('reason') or ''),
            extra=extra_payload,
            ts_val=ats
        )
        if ok:
            committed_ids.append(aid)
            committed_alerts.append(extra_payload)
        else:
            logger.error("Failed to write alert %s to CSV; not committing to seen set", aid)

    # 4. Commit successfully written IDs to seen set/deque
    with _seen_ids_lock:
        for cid in committed_ids:
            if cid not in _seen_alert_ids_set:
                if len(_seen_alert_ids_deque) >= _seen_alert_ids_deque.maxlen:
                    evicted = _seen_alert_ids_deque.popleft()
                    _seen_alert_ids_set.discard(evicted)
                _seen_alert_ids_deque.append(cid)
                _seen_alert_ids_set.add(cid)

    # 5. Update in-memory snapshot
    with _snapshot_lock:
        _alerts_snapshot['alerts'] = list(valid_alerts)
        _alerts_snapshot['ts'] = time.time()
        _alerts_snapshot['status'] = 'ok'
        _alerts_snapshot['consecutive_failures'] = 0
        _alerts_snapshot['last_error'] = None
        if valid_alerts:
            last_item = valid_alerts[-1]
            _alerts_snapshot['boot_id'] = last_item.get('boot_id')
            _alerts_snapshot['last_seq'] = last_item.get('seq')

    # 6. F-17: Coordinate any new failover requests
    for a in committed_alerts:
        if a.get('type') == 'failover_requested':
            try:
                _coordinate_failover_request(a)
            except Exception as coord_err:
                logger.exception("Error in failover coordinator: %s", coord_err)

    return len(committed_ids), gaps_detected


def _record_sync_failure(reason: str) -> None:
    with _snapshot_lock:
        _alerts_snapshot['consecutive_failures'] = _alerts_snapshot.get('consecutive_failures', 0) + 1
        failures = _alerts_snapshot['consecutive_failures']
        _alerts_snapshot['status'] = 'degraded' if failures < 3 else 'stale'
        _alerts_snapshot['last_error'] = reason


def _poll_and_sync_alerts_once() -> bool:
    try:
        ryu_base = current_ryu_api_base()
        r = _call_safe_request(f"{ryu_base}/dos/alerts", method='GET', timeout=(1.0, 2.0), service_name='ryu')
        if r and r.ok:
            data = r.json()
            if isinstance(data, list):
                _process_and_archive_alerts(data)
                return True
            else:
                _record_sync_failure('invalid_format')
                return False
        else:
            _record_sync_failure('ryu_unavailable')
            return False
    except Exception:
        _record_sync_failure('connection_error')
        return False


def _acquire_leader_lock() -> bool:
    """Non-blocking OS lock election to ensure only a single WSGI worker acts as sync leader."""
    global _leader_lock_fd, _is_sync_leader
    if _is_sync_leader:
        return True
    try:
        run_dir = current_run_dir()
        os.makedirs(run_dir, exist_ok=True)
        lock_path = os.path.join(run_dir, '.alerts_sync_worker.lock')
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'\0')
        except OSError:
            pass

        if os.name != 'nt':
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

        _leader_lock_fd = fd
        _is_sync_leader = True
        return True
    except (BlockingIOError, OSError):
        try:
            if 'fd' in locals():
                os.close(fd)
        except OSError:
            pass
        return False


def _release_leader_lock() -> None:
    """Release the OS flock leader election lock and close file descriptor."""
    global _leader_lock_fd, _is_sync_leader
    if _leader_lock_fd is not None:
        try:
            if os.name != 'nt':
                import fcntl
                fcntl.flock(_leader_lock_fd, fcntl.LOCK_UN)
            else:
                import msvcrt
                try:
                    os.lseek(_leader_lock_fd, 0, os.SEEK_SET)
                    msvcrt.locking(_leader_lock_fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        except Exception:
            pass
        finally:
            try:
                os.close(_leader_lock_fd)
            except OSError:
                pass
            _leader_lock_fd = None
            _is_sync_leader = False


def _alerts_sync_worker_loop():
    logger = _get_logger()
    logger.info("AlertsSyncWorker thread started (poll_interval=%.1fs)", ALERTS_SYNC_INTERVAL_SEC)
    while not _alerts_sync_stop_event.is_set():
        try:
            _poll_and_sync_alerts_once()
        except Exception as ex:
            logger.exception("Unexpected error in AlertsSyncWorker: %s", ex)
        if _alerts_sync_stop_event.wait(timeout=ALERTS_SYNC_INTERVAL_SEC):
            break
    logger.info("AlertsSyncWorker thread stopped gracefully")


def _start_alerts_sync_worker():
    with _alerts_sync_lifecycle_lock:
        if _get_alerts_sync_started():
            return

        use_leader_election = os.getenv('SDN_LEADER_ELECTION_ENABLED', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        if use_leader_election and not _acquire_leader_lock():
            logger = _get_logger()
            logger.info("[AlertsSync] Another worker is the elected leader; yielding sync duty.")
            return

        try:
            _bootstrap_seen_alerts_from_csv(target_alert_count=200)
        except Exception as ex:
            logger = _get_logger()
            logger.warning("Error bootstrapping alerts from CSV: %s", ex)
        try:
            _poll_and_sync_alerts_once()
        except Exception:
            pass
        _alerts_sync_stop_event.clear()
        t = threading.Thread(
            target=_alerts_sync_worker_loop,
            name="AlertsSyncWorker",
            daemon=True
        )
        _set_alerts_sync_thread(t)
        _set_alerts_sync_started(True)
        t.start()
        logger = _get_logger()
        logger.info("AlertsSyncWorker background worker started")


def _stop_alerts_sync_worker(timeout: float = 3.0):
    with _alerts_sync_lifecycle_lock:
        t = _get_alerts_sync_thread()
        if not _get_alerts_sync_started() or t is None:
            _release_leader_lock()
            return
        _alerts_sync_stop_event.set()
        _set_alerts_sync_thread(None)
        _set_alerts_sync_started(False)
    logger = _get_logger()
    if t and t.is_alive():
        t.join(timeout=timeout)
        if t.is_alive():
            logger.warning("AlertsSyncWorker thread did not stop within %.1fs timeout", timeout)
        else:
            logger.info("AlertsSyncWorker stopped cleanly")
    _release_leader_lock()


class AlertsSyncWorker:
    """Manages the background alerts synchronization worker thread and leader election."""
    def __init__(self, interval: float = ALERTS_SYNC_INTERVAL_SEC):
        self.interval = interval

    def start(self):
        return _start_alerts_sync_worker()

    def stop(self, timeout: float = 3.0):
        return _stop_alerts_sync_worker(timeout=timeout)

    def sync_cycle(self) -> bool:
        return _poll_and_sync_alerts_once()

    @property
    def is_alive(self) -> bool:
        return _alerts_sync_started and _alerts_sync_thread is not None and _alerts_sync_thread.is_alive()


def _read_events(max_rows: int = 400) -> List[dict]:
    collected = []
    try:
        with _events_lock:
            files = _list_event_files()
            for fpath in reversed(files):
                try:
                    with open(fpath, 'r', encoding='utf-8', newline='') as f:
                        rows = list(csv.DictReader(f))
                except Exception:
                    continue
                if not rows:
                    continue
                need = max_rows - len(collected)
                if need <= 0:
                    break
                chunk = rows[-need:]
                # Prepend older chunks before newer chunks so overall order stays chronological.
                collected = chunk + collected
                if len(collected) >= max_rows:
                    break
    except Exception:
        return []
    if not collected:
        return []
    out = []
    for r in collected[-max_rows:]:
        try:
            ts = float(r.get('ts') or 0)
        except Exception:
            ts = 0.0
        out.append({
            'ts': ts,
            'type': r.get('type') or '',
            'src': r.get('src') or '',
            'reason': r.get('reason') or '',
            'extra': r.get('extra_json') or '',
        })
    return out
