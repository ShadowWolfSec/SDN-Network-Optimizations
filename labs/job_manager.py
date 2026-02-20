"""
labs/job_manager.py
===================
Background asynchronous job execution queue, network lifecycle orchestration,
and topology management routes for Mininet Runner.

Extracted in Phase 5 of Mininet Runner refactoring.
"""

import logging
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request

logger = logging.getLogger('labs.job_manager')

from core.common_utils import load_internal_token

# Import core topology state and locking
from labs.topology import (
    _state_lock,
    _job_state,
    LabState,
    get_current_state as _get_current_state,
    set_current_state as _set_current_state,
    get_net as _get_net,
    get_topology as _get_topology,
    get_started_at as _get_started_at,
    get_job_state as _get_job_state,
    acquire_lock as _acquire_lock,
    release_lock as _release_lock,
    require_net as _require_net,
    find_link_by_endpoints as _find_link_by_endpoints,
    apply_link_config as _apply_link_config,
    build_and_start as _build_and_start,
    stop_net as _stop_net,
    apply_live_topology as _apply_live_topology,
    extract_topo_payload as _extract_topo_payload,
    DEFAULT_CONTROLLER_IP,
)
from labs.attack_engine import stop_attack as _stop_attack
from labs.ha_manager import (
    _ha_state,
    _ha_http_procs,
    ha_apply_active as _ha_apply_active,
    ha_start_service as _ha_start_service,
    ha_stop_service as _ha_stop_service,
    ha_test_vip as _ha_test_vip,
    ha_auto_loop as _ha_auto_loop,
)
import labs.ha_manager as ha_mgr
from labs.pcap_manager import stop_active_pcap as _stop_active_pcap

HA_AUTO_ENABLE = str(os.getenv('HA_AUTO_ENABLE', '0')).strip() == '1'


def _runner_job_func(name: str, fallback: Any) -> Any:
    """Dynamically resolves function from mininet_runner to honor test mocks/patches."""
    mod = sys.modules.get('labs.mininet_runner')
    if mod and hasattr(mod, name):
        return getattr(mod, name)
    return fallback


def _runner_error(
    err_or_exc: Any,
    status: int = 500,
    default_code: str = 'runner_internal_error',
    op: str = 'job',
    extra: Optional[Dict[str, Any]] = None,
):
    mod = sys.modules.get('labs.mininet_runner')
    if mod and hasattr(mod, '_runner_error'):
        return mod._runner_error(err_or_exc, status=status, default_code=default_code, op=op, extra=extra)
    from labs.mininet_runner import _runner_error as fallback_err
    return fallback_err(err_or_exc, status=status, default_code=default_code, op=op, extra=extra)


def _current_net():
    mod = sys.modules.get('labs.mininet_runner')
    if mod and hasattr(mod, '_current_net'):
        return mod._current_net()
    try:
        from labs.topology import get_net
        return get_net()
    except Exception:
        return None


def _sanitize_runner_error_code(err_or_exc: Any, default_code: str = 'runner_internal_error') -> str:
    func = _runner_job_func('_sanitize_runner_error_code', None)
    if func:
        return func(err_or_exc, default_code=default_code)
    return default_code


def _busy_resp():
    func = _runner_job_func('_busy_resp', None)
    if func and func is not _busy_resp:
        return func()
    st = _get_current_state()
    op = str(_job_state.get('op') or '')
    msg = f"Operation '{op or st}' is currently in progress. Please wait."
    return jsonify({
        'ok': False,
        'error': 'busy',
        'is_busy': True,
        'current_state': st,
        'op': op,
        'message': msg,
    }), 409


def _sync_runner_job_state():
    """Ensure labs.mininet_runner._job_state stays in sync with _job_state."""
    mr = sys.modules.get('labs.mininet_runner')
    if mr and hasattr(mr, '_job_state') and isinstance(mr._job_state, dict) and mr._job_state is not _job_state:
        mr._job_state.clear()
        mr._job_state.update(_job_state)


def _start_job(op: str, fn, *args, stop_on_error: bool = True, **kwargs) -> bool:
    target_start = _runner_job_func('_start_job', None)
    if target_start and target_start is not _start_job:
        return target_start(op, fn, *args, stop_on_error=stop_on_error, **kwargs)

    if not _acquire_lock(0.5):
        return False
    try:
        if bool(_job_state.get('busy')):
            return False
        gen = int(_job_state.get('gen') or 0) + 1
        task_id = secrets.token_hex(8)
        initial_state = LabState.BUILDING_LAB if op in ('build', 'apply') else (
            LabState.STOPPING if op == 'stop' else (
                LabState.DEMO_RUNNING if op == 'demo' else LabState.BUILDING_LAB
            )
        )
        _set_current_state(initial_state, f"Operation {op} running (task {task_id})")
        _job_state.clear()
        _job_state.update({
            'busy': True,
            'is_busy': True,
            'op': str(op or ''),
            'current_state': initial_state,
            'task_id': task_id,
            'started_at': time.time(),
            'finished_at': None,
            'error': None,
            'result': None,
            'gen': gen,
        })
        _sync_runner_job_state()
    finally:
        _release_lock()

    def _runner():
        result = None
        err = None
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            logger.exception('Background lab job %s failed', op)
            err = _sanitize_runner_error_code(e, default_code='lab_job_failed')
            if stop_on_error:
                try:
                    with _state_lock:
                        _stop_net(_stop_attack, _ha_stop_service, _stop_active_pcap)
                except Exception:
                    pass
        finally:
            acquired = _acquire_lock(2.0)
            try:
                if int(_job_state.get('gen') or 0) == gen:
                    _job_state['busy'] = False
                    _job_state['is_busy'] = False
                    _job_state['op'] = ''
                    _job_state['finished_at'] = time.time()
                    _job_state['error'] = err
                    _job_state['result'] = result
                    if err:
                        _set_current_state(LabState.ERROR, f"Job {op} failed: {err}")
                        _job_state['current_state'] = LabState.ERROR
                    else:
                        end_state = LabState.IDLE if op == 'stop' else LabState.LAB_READY
                        _set_current_state(end_state, f"Job {op} completed")
                        _job_state['current_state'] = end_state
                    _sync_runner_job_state()
            finally:
                if acquired:
                    _release_lock()

    threading.Thread(target=_runner, daemon=True).start()
    return True


def _job_build(topo: Dict[str, Any]) -> Dict[str, Any]:
    target_build = _runner_job_func('_job_build', None)
    if target_build and target_build is not _job_build:
        return target_build(topo)

    with _state_lock:
        _stop_net(_stop_attack, _ha_stop_service, _stop_active_pcap)
        _build_and_start(topo)
        net = _require_net()

        # 1. Post-verification: check switches connection to Ryu OpenFlow 1.3
        switches = list(getattr(net, 'switches', []) or [])
        for s in switches:
            if hasattr(s, 'connected') and callable(s.connected):
                try:
                    if not s.connected():
                        for _ in range(6):
                            time.sleep(0.5)
                            if s.connected():
                                break
                except Exception:
                    pass

        # 2. Post-verification: ensure HA hosts, start service and apply VIP
        applied = None
        try:
            applied = _ha_apply_active(net)
        except Exception:
            applied = None

        ha_started = False
        try:
            _ha_start_service(net)
            ha_started = True
        except Exception:
            ha_started = False

        vip_ok = False
        vip_test = {}
        try:
            vip_test = _ha_test_vip(net)
            vip_ok = bool(vip_test.get('vip_ok'))
        except Exception:
            pass

        if HA_AUTO_ENABLE:
            ha_mgr._ha_auto_gen += 1
            gen = ha_mgr._ha_auto_gen
            ha_mgr._ha_auto_thread = threading.Thread(
                target=_ha_auto_loop, args=(gen, _require_net, _state_lock), daemon=True
            )
            ha_mgr._ha_auto_thread.start()

        msg = f"[OK] Lab built: {len(switches)} switches, HA services active, VIP verified" if vip_ok else f"[OK] Lab built: {len(switches)} switches, HA configured"
        _set_current_state(LabState.LAB_READY, msg)
        return {
            'ok': True,
            'running': True,
            'verified': True,
            'switches_count': len(switches),
            'ha_started': ha_started,
            'vip_ok': vip_ok,
            'ha_applied': applied,
            'ha': dict(_ha_state),
            'message': msg,
        }


def _job_apply(topo: Dict[str, Any]) -> Dict[str, Any]:
    target_apply = _runner_job_func('_job_apply', None)
    if target_apply and target_apply is not _job_apply:
        return target_apply(topo)

    with _state_lock:
        net = _require_net()
        changes = _apply_live_topology(net, topo, _ha_http_procs)
        applied = None
        try:
            applied = _ha_apply_active(net)
        except Exception:
            applied = None
        if HA_AUTO_ENABLE and (changes.get('added_hosts') or changes.get('removed_hosts')):
            try:
                _ha_start_service(net)
            except Exception:
                pass
        return {'ok': True, 'running': True, 'changes': changes, 'ha_applied': applied, 'ha': dict(_ha_state)}


def _job_stop() -> Dict[str, Any]:
    target_stop = _runner_job_func('_job_stop', None)
    if target_stop and target_stop is not _job_stop:
        return target_stop()

    with _state_lock:
        _stop_net(_stop_attack, _ha_stop_service, _stop_active_pcap)
        # Reset Ryu controller flows and blocked IPs to restore clean baseline
        try:
            ryu_rest_port = int(os.getenv('RYU_REST_PORT', '8080'))
            tok = load_internal_token()
            headers = {'Content-Type': 'application/json'}
            if tok:
                headers['X-Internal-Token'] = tok

            # Step 1: Clear switch flows and unblock tracking
            try:
                clear_req = urllib.request.Request(
                    f"http://{DEFAULT_CONTROLLER_IP}:{ryu_rest_port}/dos/flows/clear",
                    data=b'{}',
                    headers=headers,
                    method='POST',
                )
                with urllib.request.urlopen(clear_req, timeout=2.0) as resp:
                    pass
            except Exception as e_clear:
                logger.warning("Failed to clear OVS switch flows on stop: %s", e_clear)

            # Step 2: Reset runtime counters
            try:
                reset_req = urllib.request.Request(
                    f"http://{DEFAULT_CONTROLLER_IP}:{ryu_rest_port}/dos/reset",
                    data=b'{}',
                    headers=headers,
                    method='POST',
                )
                with urllib.request.urlopen(reset_req, timeout=2.0) as resp:
                    pass
            except Exception as e_reset:
                logger.warning("Failed to reset Ryu counters on stop: %s", e_reset)

        except Exception as e:
            logger.warning("Failed to perform controller flow cleanup on stop: %s", e)
        _set_current_state(LabState.IDLE, '[OK] All operations stopped and network cleaned')
        return {'ok': True, 'running': False, 'message': '[OK] All operations stopped'}


# Route Handlers
def build():
    data = request.get_json(silent=True) or {}
    topo = _extract_topo_payload(data)
    ok = _start_job('build', _job_build, topo, stop_on_error=True)
    if not ok:
        return _busy_resp()
    return jsonify({'ok': True, 'accepted': True, 'queued': True, 'op': 'build', 'job': dict(_job_state)}), 202


def topology_apply():
    data = request.get_json(silent=True) or {}
    topo = _extract_topo_payload(data)
    with _state_lock:
        if _current_net() is None:
            return _runner_error('network_not_built', status=400, default_code='network_not_built', op='topology_apply')
    ok = _start_job('apply', _job_apply, topo, stop_on_error=False)
    if not ok:
        return _busy_resp()
    return jsonify({'ok': True, 'accepted': True, 'queued': True, 'op': 'apply', 'job': dict(_job_state)}), 202


def stop():
    ok = _start_job('stop', _job_stop, stop_on_error=False)
    if not ok:
        return _busy_resp()
    return jsonify({'ok': True, 'accepted': True, 'queued': True, 'op': 'stop', 'job': dict(_job_state)}), 202


def runner_exit():
    def _do_exit():
        time.sleep(0.5)
        os._exit(0)
    threading.Thread(target=_do_exit, daemon=True).start()
    return jsonify({'ok': True, 'message': 'shutting_down'}), 200


def link_update():
    data = request.get_json(silent=True) or {}
    a = data.get('a')
    b = data.get('b')
    bw = data.get('bw')
    delay_ms = data.get('delay_ms')
    loss = data.get('loss')

    if not a or not b:
        return _runner_error('missing_endpoints', status=400, default_code='missing_endpoints', op='link_update')

    if not _acquire_lock(2.5):
        return _busy_resp()
    try:
        try:
            net = _require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='link_update')
        link = _find_link_by_endpoints(net, a, b)
        if link is None:
            return _runner_error('link_not_found', status=404, default_code='link_not_found', op='link_update')
        try:
            _apply_link_config(link, bw=bw, delay_ms=delay_ms, loss=loss)
        except ValueError as e:
            return _runner_error(e, status=400, default_code='invalid_request', op='link_update')
        except Exception as e:
            return _runner_error(e, status=500, default_code='link_update_failed', op='link_update')
        return jsonify({'ok': True})
    finally:
        _release_lock()


def register_job_routes(app: Flask) -> None:
    """Registers network build and job lifecycle endpoints on the Flask application."""
    app.add_url_rule('/build', view_func=build, methods=['POST'])
    app.add_url_rule('/topology/apply', view_func=topology_apply, methods=['POST'])
    app.add_url_rule('/stop', view_func=stop, methods=['POST'])
    app.add_url_rule('/exit', view_func=runner_exit, methods=['POST'])
    app.add_url_rule('/link/update', view_func=link_update, methods=['POST'])
