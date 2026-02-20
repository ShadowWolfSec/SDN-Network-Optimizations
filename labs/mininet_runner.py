#!/usr/bin/env python3
"""
labs/mininet_runner.py
Flask orchestration daemon for Mininet network simulation and controls.
"""

import collections
import hmac
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from core.sdn_config import get_config_manager
except Exception:
    get_config_manager = None

# Subsystem Engine Imports & Backward-Compatible Re-Exports
from labs.cmd_console import (
    safe_shell_escape as _safe_shell_escape,
    safe_name as _safe_name,
    safe_target as _safe_target,
    truncate_output as _truncate_output,
    parse_ovs_flow_line as _parse_ovs_flow_line,
    ovs_dump_flows as _ovs_dump_flows,
    execute_cmd_ping,
    execute_cmd_iperf,
)
from labs.ha_manager import (
    _ha_state,
    _ha_http_procs,
    _ha_last_test,
    _ha_last_applied,
    _ha_auto_thread,
    _ha_auto_gen,
    ha_status as _ha_status,
    ha_ensure_hosts as _ha_ensure_hosts,
    ha_apply_active as _ha_apply_active,
    ha_start_service as _ha_start_service,
    ha_stop_service as _ha_stop_service,
    ha_test_vip as _ha_test_vip,
    ha_auto_loop as _ha_auto_loop,
    get_vip_ip as _get_vip_ip,
    use_vip_default as _use_vip_default,
    HA_AUTO_TEST_INTERVAL,
    HA_AUTO_REAPPLY_INTERVAL,
)
from labs.pcap_manager import (
    PCAP_DIR,
    _MANIFEST_FILE,
    PCAP_SNAPLEN,
    MAX_PCAP_FILES,
    MAX_PCAP_TOTAL_MB,
    PCAP_SINGLE_FILE_MAX_MB,
    _pcap_lock,
    _readers_lock,
    _pcap_prune_lock,
    _manifest_lock,
    _active_readers,
    _active_pcap_name,
    _finalizing_pcaps,
    _pcap_proc,
    _last_pcap_name,
    get_pcap_proc as _get_pcap_proc,
    get_active_pcap_name as _get_active_pcap_name,
    get_last_pcap_name as _get_last_pcap_name,
    pcap_snaplen as _pcap_snaplen,
    pcap_max_files as _pcap_max_files,
    pcap_max_total_mb as _pcap_max_total_mb,
    pcap_single_file_max_mb as _pcap_single_file_max_mb,
    resolve_safe_pcap_path as _resolve_safe_pcap_path,
    safe_basename as _safe_basename,
    human_size as _human_size,
    save_pinned_manifest_unlocked as _save_pinned_manifest_unlocked,
    load_pinned_manifest as _load_pinned_manifest,
    save_pinned_manifest as _save_pinned_manifest,
    pcap_prune as _pcap_prune,
    terminate_pcap_proc as _terminate_pcap_proc,
    finalize_pcap as _finalize_pcap,
    stop_active_pcap as _stop_active_pcap,
    start_pcap as _start_pcap,
    pcap_startup_reconciliation as _pcap_startup_reconciliation,
)
from labs.attack_engine import (
    AttackValidationError as _AttackValidationError,
    _attack_procs,
    reserved_ha_names as _reserved_ha_names,
    parse_preflight as _parse_preflight,
    pick_victim_and_attackers as _pick_victim_and_attackers,
    attack_status as _attack_status,
    stop_attack as _stop_attack,
    run_attack_preset as _run_attack_preset,
    ATTACK_MAX_ATTACKERS_WEAK,
    ATTACK_MAX_ATTACKERS_MEDIUM,
    ATTACK_MAX_ATTACKERS_STRONG,
)
from labs.topology import (
    Mininet,
    RemoteController,
    OVSSwitch,
    TCLink,
    setLogLevel,
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
    normalize_delay_ms as _normalize_delay_ms,
    find_link_by_endpoints as _find_link_by_endpoints,
    apply_link_config as _apply_link_config,
    normalize_topology as _normalize_topology,
    configure_ovs_stp as _configure_ovs_stp,
    apply_static_arp_all as _apply_static_arp_all,
    cleanup_stale_network_resources as _cleanup_stale_network_resources,
    build_and_start as _build_and_start,
    stop_net as _stop_net,
    apply_live_topology as _apply_live_topology,
    host_inventory as _host_inventory,
    extract_topo_payload as _extract_topo_payload,
    DEFAULT_CONTROLLER_IP,
    DEFAULT_CONTROLLER_PORT,
    OVS_STP_ENABLE,
    OVS_RSTP_ENABLE,
)
from labs.scenario_engine import (
    ALLOWED_SCENARIOS,
    run_scenario,
    execute_scenario,
)
from labs.routes_pcap import (
    register_pcap_routes,
    pcap_list,
    pcap_download,
    pcap_pin,
    pcap_unpin,
    pcap_delete,
    pcap_storage,
)
from labs.routes_ha import (
    register_ha_routes,
    ha_status,
    ha_config,
    ha_active,
    ha_service_start,
    ha_service_stop,
    ha_test,
)
from labs.routes_attack_cmd import (
    register_attack_cmd_routes,
    ovs_flows,
    cmd_run,
    attack_status,
    attack_run,
    attack_stop,
)
from labs.job_manager import (
    register_job_routes,
    _busy_resp,
    _start_job,
    _job_build,
    _job_apply,
    _job_stop,
    build,
    topology_apply,
    stop,
    runner_exit,
    link_update,
)

RUNNER_HOST = os.getenv('MININET_RUNNER_HOST', '127.0.0.1')
RUNNER_PORT = int(os.getenv('MININET_RUNNER_PORT', '9090'))
PROJECT_ROOT = _PROJECT_ROOT

HA_AUTO_ENABLE = str(os.getenv('HA_AUTO_ENABLE', '0')).strip() == '1'


# Dynamic State Accessors
def _current_net() -> Optional[Mininet]:
    try:
        from labs.topology import get_net
        return get_net()
    except Exception:
        return None


def _current_topology() -> Optional[Dict[str, Any]]:
    try:
        from labs.topology import get_topology
        return get_topology()
    except Exception:
        return None


def _current_started_at() -> Optional[float]:
    try:
        from labs.topology import get_started_at
        return get_started_at()
    except Exception:
        return None


def _current_pcap_proc() -> Optional[subprocess.Popen]:
    try:
        from labs.pcap_manager import get_pcap_proc
        return get_pcap_proc()
    except Exception:
        return None


def _current_active_pcap_name() -> Optional[str]:
    try:
        from labs.pcap_manager import get_active_pcap_name
        return get_active_pcap_name()
    except Exception:
        return None


def _current_last_pcap_name() -> Optional[str]:
    try:
        from labs.pcap_manager import get_last_pcap_name
        return get_last_pcap_name()
    except Exception:
        return None


def _current_attack_state() -> Dict[str, Any]:
    try:
        from labs import attack_engine
        return getattr(attack_engine, '_attack_state', {}) or {}
    except Exception:
        return {}


def __getattr__(name: str) -> Any:
    if name == '_net':
        return _current_net()
    if name == '_topology':
        return _current_topology()
    if name == '_started_at':
        return _current_started_at()
    if name == '_pcap_proc':
        return _current_pcap_proc()
    if name == '_active_pcap_name':
        return _current_active_pcap_name()
    if name == '_last_pcap_name':
        return _current_last_pcap_name()
    if name == '_attack_state':
        return _current_attack_state()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# Flask Application & Error Sanitization
app = Flask(__name__)

_ALLOWED_RUNNER_ERROR_CODES = {
    'unauthorized', 'busy', 'network_not_built', 'network_not_running',
    'controller_changed_rebuild_required', 'too_many_nodes_max_100',
    'tcpdump_not_installed', 'iperf_not_installed', 'hping3_not_installed',
    'ha_need_two_hosts', 'ha_backup_missing', 'ha_service_error', 'ha_test_failed',
    'ha_config_error', 'active_must_be_primary_or_backup',
    'no_hosts', 'no_linked_hosts', 'need_hosts', 'missing_endpoints',
    'link_not_found', 'link_update_failed', 'unknown_scenario',
    'unknown_command_type', 'missing_src_or_dst', 'src_not_found',
    'missing_client_or_server', 'client_must_differ_from_server',
    'client_or_server_not_found', 'switch_not_found', 'missing_switch',
    'attack_already_running', 'victim_not_found', 'victim_not_linked',
    'victim_in_attackers', 'no_attackers_available', 'attacker_not_found',
    'attacker_reserved_role', 'attacker_not_linked', 'attacker_blocked',
    'insufficient_attackers', 'ovs_dump_failed', 'cmd_failed', 'ping_failed',
    'invalid_request', 'bad_request', 'not_found', 'method_not_allowed',
    'runner_internal_error', 'lab_job_failed',
}


def _get_runner_config(name: str, fallback: Any) -> Any:
    if get_config_manager:
        try:
            val = get_config_manager().get_effective(name)
            if val is not None:
                return val
        except Exception:
            pass
    return fallback


def _runner_req_id() -> str:
    try:
        rid = getattr(g, 'request_id', '') or ''
        return str(rid)
    except Exception:
        return ''


@app.before_request
def _assign_runner_request_id():
    raw = (request.headers.get('X-Request-ID') or '').strip()
    if raw and re.fullmatch(r'[A-Za-z0-9_.-]{4,32}', raw):
        g.request_id = raw
    else:
        g.request_id = secrets.token_hex(6)


def _sanitize_runner_error_code(err_or_exc: Any, default_code: str = 'runner_internal_error') -> str:
    raw = str(err_or_exc or '').strip()
    if raw in _ALLOWED_RUNNER_ERROR_CODES:
        return raw
    return default_code


def _runner_error(
    err_or_exc: Any,
    status: int = 500,
    default_code: str = 'runner_internal_error',
    op: str = 'runner',
    extra: Optional[Dict[str, Any]] = None,
):
    code = _sanitize_runner_error_code(err_or_exc, default_code=default_code)
    rid = _runner_req_id()
    if isinstance(err_or_exc, Exception) and status >= 500:
        app.logger.exception('[req=%s] runner %s error (%s): %s', rid or '-', op, code, type(err_or_exc).__name__)
    elif code == default_code and str(err_or_exc or '').strip() not in _ALLOWED_RUNNER_ERROR_CODES:
        app.logger.warning('[req=%s] runner %s suppressed error (%s): %r', rid or '-', op, code, err_or_exc)
    body: Dict[str, Any] = {'ok': False, 'error': code}
    if rid:
        body['request_id'] = rid
    if isinstance(extra, dict):
        body.update(extra)
    return jsonify(body), int(status)


@app.errorhandler(HTTPException)
def _handle_runner_http_error(exc: HTTPException):
    sc = int(exc.code or 500)
    code_map = {
        400: 'bad_request',
        401: 'unauthorized',
        403: 'forbidden',
        404: 'not_found',
        405: 'method_not_allowed',
        409: 'conflict',
        422: 'unprocessable_entity',
    }
    code = code_map.get(sc, 'invalid_request' if sc < 500 else 'runner_internal_error')
    return _runner_error(code, status=sc, default_code=code, op='http_exception')


@app.errorhandler(Exception)
def _handle_runner_unhandled_error(exc: Exception):
    return _runner_error(exc, status=500, default_code='runner_internal_error', op='unhandled')


def _load_internal_token() -> str:
    tok = (os.getenv('SDN_INTERNAL_TOKEN') or '').strip()
    if tok:
        return tok
    try:
        tok_path = os.path.join(PROJECT_ROOT, '.run', 'internal.token')
        if os.path.isfile(tok_path):
            with open(tok_path, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except Exception:
        pass
    return ''


@app.before_request
def _internal_auth_guard():
    if request.path == '/health':
        return None
    expected = _load_internal_token()
    if not expected:
        return _runner_error('unauthorized', status=401, default_code='unauthorized', op='auth')
    provided = (request.headers.get('X-Internal-Token') or '').strip()
    if not provided or not hmac.compare_digest(provided, expected):
        return _runner_error('unauthorized', status=401, default_code='unauthorized', op='auth')
    return None


# Top-Level Health & Status Routes
@app.get('/health')
def health():
    return jsonify({'ok': True})


@app.get('/status')
def status():
    net = _current_net()
    running = net is not None
    switches = [s.name for s in (getattr(net, 'switches', []) or [])] if running else []
    hosts = _host_inventory(net, _ha_state) if running else []
    pcap_proc = _current_pcap_proc()
    pcap_running = bool(pcap_proc and pcap_proc.poll() is None)
    st = _get_current_state()
    attack_st = _current_attack_state()
    is_busy = bool(_job_state.get('busy') or _job_state.get('is_busy') or attack_st.get('running'))
    ha_info = _ha_status()
    return jsonify({
        'ok': True,
        'running': running,
        'is_busy': is_busy,
        'current_state': st,
        'started_at': _current_started_at(),
        'topology': _current_topology(),
        'switches': switches,
        'hosts': hosts,
        'hosts_info': hosts,
        'attack': attack_st,
        'pcap_running': pcap_running,
        'last_pcap': _current_last_pcap_name(),
        'ha': ha_info.get('ha'),
        'ha_active_host': ha_info.get('active_host'),
        'job': dict(_job_state),
    })


# Modular Subsystem Route Registrations
register_ha_routes(app)
register_attack_cmd_routes(app)
register_pcap_routes(app)
register_job_routes(app)


@app.post('/scenario')
def scenario():
    return run_scenario()


def main():
    setLogLevel('warning')
    _pcap_startup_reconciliation()
    app.run(host=RUNNER_HOST, port=RUNNER_PORT, debug=False, threaded=True)


if __name__ == '__main__':
    main()
