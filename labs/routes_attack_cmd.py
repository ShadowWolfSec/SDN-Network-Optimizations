"""
labs/routes_attack_cmd.py
Flask route endpoints for attack simulation and diagnostic commands.
"""

import logging
import sys
from typing import Any, Dict, List, Optional

from flask import Flask, current_app, g, jsonify, request

from labs import attack_engine
from labs.attack_engine import (
    AttackValidationError,
    _AttackValidationError,
    attack_status as get_attack_status,
    parse_preflight,
    pick_victim_and_attackers,
    run_attack_preset,
    stop_attack,
)
from labs.cmd_console import (
    execute_cmd_iperf,
    execute_cmd_ping,
    ovs_dump_flows,
    parse_ovs_flow_line,
    safe_name,
    truncate_output,
)
from labs.ha_manager import (
    _ha_state,
    get_vip_ip,
    ha_apply_active,
)
from labs.pcap_manager import (
    get_last_pcap_name,
    get_pcap_proc,
    start_pcap,
    stop_active_pcap,
)
from labs.topology import (
    LabState,
    _state_lock,
    acquire_lock,
    get_job_state,
    require_net,
    set_current_state,
)

logger = logging.getLogger('attack_cmd_routes')


def _runner_func(name: str, fallback: Any) -> Any:
    """Dynamically resolves function from mininet_runner to honor test mocks/patches."""
    mod = sys.modules.get('labs.mininet_runner')
    if mod is not None and hasattr(mod, name):
        return getattr(mod, name)
    return fallback


def _runner_req_id() -> str:
    try:
        return str(getattr(g, 'request_id', '') or '')
    except Exception:
        return ''


def _get_runner_error_fn():
    from labs.mininet_runner import _runner_error
    return _runner_error


def _get_busy_resp_fn():
    from labs.mininet_runner import _busy_resp
    return _busy_resp


def _runner_error(err_or_exc, status=500, default_code='runner_internal_error', op='runner', extra=None):
    return _get_runner_error_fn()(err_or_exc, status=status, default_code=default_code, op=op, extra=extra)


def _busy_resp():
    return _get_busy_resp_fn()()


def ovs_flows():
    """Dumps and parses OpenFlow flow entries from switch."""
    if not acquire_lock(0.5):
        return _busy_resp()
    try:
        try:
            net = require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='ovs_flows')
        switches = [s.name for s in net.switches]
    finally:
        _state_lock.release()

    sw_param = (request.args.get('switch') or '').strip()
    target_sw = sw_param if sw_param in switches else (switches[0] if switches else '')
    if not target_sw:
        return jsonify({'ok': True, 'switch': '', 'switches': switches, 'flows': []})

    dump_fn = _runner_func('_ovs_dump_flows', ovs_dump_flows)
    out, err = dump_fn(target_sw)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    flows = []
    parse_fn = _runner_func('_parse_ovs_flow_line', parse_ovs_flow_line)
    for line in lines:
        f = parse_fn(line)
        if f:
            flows.append(f)
    return jsonify({
        'ok': True,
        'switch': target_sw,
        'switches': switches,
        'flow_count': len(flows),
        'flows': flows,
        'raw': lines,
        'stderr': err,
    })


def cmd_run():
    """Executes safe diagnostic commands (ping, iperf, ovs_dump_flows) on simulated topology."""
    data = request.get_json(silent=True) or {}
    cmd_type = str(data.get('type') or '').strip().lower()
    if not _state_lock.acquire(blocking=False):
        return _busy_resp()
    try:
        try:
            net = require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='cmd_run')

        if cmd_type == 'ping':
            res, code = execute_cmd_ping(net, data, pick_victim_and_attackers)
            return jsonify(res), code

        if cmd_type in ('iperf_tcp', 'iperf_udp'):
            res, code = execute_cmd_iperf(net, data, cmd_type, pick_victim_and_attackers)
            return jsonify(res), code

        if cmd_type == 'ovs_dump_flows':
            sw_raw = (data.get('switch') or '').strip()
            sw = safe_name(sw_raw) if sw_raw else (net.switches[0].name if net.switches else 's1')
            if not sw:
                return _runner_error('missing_switch', status=400, default_code='missing_switch', op='cmd_run')
            if sw not in [s.name for s in net.switches]:
                return _runner_error('switch_not_found', status=400, default_code='switch_not_found', op='cmd_run')
            dump_fn = _runner_func('_ovs_dump_flows', ovs_dump_flows)
            out, err = dump_fn(sw)
            safe_err = ''
            if err:
                try:
                    current_app.logger.warning('[req=%s] cmd_run ovs_dump_flows(%s) stderr: %s', _runner_req_id(), sw, truncate_output(err, 400))
                except Exception:
                    logger.warning('[req=%s] cmd_run ovs_dump_flows(%s) stderr: %s', _runner_req_id(), sw, truncate_output(err, 400))
                safe_err = 'ovs_dump_failed'
            return jsonify({'ok': True, 'type': cmd_type, 'switch': sw, 'output': truncate_output(out), 'error': safe_err})

        return jsonify({'ok': False, 'error': 'unknown_command_type'}), 400
    finally:
        _state_lock.release()


def attack_status():
    """Returns current attack running status and metadata."""
    fn = _runner_func('_attack_status', get_attack_status)
    pcap_proc = get_pcap_proc()
    last_pcap = get_last_pcap_name()
    return jsonify(fn(pcap_proc, last_pcap))


def attack_run():
    """Validates parameters, checks preflight status, and triggers DoS/DDoS attack preset."""
    data = request.get_json(silent=True) or {}
    kind = str(data.get('kind') or 'ddos').lower()
    profile = str(data.get('profile') or 'medium').lower()
    proto = str(data.get('proto') or 'syn').lower()
    try:
        duration = int(data.get('duration') or 30)
    except Exception:
        duration = 30
    mixed = bool(data.get('mixed') or False)
    capture = bool(data.get('capture') or False)
    force = bool(data.get('force') or False)
    blocked_ips, min_ddos = parse_preflight(data)
    attackers_raw = data.get('attackers')
    attackers_names = []
    if isinstance(attackers_raw, list):
        for v in attackers_raw:
            try:
                s = str(v or '').strip()
            except Exception:
                s = ''
            if s and s not in attackers_names:
                attackers_names.append(s)
    preferred_victim = str(data.get('victim') or '').strip() or None

    if not acquire_lock(2.5):
        return _busy_resp()
    try:
        job_state = get_job_state()
        if bool(job_state.get('busy')):
            return _busy_resp()
        try:
            net = require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='attack_run')

        attack_st = getattr(attack_engine, '_attack_state', None)
        if bool(attack_st and attack_st.get('running')) and not force:
            return _runner_error('attack_already_running', status=409, default_code='attack_already_running', op='attack_run')

        try:
            preset_fn = _runner_func('_run_attack_preset', run_attack_preset)
            out = preset_fn(
                net,
                kind=kind,
                profile=profile,
                duration=duration,
                mixed=mixed,
                capture=capture,
                proto=proto,
                blocked_ips=blocked_ips,
                min_ddos_sources=min_ddos,
                get_vip_fn=get_vip_ip,
                apply_active_fn=ha_apply_active,
                start_pcap_fn=start_pcap,
                ha_state=_ha_state,
                state_lock=_state_lock,
                attackers_override=attackers_names or None,
                preferred_victim=preferred_victim,
            )
            set_current_state(LabState.ATTACK_RUNNING, f"Attack {kind} ({profile}) running")
            try:
                import labs.mininet_runner as mr
                mr._attack_state = attack_engine._attack_state
            except Exception:
                pass
            return jsonify(out)
        except (AttackValidationError, _AttackValidationError) as e:
            return _runner_error(e.error, status=e.status, default_code='invalid_request', op='attack_run', extra=e.details)
        except RuntimeError as e:
            return _runner_error(e, status=400, default_code='invalid_request', op='attack_run')
        except Exception as e:
            return _runner_error(e, status=500, default_code='runner_internal_error', op='attack_run')
    finally:
        _state_lock.release()


def attack_stop():
    """Halts all active attack processes and halts any running PCAP capture."""
    if not acquire_lock(2.5):
        return _busy_resp()
    try:
        try:
            net = require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='attack_stop')
        stop_fn = _runner_func('_stop_attack', stop_attack)
        out = stop_fn(net, stop_active_pcap, get_pcap_proc(), get_last_pcap_name())
        set_current_state(LabState.LAB_READY, "Lab ready (attack stopped)")
        try:
            import labs.mininet_runner as mr
            mr._attack_state = attack_engine._attack_state
        except Exception:
            pass
        return jsonify(out)
    finally:
        _state_lock.release()


def register_attack_cmd_routes(app: Flask) -> None:
    """Registers Attack and Diagnostic Command endpoints directly onto the Flask application."""
    app.add_url_rule('/ovs/flows', 'ovs_flows', ovs_flows, methods=['GET'])
    app.add_url_rule('/cmd/run', 'cmd_run', cmd_run, methods=['POST'])
    app.add_url_rule('/attack/status', 'attack_status', attack_status, methods=['GET'])
    app.add_url_rule('/attack/run', 'attack_run', attack_run, methods=['POST'])
    app.add_url_rule('/attack/stop', 'attack_stop', attack_stop, methods=['POST'])
