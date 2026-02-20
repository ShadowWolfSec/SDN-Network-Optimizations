"""
labs/scenario_engine.py
Attack scenario execution engine for Mininet simulation workflows.
"""

import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from flask import jsonify, request

from labs import attack_engine
from labs.attack_engine import (
    AttackValidationError,
    _AttackValidationError,
    parse_preflight,
    pick_victim_and_attackers,
    reserved_ha_names,
    run_attack_preset,
    stop_attack,
    attack_status,
)
from labs.ha_manager import (
    _ha_state,
    get_vip_ip,
    ha_apply_active,
    use_vip_default,
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
    get_current_state,
    get_job_state,
    release_lock,
    require_net,
    set_current_state,
)

ALLOWED_SCENARIOS = {
    'demo_normal', 'normal', 'syn_flood', 'udp_flood', 'icmp_flood',
    'portscan', 'demo_dos', 'demo_ddos_medium', 'demo_ddos_massive',
}


def _get_runner_error_fn():
    from labs.mininet_runner import _runner_error
    return _runner_error


def _get_busy_resp_fn():
    from labs.mininet_runner import _busy_resp
    return _busy_resp


def _runner_error(err_or_exc, status=500, default_code='runner_internal_error', op='scenario', extra=None):
    return _get_runner_error_fn()(err_or_exc, status=status, default_code=default_code, op=op, extra=extra)


def _busy_resp():
    return _get_busy_resp_fn()()


def run_scenario(data: Optional[Dict[str, Any]] = None) -> Any:
    """Validates parameters, allocates hosts, and executes scenario attack traffic."""
    if data is None:
        try:
            data = request.get_json(silent=True) or {}
        except Exception:
            data = {}

    name = str(data.get('name') or '').strip().lower()
    if name not in ALLOWED_SCENARIOS:
        return _runner_error('unknown_scenario', status=400, default_code='unknown_scenario', op='scenario')

    try:
        duration = int(data.get('duration') or 20)
    except Exception:
        duration = 20
    duration = max(1, min(300, duration))

    proto = str(data.get('proto') or 'syn').lower()
    capture = bool(data.get('capture') or False)
    force = bool(data.get('force') or False)
    blocked_ips, min_ddos = parse_preflight(data)
    preferred_victim = str(data.get('victim') or '').strip()
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

    if not acquire_lock(2.5):
        return _busy_resp()
    try:
        job_state = get_job_state()
        if bool(job_state.get('busy')):
            return _busy_resp()
        try:
            net = require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='scenario')

        attack_st = getattr(attack_engine, '_attack_state', None)
        if bool(attack_st and attack_st.get('running')) and not force:
            return _runner_error('attack_already_running', status=409, default_code='attack_already_running', op='scenario')

        if name in ('demo_dos', 'demo_ddos_medium', 'demo_ddos_massive'):
            preset_map = {
                'demo_dos': ('dos', 'medium', False),
                'demo_ddos_medium': ('ddos', 'medium', True),
                'demo_ddos_massive': ('ddos', 'strong', True),
            }
            kind, profile, mixed = preset_map[name]
            try:
                try:
                    stop_attack(net, stop_active_pcap, get_pcap_proc(), get_last_pcap_name())
                except Exception:
                    pass
                out = run_attack_preset(
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
                    preferred_victim=preferred_victim or None,
                )
                return jsonify(out)
            except (AttackValidationError, _AttackValidationError) as e:
                return _runner_error(e.error, status=e.status, default_code='invalid_request', op='scenario', extra=e.details)
            except RuntimeError as e:
                return _runner_error(e, status=400, default_code='invalid_request', op='scenario')
            except Exception as e:
                return _runner_error(e, status=500, default_code='runner_internal_error', op='scenario')

        reserved_ha = reserved_ha_names(_ha_state)
        is_normal = name in ('demo_normal', 'normal')
        try:
            victim_host = None
            if preferred_victim:
                try:
                    victim_host = net.get(preferred_victim)
                except Exception:
                    victim_host = None
                if victim_host is None:
                    return _runner_error('victim_not_found', status=400, op='scenario', extra={'victim': preferred_victim})
            else:
                try:
                    victim_host, _, _ = pick_victim_and_attackers(
                        net, preferred_victim='h2', preferred_attacker='h1', blocked_ips=blocked_ips, ha_state=_ha_state
                    )
                except (AttackValidationError, _AttackValidationError) as e:
                    return _runner_error(e.error, status=e.status, default_code='invalid_request', op='scenario', extra=e.details)
                except Exception as e:
                    return _runner_error(e, status=400, default_code='need_hosts', op='scenario')

            if not getattr(victim_host, 'intfs', None) or not victim_host.IP():
                return _runner_error('victim_not_linked', status=400, op='scenario', extra={'victim': victim_host.name})

            if not attackers_names:
                try:
                    _, attacker_host, _ = pick_victim_and_attackers(
                        net,
                        preferred_victim=victim_host.name,
                        preferred_attacker='h1',
                        blocked_ips=None if is_normal else blocked_ips,
                        ha_state=_ha_state,
                    )
                except (AttackValidationError, _AttackValidationError) as e:
                    return _runner_error(e.error, status=e.status, default_code='invalid_request', op='scenario', extra=e.details)
                except Exception:
                    attacker_host = None
                if attacker_host is None:
                    return _runner_error('no_attackers_available', status=400, op='scenario', extra={'excluded_ha': sorted(reserved_ha)})
                attackers_hosts = [attacker_host]
            else:
                attackers_hosts = []
                for hn in attackers_names:
                    try:
                        h = net.get(hn)
                    except Exception:
                        h = None
                    if h is None:
                        return _runner_error('attacker_not_found', status=400, op='scenario', extra={'attacker': hn})
                    if h.name == victim_host.name:
                        return _runner_error('victim_in_attackers', status=400, op='scenario', extra={'victim': victim_host.name})
                    if h.name in reserved_ha:
                        return _runner_error('attacker_reserved_role', status=400, op='scenario', extra={'attacker': h.name, 'excluded_ha': sorted(reserved_ha)})
                    if not getattr(h, 'intfs', None) or not h.IP():
                        return _runner_error('attacker_not_linked', status=400, op='scenario', extra={'attacker': h.name})
                    if (not is_normal) and h.IP() in blocked_ips:
                        return _runner_error('attacker_blocked', status=400, op='scenario', extra={'attacker': h.name, 'ip': h.IP()})
                    attackers_hosts.append(h)
                if not attackers_hosts:
                    return _runner_error('no_attackers_available', status=400, op='scenario')

            victim = victim_host.IP()
        except Exception as e:
            return _runner_error(e, status=400, default_code='need_hosts', op='scenario')

        try:
            stop_attack(net, stop_active_pcap, get_pcap_proc(), get_last_pcap_name())
        except Exception:
            pass

        if use_vip_default(data):
            vip_ip = get_vip_ip()
            if vip_ip:
                try:
                    ha_apply_active(net)
                except Exception:
                    pass
                victim = str(vip_ip)

        attack_engine._attack_state = {
            'running': True,
            'kind': 'scenario',
            'name': name,
            'proto': proto,
            'duration': duration,
            'started_at': time.time(),
            'victim': victim_host.name,
            'victim_ip': victim,
            'attackers': [h.name for h in attackers_hosts],
            'attacker_ips': [h.IP() for h in attackers_hosts],
            'legitimate': [],
            'pcap': None,
        }
        try:
            import labs.mininet_runner as mr
            mr._attack_state = attack_engine._attack_state
        except Exception:
            pass

        if capture:
            try:
                attack_engine._attack_state['pcap'] = start_pcap(duration, victim_ip=victim)
            except Exception:
                attack_engine._attack_state['pcap'] = None
            try:
                import labs.mininet_runner as mr
                mr._attack_state = attack_engine._attack_state
            except Exception:
                pass

        if name in ('demo_normal', 'normal'):
            for h in attackers_hosts:
                p = h.popen(['ping', '-i', '0.2', '-c', str(duration * 5), victim],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                attack_engine._attack_procs.append(p)
        elif name == 'syn_flood':
            for h in attackers_hosts:
                p = h.popen(['timeout', str(duration), 'hping3', '-S', '-p', '80', '-i', 'u1500', '-q', victim],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                attack_engine._attack_procs.append(p)
        elif name == 'udp_flood':
            for h in attackers_hosts:
                p = h.popen(['timeout', str(duration), 'hping3', '-2', '-p', '80', '-i', 'u1500', '-q', victim],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                attack_engine._attack_procs.append(p)
        elif name == 'icmp_flood':
            for h in attackers_hosts:
                p = h.popen(['timeout', str(duration), 'hping3', '-1', '-i', 'u1500', '-q', victim],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                attack_engine._attack_procs.append(p)
        elif name == 'portscan':
            dur = min(30, max(1, duration))
            for h in attackers_hosts:
                p = h.popen(['timeout', str(dur), 'hping3', '-S', '-p', '++1', '-i', 'u8000', '-q', victim],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                attack_engine._attack_procs.append(p)

        try:
            import labs.mininet_runner as mr
            mr._attack_procs = attack_engine._attack_procs
        except Exception:
            pass

        def _clear_later():
            time.sleep(max(1, int(duration)))
            with _state_lock:
                if isinstance(attack_engine._attack_state, dict) and attack_engine._attack_state.get('kind') == 'scenario' and attack_engine._attack_state.get('name') == name:
                    attack_engine._attack_state['running'] = False
                    try:
                        import labs.mininet_runner as mr
                        mr._attack_state = attack_engine._attack_state
                    except Exception:
                        pass
                if get_current_state() == LabState.ATTACK_RUNNING:
                    set_current_state(LabState.LAB_READY, "Lab ready (scenario completed)")

        threading.Thread(target=_clear_later, daemon=True).start()
        set_current_state(LabState.ATTACK_RUNNING, f"Scenario {name} running")
        return jsonify({'ok': True, **attack_status(get_pcap_proc(), get_last_pcap_name())})
    finally:
        release_lock()


execute_scenario = run_scenario
