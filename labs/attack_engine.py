"""
labs/attack_engine.py
Attack simulation engine for Mininet (SYN/UDP floods, ping tests).
"""

import os
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

ATTACK_MAX_ATTACKERS_WEAK = int(os.getenv('ATTACK_MAX_ATTACKERS_WEAK', '1'))
ATTACK_MAX_ATTACKERS_MEDIUM = int(os.getenv('ATTACK_MAX_ATTACKERS_MEDIUM', '3'))
ATTACK_MAX_ATTACKERS_STRONG = int(os.getenv('ATTACK_MAX_ATTACKERS_STRONG', '6'))

_attack_state: Optional[Dict[str, Any]] = None
_attack_procs: List[subprocess.Popen] = []


class AttackValidationError(Exception):
    def __init__(self, error: str, status: int = 400, **details):
        super().__init__(error)
        self.error = str(error)
        self.status = int(status)
        self.details = dict(details)


_AttackValidationError = AttackValidationError


def reserved_ha_names(ha_state: Optional[Dict[str, Any]] = None) -> Set[str]:
    """Returns set of host names reserved for HA cluster nodes."""
    state = ha_state or {}
    p = str(state.get('primary') or '').strip()
    b = str(state.get('backup') or '').strip()
    return {x for x in (p, b) if x}


def parse_preflight(data: Dict[str, Any]) -> Tuple[Set[str], int]:
    """Parses preflight validation payload containing blocked IPs and DDoS threshold."""
    pf = data.get('_preflight') if isinstance(data, dict) else None
    if not isinstance(pf, dict):
        return set(), 4
    raw_blocked = pf.get('blocked_ips') or []
    blocked = {str(ip).strip() for ip in raw_blocked if ip}
    try:
        min_ddos = max(1, int(pf.get('ddos_source_threshold') or 4))
    except Exception:
        min_ddos = 4
    return blocked, min_ddos


def pick_victim_and_attackers(
    net: Any,
    *,
    preferred_victim: str = 'h2',
    preferred_attacker: str = 'h1',
    blocked_ips: Optional[Set[str]] = None,
    ha_state: Optional[Dict[str, Any]] = None,
) -> Tuple[Any, Optional[Any], List[Any]]:
    """Selects valid victim host and pool of available attacker hosts."""
    linked_hosts = [h for h in list(net.hosts) if getattr(h, 'intfs', None) and h.IP()]
    if not linked_hosts:
        raise AttackValidationError('no_linked_hosts', 400)

    reserved_ha = reserved_ha_names(ha_state)
    blocked_set = set(blocked_ips or set())

    victim = None
    try:
        if preferred_victim:
            cand = net.get(preferred_victim)
            if cand in linked_hosts:
                victim = cand
    except Exception:
        victim = None

    if victim is None:
        victim = linked_hosts[0]

    attackers_pool = [
        h for h in linked_hosts
        if h.name != victim.name
        and h.name not in reserved_ha
        and h.IP() not in blocked_set
    ]

    attacker = None
    if preferred_attacker:
        for h in attackers_pool:
            if h.name == preferred_attacker:
                attacker = h
                break

    if attacker is None and attackers_pool:
        attacker = attackers_pool[0]

    return victim, attacker, attackers_pool


def attack_status(pcap_proc: Optional[Any] = None, last_pcap_name: Optional[str] = None) -> Dict[str, Any]:
    """Returns current attack running status and metadata."""
    running = bool(_attack_state and _attack_state.get('running'))
    pcap_running = bool(pcap_proc and pcap_proc.poll() is None)
    return {
        'ok': True,
        'running': running,
        'attack': _attack_state,
        'pcap_running': pcap_running,
        'last_pcap': last_pcap_name,
    }


def stop_attack(net: Any, stop_pcap_fn: Optional[Any] = None, pcap_proc: Optional[Any] = None, last_pcap_name: Optional[str] = None) -> Dict[str, Any]:
    """Stops all active attack processes, kills leftover traffic generators, and halts PCAP capture."""
    global _attack_state, _attack_procs

    try:
        for p in list(_attack_procs):
            try:
                if p and p.poll() is None:
                    p.terminate()
            except Exception:
                pass
    except Exception:
        pass

    try:
        time.sleep(0.05)
        for p in list(_attack_procs):
            try:
                if p and p.poll() is None:
                    p.kill()
            except Exception:
                pass
    except Exception:
        pass
    _attack_procs = []

    if hasattr(net, 'hosts'):
        for h in list(getattr(net, 'hosts', []) or []):
            if hasattr(h, 'popen'):
                try:
                    p_k = h.popen(['pkill', '-9', '-f', 'hping3|ping|iperf'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        p_k.wait(timeout=0.1)
                    except Exception:
                        pass
                except Exception:
                    pass

    if stop_pcap_fn:
        try:
            stop_pcap_fn()
        except Exception:
            pass

    if isinstance(_attack_state, dict):
        _attack_state['running'] = False
        _attack_state['stopped_at'] = time.time()

    return attack_status(pcap_proc=pcap_proc, last_pcap_name=last_pcap_name)


def run_attack_preset(
    net: Any,
    *,
    kind: str,
    profile: str,
    duration: int,
    mixed: bool,
    capture: bool,
    proto: str,
    blocked_ips: Optional[Set[str]] = None,
    min_ddos_sources: int = 4,
    get_vip_fn: Optional[Any] = None,
    apply_active_fn: Optional[Any] = None,
    start_pcap_fn: Optional[Any] = None,
    ha_state: Optional[Dict[str, Any]] = None,
    state_lock: Optional[Any] = None,
    attackers_override: Optional[List[str]] = None,
    preferred_victim: Optional[str] = None,
) -> Dict[str, Any]:
    """Generates and launches bounded attack scenario across Mininet hosts."""
    global _attack_procs, _attack_state
    kind = str(kind or 'ddos').lower()
    profile = str(profile or 'medium').lower()
    proto = str(proto or 'syn').lower()
    duration = int(duration or 30)
    mixed = bool(mixed)
    capture = bool(capture)

    if duration < 1:
        duration = 1

    if not shutil.which('hping3'):
        raise RuntimeError('hping3_not_installed')

    reserved_ha = reserved_ha_names(ha_state)
    target_victim = (preferred_victim or '').strip() or 'h2'
    victim_host, _, attackers_pool = pick_victim_and_attackers(
        net, preferred_victim=target_victim, preferred_attacker='h1', blocked_ips=blocked_ips, ha_state=ha_state
    )
    victim_ip = victim_host.IP()
    if get_vip_fn:
        vip_ip = get_vip_fn()
        if vip_ip:
            if apply_active_fn:
                try:
                    apply_active_fn(net)
                except Exception:
                    pass
            victim_ip = str(vip_ip)

    hosts = attackers_pool
    required_min = max(1, int(min_ddos_sources or 4)) if kind == 'ddos' else 1

    if profile == 'weak':
        n_attackers = max(1, int(ATTACK_MAX_ATTACKERS_WEAK))
        interval_us = 2500
        flood = False
    elif profile == 'strong':
        n_attackers = max(1, int(ATTACK_MAX_ATTACKERS_STRONG))
        interval_us = 1200
        flood = False
    else:
        n_attackers = max(1, int(ATTACK_MAX_ATTACKERS_MEDIUM))
        interval_us = 1800
        flood = False

    if attackers_override:
        selected_attackers = []
        pool_by_name = {h.name: h for h in attackers_pool}
        blocked_set = set(blocked_ips or set())
        for a_name in attackers_override:
            s_name = str(a_name or '').strip()
            if not s_name:
                continue
            if s_name == victim_host.name:
                raise AttackValidationError('victim_in_attackers', 400, victim=s_name)
            if s_name in reserved_ha:
                raise AttackValidationError('attacker_reserved_role', 400, attacker=s_name)
            if s_name in pool_by_name:
                selected_attackers.append(pool_by_name[s_name])
            else:
                try:
                    cand = net.get(s_name)
                    if cand and getattr(cand, 'IP', None) and cand.IP() in blocked_set:
                        raise AttackValidationError('attacker_blocked', 400, attacker=s_name, ip=cand.IP())
                except AttackValidationError:
                    raise
                except Exception:
                    pass
                raise AttackValidationError('attacker_not_linked', 400, attacker=s_name)

        if len(selected_attackers) < required_min:
            raise AttackValidationError(
                'insufficient_attackers',
                400,
                required=required_min,
                available=len(selected_attackers),
                available_hosts=[h.name for h in selected_attackers],
                excluded_ha=sorted(reserved_ha),
            )
        attackers = selected_attackers
        legit = []
    else:
        if len(hosts) < required_min:
            raise AttackValidationError(
                'insufficient_attackers',
                400,
                required=required_min,
                available=len(hosts),
                available_hosts=[h.name for h in hosts],
                excluded_ha=sorted(reserved_ha),
            )

        if kind == 'dos':
            n_attackers = 1

        n_attackers = min(n_attackers, len(hosts))
        attackers = hosts[:n_attackers]
        legit = hosts[n_attackers:]
        if mixed and legit:
            legit = legit[:max(1, min(6, len(legit)))]
        else:
            legit = []

    pcap_name = None
    if capture and start_pcap_fn:
        pcap_name = start_pcap_fn(duration, victim_ip=victim_ip)

    for h in legit:
        try:
            p = h.popen(
                ['ping', '-i', '0.2', '-c', str(duration * 5), victim_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _attack_procs.append(p)
        except Exception:
            pass

    safe_interval = max(1000, interval_us) if not flood else 1000
    for h in attackers:
        if proto == 'udp':
            cmd_args = ['timeout', str(duration), 'hping3', '-2', '-p', '80', '-i', f'u{safe_interval}', '-q', victim_ip]
        else:
            cmd_args = ['timeout', str(duration), 'hping3', '-S', '-p', '80', '-i', f'u{safe_interval}', '-q', victim_ip]

        try:
            p = h.popen(cmd_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _attack_procs.append(p)
        except Exception:
            pass

    _attack_state = {
        'running': True,
        'kind': kind,
        'profile': profile,
        'mixed': mixed,
        'proto': proto,
        'duration': duration,
        'started_at': time.time(),
        'victim': victim_host.name,
        'victim_ip': victim_ip,
        'attackers': [h.name for h in attackers],
        'attacker_ips': [h.IP() for h in attackers],
        'legitimate': [h.name for h in legit],
        'pcap': pcap_name,
    }

    def _clear_later():
        global _attack_state
        time.sleep(max(1, int(duration)))
        if state_lock:
            with state_lock:
                if _attack_state:
                    _attack_state['running'] = False
                try:
                    from labs.topology import get_current_state, set_current_state, LabState
                    if get_current_state() == LabState.ATTACK_RUNNING:
                        set_current_state(LabState.LAB_READY, "Lab ready (attack completed)")
                except Exception:
                    pass
        else:
            if _attack_state:
                _attack_state['running'] = False

    threading.Thread(target=_clear_later, daemon=True).start()
    return {'ok': True, **attack_status(last_pcap_name=pcap_name)}


# Backward Compatibility Aliases
_reserved_ha_names = reserved_ha_names
_parse_preflight = parse_preflight
_pick_victim_and_attackers = pick_victim_and_attackers
_run_attack_preset = run_attack_preset
_attack_status = attack_status
_stop_attack = stop_attack
