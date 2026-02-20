"""
labs/ha_manager.py
High Availability (HA) VIP allocation and failover orchestration.
"""

import os
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

HA_AUTO_TEST_INTERVAL = int(os.getenv('HA_AUTO_TEST_INTERVAL', '10'))
HA_AUTO_REAPPLY_INTERVAL = int(os.getenv('HA_AUTO_REAPPLY_INTERVAL', '15'))

_ha_state: Dict[str, Any] = {
    'enabled': True,
    'vip_ip': '10.0.0.100',
    'service_port': 8000,
    'primary': 'h2',
    'backup': 'h3',
    'active': 'primary',
    'auto_test': True,
}
_ha_http_procs: Dict[str, Any] = {}
_ha_last_test: Optional[Dict[str, Any]] = None
_ha_last_applied: Dict[str, Any] = {'vip_ip': '', 'active': '', 'ts': 0.0}
_ha_auto_thread: Optional[threading.Thread] = None
_ha_auto_gen: int = 0


def get_vip_ip() -> Optional[str]:
    """Returns active VIP IP address if HA is enabled, else None."""
    if not _ha_state.get('enabled'):
        return None
    return str(_ha_state.get('vip_ip') or '').strip() or None


def use_vip_default(data: Dict[str, Any]) -> bool:
    """Checks whether default traffic should route to VIP."""
    if not isinstance(data, dict):
        return False
    if 'use_vip' in data:
        return bool(data.get('use_vip'))
    return bool(_ha_state.get('enabled'))


def ha_status() -> Dict[str, Any]:
    """Returns current HA cluster state, active node, running services, and last probe."""
    active = str(_ha_state.get('active') or 'primary')
    primary = str(_ha_state.get('primary') or 'h2')
    backup = str(_ha_state.get('backup') or 'h3')
    active_host = primary if active == 'primary' else backup
    return {
        'ok': True,
        'ha': dict(_ha_state),
        'active_host': active_host,
        'service_running': sorted([k for k, p in _ha_http_procs.items() if p and p.poll() is None]),
        'last_test': dict(_ha_last_test) if isinstance(_ha_last_test, dict) else None,
    }


def ha_ensure_hosts(net: Any) -> Tuple[Any, Any]:
    """Validates and resolves primary and backup host objects in topology."""
    hosts = list(net.hosts)
    if len(hosts) < 2:
        raise RuntimeError('ha_need_two_hosts')

    primary_name = str(_ha_state.get('primary') or '').strip()
    backup_name = str(_ha_state.get('backup') or '').strip()

    h_primary = None
    try:
        if primary_name:
            h_primary = net.get(primary_name)
    except Exception:
        h_primary = None
    if h_primary is None:
        h_primary = hosts[0]
        _ha_state['primary'] = h_primary.name

    h_backup = None
    try:
        if backup_name:
            h_backup = net.get(backup_name)
    except Exception:
        h_backup = None

    if h_backup is None or h_backup.name == h_primary.name:
        for h in hosts:
            if h.name != h_primary.name:
                h_backup = h
                _ha_state['backup'] = h_backup.name
                break

    if h_backup is None:
        raise RuntimeError('ha_backup_missing')

    active = str(_ha_state.get('active') or 'primary')
    if active not in ('primary', 'backup'):
        _ha_state['active'] = 'primary'

    return h_primary, h_backup


def ha_apply_active(net: Any) -> Dict[str, Any]:
    """Assigns VIP to currently designated active node, removes from inactive, and flushes ARP."""
    vip_ip = str(_ha_state.get('vip_ip') or '10.0.0.100')
    active = str(_ha_state.get('active') or 'primary')

    if active not in ('primary', 'backup'):
        active = 'primary'
        _ha_state['active'] = active

    h_primary, h_backup = ha_ensure_hosts(net)

    chosen = h_primary if active == 'primary' else h_backup
    other = h_backup if active == 'primary' else h_primary

    try:
        intf_chosen = str(chosen.defaultIntf() or '') if getattr(chosen, 'intfs', None) else ''
    except Exception:
        intf_chosen = ''
    try:
        intf_other = str(other.defaultIntf() or '') if getattr(other, 'intfs', None) else ''
    except Exception:
        intf_other = ''

    now = time.time()
    changed = (
        str(_ha_last_applied.get('vip_ip') or '') != str(vip_ip or '')
        or str(_ha_last_applied.get('active') or '') != str(active or '')
        or (now - float(_ha_last_applied.get('ts') or 0.0)) >= float(max(5, int(HA_AUTO_REAPPLY_INTERVAL)))
    )

    if changed:
        if intf_other:
            try:
                p_del = other.popen(
                    ['ip', 'addr', 'del', f'{vip_ip}/32', 'dev', intf_other],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                try:
                    p_del.wait(timeout=1.0)
                except Exception:
                    pass
            except Exception:
                pass
        if intf_chosen:
            try:
                p_add = chosen.popen(
                    ['ip', 'addr', 'add', f'{vip_ip}/32', 'dev', intf_chosen],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                try:
                    p_add.wait(timeout=1.0)
                except Exception:
                    pass
            except Exception:
                pass

        chosen_mac = None
        if hasattr(chosen, 'MAC') and callable(chosen.MAC):
            try:
                chosen_mac = str(chosen.MAC() or '').strip()
            except Exception:
                chosen_mac = None

        for h in list(getattr(net, 'hosts', []) or []):
            if getattr(h, 'name', None) == chosen.name:
                continue
            intf_name = ''
            if hasattr(h, 'defaultIntf') and callable(h.defaultIntf):
                try:
                    d_intf = h.defaultIntf()
                    intf_name = str(getattr(d_intf, 'name', d_intf) or '').strip()
                except Exception:
                    intf_name = ''

            # Direct namespace ARP update using ip neigh replace (bypasses Mininet PTY shell cmd/waitOutput)
            if hasattr(h, 'popen') and intf_name and chosen_mac:
                try:
                    p_arp = h.popen(
                        ['ip', 'neigh', 'replace', str(vip_ip), 'lladdr', str(chosen_mac), 'dev', intf_name, 'nud', 'permanent'],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    try:
                        p_arp.wait(timeout=0.5)
                    except Exception:
                        pass
                except Exception:
                    pass

        if intf_chosen:
            try:
                chosen.popen(
                    ['arping', '-U', '-c', '2', '-I', intf_chosen, vip_ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass

        _ha_last_applied['vip_ip'] = vip_ip
        _ha_last_applied['active'] = active
        _ha_last_applied['ts'] = now

    return {
        'vip_ip': vip_ip,
        'active': active,
        'active_host': chosen.name,
        'active_host_ip': chosen.IP(),
    }


def ha_start_service(net: Any) -> Dict[str, Any]:
    """Starts backend Python HTTP microservice on both primary and backup hosts."""
    port = int(_ha_state.get('service_port') or 8000)
    h_primary, h_backup = ha_ensure_hosts(net)
    started_hosts = []

    def _is_listening(host, listen_port: int) -> bool:
        hex_port = f':{listen_port:04X}'
        pids = []
        proc = _ha_http_procs.get(host.name)
        if proc and getattr(proc, 'pid', None):
            pids.append(proc.pid)
        if getattr(host, 'pid', None):
            pids.append(host.pid)
        for pid in pids:
            for fname in (f'/proc/{pid}/net/tcp', f'/proc/{pid}/net/tcp6'):
                try:
                    with open(fname, 'r', encoding='utf-8') as f:
                        for line in f.readlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 4 and parts[1].endswith(hex_port) and parts[3] == '0A':
                                return True
                except Exception:
                    continue
        return False

    def _start(host, label: str):
        ha_dir = f'/tmp/ha_{host.name}'
        os.makedirs(ha_dir, exist_ok=True)
        with open(os.path.join(ha_dir, 'index.html'), 'w', encoding='utf-8') as f:
            f.write(f'{label}\n')
        if (
            host.name in _ha_http_procs
            and _ha_http_procs[host.name]
            and _ha_http_procs[host.name].poll() is None
        ):
            return
        p = host.popen(
            ['python3', '-m', 'http.server', str(port)],
            cwd=ha_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _ha_http_procs[host.name] = p
        started_hosts.append(host)

    _start(h_primary, 'PRIMARY')
    _start(h_backup, 'BACKUP')

    if started_hosts:
        deadline = time.time() + 2.5
        while time.time() < deadline:
            ready = True
            for host in started_hosts:
                proc = _ha_http_procs.get(host.name)
                if proc is None or proc.poll() is not None:
                    continue
                if not _is_listening(host, port):
                    ready = False
                    break
            if ready:
                break
            time.sleep(0.05)

    return {'ok': True, 'port': port}


def ha_stop_service() -> Dict[str, Any]:
    """Terminates all running backend HTTP processes."""
    global _ha_http_procs
    for _name, p in list(_ha_http_procs.items()):
        try:
            if p and p.poll() is None:
                p.terminate()
        except Exception:
            pass
    _ha_http_procs = {}
    return {'ok': True, 'stopped': True}


def ha_test_vip(net: Any) -> Dict[str, Any]:
    """Tests HTTP VIP reachability from a non-cluster client host."""
    global _ha_last_test
    vip_ip = str(_ha_state.get('vip_ip') or '10.0.0.100')
    port = int(_ha_state.get('service_port') or 8000)

    hosts = list(net.hosts)
    if not hosts:
        raise RuntimeError('no_hosts')

    primary = str(_ha_state.get('primary') or '').strip()
    backup = str(_ha_state.get('backup') or '').strip()

    client = None
    for h in hosts:
        if h.name not in (primary, backup):
            client = h
            break
    if client is None:
        client = hosts[0]

    curl_cmd = ['curl', '-m', '1.5', '-s', f'http://{vip_ip}:{port}/']
    wget_cmd = ['wget', '-T', '1.5', '-qO-', f'http://{vip_ip}:{port}/']

    out = ''
    curl_attempted = False
    for cmd_args in (curl_cmd, wget_cmd):
        if curl_attempted:
            break
        p = None
        try:
            if cmd_args[0] == 'curl':
                curl_attempted = True
            p = client.popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            raw_out, _ = p.communicate(timeout=2.0)
            text = (
                raw_out.decode('utf-8', errors='ignore')
                if isinstance(raw_out, bytes)
                else str(raw_out or '')
            ).strip()
            if p.returncode == 0 and text:
                out = text
                break
        except subprocess.TimeoutExpired:
            if p is not None:
                try:
                    p.kill()
                    p.communicate()
                except Exception:
                    pass
            break
        except Exception:
            curl_attempted = False
            continue

    out = out[:64]
    vip_ok = bool(out)
    _ha_last_test = {
        'ts': time.time(),
        'client': client.name,
        'vip': vip_ip,
        'port': port,
        'vip_ok': vip_ok,
        'response': out,
    }
    return dict(_ha_last_test)


def ha_auto_loop(gen: int, get_net_fn: Any, state_lock: Any) -> None:
    """Background loop ensuring continuous VIP binding and HTTP service health."""
    while True:
        time.sleep(max(1, int(HA_AUTO_TEST_INTERVAL)))
        net = None
        with state_lock:
            if gen != _ha_auto_gen:
                return
            net = get_net_fn()
        if net is None:
            return
        try:
            with state_lock:
                ha_apply_active(net)
        except Exception:
            pass
        try:
            with state_lock:
                ha_start_service(net)
        except Exception:
            pass


# Backward Compatibility Aliases
_ha_status = ha_status
_ha_ensure_hosts = ha_ensure_hosts
_ha_apply_active = ha_apply_active
_ha_start_service = ha_start_service
_ha_stop_service = ha_stop_service
_ha_test_vip = ha_test_vip
_ha_auto_loop = ha_auto_loop
_get_vip_ip = get_vip_ip
_use_vip_default = use_vip_default
