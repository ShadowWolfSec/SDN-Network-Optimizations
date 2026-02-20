"""
labs/topology.py
Mininet network topology lifecycle manager and OpenFlow bridge configuration.
"""

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.link import TCLink
    from mininet.log import setLogLevel
except ImportError:
    Mininet = Any  # type: ignore
    RemoteController = Any  # type: ignore
    OVSSwitch = Any  # type: ignore
    TCLink = Any  # type: ignore
    setLogLevel = lambda *a, **kw: None

logger = logging.getLogger('topology')

DEFAULT_CONTROLLER_IP = os.getenv('CONTROLLER_IP', '127.0.0.1')
DEFAULT_CONTROLLER_PORT = int(os.getenv('CONTROLLER_PORT', '6653'))

OVS_STP_ENABLE = str(os.getenv('OVS_STP_ENABLE', '1')).strip().lower() in ('1', 'true', 'yes', 'on')
OVS_RSTP_ENABLE = str(os.getenv('OVS_RSTP_ENABLE', '1')).strip().lower() in ('1', 'true', 'yes', 'on')

# The Single Source of Truth for Network State
_state_lock = threading.RLock()
_net: Optional[Mininet] = None
_topology: Optional[Dict[str, Any]] = None
_started_at: Optional[float] = None

class LabState:
    IDLE = 'IDLE'
    BUILDING_LAB = 'BUILDING_LAB'
    LAB_READY = 'LAB_READY'
    ATTACK_RUNNING = 'ATTACK_RUNNING'
    DEMO_RUNNING = 'DEMO_RUNNING'
    STOPPING = 'STOPPING'
    ERROR = 'ERROR'

_current_state: str = LabState.IDLE
_state_message: str = 'System idle'

_job_state: Dict[str, Any] = {
    'busy': False,
    'is_busy': False,
    'op': '',
    'current_state': LabState.IDLE,
    'started_at': None,
    'finished_at': None,
    'error': None,
    'result': None,
    'gen': 0,
    'task_id': None,
}


def get_current_state() -> str:
    global _current_state
    if _job_state.get('busy'):
        op = str(_job_state.get('op') or '')
        if op == 'build':
            return LabState.BUILDING_LAB
        if op == 'stop':
            return LabState.STOPPING
        if op == 'demo':
            return LabState.DEMO_RUNNING
    try:
        from labs import attack_engine
        if getattr(attack_engine, '_attack_state', None) and isinstance(attack_engine._attack_state, dict) and attack_engine._attack_state.get('running'):
            return LabState.ATTACK_RUNNING
    except Exception:
        pass
    if _job_state.get('error'):
        return LabState.ERROR
    if _net is not None:
        return LabState.LAB_READY
    return LabState.IDLE


def set_current_state(state: str, message: str = '') -> None:
    global _current_state, _state_message
    _current_state = state
    _state_message = message


def acquire_lock(timeout_s: float = 1.5) -> bool:
    try:
        return _state_lock.acquire(timeout=float(timeout_s))
    except TypeError:
        return _state_lock.acquire(blocking=True)


def release_lock() -> None:
    try:
        _state_lock.release()
    except RuntimeError:
        pass


def require_net() -> Mininet:
    global _net
    if _net is None:
        raise RuntimeError('network_not_built')
    return _net


def get_net() -> Optional[Mininet]:
    return _net


def get_topology() -> Optional[Dict[str, Any]]:
    return _topology


def get_started_at() -> Optional[float]:
    return _started_at


def get_job_state() -> Dict[str, Any]:
    return dict(_job_state)


def normalize_delay_ms(delay_ms: Optional[float]) -> Optional[str]:
    if delay_ms is None:
        return None
    try:
        v = float(delay_ms)
    except Exception:
        return None
    if v < 0:
        v = 0
    return f"{v}ms"


def find_link_by_endpoints(net: Mininet, a: str, b: str) -> Optional[Any]:
    a = str(a)
    b = str(b)
    for link in list(getattr(net, 'links', [])):
        try:
            n1 = link.intf1.node.name
            n2 = link.intf2.node.name
        except Exception:
            continue
        if {n1, n2} == {a, b}:
            return link
    return None


def apply_link_config(link: Any, bw: Optional[float], delay_ms: Optional[float], loss: Optional[float]) -> None:
    delay = normalize_delay_ms(delay_ms)
    params: Dict[str, Any] = {}
    if bw is not None:
        params['bw'] = float(bw)
    if delay is not None:
        params['delay'] = delay
    if loss is not None:
        params['loss'] = float(loss)

    try:
        link.intf1.config(**params)
    except Exception:
        pass
    try:
        link.intf2.config(**params)
    except Exception:
        pass


def normalize_topology(topology: Dict[str, Any]) -> Tuple[Dict[str, Any], str, int, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Normalize nested or flat topology dicts into (topology, ctrl_ip, ctrl_port, nodes, links)."""
    from labs.cmd_console import safe_name

    if 'topology' in topology and isinstance(topology['topology'], dict):
        topology = topology['topology']

    controller_ip = str(topology.get('controller_ip') or DEFAULT_CONTROLLER_IP)
    controller_port = int(topology.get('controller_port') or DEFAULT_CONTROLLER_PORT)

    raw_nodes = topology.get('nodes') or []
    raw_links = topology.get('links') or []

    nodes = []
    seen_nodes = set()
    for n in raw_nodes:
        item = None
        if isinstance(n, str):
            if n.startswith('s'):
                item = {'name': n, 'type': 'switch'}
            elif n.startswith('h'):
                item = {'name': n, 'type': 'host'}
        elif isinstance(n, dict):
            item = dict(n)
        if not item:
            continue
        name = safe_name(str(item.get('name') or ''))
        if not name or name in seen_nodes:
            continue
        seen_nodes.add(name)
        item['name'] = name
        item['type'] = str(item.get('type') or ('switch' if name.startswith('s') else 'host')).lower()
        nodes.append(item)

    if len(nodes) > 100:
        raise ValueError('too_many_nodes_max_100')

    links = []
    seen_edges = set()
    for l in raw_links:
        item = None
        if isinstance(l, dict):
            item = dict(l)
        elif isinstance(l, str) and '-' in l:
            parts = l.split('-')
            if len(parts) == 2:
                item = {'a': parts[0], 'b': parts[1]}
        if not item:
            continue
        a = safe_name(str(item.get('a') or ''))
        b = safe_name(str(item.get('b') or ''))
        if not a or not b or a == b:
            continue
        edge = frozenset((a, b))
        if edge in seen_edges:
            continue
        seen_edges.add(edge)
        item['a'] = a
        item['b'] = b
        links.append(item)

    return topology, controller_ip, controller_port, nodes, links


def configure_ovs_stp(switch_names: List[str], *, wait_if_applied: bool = True) -> None:
    stp_single = str(os.getenv('OVS_STP_SINGLE_SWITCH', '0')).strip() == '1'
    if not (OVS_STP_ENABLE and shutil.which('ovs-vsctl') and (len(switch_names) > 1 or stp_single)):
        return
    stp_applied = False
    for sname in switch_names:
        try:
            subprocess.run(
                ['ovs-vsctl', 'set', 'Bridge', sname, 'stp_enable=true'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            stp_applied = True
        except Exception:
            pass
        if OVS_RSTP_ENABLE:
            try:
                subprocess.run(
                    ['ovs-vsctl', 'set', 'Bridge', sname, 'rstp_enable=true'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass
    if stp_applied and wait_if_applied:
        try:
            rstp_wait = max(0.5, float(os.getenv('OVS_RSTP_WAIT_SEC', '4.2') or 4.2))
        except Exception:
            rstp_wait = 4.2
        time.sleep(rstp_wait)


def apply_static_arp_all(net: Mininet) -> None:
    hosts = list(getattr(net, 'hosts', []) or [])
    for src in hosts:
        if not getattr(src, 'intfs', None):
            continue
        if not src.IP() or not src.MAC():
            continue
        intf_name = src.defaultIntf().name if (hasattr(src, 'defaultIntf') and src.defaultIntf()) else (src.intfNames()[0] if hasattr(src, 'intfNames') and src.intfNames() else 'eth0')
        for dst in hosts:
            if src == dst or not getattr(dst, 'intfs', None):
                continue
            dip = dst.IP()
            dmac = dst.MAC()
            if dip and dmac:
                try:
                    if hasattr(src, 'popen'):
                        p = src.popen(
                            ['ip', 'neigh', 'replace', str(dip), 'lladdr', str(dmac), 'dev', intf_name, 'nud', 'permanent'],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        try:
                            p.wait(timeout=0.2)
                        except Exception:
                            pass
                    elif hasattr(src, 'setARP'):
                        src.setARP(ip=dip, mac=dmac)
                except Exception:
                    pass


def cleanup_stale_network_resources() -> None:
    """Clean leftover Mininet OVS bridges and veth pairs safely without killing Ryu."""
    if shutil.which('ovs-vsctl'):
        try:
            p = subprocess.run(['ovs-vsctl', 'list-br'], text=True, capture_output=True, timeout=3)
            for br in (p.stdout or '').splitlines():
                br_name = br.strip()
                if re.fullmatch(r's\d+', br_name):
                    subprocess.run(
                        ['ovs-vsctl', '--if-exists', 'del-br', br_name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=3,
                    )
        except Exception:
            pass

    if shutil.which('ip'):
        try:
            p = subprocess.run(['ip', '-o', 'link', 'show'], text=True, capture_output=True, timeout=3)
            for line in (p.stdout or '').splitlines():
                m = re.match(r'^\d+:\s+([^:@]+)[@:]', line.strip())
                if not m:
                    continue
                ifname = m.group(1).strip()
                if re.fullmatch(r'(?:h|r|s)\d+-eth\d+', ifname):
                    subprocess.run(
                        ['ip', 'link', 'del', ifname],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=2,
                    )
        except Exception:
            pass


def build_and_start(topology: Dict[str, Any]) -> None:
    global _net, _topology, _started_at
    from labs.cmd_console import safe_name

    topology, controller_ip, controller_port, nodes, links = normalize_topology(topology)
    cleanup_stale_network_resources()

    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True, autoStaticArp=False)
    try:
        c0 = RemoteController('c0', ip=controller_ip, port=controller_port)
        net.addController(c0)

        name_to_node = {}

        for n in nodes:
            ntype = str(n.get('type') or '').lower()
            name = safe_name(str(n.get('name') or ''))
            if not name or name in name_to_node:
                continue
            if ntype == 'switch':
                name_to_node[name] = net.addSwitch(name, protocols='OpenFlow13', inband=False)
            elif ntype in ('host', 'router'):
                name_to_node[name] = net.addHost(name)

        for l in links:
            a = str(l.get('a') or '')
            b = str(l.get('b') or '')
            if a not in name_to_node or b not in name_to_node:
                continue
            link = net.addLink(name_to_node[a], name_to_node[b])
            apply_link_config(link, bw=l.get('bw'), delay_ms=l.get('delay_ms'), loss=l.get('loss'))

        net.start()
        apply_static_arp_all(net)

        switch_names = [n['name'] for n in nodes if n.get('type') == 'switch' and n['name'] in name_to_node]
        configure_ovs_stp(switch_names, wait_if_applied=True)

        for n in nodes:
            if str(n.get('type') or '').lower() == 'router':
                rname = str(n.get('name') or '')
                if rname and rname in name_to_node:
                    try:
                        r = net.get(rname)
                        r.popen(
                            ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        ).wait()
                    except Exception:
                        pass
    except Exception:
        try:
            net.stop()
        except Exception:
            pass
        cleanup_stale_network_resources()
        raise

    _net = net
    _topology = topology
    _started_at = time.time()
    for mod_name in ('labs.mininet_runner', '__main__'):
        try:
            import sys
            mod = sys.modules.get(mod_name)
            if mod is not None:
                mod._net = net
                mod._topology = topology
                mod._started_at = _started_at
        except Exception:
            pass


def stop_net(stop_attack_fn: Optional[Any] = None, stop_ha_fn: Optional[Any] = None, stop_pcap_fn: Optional[Any] = None) -> None:
    global _net, _topology, _started_at
    if _net is not None:
        if stop_attack_fn:
            try:
                stop_attack_fn(_net)
            except Exception:
                pass
    if stop_pcap_fn:
        try:
            stop_pcap_fn()
        except Exception:
            pass
    if stop_ha_fn:
        try:
            stop_ha_fn()
        except Exception:
            pass

    if _net is None:
        cleanup_stale_network_resources()
        return
    try:
        _net.stop()
    finally:
        _net = None
        _topology = None
        _started_at = None
        for mod_name in ('labs.mininet_runner', '__main__'):
            try:
                import sys
                mod = sys.modules.get(mod_name)
                if mod is not None:
                    mod._net = None
                    mod._topology = None
                    mod._started_at = None
            except Exception:
                pass
        cleanup_stale_network_resources()


def apply_live_topology(net: Mininet, topology: Dict[str, Any], ha_procs_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    global _topology

    topology, controller_ip, controller_port, nodes, links = normalize_topology(topology)
    cur_ctrl_ip = str((_topology or {}).get('controller_ip') or DEFAULT_CONTROLLER_IP)
    cur_ctrl_port = int((_topology or {}).get('controller_port') or DEFAULT_CONTROLLER_PORT)
    if controller_ip != cur_ctrl_ip or int(controller_port) != cur_ctrl_port:
        raise ValueError('controller_changed_rebuild_required')

    desired_node_map = {n['name']: n for n in nodes}
    desired_edges = {
        frozenset((l['a'], l['b']))
        for l in links
        if l['a'] in desired_node_map and l['b'] in desired_node_map
    }

    switches_set = set(getattr(net, 'switches', []) or [])
    removed_links = []
    removed_hosts = []
    removed_switches = []
    added_switches = []
    added_hosts = []
    added_links = []
    updated_links = []

    # 1) Detach & remove links no longer in desired topology
    for link in list(getattr(net, 'links', []) or []):
        try:
            n1 = link.intf1.node
            n2 = link.intf2.node
        except Exception:
            continue
        edge = frozenset((n1.name, n2.name))
        if edge not in desired_edges:
            if n1 in switches_set:
                try:
                    n1.detach(link.intf1)
                except Exception:
                    pass
            if n2 in switches_set:
                try:
                    n2.detach(link.intf2)
                except Exception:
                    pass
            try:
                net.delLink(link)
                removed_links.append(f"{n1.name}-{n2.name}")
            except Exception:
                pass

    # 2) Remove hosts no longer in desired topology
    for h in list(getattr(net, 'hosts', []) or []):
        if h.name not in desired_node_map:
            if ha_procs_dict is not None:
                p = ha_procs_dict.pop(h.name, None)
                if p and p.poll() is None:
                    try:
                        p.terminate()
                    except Exception:
                        pass
            try:
                net.delHost(h)
                removed_hosts.append(h.name)
            except Exception:
                pass

    # 3) Remove switches no longer in desired topology
    for sw in list(getattr(net, 'switches', []) or []):
        if sw.name not in desired_node_map:
            try:
                net.delSwitch(sw)
                removed_switches.append(sw.name)
            except Exception:
                pass

    switches_set = set(getattr(net, 'switches', []) or [])
    ctrls = list(getattr(net, 'controllers', []) or [])

    # 4) Add new switches and attach to running controller(s)
    for n in nodes:
        if n.get('type') != 'switch':
            continue
        name = n['name']
        if name not in net.nameToNode:
            sw = net.addSwitch(name, protocols='OpenFlow13', inband=False)
            sw.start(ctrls)
            switches_set.add(sw)
            added_switches.append(name)

    # 5) Add new hosts/routers
    new_hosts_map = {}
    for n in nodes:
        if n.get('type') not in ('host', 'router'):
            continue
        name = n['name']
        if name not in net.nameToNode:
            h = net.addHost(name)
            new_hosts_map[name] = h
            added_hosts.append(name)

    # 6) Add new links and update properties on existing links
    configured_new_hosts = set()
    new_switch_topology = bool(added_switches)
    for l in links:
        a = l['a']
        b = l['b']
        if a not in net.nameToNode or b not in net.nameToNode:
            continue
        existing = find_link_by_endpoints(net, a, b)
        if existing is not None:
            if l.get('bw') is not None or l.get('delay_ms') is not None or l.get('loss') is not None:
                apply_link_config(existing, bw=l.get('bw'), delay_ms=l.get('delay_ms'), loss=l.get('loss'))
                updated_links.append(f"{a}-{b}")
            continue

        n1 = net.nameToNode[a]
        n2 = net.nameToNode[b]
        link = net.addLink(n1, n2)
        if n1 in switches_set:
            n1.attach(link.intf1)
        if n2 in switches_set:
            n2.attach(link.intf2)
        if n1 in switches_set and n2 in switches_set:
            new_switch_topology = True

        for node_obj in (n1, n2):
            if (node_obj not in switches_set) and (node_obj.name in new_hosts_map or not node_obj.IP()) and (node_obj.name not in configured_new_hosts):
                try:
                    node_obj.configDefault()
                except Exception:
                    pass
                configured_new_hosts.add(node_obj.name)
                if desired_node_map.get(node_obj.name, {}).get('type') == 'router':
                    try:
                        node_obj.popen(
                            ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        ).wait()
                    except Exception:
                        pass

        apply_link_config(link, bw=l.get('bw'), delay_ms=l.get('delay_ms'), loss=l.get('loss'))
        added_links.append(f"{a}-{b}")

    all_switch_names = [sw.name for sw in (getattr(net, 'switches', []) or [])]
    if all_switch_names:
        configure_ovs_stp(all_switch_names, wait_if_applied=new_switch_topology)

    apply_static_arp_all(net)
    _topology = topology

    return {
        'added_switches': added_switches,
        'added_hosts': added_hosts,
        'added_links': added_links,
        'updated_links': updated_links,
        'removed_switches': removed_switches,
        'removed_hosts': removed_hosts,
        'removed_links': removed_links,
    }


def host_inventory(net: Mininet, ha_state: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    state = ha_state or {}
    primary_name = str(state.get('primary') or 'h2').strip()
    backup_name = str(state.get('backup') or 'h3').strip()
    out: List[Dict[str, Any]] = []
    for h in list(getattr(net, 'hosts', []) or []):
        linked = bool(getattr(h, 'intfs', None))
        ip = None
        if linked:
            try:
                ip = h.IP() or None
            except Exception:
                ip = None
        if h.name == primary_name:
            role = 'ha_primary'
        elif h.name == backup_name:
            role = 'ha_backup'
        else:
            role = 'client'
        out.append({
            'name': h.name,
            'ip': ip,
            'linked': bool(linked and ip),
            'role': role,
        })
    return out


def extract_topo_payload(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    topo = data.get('topo') or data.get('topology') or {}
    if not topo and ('nodes' in data or 'links' in data):
        topo = data
    if isinstance(topo, dict) and 'topology' in topo and isinstance(topo['topology'], dict):
        topo = topo['topology']
    return topo if isinstance(topo, dict) else {}


# Backward Compatibility Aliases
_require_net = require_net
_normalize_delay_ms = normalize_delay_ms
_find_link_by_endpoints = find_link_by_endpoints
_apply_link_config = apply_link_config
_normalize_topology = normalize_topology
_configure_ovs_stp = configure_ovs_stp
_apply_static_arp_all = apply_static_arp_all
_cleanup_stale_network_resources = cleanup_stale_network_resources
_build_and_start = build_and_start
_stop_net = stop_net
_apply_live_topology = apply_live_topology
_host_inventory = host_inventory
_extract_topo_payload = extract_topo_payload
_acquire_lock = acquire_lock
