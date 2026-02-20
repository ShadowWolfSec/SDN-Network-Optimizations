"""
labs/cmd_console.py
Diagnostic console execution engine for Mininet (ping, iperf, ovs-ofctl).
"""

import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple


def safe_shell_escape(value: str) -> str:
    """Escape shell arguments safely using shlex.quote."""
    return shlex.quote(str(value or ''))


def safe_name(v: str) -> Optional[str]:
    """Validates alphanumeric/underscore/dash identifiers (switch, host names)."""
    s = str(v or '').strip()
    if not s:
        return None
    if not re.fullmatch(r'[A-Za-z0-9_\-]+', s):
        return None
    return s


def safe_target(v: str) -> Optional[str]:
    """Validates target address/hostname, rejecting leading dashes and command injection."""
    s = str(v or '').strip()
    if not s or s.startswith('-'):
        return None
    if not re.fullmatch(r'[A-Za-z0-9_\-\.:/\[\]]+', s):
        return None
    return s


def resolve_host(net: Any, ident: Optional[str]) -> Tuple[Optional[Any], Optional[str]]:
    """Resolves host name (e.g. 'h1') or IP address (e.g. '10.0.0.1') to a Mininet host object and its canonical name."""
    s = str(ident or '').strip()
    if not s or s.startswith('-'):
        return None, None
    if not re.fullmatch(r'[A-Za-z0-9_\-\.:]+', s):
        return None, None
    # 1. Try direct lookup by host name
    try:
        if s in net:
            h = net.get(s)
            if hasattr(h, 'popen'):
                return h, getattr(h, 'name', s)
    except Exception:
        pass
    # 2. Try lookup by host IP address across net.hosts
    try:
        hosts = getattr(net, 'hosts', []) or []
        for h in hosts:
            if hasattr(h, 'IP') and callable(h.IP):
                if h.IP() == s and hasattr(h, 'popen'):
                    return h, getattr(h, 'name', s)
    except Exception:
        pass
    return None, None


def resolve_dst_target(net: Any, dst: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Resolves destination host name (e.g. 'h2') to IP ('10.0.0.2'), or preserves target IP directly.
    Returns: (target_ip, canonical_name_if_resolved)
    """
    s = str(dst or '').strip()
    if not s or s.startswith('-'):
        return None, None
    if not re.fullmatch(r'[A-Za-z0-9_\-\.:/\[\]]+', s):
        return None, None
    # If destination matches a host name in net, resolve to that host's IP
    try:
        if s in net:
            h = net.get(s)
            if hasattr(h, 'IP') and callable(h.IP):
                return h.IP(), getattr(h, 'name', s)
    except Exception:
        pass
    return s, None


def truncate_output(out: str, max_chars: int = 6000) -> str:
    """Truncates command stdout/stderr safely to bounded length."""
    s = (out or '').strip()
    if len(s) > max_chars:
        return s[:max_chars] + "\n... (truncated)"
    return s


def parse_ovs_flow_line(line: str) -> Optional[Dict[str, Any]]:
    """Parses single ovs-ofctl dump-flows text output line into structured dictionary."""
    raw = (line or '').strip()
    if not raw:
        return None
    if raw.startswith('OFPST_FLOW'):
        return None
    if ' actions=' not in raw:
        return None
    left, actions = raw.split(' actions=', 1)
    parts = [p.strip() for p in left.split(',') if p.strip()]
    priority = None
    match_parts = []
    for p in parts:
        if p.startswith('priority='):
            try:
                priority = int(p.split('=', 1)[1])
            except Exception:
                priority = None
        elif (
            p.startswith('cookie=')
            or p.startswith('duration=')
            or p.startswith('table=')
            or p.startswith('n_packets=')
            or p.startswith('n_bytes=')
            or p.startswith('idle_age=')
            or p.startswith('hard_age=')
        ):
            continue
        else:
            match_parts.append(p)
    return {
        'priority': priority,
        'match': ','.join(match_parts),
        'actions': actions.strip(),
        'raw': raw,
    }


def ovs_dump_flows(sw: str) -> Tuple[str, str]:
    """Executes ovs-ofctl -O OpenFlow13 dump-flows on specified switch name."""
    cmd = ['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', sw]
    p = subprocess.run(cmd, text=True, capture_output=True)
    out = (p.stdout or '').strip()
    err = (p.stderr or '').strip()
    return out, err


def execute_cmd_ping(
    net: Any,
    data: Dict[str, Any],
    pick_victim_and_attackers_fn: Optional[Any] = None,
) -> Tuple[Dict[str, Any], int]:
    """Executes bounded ping command between Mininet hosts with bidirectional hostname/IP resolution."""
    src_raw = data.get('src')
    dst_raw = data.get('dst')
    try:
        count = int(data.get('count') or 4)
    except Exception:
        count = 4
    if count < 1:
        count = 1
    if count > 20:
        count = 20

    src_query = (str(src_raw).strip() if src_raw is not None else '') or 'h1'
    h, canonical_src = resolve_host(net, src_query)

    if h is None and src_raw is None and pick_victim_and_attackers_fn:
        try:
            victim, attacker, _ = pick_victim_and_attackers_fn(
                net, preferred_victim='h2', preferred_attacker='h1'
            )
            h = attacker or victim
            if h is not None:
                canonical_src = getattr(h, 'name', 'h1')
        except Exception:
            pass

    if h is None:
        return {'ok': False, 'error': 'src_not_found'}, 400

    target_ip, canonical_dst = resolve_dst_target(net, dst_raw)
    if not target_ip:
        return {'ok': False, 'error': 'missing_src_or_dst'}, 400

    p = h.popen(
        ['ping', '-c', str(count), '-W', '1', target_ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        out_bytes, _ = p.communicate(timeout=count + 5)
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        out_bytes, _ = p.communicate()

    out = (
        out_bytes.decode('utf-8', errors='replace')
        if isinstance(out_bytes, (bytes, bytearray))
        else str(out_bytes or '')
    )
    out_lines = out.splitlines()[:40]
    return {
        'ok': True,
        'type': 'ping',
        'src': canonical_src or src_query,
        'dst': dst_raw,
        'target_ip': target_ip,
        'returncode': p.returncode,
        'output': truncate_output('\n'.join(out_lines)),
    }, 200


def execute_cmd_iperf(
    net: Any,
    data: Dict[str, Any],
    cmd_type: str,
    pick_victim_and_attackers_fn: Optional[Any] = None,
) -> Tuple[Dict[str, Any], int]:
    """Executes bounded iperf client-server throughput test between Mininet hosts with bidirectional hostname/IP resolution."""
    client_raw = data.get('client')
    server_raw = data.get('server')
    client_query = (str(client_raw).strip() if client_raw is not None else '') or 'h1'
    server_query = (str(server_raw).strip() if server_raw is not None else '') or 'h2'
    try:
        duration = int(data.get('duration') or 5)
    except Exception:
        duration = 5
    if duration < 1:
        duration = 1
    if duration > 30:
        duration = 30
    try:
        port = int(data.get('port') or 5001)
    except Exception:
        port = 5001
    if port < 1 or port > 65535:
        port = 5001

    hc, client_name = resolve_host(net, client_query)
    hs, server_name = resolve_host(net, server_query)

    if (hc is None or hs is None) and client_raw is None and server_raw is None and pick_victim_and_attackers_fn:
        try:
            victim, attacker, pool = pick_victim_and_attackers_fn(
                net, preferred_victim='h2', preferred_attacker='h1'
            )
            if attacker is not None and victim is not None:
                hc = attacker
                hs = victim
                client_name = hc.name
                server_name = hs.name
        except Exception:
            pass

    if not hc or not hs:
        return {'ok': False, 'error': 'client_or_server_not_found'}, 400
    if hc == hs or client_name == server_name:
        return {'ok': False, 'error': 'client_must_differ_from_server'}, 400

    ip = hs.IP()
    iperf_bin = shutil.which('iperf') or shutil.which('iperf3')
    if not iperf_bin:
        return {'ok': False, 'error': 'iperf_not_installed'}, 500

    is_iperf3 = os.path.basename(iperf_bin).startswith('iperf3')
    is_udp = (cmd_type == 'iperf_udp')

    srv_cmd = ['timeout', str(duration + 4), iperf_bin, '-s']
    if is_iperf3:
        srv_cmd.append('-1')
    elif is_udp:
        srv_cmd.append('-u')
    srv_cmd.extend(['-p', str(port)])

    cli_cmd = ['timeout', str(duration + 5), iperf_bin, '-c', ip]
    if is_udp:
        cli_cmd.extend(['-u', '-b', '10M'])
    cli_cmd.extend(['-t', str(duration), '-p', str(port)])

    p_srv = hs.popen(srv_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rc = None
    out = ''
    try:
        time.sleep(0.35)
        p_cli = hc.popen(cli_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            out_bytes, _ = p_cli.communicate(timeout=duration + 6)
        except subprocess.TimeoutExpired:
            try:
                p_cli.kill()
            except Exception:
                pass
            out_bytes, _ = p_cli.communicate()
        rc = p_cli.returncode
        out = (
            out_bytes.decode('utf-8', errors='replace')
            if isinstance(out_bytes, (bytes, bytearray))
            else str(out_bytes or '')
        )
    finally:
        try:
            if p_srv.poll() is None:
                p_srv.terminate()
                try:
                    p_srv.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    p_srv.kill()
                    p_srv.wait(timeout=1)
            else:
                p_srv.wait(timeout=1)
        except Exception:
            pass

    return {
        'ok': True,
        'type': cmd_type,
        'client': client_name or client_query,
        'server': server_name or server_query,
        'server_ip': ip,
        'duration': duration,
        'port': port,
        'returncode': rc,
        'output': truncate_output(out),
    }, 200


# Backward Compatibility Aliases
_safe_shell_escape = safe_shell_escape
_safe_name = safe_name
_safe_target = safe_target
_truncate_output = truncate_output
_parse_ovs_flow_line = parse_ovs_flow_line
_ovs_dump_flows = ovs_dump_flows
