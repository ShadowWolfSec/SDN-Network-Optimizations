"""
tests/test_cmd_console.py
=========================
Unit tests for Command Console diagnostic engine (Ping, iPerf, OVS dump flows),
smart host/IP bidirectional resolution, and argument sanitization.
"""

import subprocess
import types
import unittest
from unittest.mock import MagicMock, patch

from labs.cmd_console import (
    execute_cmd_iperf,
    execute_cmd_ping,
    ovs_dump_flows,
    parse_ovs_flow_line,
    resolve_dst_target,
    resolve_host,
    safe_name,
    safe_shell_escape,
    safe_target,
    truncate_output,
)


class DummyHost:
    def __init__(self, name: str, ip: str):
        self.name = name
        self._ip = ip

    def IP(self) -> str:
        return self._ip

    def popen(self, cmd, stdout=None, stderr=None):
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate.return_value = (b'64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.05 ms\n', b'')
        return proc


class DummyNet:
    def __init__(self):
        self.h1 = DummyHost('h1', '10.0.0.1')
        self.h2 = DummyHost('h2', '10.0.0.2')
        self.h3 = DummyHost('h3', '10.0.0.3')
        self.hosts = [self.h1, self.h2, self.h3]
        self._sw = types.SimpleNamespace(name='s1')
        self.switches = [self._sw]

    def __contains__(self, item):
        return item in ('h1', 'h2', 'h3')

    def get(self, name):
        if name == 'h1':
            return self.h1
        if name == 'h2':
            return self.h2
        if name == 'h3':
            return self.h3
        raise KeyError(name)


class TestCmdConsole(unittest.TestCase):
    def setUp(self):
        self.net = DummyNet()

    # 1. Sanitization & escaping tests
    def test_safe_name_and_target_validation(self):
        self.assertEqual(safe_name('h1'), 'h1')
        self.assertEqual(safe_name('s_1-2'), 's_1-2')
        self.assertIsNone(safe_name('h1; rm -rf /'))
        self.assertIsNone(safe_name(''))

        self.assertEqual(safe_target('10.0.0.1'), '10.0.0.1')
        self.assertEqual(safe_target('h2'), 'h2')
        self.assertIsNone(safe_target('-c 10'))
        self.assertIsNone(safe_target('h2; reboot'))

    # 2. Smart Host/IP resolution tests
    def test_resolve_host_by_name_and_by_ip(self):
        # By host name
        h, name = resolve_host(self.net, 'h1')
        self.assertIsNotNone(h)
        self.assertEqual(name, 'h1')
        self.assertEqual(h.IP(), '10.0.0.1')

        # By IP address
        h_ip, name_ip = resolve_host(self.net, '10.0.0.2')
        self.assertIsNotNone(h_ip)
        self.assertEqual(name_ip, 'h2')
        self.assertEqual(h_ip.name, 'h2')

        # Non-existent or invalid
        h_none, name_none = resolve_host(self.net, '10.0.0.99')
        self.assertIsNone(h_none)
        self.assertIsNone(name_none)

        h_inj, name_inj = resolve_host(self.net, 'h1; cat /etc/shadow')
        self.assertIsNone(h_inj)

    def test_resolve_dst_target(self):
        # Host name resolved to IP
        ip, canon = resolve_dst_target(self.net, 'h2')
        self.assertEqual(ip, '10.0.0.2')
        self.assertEqual(canon, 'h2')

        # Direct IP preserved
        ip_direct, canon_direct = resolve_dst_target(self.net, '10.0.0.5')
        self.assertEqual(ip_direct, '10.0.0.5')
        self.assertIsNone(canon_direct)

        # VIP preserved
        ip_vip, _ = resolve_dst_target(self.net, '10.0.0.100')
        self.assertEqual(ip_vip, '10.0.0.100')

    # 3. Ping execution tests
    def test_execute_cmd_ping_with_hostnames_resolves_destination(self):
        data = {'src': 'h1', 'dst': 'h2', 'count': 2}
        res, code = execute_cmd_ping(self.net, data)
        self.assertEqual(code, 200)
        self.assertTrue(res['ok'])
        self.assertEqual(res['src'], 'h1')
        self.assertEqual(res['dst'], 'h2')
        self.assertEqual(res['target_ip'], '10.0.0.2')
        self.assertIn('icmp_seq=1', res['output'])

    def test_execute_cmd_ping_with_ips(self):
        data = {'src': '10.0.0.1', 'dst': '10.0.0.2', 'count': 4}
        res, code = execute_cmd_ping(self.net, data)
        self.assertEqual(code, 200)
        self.assertTrue(res['ok'])
        self.assertEqual(res['src'], 'h1')
        self.assertEqual(res['target_ip'], '10.0.0.2')

    def test_execute_cmd_ping_missing_or_bad_destination(self):
        data = {'src': 'h1', 'dst': ''}
        res, code = execute_cmd_ping(self.net, data)
        self.assertEqual(code, 400)
        self.assertFalse(res['ok'])
        self.assertEqual(res['error'], 'missing_src_or_dst')

    # 4. iPerf execution tests
    def test_execute_cmd_iperf_bidirectional_resolution(self):
        with patch('shutil.which', return_value='/usr/bin/iperf'):
            data = {'client': '10.0.0.1', 'server': '10.0.0.2', 'duration': 2}
            res, code = execute_cmd_iperf(self.net, data, 'iperf_tcp')
            self.assertEqual(code, 200)
            self.assertTrue(res['ok'])
            self.assertEqual(res['client'], 'h1')
            self.assertEqual(res['server'], 'h2')

    def test_execute_cmd_iperf_same_host_rejected(self):
        data = {'client': 'h1', 'server': '10.0.0.1'}
        res, code = execute_cmd_iperf(self.net, data, 'iperf_tcp')
        self.assertEqual(code, 400)
        self.assertEqual(res['error'], 'client_must_differ_from_server')

    # 5. OVS flow parsing test
    def test_parse_ovs_flow_line(self):
        line = 'cookie=0x0, duration=10.5s, table=0, n_packets=42, n_bytes=3528, priority=100,ip,nw_dst=10.0.0.1 actions=output:1'
        parsed = parse_ovs_flow_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['priority'], 100)
        self.assertEqual(parsed['actions'], 'output:1')
        self.assertIn('ip,nw_dst=10.0.0.1', parsed['match'])


if __name__ == '__main__':
    unittest.main()
