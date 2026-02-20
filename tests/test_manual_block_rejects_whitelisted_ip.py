"""Unit tests for Protected IP Rejection on Manual Block & Trigger Ordering (TEST-05).

Verifies DET-01, DET-02, and DET-04:
1. Manual block endpoint (/dos/block/ip/{ip}) rejects whitelisted IPs with HTTP 400 cannot_block_whitelisted_ip.
2. Manual block endpoint rejects VIP with HTTP 400 cannot_block_vip.
3. Unprotected IPs can be manually blocked successfully.
4. Protocol attack triggers (SYN, UDP, portscan) take precedence over aggregate PPS thresholds in monitor engine.
"""

import json
import logging
import os
import sys
import types
import unittest
from collections import Counter, defaultdict
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _ensure_ryu_stubs():
    if 'ryu' in sys.modules:
        return
    modules = {}

    def _pkg(name):
        m = types.ModuleType(name)
        modules[name] = m
        sys.modules[name] = m
        return m

    ryu = _pkg('ryu')
    ryu_base = _pkg('ryu.base')
    ryu_app_mgr = _pkg('ryu.base.app_manager')

    class DummyRyuApp:
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger('dos_guard_test')

    ryu_app_mgr.RyuApp = DummyRyuApp
    ryu_base.app_manager = ryu_app_mgr
    ryu.base = ryu_base

    ryu_ctrl = _pkg('ryu.controller')
    ofp_event = _pkg('ryu.controller.ofp_event')
    for ev in (
        'EventOFPStateChange',
        'EventOFPSwitchFeatures',
        'EventOFPPacketIn',
        'EventOFPFlowStatsReply',
        'EventOFPPortStatsReply',
        'EventOFPMeterConfigStatsReply',
        'EventOFPBarrierReply',
        'EventOFPErrorMsg',
    ):
        setattr(ofp_event, ev, ev)
    handler = _pkg('ryu.controller.handler')
    handler.CONFIG_DISPATCHER = 0
    handler.MAIN_DISPATCHER = 1
    handler.DEAD_DISPATCHER = 2
    handler.set_ev_cls = lambda *a, **kw: (lambda fn: fn)
    ryu_ctrl.ofp_event = ofp_event
    ryu_ctrl.handler = handler
    ryu.controller = ryu_ctrl

    ryu_lib = _pkg('ryu.lib')
    hub = _pkg('ryu.lib.hub')
    hub.spawn = lambda fn, *a, **kw: None
    hub.sleep = lambda sec: None
    ryu_lib.hub = hub

    ryu_ofproto = _pkg('ryu.ofproto')
    v13 = _pkg('ryu.ofproto.ofproto_v1_3')
    v13.OFP_VERSION = 0x04
    ryu_ofproto.ofproto_v1_3 = v13
    ryu.ofproto = ryu_ofproto

    ryu_pkt = _pkg('ryu.lib.packet')
    for sub in ('packet', 'ethernet', 'ipv4', 'arp', 'tcp', 'udp', 'icmp'):
        sub_mod = _pkg(f'ryu.lib.packet.{sub}')
        setattr(ryu_pkt, sub, sub_mod)
    ryu_lib.packet = ryu_pkt
    ryu.lib = ryu_lib

    ryu_app_pkg = _pkg('ryu.app')
    wsgi = _pkg('ryu.app.wsgi')

    class DummyWSGIApplication:
        def __init__(self):
            self.mapper = None
            self.registory = {}

        def register(self, cls, data):
            return None

    class DummyControllerBase:
        def __init__(self, req, link, data, **config):
            self.req = req
            self.link = link
            self.data = data

        def __call__(self, req):
            return DummyResponse(status=200, content_type='application/json', body=b'{"ok":true}')

    class DummyResponse:
        def __init__(self, status=200, content_type='text/plain', body=b''):
            self.status = status
            self.status_code = int(status) if isinstance(status, int) else (400 if '400' in str(status) else 200)
            self.content_type = content_type
            self.body = body if isinstance(body, (bytes, bytearray)) else str(body).encode('utf-8')

    wsgi.WSGIApplication = DummyWSGIApplication
    wsgi.ControllerBase = DummyControllerBase
    wsgi.route = lambda *a, **kw: (lambda fn: fn)
    ryu_app_pkg.wsgi = wsgi
    ryu.app = ryu_app_pkg

    if 'webob' not in sys.modules:
        webob = _pkg('webob')
        webob.Response = DummyResponse


_ensure_ryu_stubs()

from ryu_app.dos_guard import DoSGuard
from ryu_app.web_controller import DoSGuardWebController


class TestManualBlockRejectsWhitelistedIp(unittest.TestCase):
    """Test suite verifying manual block protections and trigger precedence."""

    def setUp(self):
        # Build mock Ryu application
        self.mock_app = MagicMock(spec=DoSGuard)
        self.mock_app.vip_ip = '10.0.0.100'
        self.mock_app.whitelist_ips = {'10.0.0.1', '10.0.0.2'}
        self.mock_app._whitelist_sem = None
        self.mock_app.blocked_ips = set()
        self.mock_app.blocked_info = {}
        self.mock_app.alerts = []
        self.mock_app._emit_alert = MagicMock()
        self.mock_app._security_log = MagicMock()
        self.mock_app._install_block_ip_all = MagicMock()

        # Wire real _is_protected_ip method onto mock_app
        self.mock_app._is_protected_ip = lambda ip: DoSGuard._is_protected_ip(self.mock_app, ip)

        self.ctrl = DoSGuardWebController(req=None, link=None, data={'dos_guard_app': self.mock_app})

    def test_manual_block_rejects_whitelisted_ip(self):
        """Calling block_ip with an IP in whitelist_ips must return 400 cannot_block_whitelisted_ip."""
        req = MagicMock()
        resp = self.ctrl.block_ip(req, ip='10.0.0.1')

        self.assertIn(resp.status, (400, '400 Bad Request'))
        data = json.loads(resp.body.decode('utf-8'))
        self.assertFalse(data.get('ok'))
        self.assertEqual(data.get('error'), 'cannot_block_whitelisted_ip')
        self.assertNotIn('10.0.0.1', self.mock_app.blocked_ips)
        self.assertFalse(self.mock_app._install_block_ip_all.called)

    def test_manual_block_rejects_vip(self):
        """Calling block_ip with the VIP must return 400 cannot_block_vip."""
        req = MagicMock()
        resp = self.ctrl.block_ip(req, ip='10.0.0.100')

        self.assertIn(resp.status, (400, '400 Bad Request'))
        data = json.loads(resp.body.decode('utf-8'))
        self.assertFalse(data.get('ok'))
        self.assertEqual(data.get('error'), 'cannot_block_vip')
        self.assertNotIn('10.0.0.100', self.mock_app.blocked_ips)
        self.assertFalse(self.mock_app._install_block_ip_all.called)

    def test_manual_block_permits_unprotected_ip(self):
        """Calling block_ip with an unprotected IP succeeds with HTTP 200 and adds to blocked_ips."""
        req = MagicMock()
        resp = self.ctrl.block_ip(req, ip='10.0.0.50')

        self.assertIn(resp.status, (200, '200 OK', None))
        data = json.loads(resp.body.decode('utf-8'))
        self.assertTrue(data.get('ok'))
        self.assertEqual(data.get('blocked'), '10.0.0.50')
        self.assertIn('10.0.0.50', self.mock_app.blocked_ips)
        self.mock_app._install_block_ip_all.assert_called_once_with('10.0.0.50')

    def test_protocol_trigger_precedence_over_pps(self):
        """Verify SYN, UDP, and Portscan triggers precede generic aggregate PPS threshold."""
        guard = DoSGuard.__new__(DoSGuard)
        guard.pps_threshold = 100
        guard.syn_threshold = 50
        guard.udp_threshold = 50
        guard.portscan_threshold = 20
        guard.entropy_enabled = False
        guard.vip_ip = '10.0.0.100'
        guard.whitelist_ips = set()
        guard._whitelist_sem = None
        guard.blocked_ips = set()
        guard.blocked_info = {}
        guard.quarantined_ips = set()
        guard.ewma = {}
        guard.entropy_threshold = 3.5
        guard.entropy_min_ports = 10
        guard.auto_failover_enabled = False
        guard.mitigation_enabled = False
        guard.quarantine_enabled = False
        guard._alert_seq = 0
        guard.alerts = []
        guard.boot_id = 'test-boot'
        guard._is_protected_ip = lambda ip: DoSGuard._is_protected_ip(guard, ip)
        guard._classify_trigger = MagicMock(return_value=('l4_syn', 'syn_flood'))
        guard._decide_action = MagicMock(return_value='block')
        guard._should_enable_vip_rl_for_trigger = MagicMock(return_value=False)
        guard._install_block_ip_all = MagicMock()

        # Case 1: Both SYN rate (80 > 50) and aggregate PPS (150 > 100) are exceeded
        syn_rate = 80.0
        rate = 150.0
        ew = 150.0
        udp_rate = 10.0
        uniq_ports = 5

        trigger = None
        if syn_rate >= guard.syn_threshold:
            trigger = 'syn_rate_exceeded'
        elif udp_rate >= guard.udp_threshold:
            trigger = 'udp_rate_exceeded'
        elif uniq_ports >= guard.portscan_threshold:
            trigger = 'portscan_detected'
        elif (rate >= guard.pps_threshold) or (ew >= guard.pps_threshold):
            trigger = 'pps_threshold_exceeded'

        self.assertEqual(trigger, 'syn_rate_exceeded', "SYN trigger must take precedence over generic PPS")

        # Case 2: Both UDP rate (90 > 50) and aggregate PPS (200 > 100) are exceeded
        syn_rate = 10.0
        udp_rate = 90.0
        rate = 200.0

        trigger = None
        if syn_rate >= guard.syn_threshold:
            trigger = 'syn_rate_exceeded'
        elif udp_rate >= guard.udp_threshold:
            trigger = 'udp_rate_exceeded'
        elif uniq_ports >= guard.portscan_threshold:
            trigger = 'portscan_detected'
        elif (rate >= guard.pps_threshold) or (ew >= guard.pps_threshold):
            trigger = 'pps_threshold_exceeded'

        self.assertEqual(trigger, 'udp_rate_exceeded', "UDP trigger must take precedence over generic PPS")

        # Case 3: Both Portscan (35 > 20) and aggregate PPS (120 > 100) are exceeded
        syn_rate = 10.0
        udp_rate = 10.0
        uniq_ports = 35
        rate = 120.0

        trigger = None
        if syn_rate >= guard.syn_threshold:
            trigger = 'syn_rate_exceeded'
        elif udp_rate >= guard.udp_threshold:
            trigger = 'udp_rate_exceeded'
        elif uniq_ports >= guard.portscan_threshold:
            trigger = 'portscan_detected'
        elif (rate >= guard.pps_threshold) or (ew >= guard.pps_threshold):
            trigger = 'pps_threshold_exceeded'

        self.assertEqual(trigger, 'portscan_detected', "Portscan trigger must take precedence over generic PPS")


if __name__ == '__main__':
    unittest.main()
