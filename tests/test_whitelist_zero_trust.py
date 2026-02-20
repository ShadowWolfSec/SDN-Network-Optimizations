"""
Unit tests for IP whitelisting, verification of protection from drop flows,
and RBAC enforcement on whitelist endpoints.
"""

import json
import logging
import os
import sys
import tempfile
import types
import unittest
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

from werkzeug.security import generate_password_hash
import webapp.server as srv
from ryu_app.dos_guard import DoSGuard
import ryu_app.web_controller as web_controller
from ryu_app.web_controller import DoSGuardWebController


class TestWhitelistZeroTrust(unittest.TestCase):
    """Test suite establishing and verifying the Zero-Trust boundary for Whitelisting."""

    WHITELIST_SERVER_IP = '10.0.0.50'
    VIP_IP = '10.0.0.100'
    ATTACKER_IP = '10.0.0.99'

    def setUp(self):
        srv.app.config['TESTING'] = True
        self.tmpdir = tempfile.TemporaryDirectory()
        self.test_users_file = os.path.join(self.tmpdir.name, 'users.json')
        with open(self.test_users_file, 'w', encoding='utf-8') as f:
            json.dump(
                {
                    'admin': {
                        'password': generate_password_hash('AdminPass123!'),
                        'role': 'admin',
                    },
                    'user': {
                        'password': generate_password_hash('UserPass123!'),
                        'role': 'user',
                    },
                },
                f,
            )

        self.orig_users_file = srv.USERS_FILE
        srv.USERS_FILE = self.test_users_file
        with srv._users_cache_lock:
            srv._users_cache = {}
            srv._users_cache_mtime = 0.0
        with srv._rate_lock:
            srv._rate_state.clear()

        self.client = srv.app.test_client()

    def tearDown(self):
        srv.USERS_FILE = self.orig_users_file
        with srv._users_cache_lock:
            srv._users_cache = {}
            srv._users_cache_mtime = 0.0
        with srv._rate_lock:
            srv._rate_state.clear()
        self.tmpdir.cleanup()

    # =========================================================================
    # 1. Defensive Network Protection (Dropping Prevention Only)
    # =========================================================================

    def test_whitelist_prevents_drop_rules_only(self):
        """Whitelisted IP and VIP are protected from drop flow injection; normal IPs are not."""
        wsgi = sys.modules['ryu.app.wsgi'].WSGIApplication()
        app = DoSGuard(wsgi=wsgi)
        app.vip_ip = self.VIP_IP
        app.whitelist_ips.add(self.WHITELIST_SERVER_IP)
        app._install_block_ip_all = MagicMock()

        ctrl = DoSGuardWebController(req=None, link=None, data={'dos_guard_app': app})

        # 1. Protection verification
        self.assertTrue(app._is_protected_ip(self.WHITELIST_SERVER_IP), "Whitelisted IP must be recognized as protected")
        self.assertTrue(app._is_protected_ip(self.VIP_IP), "VIP must be recognized as protected")
        self.assertFalse(app._is_protected_ip(self.ATTACKER_IP), "Normal IP must not be protected")

        # 2. Block IP rejects protected entities
        req = types.SimpleNamespace(headers={'X-Internal-Token': 'test'})
        resp_wl = ctrl.block_ip(req, ip=self.WHITELIST_SERVER_IP)
        self.assertEqual(resp_wl.status_code, 400, "block_ip must return 400 for whitelisted IP")
        self.assertIn(b'cannot_block_whitelisted_ip', resp_wl.body)

        resp_vip = ctrl.block_ip(req, ip=self.VIP_IP)
        self.assertEqual(resp_vip.status_code, 400, "block_ip must return 400 for VIP")
        self.assertIn(b'cannot_block_vip', resp_vip.body)

        # 3. Non-whitelisted IP is successfully blocked
        resp_norm = ctrl.block_ip(req, ip=self.ATTACKER_IP)
        self.assertEqual(resp_norm.status_code, 200, "block_ip must succeed for unprotected IP")
        self.assertIn(self.ATTACKER_IP, app.blocked_ips)

    # =========================================================================
    # 2. Zero-Trust Boundary: Whitelisted IP Cannot Bypass Authentication
    # =========================================================================

    def test_unauthenticated_request_from_whitelisted_ip_strictly_rejected(self):
        """Calls originating from or spoofing a whitelisted IP receive 401 Unauthorized without session."""
        protected_endpoints = [
            ('GET', '/api/lab/status'),
            ('GET', '/api/alerts'),
            ('GET', '/api/flows'),
            ('GET', '/api/metrics'),
            ('POST', '/api/config'),
            ('POST', '/api/lab/cmd/run'),
            ('POST', '/api/lab/build'),
        ]

        for method, url in protected_endpoints:
            # Test direct remote address as whitelisted IP
            resp = self.client.open(
                url,
                method=method,
                environ_base={'REMOTE_ADDR': self.WHITELIST_SERVER_IP},
                headers={
                    'X-Forwarded-For': self.WHITELIST_SERVER_IP,
                    'Client-IP': self.WHITELIST_SERVER_IP,
                },
            )
            self.assertEqual(
                resp.status_code,
                401,
                f"Endpoint {url} allowed unauthenticated access from whitelisted IP {self.WHITELIST_SERVER_IP}",
            )
            data = resp.get_json(silent=True) or {}
            self.assertEqual(data.get('error'), 'unauthorized')

    # =========================================================================
    # 3. Zero-Trust Boundary: User Session from Whitelisted IP Denied Admin Actions
    # =========================================================================

    def test_whitelisted_ip_with_user_session_denied_administrative_access(self):
        """An authenticated 'user' connecting from a whitelisted IP still receives 403 Forbidden on admin APIs."""
        with self.client.session_transaction() as sess:
            sess['user'] = 'user'
            sess['role'] = 'user'
            sess['csrf_token'] = 'test-valid-csrf'
            sess['boot_id'] = srv._SERVER_BOOT_ID

        headers = {
            'X-CSRF-Token': 'test-valid-csrf',
            'X-Forwarded-For': self.WHITELIST_SERVER_IP,
            'Client-IP': self.WHITELIST_SERVER_IP,
        }

        admin_mutations = [
            ('POST', '/api/whitelist/ip', {'ip': '10.0.0.77'}),
            ('POST', '/api/unwhitelist/ip', {'ip': '10.0.0.77'}),
            ('POST', '/api/whitelist/clear', {}),
            ('POST', '/api/whitelist/save', {}),
            ('POST', '/api/whitelist/restore', {}),
            ('DELETE', '/api/whitelist/persistent', {}),
            ('POST', '/api/block/ip', {'ip': '10.0.0.99'}),
            ('POST', '/api/unblock/ip', {'ip': '10.0.0.99'}),
            ('POST', '/api/config', {'syn_threshold': 500}),
            ('POST', '/api/lab/build', {}),
            ('POST', '/api/lab/stop', {}),
            ('POST', '/api/lab/cmd/run', {'type': 'ping'}),
        ]

        for method, url, payload in admin_mutations:
            resp = self.client.open(
                url,
                method=method,
                json=payload,
                headers=headers,
                environ_base={'REMOTE_ADDR': self.WHITELIST_SERVER_IP},
            )
            self.assertEqual(
                resp.status_code,
                403,
                f"Whitelisted IP bypassed RBAC on {url}: status={resp.status_code}",
            )
            data = resp.get_json(silent=True) or {}
            self.assertEqual(data.get('error'), 'forbidden')

    # =========================================================================
    # 4. Internal Controller Token Isolation
    # =========================================================================

    def test_ryu_controller_rejects_whitelisted_ip_without_internal_token(self):
        """Ryu REST endpoints reject requests from whitelisted IPs unless valid X-Internal-Token is present."""
        ctrl = DoSGuardWebController(req=None, link=None, data={})

        dummy_super_resp = getattr(web_controller, 'Response')(status=200, content_type='application/json', body=b'{"ok": true}')
        with patch.object(web_controller, '_load_internal_token', return_value='secret-shared-token-999'), \
             patch('ryu_app.web_controller.ControllerBase.__call__', return_value=dummy_super_resp):
            # 1. Request from whitelisted IP without token -> 401
            req_no_token = types.SimpleNamespace(
                headers={'X-Forwarded-For': self.WHITELIST_SERVER_IP},
                environ={'REMOTE_ADDR': self.WHITELIST_SERVER_IP},
            )
            resp1 = ctrl(req_no_token)
            self.assertEqual(resp1.status_code, 401, "Ryu must reject whitelisted IP when token is missing")

            # 2. Request from whitelisted IP with wrong token -> 401
            req_bad_token = types.SimpleNamespace(
                headers={
                    'X-Internal-Token': 'wrong-attacker-token',
                    'X-Forwarded-For': self.WHITELIST_SERVER_IP,
                },
                environ={'REMOTE_ADDR': self.WHITELIST_SERVER_IP},
            )
            resp2 = ctrl(req_bad_token)
            self.assertEqual(resp2.status_code, 401, "Ryu must reject whitelisted IP when token is invalid")

            # 3. Request from whitelisted IP with correct token -> 200 / Authorized
            req_valid = types.SimpleNamespace(
                headers={
                    'X-Internal-Token': 'secret-shared-token-999',
                    'X-Forwarded-For': self.WHITELIST_SERVER_IP,
                },
                environ={'REMOTE_ADDR': self.WHITELIST_SERVER_IP},
            )
            resp3 = ctrl(req_valid)
            self.assertEqual(resp3.status_code, 200, "Ryu must accept request when valid internal token is supplied")

    # =========================================================================
    # 5. Whitelist Mutation Authorization (Admin Role Required)
    # =========================================================================

    def test_admin_session_can_manage_whitelist(self):
        """Authenticated 'admin' session successfully passes authorization on whitelist operations."""
        with self.client.session_transaction() as sess:
            sess['user'] = 'admin'
            sess['role'] = 'admin'
            sess['csrf_token'] = 'admin-csrf-valid'
            sess['boot_id'] = srv._SERVER_BOOT_ID

        headers = {'X-CSRF-Token': 'admin-csrf-valid'}

        # Status check
        r_status = self.client.get('/api/whitelist/status', headers=headers)
        self.assertIn(r_status.status_code, (200, 502), "Admin must be authorized to view whitelist status")

        # Mutating endpoints must NOT return 403 Forbidden for admin
        for method, url, payload in [
            ('POST', '/api/whitelist/save', {}),
            ('POST', '/api/whitelist/restore', {}),
            ('DELETE', '/api/whitelist/persistent', {}),
        ]:
            resp = self.client.open(url, method=method, json=payload, headers=headers)
            self.assertNotEqual(resp.status_code, 403, f"Admin must pass RBAC check on {url}")


if __name__ == '__main__':
    unittest.main()
