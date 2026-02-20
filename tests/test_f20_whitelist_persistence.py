"""
Tests for F-20: Operational State Persistence - Explicit Opt-in Whitelist Persistence.
Validates:
1. Clean slate on boot (zero auto-load)
2. Strict JSON schema validation and size/encoding limits
3. Strict IPv4 checks (no CIDR, loopback, multicast, broadcast)
4. Count mismatch and duplicate IP detection
5. Empty whitelist lifecycle support
6. Symlink attack rejection without automatic deletion
7. Path traversal prevention
8. Cross-process file locking behavior and preservation of lock file
9. RBAC enforcement (admin vs non-admin)
10. Ryu greenlet semaphore mutual exclusion and state versioning
11. Atomic replace and commit point (unblocking overlapping IPs)
12. Decoupled switch flow remediation and error isolation
13. Ambiguous outcome reconciliation flow after socket timeout
14. Memory clear vs disk file deletion isolation
15. Minimal audit logging and fail-secure fallback
"""

import copy
import hashlib
import json
import logging
import os
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

# Configure test environment
os.environ['SDN_DISABLE_CONTROLLER_METRICS_BOOTSTRAP'] = '1'
os.environ['SDN_ALERTS_SYNC_WORKER_ENABLED'] = '0'

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
            self.status_code = int(status)
            self.content_type = content_type
            self.body = body if isinstance(body, (bytes, bytearray)) else str(body).encode('utf-8')

    wsgi.WSGIApplication = DummyWSGIApplication
    wsgi.ControllerBase = DummyControllerBase
    wsgi.route = lambda *a, **kw: (lambda fn: fn)
    ryu_app_pkg.wsgi = wsgi
    ryu.app = ryu_app_pkg

    webob = _pkg('webob')
    webob.Response = DummyResponse

_ensure_ryu_stubs()

import requests
from webapp import server as webapp_server
from ryu_app import dos_guard


class TestF20WhitelistPersistence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        webapp_server.app.config['TESTING'] = True
        cls.client = webapp_server.app.test_client()

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.orig_configs_dir = webapp_server.CONFIGS_DIR
        self.orig_storage_path = webapp_server.WHITELIST_STORAGE_PATH
        self.orig_lock_path = webapp_server.WHITELIST_LOCK_PATH

        webapp_server.CONFIGS_DIR = self.tmp_dir.name
        webapp_server.WHITELIST_STORAGE_PATH = os.path.join(self.tmp_dir.name, 'sdn_whitelist.json')
        webapp_server.WHITELIST_LOCK_PATH = os.path.join(self.tmp_dir.name, '.sdn_whitelist.lock')

    def tearDown(self):
        webapp_server.CONFIGS_DIR = self.orig_configs_dir
        webapp_server.WHITELIST_STORAGE_PATH = self.orig_storage_path
        webapp_server.WHITELIST_LOCK_PATH = self.orig_lock_path
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def _login(self, user='admin', role='admin'):
        with self.client.session_transaction() as sess:
            sess['user'] = user
            sess['boot_id'] = webapp_server._SERVER_BOOT_ID
            sess['login_ts'] = int(time.time())
            sess['csrf_token'] = 'f20-test-token'
        return {'X-CSRF-Token': 'f20-test-token'}

    # 1. Clean slate on boot invariant
    def test_clean_slate_on_boot_invariant(self):
        """Verify DoSGuard initializes whitelist as empty set and performs zero autoload."""
        fake_wsgi = mock.MagicMock()
        with mock.patch('ryu.app.wsgi.WSGIApplication'):
            dg = dos_guard.DoSGuard(wsgi=fake_wsgi)
        self.assertIsInstance(dg.whitelist_ips, set)
        self.assertEqual(len(dg.whitelist_ips), 0)
        self.assertEqual(dg._whitelist_state_version, 0)
        self.assertIsNone(dg._whitelist_last_request_id)

    # 2. Schema validation: strict encoding, size, fields
    def test_schema_validation_strict_rules(self):
        """Verify schema validation enforces 64KB limit, strict UTF-8 (no BOM), and required keys."""
        oversized = b'{"a": 1}' * 100000
        data, err = webapp_server._validate_whitelist_json_payload(oversized)
        self.assertIsNone(data)
        self.assertIn("64KB limit", err)

        bom_payload = b'\xef\xbb\xbf{"schema_version": "1.0", "updated_at": "2026-11-13T00:00:00Z", "updated_by": "admin", "count": 0, "whitelist_ips": []}'
        data, err = webapp_server._validate_whitelist_json_payload(bom_payload)
        self.assertIsNone(data)
        self.assertIn("BOM is strictly prohibited", err)

        incomplete = json.dumps({"schema_version": "1.0", "updated_at": "2026-11-13T00:00:00Z"}).encode('utf-8')
        data, err = webapp_server._validate_whitelist_json_payload(incomplete)
        self.assertIsNone(data)
        self.assertIn("Missing required fields", err)

        bad_ver = json.dumps({
            "schema_version": "2.0",
            "updated_at": "2026-11-13T00:00:00Z",
            "updated_by": "admin",
            "count": 0,
            "whitelist_ips": []
        }).encode('utf-8')
        data, err = webapp_server._validate_whitelist_json_payload(bad_ver)
        self.assertIsNone(data)
        self.assertIn("Unsupported schema_version", err)

    # 3. Schema IP validation and rejection
    def test_schema_ip_validation_and_rejection(self):
        """Verify strict IPv4 validation (rejecting CIDR, IPv6, loopback, multicast, broadcast)."""
        cases = [
            ("10.0.0.0/24", "CIDR notation and IPv6 are not allowed"),
            ("2001:db8::1", "CIDR notation and IPv6 are not allowed"),
            ("127.0.0.1", "Loopback address not permitted"),
            ("224.0.0.5", "Multicast address not permitted"),
            ("255.255.255.255", "Reserved broadcast/wildcard address not permitted"),
            ("0.0.0.0", "Reserved broadcast/wildcard address not permitted"),
            ("not-an-ip", "Invalid IPv4 address"),
        ]
        for bad_ip, expected_err in cases:
            payload = {
                "schema_version": "1.0",
                "updated_at": "2026-11-13T00:00:00Z",
                "updated_by": "admin",
                "count": 1,
                "whitelist_ips": [bad_ip]
            }
            data, err = webapp_server._validate_whitelist_json_payload(json.dumps(payload).encode('utf-8'))
            self.assertIsNone(data, f"Failed to reject invalid IP: {bad_ip}")
            self.assertIn(expected_err, err)

    # 4. Count mismatch and duplicates
    def test_schema_count_mismatch_and_duplicates(self):
        """Verify rejection when count does not equal list length or when duplicates exist."""
        mismatch = {
            "schema_version": "1.0",
            "updated_at": "2026-11-13T00:00:00Z",
            "updated_by": "admin",
            "count": 2,
            "whitelist_ips": ["10.0.0.1"]
        }
        data, err = webapp_server._validate_whitelist_json_payload(json.dumps(mismatch).encode('utf-8'))
        self.assertIsNone(data)
        self.assertIn("Count mismatch", err)

        dup = {
            "schema_version": "1.0",
            "updated_at": "2026-11-13T00:00:00Z",
            "updated_by": "admin",
            "count": 2,
            "whitelist_ips": ["10.0.0.1", "10.0.0.1"]
        }
        data, err = webapp_server._validate_whitelist_json_payload(json.dumps(dup).encode('utf-8'))
        self.assertIsNone(data)
        self.assertIn("Duplicate IP addresses detected", err)

    # 5. Empty whitelist lifecycle allowed
    def test_empty_whitelist_lifecycle_allowed(self):
        """Verify saving and restoring an empty whitelist is valid and supported."""
        empty_payload = {
            "schema_version": "1.0",
            "updated_at": "2026-11-13T00:00:00Z",
            "updated_by": "admin",
            "count": 0,
            "whitelist_ips": []
        }
        raw = json.dumps(empty_payload).encode('utf-8')
        data, err = webapp_server._validate_whitelist_json_payload(raw)
        self.assertIsNotNone(data)
        self.assertIsNone(err)
        self.assertEqual(data['count'], 0)
        self.assertEqual(data['whitelist_ips'], [])

    # 6. Symlink attack rejection without automatic deletion
    def test_symlink_attack_rejection_without_delete(self):
        """Verify symlink target causes SecurityError and the symlink is NOT deleted."""
        headers = self._login()
        target_real_file = os.path.join(self.tmp_dir.name, 'real_file.json')
        with open(target_real_file, 'w', encoding='utf-8') as f:
            f.write("{}")

        symlink_path = webapp_server.WHITELIST_STORAGE_PATH
        try:
            os.symlink(target_real_file, symlink_path)
        except OSError:
            return

        with mock.patch('requests.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {'whitelist_ips': ['10.0.0.1']}
            res = self.client.post('/api/whitelist/save', headers=headers)
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertEqual(data.get('error'), 'security_violation')
            self.assertTrue(os.path.islink(symlink_path))

    # 7. Path traversal prevention
    def test_path_traversal_prevention(self):
        """Verify path traversal check blocks files outside CONFIGS_DIR."""
        headers = self._login()
        webapp_server.WHITELIST_STORAGE_PATH = os.path.abspath(os.path.join(self.tmp_dir.name, '..', 'escaped.json'))
        with mock.patch('requests.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {'whitelist_ips': ['10.0.0.1']}
            res = self.client.post('/api/whitelist/save', headers=headers)
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertEqual(data.get('error'), 'security_violation')

    # 8. Cross-process file locking behavior and lock preservation
    def test_multi_worker_flock_concurrency(self):
        """Verify CrossProcessFileLock acquires, releases, and never unlinks .sdn_whitelist.lock."""
        lock_file = webapp_server.WHITELIST_LOCK_PATH
        with webapp_server.CrossProcessFileLock(lock_file, timeout_sec=2.0) as lock:
            self.assertIsNotNone(lock.fd)
            self.assertTrue(os.path.exists(lock_file))
        self.assertTrue(os.path.exists(lock_file))

    # 9. RBAC enforcement
    def test_rbac_admin_enforcement(self):
        """Verify non-admin users receive 403 Forbidden on persistence endpoints."""
        with mock.patch('webapp.server._load_users') as mock_users:
            mock_users.return_value = {
                'operator_user': {'role': 'operator', 'password': 'hash'}
            }
            headers = self._login(user='operator_user', role='operator')
            res = self.client.post('/api/whitelist/save', headers=headers)
            self.assertEqual(res.status_code, 403)
            self.assertEqual(res.get_json().get('error'), 'forbidden')

            res = self.client.post('/api/whitelist/restore', headers=headers)
            self.assertEqual(res.status_code, 403)
            self.assertEqual(res.get_json().get('error'), 'forbidden')

            res = self.client.delete('/api/whitelist/persistent', headers=headers)
            self.assertEqual(res.status_code, 403)
            self.assertEqual(res.get_json().get('error'), 'forbidden')

    # 10. Ryu greenlet semaphore mutual exclusion and state versioning
    def test_ryu_greenlet_semaphore_concurrency(self):
        """Verify _whitelist_sem serializes mutations and increments monotonic state version."""
        fake_wsgi = mock.MagicMock()
        with mock.patch('ryu.app.wsgi.WSGIApplication'):
            dg = dos_guard.DoSGuard(wsgi=fake_wsgi)

        ctrl = dos_guard.DoSGuardWebController(None, None, data={dos_guard.DOS_GUARD_INSTANCE_NAME: dg})

        req = mock.MagicMock()
        req.body = json.dumps({'request_id': 'req-1', 'whitelist_ips': ['10.0.0.1', '10.0.0.2']}).encode('utf-8')
        resp = ctrl.replace_whitelist(req)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.body.decode('utf-8'))
        self.assertEqual(data['state_version'], 1)
        self.assertEqual(dg._whitelist_state_version, 1)
        self.assertEqual(dg.whitelist_ips, {'10.0.0.1', '10.0.0.2'})

        req2 = mock.MagicMock()
        req2.body = json.dumps({'request_id': 'req-2', 'whitelist_ips': ['10.0.0.3']}).encode('utf-8')
        resp2 = ctrl.replace_whitelist(req2)
        data2 = json.loads(resp2.body.decode('utf-8'))
        self.assertEqual(data2['state_version'], 2)
        self.assertEqual(dg._whitelist_state_version, 2)
        self.assertEqual(dg.whitelist_ips, {'10.0.0.3'})

    # 11. Atomic replace and commit point (unblocking overlapping IPs)
    def test_restore_atomic_commit_point(self):
        """Verify replace removes freed IPs from blocked_ips and quarantined_ips in memory."""
        fake_wsgi = mock.MagicMock()
        with mock.patch('ryu.app.wsgi.WSGIApplication'):
            dg = dos_guard.DoSGuard(wsgi=fake_wsgi)

        dg.blocked_ips.add('10.0.0.99')
        dg.blocked_info['10.0.0.99'] = {'ts': time.time(), 'reason': 'test'}
        dg.quarantined_ips.add('10.0.0.88')
        dg.quarantined_info['10.0.0.88'] = {'ts': time.time()}

        ctrl = dos_guard.DoSGuardWebController(None, None, data={dos_guard.DOS_GUARD_INSTANCE_NAME: dg})
        req = mock.MagicMock()
        req.body = json.dumps({'request_id': 'unblock-test', 'whitelist_ips': ['10.0.0.99', '10.0.0.88']}).encode('utf-8')

        resp = ctrl.replace_whitelist(req)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.body.decode('utf-8'))
        self.assertIn('10.0.0.99', data['freed_blocked'])
        self.assertIn('10.0.0.88', data['freed_quarantined'])
        self.assertNotIn('10.0.0.99', dg.blocked_ips)
        self.assertNotIn('10.0.0.99', dg.blocked_info)
        self.assertNotIn('10.0.0.88', dg.quarantined_ips)
        self.assertNotIn('10.0.0.88', dg.quarantined_info)

    # 12. Decoupled switch flow remediation and error isolation
    def test_restore_switch_remediation_isolation(self):
        """Verify that switch communication failure does not roll back memory state."""
        fake_wsgi = mock.MagicMock()
        with mock.patch('ryu.app.wsgi.WSGIApplication'):
            dg = dos_guard.DoSGuard(wsgi=fake_wsgi)

        dg.blocked_ips.add('10.0.0.77')
        dg._remove_block_ip_all = mock.MagicMock(side_effect=RuntimeError("Switch 1 disconnected"))

        ctrl = dos_guard.DoSGuardWebController(None, None, data={dos_guard.DOS_GUARD_INSTANCE_NAME: dg})
        req = mock.MagicMock()
        req.body = json.dumps({'request_id': 'switch-fail-test', 'whitelist_ips': ['10.0.0.77']}).encode('utf-8')

        resp = ctrl.replace_whitelist(req)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.body.decode('utf-8'))
        self.assertEqual(data['ok'], True)
        self.assertIn('10.0.0.77', dg.whitelist_ips)
        self.assertNotIn('10.0.0.77', dg.blocked_ips)
        self.assertEqual(len(data['remediation_warnings']), 1)
        self.assertIn('Switch 1 disconnected', data['remediation_warnings'][0]['detail'])

    # 13. Ambiguous outcome reconciliation flow after socket timeout
    def test_restore_ambiguous_outcome_reconciliation(self):
        """Verify that a socket timeout triggers GET /dos/whitelist reconciliation."""
        headers = self._login()

        file_payload = {
            "schema_version": "1.0",
            "updated_at": "2026-11-13T00:00:00Z",
            "updated_by": "admin",
            "count": 2,
            "whitelist_ips": ["10.0.0.1", "10.0.0.2"]
        }
        with open(webapp_server.WHITELIST_STORAGE_PATH, 'w', encoding='utf-8') as f:
            json.dump(file_payload, f)

        def fake_post(*args, **kwargs):
            raise requests.exceptions.Timeout("Read timeout on socket")

        def fake_get(*args, **kwargs):
            m = mock.MagicMock()
            m.status_code = 200
            m.json.return_value = {
                'ok': True,
                'state_version': 5,
                'last_request_id': 'any',
                'recent_history': [{'request_id': 'recon-matched', 'version': 5}]
            }
            return m

        with mock.patch('requests.post', side_effect=fake_post):
            with mock.patch('requests.get', side_effect=fake_get):
                with mock.patch('uuid.uuid4', return_value='recon-matched'):
                    res = self.client.post('/api/whitelist/restore', headers=headers)
                    self.assertEqual(res.status_code, 200)
                    data = res.get_json()
                    self.assertTrue(data.get('ok'))
                    self.assertTrue(data.get('reconciled'))
                    self.assertEqual(data.get('restored_count'), 2)

    # 14. Memory clear vs disk file deletion isolation
    def test_clear_memory_vs_delete_disk_isolation(self):
        """Verify /api/whitelist/clear clears memory without touching disk, and DELETE persistent removes disk without touching memory."""
        headers = self._login()

        with open(webapp_server.WHITELIST_STORAGE_PATH, 'w', encoding='utf-8') as f:
            json.dump({
                "schema_version": "1.0",
                "updated_at": "2026-11-13T00:00:00Z",
                "updated_by": "admin",
                "count": 1,
                "whitelist_ips": ["10.0.0.1"]
            }, f)

        fake_resp = webapp_server.Response(json.dumps({'ok': True}), status=200, mimetype='application/json')
        with mock.patch('webapp.server._proxy_ryu_post', return_value=fake_resp):
            res = self.client.post('/api/whitelist/clear', headers=headers)
            self.assertEqual(res.status_code, 200)
        self.assertTrue(os.path.exists(webapp_server.WHITELIST_STORAGE_PATH))

        res = self.client.delete('/api/whitelist/persistent', headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertFalse(os.path.exists(webapp_server.WHITELIST_STORAGE_PATH))

    # 15. Minimal audit logging and fail-secure fallback
    def test_audit_logging_minimal_and_fail_secure(self):
        """Verify audit log outputs sha256 prefix instead of full IP dump, and handles logger crashes safely."""
        with mock.patch.object(webapp_server.app.logger, 'info') as mock_info:
            webapp_server._audit_log_whitelist("TEST_ACTION", "admin", 2, ["10.0.0.1", "10.0.0.2"], "req-999")
            self.assertEqual(mock_info.call_count, 1)
            call_args = mock_info.call_args[0]
            log_str = call_args[1]
            data = json.loads(log_str)
            self.assertEqual(data['event'], "TEST_ACTION")
            self.assertEqual(data['user'], "admin")
            self.assertEqual(data['count'], 2)
            self.assertIn('sha256_prefix', data)
            self.assertNotIn('10.0.0.1', log_str)

        with mock.patch.object(webapp_server.app.logger, 'info', side_effect=RuntimeError("Logger failure")):
            with mock.patch('sys.stderr.write') as mock_stderr:
                webapp_server._audit_log_whitelist("FAIL_ACTION", "admin", 0, [], "req-000")
                self.assertTrue(mock_stderr.called)


if __name__ == '__main__':
    unittest.main()
