"""Unit tests for Role-Based Access Control (RBAC) and Admin Role Denial (TEST-03).

Verifies SEC-02, SEC-04, and SEC-05:
1. Unauthenticated requests to administrative endpoints return 401 Unauthorized.
2. Unprivileged 'user' (role: 'user') receives 403 Forbidden on all 22 administrative endpoints.
3. Authenticated 'admin' (role: 'admin') passes RBAC check on administrative endpoints.
4. Dual-schema parsing in _load_users() correctly parses dicts and legacy string hashes.
5. Plaintext passwords in storage are strictly rejected by _verify_password().
"""

import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from werkzeug.security import generate_password_hash
import webapp.server as srv


class TestRBACUserDenial(unittest.TestCase):
    """Test suite verifying RBAC enforcement across all operational/destructive routes."""

    ADMIN_MUTATING_ENDPOINTS = [
        ('POST', '/api/controller/start', {'learning_enabled': False}),
        ('POST', '/api/controller/stop', {}),
        ('POST', '/api/config', {'dos_threshold_pps': 200}),
        ('POST', '/api/config/update', {'dos_threshold_pps': 200}),
        ('POST', '/api/lab/build', {'nodes': ['s1'], 'links': []}),
        ('POST', '/api/lab/topology/apply', {'nodes': ['s1'], 'links': []}),
        ('POST', '/api/lab/stop', {}),
        ('POST', '/api/lab/link/update', {'src': 'h1', 'dst': 's1', 'loss': 0}),
        ('POST', '/api/lab/scenario', {'name': 'syn_flood'}),
        ('POST', '/api/lab/attack/run', {'kind': 'syn_flood'}),
        ('POST', '/api/lab/attack/stop', {}),
        ('POST', '/api/lab/pcap/pin/sample.pcap', {}),
        ('POST', '/api/lab/pcap/unpin/sample.pcap', {}),
        ('DELETE', '/api/lab/pcap/delete/sample.pcap', {}),
        ('POST', '/api/lab/ha/config', {'active': 'primary'}),
        ('POST', '/api/lab/ha/active', {'active': 'primary'}),
        ('POST', '/api/lab/ha/service/start', {}),
        ('POST', '/api/lab/ha/service/stop', {}),
        ('POST', '/api/lab/cmd/run', {'node': 'h1', 'cmd': 'ls'}),
        ('POST', '/api/whitelist/save', {}),
        ('POST', '/api/whitelist/restore', {}),
        ('DELETE', '/api/whitelist/persistent', {}),
        ('POST', '/api/block/ip', {'ip': '10.0.0.99'}),
        ('POST', '/api/unblock/ip', {'ip': '10.0.0.99'}),
        ('POST', '/api/unblock/all', {}),
        ('POST', '/api/block/mac', {'mac': '00:00:00:00:00:99'}),
        ('POST', '/api/unblock/mac', {'mac': '00:00:00:00:00:99'}),
        ('POST', '/api/unblock/mac/all', {}),
        ('POST', '/api/whitelist/ip', {'ip': '10.0.0.99'}),
        ('POST', '/api/unwhitelist/ip', {'ip': '10.0.0.99'}),
        ('POST', '/api/whitelist/clear', {}),
        ('POST', '/api/flows/clear', {}),
        ('POST', '/api/alerts/clear', {}),
        ('POST', '/api/settings', {'ryu_api_base': 'http://127.0.0.1:8080'}),
    ]

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

    def _login_session(self, username: str, role: str):
        csrf = f'csrf_token_{username}'
        with self.client.session_transaction() as sess:
            sess['user'] = username
            sess['role'] = role
            sess['boot_id'] = srv._SERVER_BOOT_ID
            sess['login_ts'] = int(time.time())
            sess['csrf_token'] = csrf
        return {'X-CSRF-Token': csrf}

    def test_unauthenticated_requests_receive_401(self):
        """Unauthenticated requests must be rejected with 401 Unauthorized by _auth_guard."""
        for method, endpoint, payload in self.ADMIN_MUTATING_ENDPOINTS:
            with self.subTest(endpoint=endpoint, method=method):
                if method == 'POST':
                    res = self.client.post(endpoint, json=payload)
                elif method == 'DELETE':
                    res = self.client.delete(endpoint)
                else:
                    res = self.client.open(endpoint, method=method)
                self.assertEqual(res.status_code, 401, f'Endpoint {endpoint} allowed unauthenticated access')
                body = res.get_json() or {}
                self.assertEqual(body.get('error'), 'unauthorized')

    def test_unprivileged_user_receives_403_on_all_admin_endpoints(self):
        """User with role 'user' must receive HTTP 403 Forbidden on all administrative endpoints."""
        headers = self._login_session(username='user', role='user')

        for method, endpoint, payload in self.ADMIN_MUTATING_ENDPOINTS:
            with self.subTest(endpoint=endpoint, method=method):
                if method == 'POST':
                    res = self.client.post(endpoint, json=payload, headers=headers)
                elif method == 'DELETE':
                    res = self.client.delete(endpoint, headers=headers)
                else:
                    res = self.client.open(endpoint, method=method, headers=headers)

                self.assertEqual(
                    res.status_code,
                    403,
                    f'Unprivileged user was not blocked with 403 on {method} {endpoint}; got {res.status_code}: {res.get_data(as_text=True)}',
                )
                body = res.get_json() or {}
                self.assertEqual(body.get('error'), 'forbidden', f'Expected error=forbidden on {endpoint}')

    def test_admin_user_passes_rbac_on_admin_endpoints(self):
        """Admin user with role 'admin' must pass RBAC without 403 Forbidden."""
        headers = self._login_session(username='admin', role='admin')
        mock_resp = srv.Response(json.dumps({'ok': True}), status=200, mimetype='application/json')

        # Mock downstream backends so calls that pass RBAC don't fail with connection errors
        with patch('webapp.blueprints.controller._call_controller_status', return_value={'ok': True, 'running': True}), \
             patch('webapp.blueprints.controller._get_subprocess_module') as mock_sub, \
             patch('webapp.blueprints.lab_proxy._call_proxy_runner', return_value=mock_resp), \
             patch('webapp.blueprints.mitigation._call_proxy_ryu_post', return_value=(mock_resp, 200)), \
             patch('webapp.blueprints.whitelist.requests.get') as mock_req_get, \
             patch('webapp.blueprints.whitelist.requests.post') as mock_req_post, \
             patch('webapp.blueprints.whitelist.CrossProcessFileLock'):

            mock_sub.Popen.return_value = MagicMock(pid=12345)
            mock_req_get.return_value.status_code = 200
            mock_req_get.return_value.json.return_value = {'whitelist_ips': []}
            mock_req_post.return_value.status_code = 200
            mock_req_post.return_value.json.return_value = {'ok': True}

            for method, endpoint, payload in self.ADMIN_MUTATING_ENDPOINTS:
                with self.subTest(endpoint=endpoint, method=method):
                    if method == 'POST':
                        res = self.client.post(endpoint, json=payload, headers=headers)
                    elif method == 'DELETE':
                        res = self.client.delete(endpoint, headers=headers)
                    else:
                        res = self.client.open(endpoint, method=method, headers=headers)

                    self.assertNotEqual(
                        res.status_code,
                        403,
                        f'Admin user was incorrectly blocked with 403 on {method} {endpoint}',
                    )
                    self.assertNotEqual(
                        res.status_code,
                        401,
                        f'Admin user received 401 on {method} {endpoint}',
                    )

    def test_dual_schema_user_loading(self):
        """Verify _load_users() supports both dict schema and legacy string schema."""
        test_file = os.path.join(self.tmpdir.name, 'dual_schema_users.json')
        sample_hash = generate_password_hash('TestPass123!')
        with open(test_file, 'w', encoding='utf-8') as f:
            json.dump(
                {
                    'admin_user': {'password': sample_hash, 'role': 'admin'},
                    'legacy_user': sample_hash,  # String format defaults to role 'user'
                    'dict_no_role': {'password': sample_hash},  # Defaults to role 'user'
                },
                f,
            )

        orig = srv.USERS_FILE
        try:
            srv.USERS_FILE = test_file
            with srv._users_cache_lock:
                srv._users_cache = {}
                srv._users_cache_mtime = 0.0

            loaded = srv._load_users()
            self.assertIn('admin_user', loaded)
            self.assertEqual(loaded['admin_user']['role'], 'admin')
            self.assertEqual(loaded['admin_user']['password'], sample_hash)

            self.assertIn('legacy_user', loaded)
            self.assertEqual(loaded['legacy_user']['role'], 'user')
            self.assertEqual(loaded['legacy_user']['password'], sample_hash)

            self.assertIn('dict_no_role', loaded)
            self.assertEqual(loaded['dict_no_role']['role'], 'user')
            self.assertEqual(loaded['dict_no_role']['password'], sample_hash)
        finally:
            srv.USERS_FILE = orig
            with srv._users_cache_lock:
                srv._users_cache = {}
                srv._users_cache_mtime = 0.0

    def test_plaintext_password_rejected_at_verification(self):
        """Plaintext passwords in database must be strictly rejected by _verify_password()."""
        # Hashed password passes
        h = generate_password_hash('ValidSecurePass123!')
        self.assertTrue(srv._verify_password(h, 'ValidSecurePass123!'))
        self.assertFalse(srv._verify_password(h, 'WrongPass!'))

        # Plaintext password in database MUST NOT match even if identical
        self.assertFalse(srv._verify_password('PlaintextSecret123', 'PlaintextSecret123'))
        self.assertFalse(srv._verify_password('', 'password'))
        self.assertFalse(srv._verify_password('password', ''))


if __name__ == '__main__':
    unittest.main()
