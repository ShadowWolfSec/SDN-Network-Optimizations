"""
tests/test_auth_fail_secure.py
Unit tests verifying fail-secure behavior for internal API tokens and foreign path removal (TEST-04, SEC-01, SEC-03).
"""

import json
import os
import types
import unittest
from unittest import mock

from core.common_utils import load_internal_token
from ryu_app.web_controller import DoSGuardWebController
from labs.mininet_runner import app as runner_app


class TestAuthFailSecure(unittest.TestCase):
    """Verify that token validation is strictly fail-secure across all internal services."""

    def test_common_utils_never_reads_foreign_path(self):
        """load_internal_token must never load from foreign project directory sdn-ddos-mitigation-ha."""
        foreign_path = '/home/ubuntu/Desktop/sdn-ddos-mitigation-ha/.run/internal.token'
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch('os.path.isfile') as mock_isfile:
                mock_isfile.side_effect = lambda p: p == foreign_path
                with mock.patch('builtins.open', mock.mock_open(read_data='leaked_foreign_secret')):
                    tok = load_internal_token()
                    self.assertEqual(tok, '', f"Foreign token path was read: {foreign_path}")

    def test_web_controller_fail_secure_when_token_missing(self):
        """When no token is configured anywhere, web_controller must reject all calls with 401."""
        ctrl = DoSGuardWebController(req=None, link=None, data={})
        with mock.patch('ryu_app.web_controller._load_internal_token', return_value=''):
            req = types.SimpleNamespace(headers={})
            resp = ctrl(req)
            self.assertIsNotNone(resp)
            self.assertEqual(resp.status_code, 401)
            data = json.loads(resp.body.decode('utf-8'))
            self.assertFalse(data.get('ok'))
            self.assertEqual(data.get('error'), 'unauthorized')

    def test_web_controller_rejects_missing_or_bad_token(self):
        """When token is configured, missing or invalid token must return 401."""
        ctrl = DoSGuardWebController(req=None, link=None, data={})
        with mock.patch('ryu_app.web_controller._load_internal_token', return_value='expected-secret-123'):
            # Missing header
            req_missing = types.SimpleNamespace(headers={})
            resp1 = ctrl(req_missing)
            self.assertIsNotNone(resp1)
            self.assertEqual(resp1.status_code, 401)

            # Wrong header
            req_bad = types.SimpleNamespace(headers={'X-Internal-Token': 'wrong-token'})
            resp2 = ctrl(req_bad)
            self.assertIsNotNone(resp2)
            self.assertEqual(resp2.status_code, 401)

    def test_web_controller_accepts_valid_token(self):
        """When matching token is provided, controller proceeds past authentication."""
        ctrl = DoSGuardWebController(req=None, link=None, data={})
        with mock.patch('ryu_app.web_controller._load_internal_token', return_value='expected-secret-123'):
            with mock.patch.object(DoSGuardWebController, '__call__', autospec=True) as mock_call:
                # Test the actual logic
                pass
        # Direct check on DoSGuardWebController logic
        with mock.patch('ryu_app.web_controller._load_internal_token', return_value='expected-secret-123'):
            req_ok = types.SimpleNamespace(headers={'X-Internal-Token': 'expected-secret-123'})
            with mock.patch('ryu_app.web_controller.ControllerBase.__call__', return_value='ok_from_super'):
                resp = ctrl(req_ok)
                self.assertEqual(resp, 'ok_from_super')

    def test_mininet_runner_health_is_public(self):
        """The /health endpoint must remain accessible without a token."""
        with runner_app.test_client() as client:
            resp = client.get('/health')
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.get_json().get('ok'))

    def test_mininet_runner_fail_secure_when_token_missing(self):
        """When token file is missing or empty, runner endpoints must reject requests with 401."""
        with runner_app.test_client() as client:
            with mock.patch('labs.mininet_runner._load_internal_token', return_value=''):
                resp = client.get('/status')
                self.assertEqual(resp.status_code, 401)
                self.assertFalse(resp.get_json().get('ok'))
                self.assertEqual(resp.get_json().get('error'), 'unauthorized')

    def test_mininet_runner_rejects_missing_or_bad_token(self):
        """When token is configured, requests without valid token must return 401."""
        with runner_app.test_client() as client:
            with mock.patch('labs.mininet_runner._load_internal_token', return_value='secure-token-abc'):
                # No token
                resp1 = client.get('/status')
                self.assertEqual(resp1.status_code, 401)

                # Wrong token
                resp2 = client.get('/status', headers={'X-Internal-Token': 'invalid-token'})
                self.assertEqual(resp2.status_code, 401)

    def test_mininet_runner_accepts_valid_token(self):
        """When matching token is supplied, runner endpoint responds normally."""
        with runner_app.test_client() as client:
            with mock.patch('labs.mininet_runner._load_internal_token', return_value='secure-token-abc'):
                resp = client.get('/status', headers={'X-Internal-Token': 'secure-token-abc'})
                self.assertEqual(resp.status_code, 200)
                self.assertTrue(resp.get_json().get('ok'))


if __name__ == '__main__':
    unittest.main()
