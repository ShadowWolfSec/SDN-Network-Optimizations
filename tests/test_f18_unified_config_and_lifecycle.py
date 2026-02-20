"""
tests/test_f18_unified_config_and_lifecycle.py
Unit & Integration Tests for F-18 Unified Configuration & Lifecycle
"""
import unittest
import os
import json
import tempfile
import shutil
import time
from core.sdn_config import (
    SDNConfigManager,
    SDNConfigSchema,
    ConfigSource,
    ConfigMutability,
)


class TestSDNUnifiedConfig(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="sdn_cfg_test_")
        self.cfg_file = os.path.join(self.test_dir, "sdn_config.json")
        self.clean_env = os.environ.copy()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.clean_env)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_default_values_safety(self):
        """Verify sensitive defaults are strictly False."""
        mgr = SDNConfigManager(config_file=self.cfg_file)
        eff = mgr.get_all_effective()
        self.assertFalse(eff['fastpath_enable'], "fastpath_enable must be False by default")
        self.assertFalse(eff['ctrl_meter_enable'], "ctrl_meter_enable must be False by default")
        self.assertFalse(eff['auto_failover_enable'], "auto_failover_enable must be False by default")
        self.assertEqual(eff['threshold_pps'], 300.0)
        self.assertEqual(eff['alpha'], 0.3)

    def test_config_hierarchy_precedence(self):
        """Test layer precedence: Env (Canonical) > Env (Legacy) > File > Defaults."""
        # Layer 2: File
        with open(self.cfg_file, 'w', encoding='utf-8') as f:
            json.dump({'threshold_pps': 450.0, 'alpha': 0.5}, f)

        # Layer 3: Legacy env
        os.environ['ALPHA'] = '0.75'
        # Layer 3: Canonical env
        os.environ['SDN_THRESHOLD_PPS'] = '600.0'

        mgr = SDNConfigManager(config_file=self.cfg_file)
        self.assertEqual(mgr.get_effective('threshold_pps'), 600.0, "Canonical env must override file")
        self.assertEqual(mgr.get_effective('alpha'), 0.75, "Legacy env must override file")

    def test_runtime_override_ephemeral(self):
        """Verify in-memory updates do not persist when persist=False."""
        mgr = SDNConfigManager(config_file=self.cfg_file)
        changed, errors, persisted = mgr.apply_runtime_override({'threshold_pps': 550.0}, persist=False)
        self.assertEqual(changed.get('threshold_pps'), 550.0)
        self.assertFalse(persisted)
        self.assertFalse(os.path.exists(self.cfg_file))
        self.assertEqual(mgr.get_effective('threshold_pps'), 550.0)

        # Reload clean
        mgr.load_startup()
        self.assertEqual(mgr.get_effective('threshold_pps'), 300.0, "Ephemeral change must revert on reload")

    def test_atomic_persistence(self):
        """Verify atomic two-phase write when persist=True."""
        mgr = SDNConfigManager(config_file=self.cfg_file)
        changed, errors, persisted = mgr.apply_runtime_override({'threshold_pps': 700.0}, persist=True)
        self.assertTrue(persisted)
        self.assertTrue(os.path.exists(self.cfg_file))

        with open(self.cfg_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.assertEqual(data.get('threshold_pps'), 700.0)

        # Reload clean from file
        mgr2 = SDNConfigManager(config_file=self.cfg_file)
        self.assertEqual(mgr2.get_effective('threshold_pps'), 700.0, "Persisted change must survive reload")

    def test_bounds_and_type_validation(self):
        """Verify out of bounds and wrong types are rejected cleanly."""
        mgr = SDNConfigManager(config_file=self.cfg_file)
        changed, errors, persisted = mgr.apply_runtime_override({'alpha': 1.5, 'wsapi_port': -1})
        self.assertIn('alpha', errors)
        self.assertIn('wsapi_port', errors)
        self.assertEqual(changed, {})

    def test_export_for_subprocess(self):
        """Verify child environment includes both canonical and legacy aliases."""
        mgr = SDNConfigManager(config_file=self.cfg_file)
        mgr.apply_runtime_override({'vip_ip': '10.0.0.99', 'fastpath_enable': False}, persist=False)
        sub_env = mgr.export_for_subprocess()

        self.assertEqual(sub_env.get('SDN_VIP_IP'), '10.0.0.99')
        self.assertEqual(sub_env.get('VIP_IP'), '10.0.0.99')
        self.assertEqual(sub_env.get('SDN_FASTPATH_ENABLE'), '0')
        self.assertEqual(sub_env.get('DP_FASTPATH_ENABLE'), '0')


class TestServerLifecycleAndAPI(unittest.TestCase):

    def setUp(self):
        import webapp.server as srv
        self.srv = srv
        self.app = srv.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def _login(self):
        with self.client.session_transaction() as sess:
            sess['user'] = 'admin'
            sess['boot_id'] = self.srv._SERVER_BOOT_ID
            sess['login_ts'] = int(time.time())
            sess['csrf_token'] = 'test-token'
        return {'X-CSRF-Token': 'test-token'}

    def test_decoupled_readiness_structure(self):
        """Verify GET /api/controller/status returns the 4 decoupled readiness stages."""
        self._login()
        res = self.client.get('/api/controller/status')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))
        self.assertIn('readiness', data)
        readiness = data['readiness']
        self.assertIn('process_started', readiness)
        self.assertIn('rest_ready', readiness)
        self.assertIn('openflow_listener_ready', readiness)
        self.assertIn('datapath_ready', readiness)
        self.assertIn('datapaths_count', readiness)
        self.assertIn('datapaths', readiness)
        self.assertIn('overall_state', data)

    def test_unverified_process_stop_protection(self):
        """Verify API rejects stop request with 409 Conflict if process identity is unverified."""
        from unittest import mock
        headers = self._login()

        # Mock unverified identity (e.g. stale reused PID)
        with mock.patch.object(self.srv, '_read_pid', return_value=99999):
            with mock.patch.object(self.srv, '_verify_process_identity', return_value=('stale_pid_reused', False, None)):
                res = self.client.post('/api/controller/stop', headers=headers)
                self.assertEqual(res.status_code, 409)
                data = res.get_json()
                self.assertFalse(data.get('ok'))
                self.assertEqual(data.get('error'), 'process_identity_unverified')

    def test_openflow_listener_bypassed_when_headless(self):
        """Verify listener check returns bypassed_headless when ofp_port <= 0."""
        ready, status = self.srv._check_ofp_listener(0, None)
        self.assertTrue(ready)
        self.assertEqual(status, 'bypassed_headless')

    def test_api_config_persistence_contract(self):
        """Verify GET and POST /api/config lifecycle."""
        from unittest import mock
        headers = self._login()

        # Test GET /api/config
        res_get = self.client.get('/api/config')
        self.assertEqual(res_get.status_code, 200)
        get_data = res_get.get_json()
        self.assertTrue(get_data.get('ok'))
        self.assertIn('metadata', get_data)
        self.assertIn('effective', get_data)

        # Test POST /api/config validation failure
        res_bad = self.client.post('/api/config', json={'alpha': 2.5, 'persist': True}, headers=headers)
        self.assertEqual(res_bad.status_code, 400)
        self.assertEqual(res_bad.get_json().get('error'), 'validation_failed')

        # Test POST /api/config successful ephemeral
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True
        mock_resp.json.return_value = {'ok': True, 'changed': {'threshold_pps': 380.0}}

        with mock.patch.object(self.srv, '_proxy_ryu_post', return_value=mock_resp):
            res_good = self.client.post('/api/config', json={'threshold_pps': 380, 'persist': False}, headers=headers)
            self.assertEqual(res_good.status_code, 200)
            data = res_good.get_json()
            self.assertTrue(data.get('ok'))
            self.assertEqual(data.get('durability'), 'ephemeral')
            self.assertFalse(data.get('persisted'))


if __name__ == '__main__':
    unittest.main()

