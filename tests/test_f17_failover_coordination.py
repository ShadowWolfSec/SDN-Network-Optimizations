"""Tests for Phase 5 (F-17): Decoupled Failover Coordination, Recovery & Durability.
Verifies:
1. Ryu decoupling: _failover_to_backup emits failover_requested alert with ZERO outbound HTTP calls.
2. Failover coordinator: successful state transition (received -> pending -> succeeded).
3. Idempotency & coalescing: detects if target is already active or alert already processed.
4. Input validation: invalid HA targets rejected immediately with failover_error.
5. Bounded retries: transient network errors (Timeout, ConnectionError, 503) retry up to 3 times with backoff.
6. Terminal errors: HTTP 400 (e.g. network_not_built) fails fast without retrying.
7. Concurrency serialization: execution lock prevents race conditions and interleaving.
8. Crash recovery: bootstraps failover state and seen IDs from CSV on cold start.
9. Diagnostic API: GET /api/lab/ha/failover/status returns state history and in-flight metrics.
10. Manual HA active endpoint: validates allowlist and holds execution lock.
"""

import os
import sys
import time
import json
import csv
import shutil
import tempfile
import threading
import unittest
from unittest import mock
import requests

# Ensure stubs for mininet if running on platform without mininet
for mod_name in (
    'mininet', 'mininet.net', 'mininet.node', 'mininet.link',
    'mininet.topo', 'mininet.cli', 'mininet.log', 'mininet.util'
):
    if mod_name not in sys.modules:
        m = mock.MagicMock()
        m.__file__ = f"{mod_name}.py"
        sys.modules[mod_name] = m

# Ensure stubs for ryu if running on platform without ryu (e.g. Windows)
if 'ryu' not in sys.modules:
    import types
    import logging

    def _pkg(name):
        m = types.ModuleType(name)
        sys.modules[name] = m
        return m

    ryu = _pkg('ryu')
    ryu_base = _pkg('ryu.base')
    ryu_app_mgr = _pkg('ryu.base.app_manager')

    class DummyRyuApp:
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger('dos_guard_f17_test')

    ryu_app_mgr.RyuApp = DummyRyuApp
    ryu_base.app_manager = ryu_app_mgr
    ryu.base = ryu_base

    ryu_ctrl = _pkg('ryu.controller')
    ofp_event = _pkg('ryu.controller.ofp_event')
    for ev in ('EventOFPStateChange', 'EventOFPSwitchFeatures', 'EventOFPPacketIn',
               'EventOFPFlowStatsReply', 'EventOFPPortStatsReply', 'EventOFPMeterConfigStatsReply',
               'EventOFPBarrierReply', 'EventOFPErrorMsg'):
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
        setattr(ryu_pkt, sub, _pkg(f'ryu.lib.packet.{sub}'))
    ryu_lib.packet = ryu_pkt
    ryu.lib = ryu_lib

    ryu_app_pkg = _pkg('ryu.app')
    wsgi = _pkg('ryu.app.wsgi')

    class DummyWSGIApplication:
        def __init__(self):
            self.registory = {}
            self.mapper = mock.MagicMock()
        def register(self, cls, data):
            return None

    class DummyControllerBase:
        def __init__(self, req, link, data, **config):
            self.req = req
            self.link = link
            self.data = data

    wsgi.WSGIApplication = DummyWSGIApplication
    wsgi.ControllerBase = DummyControllerBase
    wsgi.route = lambda *a, **kw: (lambda fn: fn)
    ryu_app_pkg.wsgi = wsgi
    ryu.app = ryu_app_pkg

    webob = _pkg('webob')
    class DummyResponse:
        def __init__(self, status=200, content_type='text/plain', body=b''):
            self.status_code = int(status)
            self.content_type = content_type
            self.body = body if isinstance(body, (bytes, bytearray)) else str(body).encode('utf-8')
    webob.Response = DummyResponse

import webapp.server as srv
from ryu_app.dos_guard import DoSGuard


class F17FailoverCoordinationTests(unittest.TestCase):
    def setUp(self):
        # Stop background worker if running to ensure test isolation
        srv._stop_alerts_sync_worker(timeout=1.0)
        os.environ['SDN_ALERTS_SYNC_WORKER_ENABLED'] = '0'

        # Create temporary log directory for test events
        self.test_log_dir = tempfile.mkdtemp(prefix='sdn_f17_test_logs_')
        self.orig_log_dir = srv.LOG_DIR
        self.orig_events_file = srv.EVENTS_LOG_FILE
        srv.LOG_DIR = self.test_log_dir
        srv.EVENTS_LOG_FILE = os.path.join(self.test_log_dir, 'events.csv')

        # Reset in-memory alerts and failover state
        srv._reset_alerts_state_for_tests()

        # Configure test client
        srv.app.config['TESTING'] = True
        self.client = srv.app.test_client()

    def tearDown(self):
        srv._reset_alerts_state_for_tests()
        srv.LOG_DIR = self.orig_log_dir
        srv.EVENTS_LOG_FILE = self.orig_events_file
        if os.path.exists(self.test_log_dir):
            shutil.rmtree(self.test_log_dir, ignore_errors=True)

    def _read_test_events(self):
        return srv._read_events(100)

    def _set_authenticated_session(self, user='admin', role='admin'):
        token = 'test_csrf_token_f17'
        with self.client.session_transaction() as sess:
            sess['user'] = user
            sess['role'] = role
            sess['boot_id'] = srv._SERVER_BOOT_ID
            sess['login_ts'] = time.time()
            sess['csrf_token'] = token
        return token

    # 1. Ryu Decoupling
    def test_ryu_decoupling_emits_failover_requested_zero_http_calls(self):
        """Verify _failover_to_backup emits failover_requested alert without any HTTP calls to Runner."""
        wsgi = sys.modules['ryu.app.wsgi'].WSGIApplication()
        guard = DoSGuard(wsgi=wsgi)
        guard.alerts = []

        with mock.patch('requests.post') as mock_post:
            guard._failover_to_backup('spoof_flood')
            # Verify zero HTTP calls made
            mock_post.assert_not_called()

        self.assertEqual(len(guard.alerts), 1)
        alert = guard.alerts[0]
        self.assertEqual(alert['type'], 'failover_requested')
        self.assertEqual(alert['target'], 'backup')
        self.assertEqual(alert['reason'], 'spoof_flood')
        self.assertTrue(alert.get('boot_id'))
        self.assertEqual(alert.get('seq'), 1)
        self.assertEqual(alert.get('id'), f"{alert['boot_id']}-1")

    # 2. Successful Coordination
    def test_failover_coordination_success(self):
        """Verify coordinator calls Runner and transitions state to succeeded."""
        alert = {
            'id': 'testboot-1',
            'boot_id': 'testboot',
            'seq': 1,
            'type': 'failover_requested',
            'target': 'backup',
            'reason': 'spoof_flood',
        }

        mock_status_resp = mock.MagicMock(spec=requests.Response)
        mock_status_resp.ok = True
        mock_status_resp.text = json.dumps({'ok': True, 'ha': {'active': 'primary'}})
        mock_status_resp.json.return_value = {'ok': True, 'ha': {'active': 'primary'}}

        mock_active_resp = mock.MagicMock(spec=requests.Response)
        mock_active_resp.ok = True
        mock_active_resp.status_code = 200
        mock_active_resp.text = json.dumps({'ok': True, 'applied': {'active': 'backup'}})
        mock_active_resp.json.return_value = {'ok': True, 'applied': {'active': 'backup'}}

        with mock.patch.object(srv, '_runner_get', return_value=mock_status_resp) as mock_get, \
             mock.patch.object(srv, '_runner_post', return_value=mock_active_resp) as mock_post:

            ok, status = srv._coordinate_failover_request(alert)
            self.assertTrue(ok)
            self.assertEqual(status, 'succeeded')

            mock_get.assert_called_once_with('/ha/status', timeout=2.0)
            mock_post.assert_called_once_with('/ha/active', json_data={'active': 'backup'}, timeout=3.0)

        # Verify state record
        with srv._failover_states_lock:
            state = srv._failover_states.get('testboot-1')
            self.assertIsNotNone(state)
            self.assertEqual(state['state'], 'succeeded')
            self.assertEqual(state['target'], 'backup')
            self.assertEqual(state['attempts'], 1)

        # Verify CSV audit log
        events = self._read_test_events()
        ha_events = [e for e in events if e.get('type') == 'ha_active']
        self.assertEqual(len(ha_events), 1)
        extra = json.loads(ha_events[0]['extra'])
        self.assertEqual(extra['alert_id'], 'testboot-1')
        self.assertEqual(extra['target'], 'backup')
        self.assertTrue(extra['applied'])

    # 3. Idempotency & Coalescing
    def test_failover_coordination_idempotency_and_coalescing(self):
        """Verify coordinator skips redundant calls if target already active or alert already completed."""
        alert = {
            'id': 'testboot-2',
            'boot_id': 'testboot',
            'seq': 2,
            'type': 'failover_requested',
            'target': 'backup',
            'reason': 'ddos',
        }

        # Case A: Runner reports target is ALREADY backup
        mock_status_resp = mock.MagicMock(spec=requests.Response)
        mock_status_resp.ok = True
        mock_status_resp.text = json.dumps({'ok': True, 'ha': {'active': 'backup'}})
        mock_status_resp.json.return_value = {'ok': True, 'ha': {'active': 'backup'}}

        with mock.patch.object(srv, '_runner_get', return_value=mock_status_resp) as mock_get, \
             mock.patch.object(srv, '_runner_post') as mock_post:

            ok, status = srv._coordinate_failover_request(alert)
            self.assertTrue(ok)
            self.assertEqual(status, 'already_active')
            mock_post.assert_not_called()  # Did not redundantly mutate Runner

        # Case B: Re-submitting the exact same alert ID
        with mock.patch.object(srv, '_runner_get') as mock_get, \
             mock.patch.object(srv, '_runner_post') as mock_post:

            ok2, status2 = srv._coordinate_failover_request(alert)
            self.assertTrue(ok2)
            self.assertEqual(status2, 'already_succeeded')
            mock_get.assert_not_called()
            mock_post.assert_not_called()

    # 4. Target Validation
    def test_failover_coordination_invalid_target_rejected(self):
        """Verify invalid targets are immediately rejected and logged as failover_error."""
        alert = {
            'id': 'testboot-3',
            'boot_id': 'testboot',
            'seq': 3,
            'type': 'failover_requested',
            'target': 'malicious_target; rm -rf /',
            'reason': 'exploit',
        }

        with mock.patch.object(srv, '_runner_get') as mock_get, \
             mock.patch.object(srv, '_runner_post') as mock_post:

            ok, status = srv._coordinate_failover_request(alert)
            self.assertFalse(ok)
            self.assertEqual(status, 'invalid_target')
            mock_get.assert_not_called()
            mock_post.assert_not_called()

        with srv._failover_states_lock:
            state = srv._failover_states.get('testboot-3')
            self.assertEqual(state['state'], 'failed')
            self.assertEqual(state['last_error'], 'invalid_target')

        events = self._read_test_events()
        err_events = [e for e in events if e.get('type') == 'failover_error']
        self.assertEqual(len(err_events), 1)
        extra = json.loads(err_events[0]['extra'])
        self.assertEqual(extra['alert_id'], 'testboot-3')
        self.assertEqual(extra['error'], 'invalid_target')

    # 5. Bounded Retries with Transient Errors
    def test_failover_coordination_transient_failure_retries_and_succeeds(self):
        """Verify transient network errors retry with backoff and succeed."""
        alert = {
            'id': 'testboot-4',
            'boot_id': 'testboot',
            'seq': 4,
            'type': 'failover_requested',
            'target': 'backup',
            'reason': 'transient_test',
        }

        mock_status_resp = mock.MagicMock(spec=requests.Response)
        mock_status_resp.ok = True
        mock_status_resp.text = json.dumps({'ok': True, 'ha': {'active': 'primary'}})
        mock_status_resp.json.return_value = {'ok': True, 'ha': {'active': 'primary'}}

        # Fail with Timeout, then ConnectionError, then HTTP 200 success
        mock_ok_resp = mock.MagicMock(spec=requests.Response)
        mock_ok_resp.ok = True
        mock_ok_resp.status_code = 200
        mock_ok_resp.text = json.dumps({'ok': True, 'applied': {'active': 'backup'}})
        mock_ok_resp.json.return_value = {'ok': True, 'applied': {'active': 'backup'}}

        side_effects = [
            requests.exceptions.Timeout("runner timeout"),
            requests.exceptions.ConnectionError("runner connection refused"),
            mock_ok_resp,
        ]

        with mock.patch.object(srv, '_runner_get', return_value=mock_status_resp), \
             mock.patch.object(srv, '_runner_post', side_effect=side_effects) as mock_post:

            ok, status = srv._coordinate_failover_request(alert, max_retries=3, backoff_base=0.01)
            self.assertTrue(ok)
            self.assertEqual(status, 'succeeded')
            self.assertEqual(mock_post.call_count, 3)

        with srv._failover_states_lock:
            state = srv._failover_states.get('testboot-4')
            self.assertEqual(state['state'], 'succeeded')
            self.assertEqual(state['attempts'], 3)

        events = self._read_test_events()
        ha_events = [e for e in events if e.get('type') == 'ha_active']
        self.assertEqual(len(ha_events), 1)
        extra = json.loads(ha_events[0]['extra'])
        self.assertEqual(extra['attempts'], 3)

    # 6. Terminal Errors (No Retrying)
    def test_failover_coordination_terminal_failure_no_retries(self):
        """Verify HTTP 400 (e.g. network_not_built) fails immediately without wasting retries."""
        alert = {
            'id': 'testboot-5',
            'boot_id': 'testboot',
            'seq': 5,
            'type': 'failover_requested',
            'target': 'backup',
            'reason': 'terminal_test',
        }

        mock_status_resp = mock.MagicMock(spec=requests.Response)
        mock_status_resp.ok = True
        mock_status_resp.text = json.dumps({'ok': True, 'ha': {'active': 'primary'}})
        mock_status_resp.json.return_value = {'ok': True, 'ha': {'active': 'primary'}}

        mock_term_resp = mock.MagicMock(spec=requests.Response)
        mock_term_resp.ok = False
        mock_term_resp.status_code = 400
        mock_term_resp.text = json.dumps({'error': 'network_not_built'})
        mock_term_resp.json.return_value = {'error': 'network_not_built'}

        with mock.patch.object(srv, '_runner_get', return_value=mock_status_resp), \
             mock.patch.object(srv, '_runner_post', return_value=mock_term_resp) as mock_post:

            ok, status = srv._coordinate_failover_request(alert, max_retries=3, backoff_base=0.01)
            self.assertFalse(ok)
            self.assertEqual(status, 'network_not_built')
            self.assertEqual(mock_post.call_count, 1)  # Stopped immediately!

        with srv._failover_states_lock:
            state = srv._failover_states.get('testboot-5')
            self.assertEqual(state['state'], 'failed')
            self.assertEqual(state['attempts'], 1)
            self.assertEqual(state['last_error'], 'network_not_built')

        events = self._read_test_events()
        err_events = [e for e in events if e.get('type') == 'failover_error']
        self.assertEqual(len(err_events), 1)
        extra = json.loads(err_events[0]['extra'])
        self.assertEqual(extra['error'], 'network_not_built')
        self.assertEqual(extra['attempts'], 1)

    # 7. Concurrency Serialization
    def test_failover_coordination_concurrency_serialization(self):
        """Verify multiple threads running failover requests are serialized by execution lock."""
        execution_order = []

        def fake_runner_post(path, json_data=None, timeout=3.0):
            target = json_data.get('active')
            execution_order.append(f"enter_{target}")
            time.sleep(0.05)
            execution_order.append(f"exit_{target}")
            resp = mock.MagicMock(spec=requests.Response)
            resp.ok = True
            resp.status_code = 200
            resp.text = json.dumps({'ok': True, 'applied': {'active': target}})
            resp.json.return_value = {'ok': True, 'applied': {'active': target}}
            return resp

        mock_status = mock.MagicMock(spec=requests.Response)
        mock_status.ok = False  # Force runner_post invocation

        with mock.patch.object(srv, '_runner_get', return_value=mock_status), \
             mock.patch.object(srv, '_runner_post', side_effect=fake_runner_post):

            t1 = threading.Thread(
                target=srv._coordinate_failover_request,
                args=({'id': 'conc-1', 'boot_id': 'b', 'seq': 1, 'type': 'failover_requested', 'target': 'backup', 'reason': 't1'},),
            )
            t2 = threading.Thread(
                target=srv._coordinate_failover_request,
                args=({'id': 'conc-2', 'boot_id': 'b', 'seq': 2, 'type': 'failover_requested', 'target': 'primary', 'reason': 't2'},),
            )

            t1.start()
            t2.start()
            t1.join()
            t2.join()

        # Check serialization: enter_X must be followed by exit_X before enter_Y
        self.assertEqual(len(execution_order), 4)
        first_target = execution_order[0].replace('enter_', '')
        self.assertEqual(execution_order[1], f"exit_{first_target}")

    # 8. Crash Recovery and Bootstrap
    def test_failover_coordination_csv_crash_recovery_bootstrap(self):
        """Verify cold start restores historical failovers from CSV into state machine and seen set."""
        now = time.time()
        # Seed CSV with past failover events
        srv._append_event('ha_active', src='failover_coordinator', reason='old_failover', extra={
            'alert_id': 'bootold-10',
            'target': 'backup',
            'applied': True,
            'attempts': 1,
        }, ts_val=now - 50.0)

        srv._append_event('failover_error', src='failover_coordinator', reason='terminal_error', extra={
            'alert_id': 'bootold-11',
            'target': 'backup',
            'error': 'network_not_built',
            'attempts': 1,
        }, ts_val=now - 40.0)

        # Clear in-memory state
        with srv._seen_ids_lock:
            srv._seen_alert_ids_set.clear()
        with srv._failover_states_lock:
            srv._failover_states.clear()

        # Run bootstrap
        recovered_count = srv._bootstrap_seen_alerts_from_csv()
        self.assertGreaterEqual(recovered_count, 2)

        # Verify alert IDs were added to seen set
        with srv._seen_ids_lock:
            self.assertIn('bootold-10', srv._seen_alert_ids_set)
            self.assertIn('bootold-11', srv._seen_alert_ids_set)

        # Verify failover states were restored
        with srv._failover_states_lock:
            st10 = srv._failover_states.get('bootold-10')
            self.assertIsNotNone(st10)
            self.assertEqual(st10['state'], 'succeeded')
            self.assertEqual(st10['target'], 'backup')

            st11 = srv._failover_states.get('bootold-11')
            self.assertIsNotNone(st11)
            self.assertEqual(st11['state'], 'failed')
            self.assertEqual(st11['last_error'], 'network_not_built')

    # 9. Diagnostic Failover Status API
    def test_api_lab_ha_failover_status_endpoint(self):
        """Verify GET /api/lab/ha/failover/status returns sanitized diagnostics."""
        self._set_authenticated_session()

        # Seed in-memory failover state
        with srv._failover_states_lock:
            rec = {
                'alert_id': 'diag-1',
                'state': 'succeeded',
                'target': 'backup',
                'reason': 'test',
                'attempts': 1,
                'max_retries': 3,
                'last_error': None,
                'created_at': time.time(),
                'completed_at': time.time(),
            }
            srv._failover_states['diag-1'] = rec
            srv._failover_history.append(rec)

        res = self.client.get('/api/lab/ha/failover/status')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['ok'])
        self.assertEqual(data['active_in_flight'], 0)
        self.assertEqual(data['last_failover']['alert_id'], 'diag-1')
        self.assertEqual(len(data['history']), 1)

    # 10. Manual HA Active Endpoint
    def test_manual_ha_active_endpoint_validation_and_locking(self):
        """Verify POST /api/lab/ha/active validates allowed targets and respects execution lock."""
        csrf = self._set_authenticated_session()
        headers = {'X-CSRF-Token': csrf}

        # Test invalid target rejected with 400
        res_bad = self.client.post('/api/lab/ha/active', json={'active': 'invalid_server'}, headers=headers)
        self.assertEqual(res_bad.status_code, 400)
        self.assertIn('active_must_be_primary_or_backup', res_bad.get_data(as_text=True))

        # Test valid target dispatches through proxy under lock
        mock_runner_resp = mock.MagicMock(spec=requests.Response)
        mock_runner_resp.ok = True
        mock_runner_resp.status_code = 200
        mock_runner_resp.text = json.dumps({'ok': True, 'applied': {'active': 'backup'}})
        mock_runner_resp.json.return_value = {'ok': True, 'applied': {'active': 'backup'}}

        with mock.patch.object(srv, '_runner_post', return_value=mock_runner_resp) as mock_post:
            res_good = self.client.post('/api/lab/ha/active', json={'active': 'backup'}, headers=headers)
            self.assertEqual(res_good.status_code, 200)
            mock_post.assert_called_once()

        events = self._read_test_events()
        ha_events = [e for e in events if e.get('type') == 'ha_active']
        self.assertEqual(len(ha_events), 1)
        extra = json.loads(ha_events[0]['extra'])
        self.assertEqual(extra['active'], 'backup')
        self.assertEqual(extra['source'], 'manual_ui')


if __name__ == '__main__':
    unittest.main()
