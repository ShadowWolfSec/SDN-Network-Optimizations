"""Tests for Phase 5 (F-19): Alerts In-Memory Snapshot & Background Worker Architecture.
Verifies:
1. Snapshot pure-read and zero I/O on GET /api/alerts.
2. Snapshot staleness and graceful fallback.
3. CSV recovery across rotated files and non-alert events (targeting >= 200 alert IDs).
4. Confirmed gap detection vs indeterminate gap detection.
5. Out-of-order and same-timestamp preservation.
6. Write-failure resilience (atomic write-before-commit order).
7. Worker lifecycle and clean shutdown within 3.0s.
"""

import os
import sys
import time
import json
import csv
import shutil
import tempfile
import unittest
from unittest import mock
from collections import deque

# Ensure stubs for mininet if running on platform without mininet
for mod_name in (
    'mininet', 'mininet.net', 'mininet.node', 'mininet.link',
    'mininet.topo', 'mininet.cli', 'mininet.log', 'mininet.util'
):
    if mod_name not in sys.modules:
        m = mock.MagicMock()
        m.__file__ = f"{mod_name}.py"
        sys.modules[mod_name] = m

import webapp.server as srv


class F19AlertsSyncTests(unittest.TestCase):
    def setUp(self):
        # Stop background worker if running to ensure strict test isolation
        srv._stop_alerts_sync_worker(timeout=1.0)
        os.environ['SDN_ALERTS_SYNC_WORKER_ENABLED'] = '0'

        # Create temporary log directory for test events
        self.test_log_dir = tempfile.mkdtemp(prefix='sdn_f19_test_logs_')
        self.orig_log_dir = srv.LOG_DIR
        self.orig_events_file = srv.EVENTS_LOG_FILE
        srv.LOG_DIR = self.test_log_dir
        srv.EVENTS_LOG_FILE = os.path.join(self.test_log_dir, 'events.csv')

        # Reset in-memory state
        with srv._snapshot_lock:
            srv._alerts_snapshot.clear()
            srv._alerts_snapshot.update({
                'alerts': [],
                'ts': 0.0,
                'status': 'initializing',
                'boot_id': None,
                'last_seq': None,
                'consecutive_failures': 0,
                'last_error': None,
            })

        with srv._seen_ids_lock:
            srv._seen_alert_ids_set.clear()
            srv._seen_alert_ids_deque.clear()
            srv._last_seen_boot_id = None
            srv._last_seen_seq = None

        srv._events_last_ts = 0.0
        srv._events_ts_initialized = False

        srv.app.config['TESTING'] = True
        self.client = srv.app.test_client()
        with self.client.session_transaction() as sess:
            sess['user'] = 'tester'
            sess['role'] = 'admin'
            sess['boot_id'] = srv._SERVER_BOOT_ID
            sess['login_ts'] = int(time.time())

    def tearDown(self):
        srv._stop_alerts_sync_worker(timeout=1.0)
        srv._reset_alerts_state_for_tests()
        srv.LOG_DIR = self.orig_log_dir
        srv.EVENTS_LOG_FILE = self.orig_events_file
        if os.path.exists(self.test_log_dir):
            try:
                shutil.rmtree(self.test_log_dir)
            except Exception:
                pass

    def test_01_snapshot_pure_read_and_zero_io(self):
        """GET /api/alerts must be a pure-read from RAM with zero network calls and zero file writes."""
        test_alerts = [
            {'id': 'boot123-1', 'boot_id': 'boot123', 'seq': 1, 'ts': 100.0, 'type': 'detect', 'src': '10.0.0.1'},
            {'id': 'boot123-2', 'boot_id': 'boot123', 'seq': 2, 'ts': 101.0, 'type': 'block', 'src': '10.0.0.1'}
        ]
        with srv._snapshot_lock:
            srv._alerts_snapshot.update({
                'alerts': test_alerts,
                'ts': time.time(),
                'status': 'ok',
                'boot_id': 'boot123',
                'last_seq': 2,
                'consecutive_failures': 0
            })

        with mock.patch.object(srv, '_safe_request') as spy_req, \
             mock.patch.object(srv, '_append_event') as spy_append:
            res = self.client.get('/api/alerts')

            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 2)
            self.assertEqual(data[0]['id'], 'boot123-1')
            self.assertEqual(data[1]['id'], 'boot123-2')

            # Verify diagnostic headers
            self.assertEqual(res.headers.get('X-Snapshot-Status'), 'ok')
            self.assertIn('X-Snapshot-Age', res.headers)
            self.assertEqual(res.headers.get('X-Ryu-Boot-ID'), 'boot123')
            self.assertEqual(res.headers.get('X-Ryu-Last-Seq'), '2')

            # Assert ZERO upstream HTTP calls and ZERO CSV writes
            self.assertEqual(spy_req.call_count, 0, "GET /api/alerts must NEVER call Ryu directly")
            self.assertEqual(spy_append.call_count, 0, "GET /api/alerts must NEVER write to CSV")

    def test_02_snapshot_staleness_and_fallback(self):
        """When Ryu is down, cached alerts are served with X-Snapshot-Status: stale;
        when no alerts exist and Ryu is down, 502 is returned."""
        # 1. Uninitialized snapshot and Ryu failure -> 502
        with srv._snapshot_lock:
            srv._alerts_snapshot.update({
                'alerts': [],
                'status': 'degraded',
                'consecutive_failures': 1
            })
        with mock.patch.dict(srv._service_health, {'ryu': {'healthy': False, 'last_check': 0.0, 'error': 'service_unavailable'}}):
            res1 = self.client.get('/api/alerts')
            self.assertEqual(res1.status_code, 502)
            self.assertFalse(res1.get_json().get('ok'))

        # 2. Cached alerts exist and Ryu fails -> 200 with stale cache intact
        cached_alerts = [{'id': 'b1-1', 'boot_id': 'b1', 'seq': 1, 'ts': 50.0, 'type': 'vip_rl_on'}]
        with srv._snapshot_lock:
            srv._alerts_snapshot.update({
                'alerts': cached_alerts,
                'ts': time.time() - 15.0,
                'status': 'stale',
                'boot_id': 'b1',
                'last_seq': 1,
                'consecutive_failures': 5
            })

        res2 = self.client.get('/api/alerts')
        self.assertEqual(res2.status_code, 200)
        data = res2.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['type'], 'vip_rl_on')
        self.assertEqual(res2.headers.get('X-Snapshot-Status'), 'stale')
        self.assertEqual(res2.headers.get('X-Snapshot-Failures'), '5')

    def test_03_csv_recovery_across_rotated_files_and_other_events(self):
        """Recovery must scan backwards across multiple files and non-alert events
        until >= 200 alert IDs are retrieved."""
        # Create 3 daily/rotated CSV files
        file1 = os.path.join(self.test_log_dir, 'events-2026-11-10.csv')
        file2 = os.path.join(self.test_log_dir, 'events-2026-11-11.1.csv')
        file3 = os.path.join(self.test_log_dir, 'events-2026-11-12.csv')

        # Populate file1: 100 alerts (seq 1..100) mixed with 50 non-alert events
        with open(file1, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            w.writerow(['ts', 'type', 'src', 'reason', 'extra_json'])
            for i in range(1, 101):
                w.writerow([1000 + i, 'detect', '10.0.0.1', '', json.dumps({'id': f'bootA-{i}', 'boot_id': 'bootA', 'seq': i})])
                if i % 2 == 0:
                    w.writerow([1000 + i, 'lab_build', 'admin', '', json.dumps({'nodes': 4})])

        # Populate file2: 80 alerts (seq 101..180) mixed with scenarios
        with open(file2, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            w.writerow(['ts', 'type', 'src', 'reason', 'extra_json'])
            for i in range(101, 181):
                w.writerow([2000 + i, 'block', '10.0.0.2', '', json.dumps({'id': f'bootA-{i}', 'boot_id': 'bootA', 'seq': i})])
                w.writerow([2000 + i, 'scenario', 'admin', '', json.dumps({'name': 'syn_flood'})])

        # Populate file3: 50 alerts (seq 181..230) mixed with attack runs
        with open(file3, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            w.writerow(['ts', 'type', 'src', 'reason', 'extra_json'])
            for i in range(181, 231):
                w.writerow([3000 + i, 'quarantine', '10.0.0.3', '', json.dumps({'id': f'bootA-{i}', 'boot_id': 'bootA', 'seq': i})])
                w.writerow([3000 + i, 'attack_run', 'admin', '', json.dumps({'target': 'vip'})])

        # Total alerts across 3 files: 100 + 80 + 50 = 230 alerts
        recovered_count = srv._bootstrap_seen_alerts_from_csv(target_alert_count=200)
        self.assertGreaterEqual(recovered_count, 200)
        self.assertGreaterEqual(len(srv._seen_alert_ids_set), 200)

        # Verify latest boot and sequence seeded from the newest alert in file3 (seq 230)
        self.assertEqual(srv._last_seen_boot_id, 'bootA')
        self.assertEqual(srv._last_seen_seq, 230)

        # Verify deduplication: processing already-recovered alerts produces 0 new CSV writes
        already_seen_batch = [
            {'id': 'bootA-229', 'boot_id': 'bootA', 'seq': 229, 'ts': 3229.0, 'type': 'quarantine'},
            {'id': 'bootA-230', 'boot_id': 'bootA', 'seq': 230, 'ts': 3230.0, 'type': 'quarantine'}
        ]
        with mock.patch.object(srv, '_append_event') as spy_append:
            committed, gaps = srv._process_and_archive_alerts(already_seen_batch)
            self.assertEqual(committed, 0)
            self.assertEqual(gaps, 0)
            self.assertEqual(spy_append.call_count, 0)

    def test_04_confirmed_gap_detection(self):
        """Sequence jump within the same boot_id triggers alert_gap_detected with exact missed count."""
        srv._last_seen_boot_id = 'bootX'
        srv._last_seen_seq = 10
        srv._seen_alert_ids_set.update({f'bootX-{i}' for i in range(1, 11)})

        # Batch arrives jumping from seq 10 to seq 15
        batch = [
            {'id': 'bootX-15', 'boot_id': 'bootX', 'seq': 15, 'ts': 500.0, 'type': 'detect', 'src': '10.0.0.5'},
            {'id': 'bootX-16', 'boot_id': 'bootX', 'seq': 16, 'ts': 501.0, 'type': 'block', 'src': '10.0.0.5'}
        ]

        committed, gaps = srv._process_and_archive_alerts(batch)
        self.assertEqual(committed, 2)
        self.assertEqual(gaps, 1)
        self.assertEqual(srv._last_seen_seq, 16)

        # Verify alert_gap_detected event recorded in CSV
        events = srv._read_events(50)
        gap_events = [e for e in events if e.get('type') == 'alert_gap_detected']
        self.assertEqual(len(gap_events), 1)
        extra = json.loads(gap_events[0]['extra'])
        self.assertEqual(extra['dropped_count'], 4)  # 11, 12, 13, 14
        self.assertEqual(extra['expected_seq'], 11)
        self.assertEqual(extra['received_seq'], 15)
        self.assertEqual(extra['boot_id'], 'bootX')

    def test_05_indeterminate_gap_detection(self):
        """Controller reboot/session change does NOT calculate dropped count, records ryu_session_changed."""
        srv._last_seen_boot_id = 'bootOld'
        srv._last_seen_seq = 85

        # New boot session arrives starting from seq 1
        new_session_batch = [
            {'id': 'bootNew-1', 'boot_id': 'bootNew', 'seq': 1, 'ts': 600.0, 'type': 'failsafe_on'}
        ]

        committed, gaps = srv._process_and_archive_alerts(new_session_batch)
        self.assertEqual(committed, 1)
        self.assertEqual(gaps, 0, "Session change must NOT report confirmed dropped gap")
        self.assertEqual(srv._last_seen_boot_id, 'bootNew')
        self.assertEqual(srv._last_seen_seq, 1)

        events = srv._read_events(50)
        session_events = [e for e in events if e.get('type') == 'ryu_session_changed']
        self.assertEqual(len(session_events), 1)
        extra = json.loads(session_events[0]['extra'])
        self.assertEqual(extra['old_boot_id'], 'bootOld')
        self.assertEqual(extra['new_boot_id'], 'bootNew')
        self.assertEqual(extra['new_seq'], 1)

    def test_06_out_of_order_and_same_timestamp_preservation(self):
        """Alerts with identical timestamps or out-of-order arrival are sorted by seq and preserved without drops."""
        srv._last_seen_boot_id = 'bootM'
        srv._last_seen_seq = 0

        # Batch arrived out of order with same timestamps
        scrambled_batch = [
            {'id': 'bootM-3', 'boot_id': 'bootM', 'seq': 3, 'ts': 100.0, 'type': 'detect', 'src': '10.0.0.3'},
            {'id': 'bootM-1', 'boot_id': 'bootM', 'seq': 1, 'ts': 100.0, 'type': 'detect', 'src': '10.0.0.1'},
            {'id': 'bootM-2', 'boot_id': 'bootM', 'seq': 2, 'ts': 100.0, 'type': 'detect', 'src': '10.0.0.2'},
        ]

        committed, gaps = srv._process_and_archive_alerts(scrambled_batch)
        self.assertEqual(committed, 3)
        self.assertEqual(gaps, 0)
        self.assertEqual(srv._last_seen_seq, 3)

        # Verify all 3 are stored in seen set
        self.assertIn('bootM-1', srv._seen_alert_ids_set)
        self.assertIn('bootM-2', srv._seen_alert_ids_set)
        self.assertIn('bootM-3', srv._seen_alert_ids_set)

    def test_07_write_failure_preserves_uncommitted_ids(self):
        """If disk write fails, uncommitted IDs are NOT marked seen and will retry on next poll."""
        batch = [
            {'id': 'bootF-1', 'boot_id': 'bootF', 'seq': 1, 'ts': 200.0, 'type': 'block', 'src': '10.0.0.9'}
        ]

        # Simulate disk failure
        with mock.patch.object(srv, '_append_event', return_value=False):
            committed, _ = srv._process_and_archive_alerts(batch)
            self.assertEqual(committed, 0)
            self.assertNotIn('bootF-1', srv._seen_alert_ids_set, "Failed write must NOT be marked seen")

        # Next cycle: disk is healthy -> succeeds
        committed2, _ = srv._process_and_archive_alerts(batch)
        self.assertEqual(committed2, 1)
        self.assertIn('bootF-1', srv._seen_alert_ids_set)

    def test_08_worker_lifecycle_and_clean_shutdown(self):
        """Worker thread starts cleanly, is idempotent, and shuts down within 3.0s timeout."""
        with mock.patch.object(srv, '_safe_request', return_value=mock.MagicMock(ok=True, json=lambda: [])):
            srv._start_alerts_sync_worker()
            self.assertTrue(srv._alerts_sync_started)
            self.assertIsNotNone(srv._alerts_sync_thread)
            self.assertTrue(srv._alerts_sync_thread.is_alive())

            # Idempotent: starting again does not spawn second thread
            orig_t = srv._alerts_sync_thread
            srv._start_alerts_sync_worker()
            self.assertIs(srv._alerts_sync_thread, orig_t)

            # Clean shutdown within 3s
            start_stop = time.time()
            srv._stop_alerts_sync_worker(timeout=3.0)
            stop_elapsed = time.time() - start_stop

            self.assertFalse(srv._alerts_sync_started)
            self.assertIsNone(srv._alerts_sync_thread)
            self.assertFalse(orig_t.is_alive())
            self.assertLess(stop_elapsed, 3.0, "Shutdown should wake immediately via Event and exit promptly")


if __name__ == '__main__':
    unittest.main()
