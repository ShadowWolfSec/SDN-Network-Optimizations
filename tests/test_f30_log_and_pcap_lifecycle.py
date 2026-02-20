#!/usr/bin/env python3
"""tests/test_f30_log_and_pcap_lifecycle.py
Comprehensive test suite for F-30: Log Rotation & PCAP Lifecycle Management.

Covers:
- Configuration schema consolidation in core/sdn_config.py
- Bounded iterative reverse-seek log tailing in webapp/server.py
- PCAP lifecycle state transitions, pinning, and pruning guards (Batches 2 & 3)
"""

import glob
import os
import shutil
import sys
import tempfile
import time
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Ensure stubs for mininet if running on platform without mininet (e.g. Windows)
from unittest import mock
for mod_name in (
    'mininet', 'mininet.net', 'mininet.node', 'mininet.link',
    'mininet.topo', 'mininet.cli', 'mininet.log', 'mininet.util'
):
    if mod_name not in sys.modules:
        m = mock.MagicMock()
        m.__file__ = f"{mod_name}.py"
        sys.modules[mod_name] = m

from core.sdn_config import SDNConfigSchema, SDNConfigManager, ConfigMutability
from webapp.server import _tail_file


class TestF30ConfigSchema(unittest.TestCase):
    """Test validation and behavior of consolidated F-30 configuration fields."""

    def test_sdn_config_f30_schema_fields(self):
        fields = SDNConfigSchema.FIELDS

        expected_f30_fields = [
            "log_max_bytes",
            "log_backup_count",
            "log_tail_max_bytes",
            "pcap_max_files",
            "pcap_max_total_mb",
            "pcap_single_file_max_mb",
            "pcap_snaplen",
            "events_max_file_mb",
            "events_retention_days",
        ]

        for field_name in expected_f30_fields:
            self.assertIn(field_name, fields, f"Field '{field_name}' must be registered in SDNConfigSchema.FIELDS")
            f = fields[field_name]
            self.assertIsNotNone(f.canonical_env, f"Field '{field_name}' must have a canonical_env")
            self.assertIsNotNone(f.default_value, f"Field '{field_name}' must have a default_value")

    def test_f30_defaults_and_bounds(self):
        mgr = SDNConfigManager()

        # log_max_bytes
        self.assertEqual(mgr.get_effective("log_max_bytes"), 10 * 1024 * 1024)
        # log_backup_count
        self.assertEqual(mgr.get_effective("log_backup_count"), 5)
        # log_tail_max_bytes
        self.assertEqual(mgr.get_effective("log_tail_max_bytes"), 256 * 1024)
        # pcap_max_files
        self.assertEqual(mgr.get_effective("pcap_max_files"), 30)
        # pcap_max_total_mb
        self.assertEqual(mgr.get_effective("pcap_max_total_mb"), 200)
        # pcap_single_file_max_mb
        self.assertEqual(mgr.get_effective("pcap_single_file_max_mb"), 25)
        # pcap_snaplen
        self.assertEqual(mgr.get_effective("pcap_snaplen"), 96)
        # events_max_file_mb
        self.assertEqual(mgr.get_effective("events_max_file_mb"), 10)
        # events_retention_days
        self.assertEqual(mgr.get_effective("events_retention_days"), 14)

    def test_f30_aliases_and_legacy_envs(self):
        old_env = os.environ.get("MAX_PCAP_FILES")
        try:
            os.environ["MAX_PCAP_FILES"] = "45"
            mgr = SDNConfigManager()
            self.assertEqual(mgr.get_effective("pcap_max_files"), 45)
        finally:
            if old_env is not None:
                os.environ["MAX_PCAP_FILES"] = old_env
            else:
                os.environ.pop("MAX_PCAP_FILES", None)


class TestF30TailFileBoundedReverseSeek(unittest.TestCase):
    """Test unit behavior, safety bounds, and edge cases of _tail_file()."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_tail_file_empty_and_nonexistent(self):
        self.assertEqual(_tail_file(None), '')
        self.assertEqual(_tail_file(''), '')
        self.assertEqual(_tail_file(os.path.join(self.temp_dir.name, 'non_existent.log')), '')

        empty_file = os.path.join(self.temp_dir.name, 'empty.log')
        with open(empty_file, 'w', encoding='utf-8') as f:
            pass
        self.assertEqual(_tail_file(empty_file), '')

    def test_tail_file_small_file_all_lines(self):
        path = os.path.join(self.temp_dir.name, 'small.log')
        lines = [f"Log line {i}\n" for i in range(1, 6)]
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

        tail = _tail_file(path, max_lines=10)
        self.assertIn("Log line 1", tail)
        self.assertIn("Log line 5", tail)
        tail_lines = [l for l in tail.splitlines() if l.strip()]
        self.assertEqual(len(tail_lines), 5)

    def test_tail_file_large_file_bounded_memory(self):
        path = os.path.join(self.temp_dir.name, 'large.log')
        # Generate 15,000 lines (~1.5 MB)
        with open(path, 'w', encoding='utf-8') as f:
            for i in range(1, 15001):
                f.write(f"2026-11-13 12:00:00 [{i:06d}] INFO controller.core packet_in processed dpid=1\n")

        t0 = time.time()
        tail = _tail_file(path, max_lines=20)
        elapsed = time.time() - t0

        self.assertLess(elapsed, 0.1, f"Tail on 15,000 lines took {elapsed:.4f}s, must be < 100ms")
        tail_lines = [l for l in tail.splitlines() if l.strip()]
        self.assertEqual(len(tail_lines), 20)
        self.assertIn("[015000]", tail)
        self.assertIn("[014981]", tail)
        self.assertNotIn("[000001]", tail)

    def test_tail_file_utf8_split_character(self):
        path = os.path.join(self.temp_dir.name, 'utf8.log')
        with open(path, 'w', encoding='utf-8') as f:
            for i in range(1, 300):
                f.write(f"جلسة أمنية رقم {i:04d} تفاصيل التنبيه: كشف هجوم حجب خدمة ⚠️\n")

        tail = _tail_file(path, max_lines=15)
        self.assertIn("تفاصيل التنبيه", tail)
        self.assertIn("⚠️", tail)
        tail_lines = [l for l in tail.splitlines() if l.strip()]
        self.assertEqual(len(tail_lines), 15)

    def test_tail_file_long_lines_safety_ceiling(self):
        path = os.path.join(self.temp_dir.name, 'long_lines.log')
        # Write lines each 50KB long
        with open(path, 'w', encoding='utf-8') as f:
            for i in range(1, 10):
                f.write(f"START_{i}_" + ("X" * 50000) + f"_END_{i}\n")

        # Must not hang, crash, or exceed bounds
        tail = _tail_file(path, max_lines=5, max_chars=4096)
        self.assertTrue(len(tail) <= 4096)
        self.assertTrue("START_9_" in tail or "END_9" in tail or len(tail) > 0)

    def test_tail_file_single_line_no_newline(self):
        path = os.path.join(self.temp_dir.name, 'no_newline.log')
        with open(path, 'w', encoding='utf-8') as f:
            f.write("A single log message without any newline character")

        tail = _tail_file(path, max_lines=10)
        self.assertIn("A single log message without any newline character", tail)


class TestF30PcapLifecycle(unittest.TestCase):
    """Test PCAP lifecycle, pinning manifest, download guards, and storage pruning."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_pcap_dir = os.path.realpath(self.temp_dir.name)

        # Import mininet_runner
        import labs.mininet_runner as runner
        self.runner = runner

        # Save previous state
        self.orig_pcap_dir = runner.PCAP_DIR
        self.orig_manifest_file = runner._MANIFEST_FILE
        self.orig_max_files = runner.MAX_PCAP_FILES
        self.orig_max_mb = runner.MAX_PCAP_TOTAL_MB

        # Patch runner to use test directory
        runner.PCAP_DIR = self.test_pcap_dir
        runner._MANIFEST_FILE = os.path.join(self.test_pcap_dir, '.pinned_manifest.json')
        runner._active_pcap_name = None
        runner._finalizing_pcaps = set()
        runner._active_readers = runner.collections.defaultdict(int)
        self.test_token = 'f30-test-internal-token-12345'
        self.token_patcher = mock.patch.object(runner, '_load_internal_token', return_value=self.test_token)
        self.token_patcher.start()

        raw_client = runner.app.test_client()
        class AuthenticatedTestClient:
            def __init__(self, client, token):
                self._client = client
                self._token = token
            def _inject(self, kwargs):
                headers = kwargs.get('headers')
                if headers is None:
                    headers = {}
                if isinstance(headers, dict):
                    headers.setdefault('X-Internal-Token', self._token)
                kwargs['headers'] = headers
                return kwargs
            def get(self, *a, **kw):
                return self._client.get(*a, **self._inject(kw))
            def post(self, *a, **kw):
                return self._client.post(*a, **self._inject(kw))
            def delete(self, *a, **kw):
                return self._client.delete(*a, **self._inject(kw))
            def put(self, *a, **kw):
                return self._client.put(*a, **self._inject(kw))
            def session_transaction(self, *a, **kw):
                return self._client.session_transaction(*a, **kw)
            def __getattr__(self, name):
                return getattr(self._client, name)

        self.client = AuthenticatedTestClient(raw_client, self.test_token)

    def tearDown(self):
        if hasattr(self, 'token_patcher'):
            self.token_patcher.stop()
        self.runner.PCAP_DIR = self.orig_pcap_dir
        self.runner._MANIFEST_FILE = self.orig_manifest_file
        self.runner.MAX_PCAP_FILES = self.orig_max_files
        self.runner.MAX_PCAP_TOTAL_MB = self.orig_max_mb
        self.runner._active_pcap_name = None
        self.runner._finalizing_pcaps = set()
        self.runner._active_readers = self.runner.collections.defaultdict(int)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _create_dummy_pcap(self, name: str, size_bytes: int = 100, mtime: float = None) -> str:
        path = os.path.join(self.test_pcap_dir, name)
        with open(path, 'wb') as f:
            # Write standard PCAP global header magic 0xa1b2c3d4 + dummy bytes
            header = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00'
            f.write(header)
            if size_bytes > len(header):
                f.write(b'\x00' * (size_bytes - len(header)))
        if mtime is not None:
            os.utime(path, (mtime, mtime))
        return path

    def test_resolve_safe_pcap_path_valid_and_invalid(self):
        # Valid path
        valid_path = self.runner._resolve_safe_pcap_path("attack_20261113_120000.pcap")
        self.assertTrue(valid_path.startswith(self.test_pcap_dir))

        # Invalid cases: directory traversal, invalid extensions, separators
        invalid_names = [
            None,
            "",
            "   ",
            "../secret.pcap",
            "..\\secret.pcap",
            "dir/attack.pcap",
            "dir\\attack.pcap",
            "attack.txt",
            "attack.exe",
            "attack.pcap.sh",
            "attack_*.pcap",
        ]
        for bad_name in invalid_names:
            with self.assertRaises(ValueError, msg=f"Should reject: {bad_name}"):
                self.runner._resolve_safe_pcap_path(bad_name)

    def test_pinned_manifest_crud_and_corruption_resilience(self):
        # Save pinned files
        initial_set = {"attack_01.pcap", "attack_02.pcap"}
        ok = self.runner._save_pinned_manifest(initial_set)
        self.assertTrue(ok)

        # Load pinned files
        loaded = self.runner._load_pinned_manifest()
        self.assertEqual(loaded, initial_set)

        # Corrupt manifest file with invalid JSON
        with open(self.runner._MANIFEST_FILE, "w", encoding="utf-8") as f:
            f.write("{malformed json syntax ...")

        # Must not crash, should return empty set
        resilient_loaded = self.runner._load_pinned_manifest()
        self.assertIsInstance(resilient_loaded, set)

    def test_pcap_prune_enforces_count_limit(self):
        self.runner.MAX_PCAP_FILES = 5
        self.runner.MAX_PCAP_TOTAL_MB = 100

        # Create 10 files with increasing mtimes
        base_time = time.time() - 1000
        for i in range(1, 11):
            self._create_dummy_pcap(f"attack_{i:02d}.pcap", size_bytes=100, mtime=base_time + (i * 10))

        # Prune
        stats = self.runner._pcap_prune()
        self.assertEqual(stats['deleted_count'], 5)
        self.assertEqual(stats['remaining_count'], 5)

        remaining_files = sorted([f for f in os.listdir(self.test_pcap_dir) if f.endswith('.pcap')])
        self.assertEqual(len(remaining_files), 5)
        # Oldest 5 (attack_01 to attack_05) must have been deleted
        self.assertEqual(remaining_files, ["attack_06.pcap", "attack_07.pcap", "attack_08.pcap", "attack_09.pcap", "attack_10.pcap"])

    def test_pcap_prune_enforces_size_limit(self):
        self.runner.MAX_PCAP_FILES = 20
        self.runner.MAX_PCAP_TOTAL_MB = 1  # 1 MB = 1048576 bytes

        base_time = time.time() - 500
        # Create 4 files of 400 KB each (total 1600 KB > 1024 KB)
        file_size = 400 * 1024
        for i in range(1, 5):
            self._create_dummy_pcap(f"attack_sz_{i:02d}.pcap", size_bytes=file_size, mtime=base_time + (i * 10))

        stats = self.runner._pcap_prune()
        self.assertTrue(stats['deleted_count'] >= 2)
        remaining_files = [f for f in os.listdir(self.test_pcap_dir) if f.endswith('.pcap')]
        total_size = sum(os.path.getsize(os.path.join(self.test_pcap_dir, f)) for f in remaining_files)
        self.assertLessEqual(total_size, 1024 * 1024)

    def test_pcap_prune_protects_active_and_finalizing_captures(self):
        self.runner.MAX_PCAP_FILES = 1
        self.runner.MAX_PCAP_TOTAL_MB = 100

        base_time = time.time() - 200
        f1 = "attack_active.pcap"
        f2 = "attack_finalizing.pcap"
        f3 = "attack_ephemeral.pcap"

        self._create_dummy_pcap(f1, size_bytes=100, mtime=base_time)
        self._create_dummy_pcap(f2, size_bytes=100, mtime=base_time + 10)
        self._create_dummy_pcap(f3, size_bytes=100, mtime=base_time + 20)

        # Mark f1 active, f2 finalizing
        self.runner._active_pcap_name = f1
        self.runner._finalizing_pcaps.add(f2)

        stats = self.runner._pcap_prune()

        # f3 should be pruned, while f1 and f2 must be preserved
        remaining_files = set(os.listdir(self.test_pcap_dir))
        self.assertIn(f1, remaining_files)
        self.assertIn(f2, remaining_files)
        self.assertNotIn(f3, remaining_files)

    def test_pcap_prune_protects_pinned_evidence(self):
        self.runner.MAX_PCAP_FILES = 1
        self.runner.MAX_PCAP_TOTAL_MB = 100

        base_time = time.time() - 200
        p1 = "pinned_evidence.pcap"
        p2 = "unpinned_01.pcap"
        p3 = "unpinned_02.pcap"

        self._create_dummy_pcap(p1, size_bytes=100, mtime=base_time)
        self._create_dummy_pcap(p2, size_bytes=100, mtime=base_time + 10)
        self._create_dummy_pcap(p3, size_bytes=100, mtime=base_time + 20)

        # Pin p1
        self.runner._save_pinned_manifest({p1})

        stats = self.runner._pcap_prune()

        remaining_files = set(os.listdir(self.test_pcap_dir))
        self.assertIn(p1, remaining_files, "Pinned evidence file must NEVER be pruned")
        self.assertEqual(stats['pinned_count'], 1)

    def test_pcap_prune_protects_active_readers_during_download(self):
        self.runner.MAX_PCAP_FILES = 1
        self.runner.MAX_PCAP_TOTAL_MB = 100

        base_time = time.time() - 200
        f_download = "downloading.pcap"
        f_normal = "other.pcap"

        self._create_dummy_pcap(f_download, size_bytes=100, mtime=base_time)
        self._create_dummy_pcap(f_normal, size_bytes=100, mtime=base_time + 10)

        # Simulate active reader
        with self.runner._readers_lock:
            self.runner._active_readers[f_download] = 1

        stats = self.runner._pcap_prune()

        remaining_files = set(os.listdir(self.test_pcap_dir))
        self.assertIn(f_download, remaining_files, "File with active reader must NOT be deleted")
        self.assertNotIn(f_normal, remaining_files)

    def test_pcap_download_endpoint_stream_and_reader_count(self):
        fname = "stream_test.pcap"
        self._create_dummy_pcap(fname, size_bytes=500)

        res = self.client.get(f"/pcap/download/{fname}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'application/vnd.tcpdump.pcap')
        self.assertEqual(len(res.data), 500)

        # Active reader counter must return to 0 after download ends
        with self.runner._readers_lock:
            self.assertEqual(self.runner._active_readers[fname], 0)

    def test_pcap_download_returns_409_when_capturing(self):
        fname = "active_capture.pcap"
        self._create_dummy_pcap(fname, size_bytes=100)
        self.runner._active_pcap_name = fname

        res = self.client.get(f"/pcap/download/{fname}")
        self.assertEqual(res.status_code, 409)
        self.assertIn("pcap_capture_in_progress", res.get_json()['error'])

    def test_pcap_pin_unpin_and_delete_endpoints(self):
        fname = "endpoint_test.pcap"
        self._create_dummy_pcap(fname, size_bytes=100)

        # Pin
        r_pin = self.client.post(f"/pcap/pin/{fname}")
        self.assertEqual(r_pin.status_code, 200)
        self.assertTrue(r_pin.get_json()['pinned'])
        self.assertIn(fname, self.runner._load_pinned_manifest())

        # Unpin
        r_unpin = self.client.post(f"/pcap/unpin/{fname}")
        self.assertEqual(r_unpin.status_code, 200)
        self.assertFalse(r_unpin.get_json()['pinned'])
        self.assertNotIn(fname, self.runner._load_pinned_manifest())

        # Delete
        r_del = self.client.delete(f"/pcap/delete/{fname}")
        self.assertEqual(r_del.status_code, 200)
        self.assertFalse(os.path.isfile(os.path.join(self.test_pcap_dir, fname)))

    def test_pcap_storage_endpoint(self):
        self.runner.MAX_PCAP_TOTAL_MB = 10
        self.runner.MAX_PCAP_FILES = 20

        self._create_dummy_pcap("p1.pcap", size_bytes=2000)
        self._create_dummy_pcap("p2.pcap", size_bytes=3000)
        self.runner._save_pinned_manifest({"p1.pcap"})

        res = self.client.get("/pcap/storage")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['total_bytes'], 5000)
        self.assertEqual(data['pinned_bytes'], 2000)
        self.assertEqual(data['ephemeral_bytes'], 3000)
        self.assertEqual(data['total_files'], 2)
        self.assertEqual(data['pinned_files'], 1)

    def test_pcap_startup_reconciliation_preseeding(self):
        # Create 3 baseline files without manifest
        self._create_dummy_pcap("baseline_01.pcap", size_bytes=100)
        self._create_dummy_pcap("baseline_02.pcap", size_bytes=200)

        # Call startup reconciliation
        self.runner._pcap_startup_reconciliation()

        # Manifest must have been pre-seeded to protect these baseline files
        manifest = self.runner._load_pinned_manifest()
        self.assertIn("baseline_01.pcap", manifest)
        self.assertIn("baseline_02.pcap", manifest)

    def test_pcap_start_rejects_when_quota_exhausted(self):
        self.runner.MAX_PCAP_TOTAL_MB = 100
        # Create a large pinned file occupying 96 MB (>= 95% of 100 MB)
        fname = "huge_pinned.pcap"
        self._create_dummy_pcap(fname, size_bytes=96 * 1024 * 1024)
        self.runner._save_pinned_manifest({fname})

        # Attempt to start pcap must raise RuntimeError('pcap_storage_quota_exhausted')
        with mock.patch("shutil.which", return_value="/usr/bin/tcpdump"):
            with self.assertRaises(RuntimeError) as ctx:
                self.runner._start_pcap(10)
            self.assertEqual(str(ctx.exception), "pcap_storage_quota_exhausted")


class TestF30ServerProxyEndpoints(unittest.TestCase):
    """Test webapp/server.py proxy endpoints for PCAP operations."""

    def setUp(self):
        import webapp.server as server
        self.server = server
        self.client = server.app.test_client()
        self.csrf = "test_csrf_token_123"
        with self.client.session_transaction() as sess:
            sess['user'] = 'admin'
            sess['role'] = 'admin'
            sess['boot_id'] = server._SERVER_BOOT_ID
            sess['login_ts'] = int(time.time())
            sess['csrf_token'] = self.csrf
        self.headers = {'X-CSRF-Token': self.csrf}

    def test_server_pcap_path_traversal_prevention(self):
        # Invalid extensions must return 400 invalid_pcap_name
        for bad_ext in ["bad.exe", "attack.txt", "script.sh"]:
            r_pin = self.client.post(f"/api/lab/pcap/pin/{bad_ext}", headers=self.headers)
            self.assertEqual(r_pin.status_code, 400)
            self.assertEqual(r_pin.get_json()['error'], 'invalid_pcap_name')

            r_unpin = self.client.post(f"/api/lab/pcap/unpin/{bad_ext}", headers=self.headers)
            self.assertEqual(r_unpin.status_code, 400)

            r_del = self.client.delete(f"/api/lab/pcap/delete/{bad_ext}", headers=self.headers)
            self.assertEqual(r_del.status_code, 400)

            r_down = self.client.get(f"/api/lab/pcap/download/{bad_ext}", headers=self.headers)
            self.assertEqual(r_down.status_code, 400)

        # Path traversal characters must be blocked by router/handler (400 or 404)
        for bad_path in ["../evil.pcap", "..\\evil.pcap", "foo/bar.pcap"]:
            r_pin = self.client.post(f"/api/lab/pcap/pin/{bad_path}", headers=self.headers)
            self.assertIn(r_pin.status_code, (400, 404))

            r_del = self.client.delete(f"/api/lab/pcap/delete/{bad_path}", headers=self.headers)
            self.assertIn(r_del.status_code, (400, 404))

            r_down = self.client.get(f"/api/lab/pcap/download/{bad_path}", headers=self.headers)
            self.assertIn(r_down.status_code, (400, 404))


class TestF30ShellLoggingAndRotation(unittest.TestCase):
    """Test session logging, copytruncate rotation semantics, and cleanup safety."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="f30_log_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_session_demarcation_banner_and_append(self):
        """Verify multiple start sessions append without overwriting previous logs."""
        log_path = os.path.join(self.test_dir, "runner.log")

        # Session 1
        banner1 = "[BOOT] === Session Started: 2026-11-13 12:00:00 UTC | Service: runner | PID: 1001 ===\n"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(banner1)
            f.write("Line 1 from session 1\n")
            f.write("Line 2 from session 1\n")

        # Session 2 (append mode >>)
        banner2 = "[BOOT] === Session Started: 2026-11-13 13:00:00 UTC | Service: runner | PID: 1002 ===\n"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(banner2)
            f.write("Line 1 from session 2\n")

        # Verify complete log retains both sessions and both banners
        with open(log_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn(banner1, content)
        self.assertIn("Line 1 from session 1", content)
        self.assertIn(banner2, content)
        self.assertIn("Line 1 from session 2", content)
        # Verify order is preserved
        self.assertTrue(content.index("session 1") < content.index("session 2"))

    def test_copytruncate_rotation_preserves_open_descriptor_and_data(self):
        """Simulate copytruncate log rotation with an open file descriptor."""
        log_path = os.path.join(self.test_dir, "web.log")

        # Process starts and holds an open file descriptor in append mode (like nohup >> web.log)
        proc_fd = open(log_path, "a", encoding="utf-8", buffering=1)  # line-buffered
        try:
            proc_fd.write("Initial log data prior to rotation\n")
            proc_fd.flush()

            # External rotation triggered (copytruncate semantics)
            backup_path = f"{log_path}.1"
            shutil.copyfile(log_path, backup_path)
            # Truncate original file in-place (keeps same inode)
            with open(log_path, "r+") as trunc_f:
                trunc_f.truncate(0)

            # Process continues writing to the exact same open file descriptor without restart
            proc_fd.write("New log data after copytruncate rotation\n")
            proc_fd.flush()

            # Verify backup contains the initial pre-rotation data
            with open(backup_path, "r", encoding="utf-8") as bf:
                backup_data = bf.read()
            self.assertEqual(backup_data, "Initial log data prior to rotation\n")

            # Verify active log file contains the new post-rotation data
            with open(log_path, "r", encoding="utf-8") as af:
                active_data = af.read()
            self.assertIn("New log data after copytruncate rotation\n", active_data)
            self.assertNotIn("Initial log data prior to rotation", active_data)
        finally:
            proc_fd.close()

    def test_backup_rotation_indexing_and_shift(self):
        """Verify shifting older backups .1 -> .2 -> .3 and dropping beyond max_backups."""
        log_path = os.path.join(self.test_dir, "ryu.log")
        # Create .1 and .2 backups
        with open(f"{log_path}.1", "w") as f:
            f.write("generation 1")
        with open(f"{log_path}.2", "w") as f:
            f.write("generation 2")
        with open(log_path, "w") as f:
            f.write("current generation")

        max_backups = 3
        # Shift backups: .2 -> .3, .1 -> .2
        for i in range(max_backups - 1, 0, -1):
            src = f"{log_path}.{i}"
            dst = f"{log_path}.{i + 1}"
            if os.path.exists(src):
                if i + 1 <= max_backups:
                    shutil.move(src, dst)
                else:
                    os.remove(src)

        # Copy current to .1 and truncate active
        shutil.copyfile(log_path, f"{log_path}.1")
        with open(log_path, "r+") as f:
            f.truncate(0)

        # Verify generations
        with open(f"{log_path}.1") as f:
            self.assertEqual(f.read(), "current generation")
        with open(f"{log_path}.2") as f:
            self.assertEqual(f.read(), "generation 1")
        with open(f"{log_path}.3") as f:
            self.assertEqual(f.read(), "generation 2")
        # Active file is now empty
        self.assertEqual(os.path.getsize(log_path), 0)

    def test_clean_logs_dry_run_simulation(self):
        """Verify dry-run identifies target backups without deletion."""
        active_log = os.path.join(self.test_dir, "web.log")
        backup_1 = os.path.join(self.test_dir, "web.log.1")
        backup_2 = os.path.join(self.test_dir, "web.log.2")

        with open(active_log, "w") as f:
            f.write("active web log")
        with open(backup_1, "w") as f:
            f.write("backup 1")
        with open(backup_2, "w") as f:
            f.write("backup 2")

        # Simulate dry-run
        import glob
        backups = glob.glob(os.path.join(self.test_dir, "*.log.[0-9]*"))
        self.assertEqual(len(backups), 2)
        # In dry run, files must NOT be unlinked
        self.assertTrue(os.path.exists(backup_1))
        self.assertTrue(os.path.exists(backup_2))
        self.assertTrue(os.path.exists(active_log))

        # Simulate confirmed clean: only delete *.log.[0-9]*, never active .log
        for b in backups:
            os.remove(b)

        self.assertFalse(os.path.exists(backup_1))
        self.assertFalse(os.path.exists(backup_2))
        self.assertTrue(os.path.exists(active_log))


class TestF30UICompatibilityAndMetadata(unittest.TestCase):
    """Test API compatibility for PCAP UI (legacy arrays and rich metadata)."""

    def setUp(self):
        sys.modules.setdefault("mininet", mock.MagicMock())
        sys.modules.setdefault("mininet.net", mock.MagicMock())
        sys.modules.setdefault("mininet.node", mock.MagicMock())
        sys.modules.setdefault("mininet.link", mock.MagicMock())
        sys.modules.setdefault("mininet.cli", mock.MagicMock())
        sys.modules.setdefault("mininet.log", mock.MagicMock())

        import labs.mininet_runner as runner
        self.runner = runner
        self.test_dir = tempfile.mkdtemp(prefix="f30_ui_test_")
        self.orig_pcap_dir = runner.PCAP_DIR
        self.runner.PCAP_DIR = self.test_dir
        self.runner._MANIFEST_FILE = os.path.join(self.test_dir, ".pinned_manifest.json")
        self.runner._active_pcap_name = None
        self.runner._finalizing_pcaps.clear()
        self.runner._active_readers.clear()
        self.test_token = 'f30-ui-test-token-67890'
        self.token_patcher = mock.patch.object(runner, '_load_internal_token', return_value=self.test_token)
        self.token_patcher.start()

        raw_client = runner.app.test_client()
        class AuthenticatedUIClient:
            def __init__(self, client, token):
                self._client = client
                self._token = token
            def _inject(self, kwargs):
                headers = kwargs.get('headers')
                if headers is None:
                    headers = {}
                if isinstance(headers, dict):
                    headers.setdefault('X-Internal-Token', self._token)
                kwargs['headers'] = headers
                return kwargs
            def get(self, *a, **kw):
                return self._client.get(*a, **self._inject(kw))
            def post(self, *a, **kw):
                return self._client.post(*a, **self._inject(kw))
            def delete(self, *a, **kw):
                return self._client.delete(*a, **self._inject(kw))
            def put(self, *a, **kw):
                return self._client.put(*a, **self._inject(kw))
            def __getattr__(self, name):
                return getattr(self._client, name)

        self.client = AuthenticatedUIClient(raw_client, self.test_token)

    def tearDown(self):
        if hasattr(self, 'token_patcher'):
            self.token_patcher.stop()
        self.runner.PCAP_DIR = self.orig_pcap_dir
        self.runner._MANIFEST_FILE = os.path.join(self.orig_pcap_dir, ".pinned_manifest.json")
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_pcap(self, name: str, size: int = 1024):
        p = os.path.join(self.test_dir, name)
        with open(p, "wb") as f:
            f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * (size - 4))
        return p

    def test_pcap_list_response_backward_and_forward_compatibility(self):
        """Verify /pcap/list returns both legacy 'pcaps' string list and rich 'pcap_details'."""
        self._create_pcap("capture_test_1.pcap", 2048)
        self._create_pcap("capture_test_2.pcap", 4096)
        self.runner._save_pinned_manifest({"capture_test_2.pcap"})

        r = self.client.get("/pcap/list")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data.get("ok"))

        # Legacy backward compatibility: 'pcaps' must be a list of strings
        self.assertIn("pcaps", data)
        self.assertIsInstance(data["pcaps"], list)
        self.assertEqual(len(data["pcaps"]), 2)
        self.assertIn("capture_test_1.pcap", data["pcaps"])
        self.assertIn("capture_test_2.pcap", data["pcaps"])

        # Modern UI enrichment: 'pcap_details' must be a list of dicts with full metadata
        self.assertIn("pcap_details", data)
        details = data["pcap_details"]
        self.assertEqual(len(details), 2)

        det_map = {item["name"]: item for item in details}
        self.assertIn("capture_test_1.pcap", det_map)
        self.assertIn("capture_test_2.pcap", det_map)

        item1 = det_map["capture_test_1.pcap"]
        self.assertEqual(item1["size_bytes"], 2048)
        self.assertEqual(item1["size_human"], "2.0 KB")
        self.assertEqual(item1["status"], "completed")
        self.assertFalse(item1["pinned"])

        item2 = det_map["capture_test_2.pcap"]
        self.assertEqual(item2["size_bytes"], 4096)
        self.assertEqual(item2["size_human"], "4.0 KB")
        self.assertEqual(item2["status"], "completed")
        self.assertTrue(item2["pinned"])

    def test_pcap_storage_schema_fields(self):
        """Verify /pcap/storage returns valid quota and capacity breakdown."""
        self._create_pcap("file1.pcap", 1024 * 1024)  # 1 MB
        self._create_pcap("file2.pcap", 2 * 1024 * 1024)  # 2 MB
        self.runner._save_pinned_manifest({"file1.pcap"})

        r = self.client.get("/pcap/storage")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data.get("ok"))

        for key in ["used_bytes", "used_mb", "limit_mb", "pinned_count", "unpinned_count", "percent_used"]:
            self.assertIn(key, data)

        self.assertEqual(data["pinned_count"], 1)
        self.assertEqual(data["unpinned_count"], 1)
        self.assertGreaterEqual(data["used_mb"], 3.0)


if __name__ == '__main__':
    unittest.main()

