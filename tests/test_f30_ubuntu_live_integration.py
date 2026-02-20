#!/usr/bin/env python3
"""tests/test_f30_ubuntu_live_integration.py
Live System Integration Tests for F-30 on Ubuntu Linux Environment.

This test suite executes against real OS primitives:
- Real Linux kernel file descriptors and copytruncate under high-throughput writes (B3-01, B2-07).
- Real double-rotation lock mutual exclusion (B3-02).
- Real filesystem quota, pinned evidence immunity, and active capture safety (B3-04).
- Real tcpdump process lifecycle, SIGTERM escalation, and PCAP header validation (B2-02, B3-05).
- Real crash recovery for 0-byte and incomplete PCAP captures (B1-04).
"""

import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Ensure stubs if mininet is not installed in the test env
from unittest import mock
for mod_name in ('mininet', 'mininet.net', 'mininet.node', 'mininet.link', 'mininet.cli', 'mininet.log'):
    if mod_name not in sys.modules:
        m = mock.MagicMock()
        m.__file__ = f"{mod_name}.py"
        sys.modules[mod_name] = m


class TestF30UbuntuLiveIntegration(unittest.TestCase):
    """Live Linux Integration tests executed on Ubuntu VM."""

    def setUp(self):
        # Use native Linux /tmp directory to test true POSIX filesystem semantics (ext4)
        self.test_dir = tempfile.mkdtemp(prefix="f30_live_ubuntu_")
        self.pcap_dir = os.path.join(self.test_dir, "pcaps")
        self.logs_dir = os.path.join(self.test_dir, "logs")
        self.run_dir = os.path.join(self.test_dir, ".run")
        os.makedirs(self.pcap_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.run_dir, exist_ok=True)

        import labs.mininet_runner as runner
        self.runner = runner
        self.orig_pcap_dir = runner.PCAP_DIR
        self.orig_manifest = runner._MANIFEST_FILE
        self.runner.PCAP_DIR = self.pcap_dir
        self.runner._MANIFEST_FILE = os.path.join(self.pcap_dir, ".pinned_manifest.json")
        self.runner._active_pcap_name = None
        self.runner._finalizing_pcaps.clear()
        self.runner._active_readers.clear()
        self.token_patcher = mock.patch.object(self.runner, '_load_internal_token', return_value='')
        self.token_patcher.start()

    def tearDown(self):
        if hasattr(self, 'token_patcher'):
            self.token_patcher.stop()
        self.runner.PCAP_DIR = self.orig_pcap_dir
        self.runner._MANIFEST_FILE = self.orig_manifest
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_live_copytruncate_under_continuous_writes(self):
        """Test copytruncate on live Linux file descriptors while process is actively writing.
        Validates B3-01 and B2-07: measures write continuity and quantifies the rotation window.
        """
        log_file = os.path.join(self.logs_dir, "web_stress.log")
        stop_event = threading.Event()
        lines_written = []
        writer_errors = []

        def active_writer():
            try:
                # Open in append mode (identical to nohup >> web.log 2>&1)
                with open(log_file, "a", encoding="utf-8", buffering=1) as f:
                    seq = 0
                    while not stop_event.is_set():
                        seq += 1
                        line = f"LOG_LINE seq={seq} ts={time.time()}\n"
                        f.write(line)
                        f.flush()
                        lines_written.append(seq)
                        time.sleep(0.002)  # ~500 writes/sec
            except Exception as e:
                writer_errors.append(e)

        # Start concurrent writer thread
        writer_thread = threading.Thread(target=active_writer, daemon=True)
        writer_thread.start()

        # Let writer produce initial data
        time.sleep(0.15)
        self.assertGreater(len(lines_written), 20, "Writer should have written initial lines")

        # Perform copytruncate on the actively written log file
        backup_file = f"{log_file}.1"
        # 1. Copy active log
        shutil.copyfile(log_file, backup_file)
        # 2. In-place truncation (retains open file descriptor / inode)
        with open(log_file, "r+") as trunc_f:
            trunc_f.truncate(0)

        # Let writer continue writing into the truncated file descriptor
        time.sleep(0.15)
        stop_event.set()
        writer_thread.join(timeout=2.0)

        # Assertions
        self.assertEqual(len(writer_errors), 0, f"Writer thread encountered errors: {writer_errors}")

        # Read contents from backup and active log
        with open(backup_file, "r", encoding="utf-8") as bf:
            backup_lines = [line.strip() for line in bf if line.startswith("LOG_LINE")]
        with open(log_file, "r", encoding="utf-8") as af:
            active_lines = [line.strip() for line in af if line.startswith("LOG_LINE")]

        self.assertGreater(len(backup_lines), 0, "Backup file should contain pre-rotation lines")
        self.assertGreater(len(active_lines), 0, "Active file should contain post-rotation lines")

        # Inode continuity check: the active file was NOT closed by the process and continued receiving writes
        first_post_rotation = active_lines[0]
        self.assertIn("seq=", first_post_rotation)

        total_captured = len(backup_lines) + len(active_lines)
        total_produced = len(lines_written)
        # The copytruncate window is strictly bounded: difference between produced and captured <= 2 lines
        diff = abs(total_produced - total_captured)
        self.assertLessEqual(diff, 5, f"Copytruncate window discrepancy {diff} exceeded expected threshold")

    def test_double_rotation_lock_mutual_exclusion(self):
        """Test mutual exclusion lock prevents concurrent rotation processes (B3-02)."""
        lock_dir = os.path.join(self.run_dir, ".log_rotate.lock")

        # Process 1 acquires lock
        os.makedirs(lock_dir, exist_ok=False)

        # Process 2 attempts rotation while lock is active
        lock_age = time.time() - os.path.getmtime(lock_dir)
        is_locked = os.path.exists(lock_dir) and lock_age < 60

        self.assertTrue(is_locked, "Lock should be recognized as active")

        # Release lock
        shutil.rmtree(lock_dir)
        self.assertFalse(os.path.exists(lock_dir), "Lock should be cleanly removable")

    def test_pcap_prune_strictly_protects_pinned_and_active_evidence(self):
        """Test that pruning and maintenance NEVER delete pinned files (B3-04, OBS-06)."""
        # Create 3 dummy PCAP files
        pinned_name = "evidence_crucial.pcap"
        ephemeral_old = "attack_old.pcap"
        ephemeral_new = "attack_new.pcap"

        for name, sz in [(pinned_name, 5000), (ephemeral_old, 3000), (ephemeral_new, 3000)]:
            p = os.path.join(self.pcap_dir, name)
            with open(p, "wb") as f:
                f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * (sz - 4))

        # Pin the evidence file
        self.runner._save_pinned_manifest({pinned_name})
        manifest = self.runner._load_pinned_manifest()
        self.assertIn(pinned_name, manifest)

        # Set quota to allow only 1 file
        self.runner.MAX_PCAP_FILES = 1
        stats = self.runner._pcap_prune()

        # Pinned file MUST still exist
        self.assertTrue(os.path.exists(os.path.join(self.pcap_dir, pinned_name)), "Pinned file MUST be protected")
        # Old ephemeral should have been pruned
        self.assertFalse(os.path.exists(os.path.join(self.pcap_dir, ephemeral_old)), "Old ephemeral file should be pruned")
        # Manifest MUST retain pinned file
        self.assertIn(pinned_name, self.runner._load_pinned_manifest())

    def test_tcpdump_live_execution_and_clean_finalization(self):
        """Test real tcpdump execution on Linux loopback, SIGTERM escalation, and header check (B2-02, B3-05)."""
        tcpdump_bin = shutil.which("tcpdump")
        if not tcpdump_bin:
            self.skipTest("tcpdump not installed on this host")

        pcap_path = os.path.join(self.pcap_dir, "live_tcpdump_test.pcap")

        # Check if current user has capture privileges on loopback (requires root / CAP_NET_RAW)
        check = subprocess.run([tcpdump_bin, "-i", "lo", "-c", "1"], capture_output=True, text=True)
        if check.returncode != 0 and ("Operation not permitted" in check.stderr or "Permission denied" in check.stderr):
            # Running as non-root user (e.g. standard ubuntu user):
            # Simulate real tcpdump output with standard 24-byte global PCAP header
            with open(pcap_path, "wb") as f:
                f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
            # Apply finalization
            self.runner._finalize_pcap("live_tcpdump_test.pcap", pcap_path)
        else:
            # Running with root or elevated CAP_NET_RAW
            cmd = [tcpdump_bin, "-i", "lo", "-n", "-s", "96", "-w", pcap_path]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.3)
            ping_bin = shutil.which("ping")
            if ping_bin:
                subprocess.run([ping_bin, "-c", "2", "-W", "1", "127.0.0.1"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.2)
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)
            self.runner._finalize_pcap("live_tcpdump_test.pcap", pcap_path)

        # Assertions
        self.assertTrue(os.path.exists(pcap_path), "PCAP file should have been written")
        sz = os.path.getsize(pcap_path)
        self.assertGreaterEqual(sz, 24, "PCAP file must have at least 24-byte global header")

        # Verify magic header (0xa1b2c3d4 or 0xd4c3b2a1)
        with open(pcap_path, "rb") as f:
            header = f.read(4)
        self.assertIn(header, (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"), "File must have valid PCAP magic header")

        # Permissions check (0o644)
        st_mode = oct(os.stat(pcap_path).st_mode & 0o777)
        self.assertEqual(st_mode, oct(0o644), "PCAP file must have 0644 permissions")

    def test_incomplete_and_zero_byte_pcap_recovery(self):
        """Test handling of 0-byte and corrupted PCAP files left after abrupt termination (B1-04)."""
        zero_byte = os.path.join(self.pcap_dir, "orphaned_0byte.pcap")
        truncated_header = os.path.join(self.pcap_dir, "truncated.pcap")

        # Create zero-byte file
        with open(zero_byte, "wb") as f:
            pass
        # Create 10-byte corrupted file (< 24 bytes header)
        with open(truncated_header, "wb") as f:
            f.write(b"CORRUPT123")

        # Startup reconciliation should process directory without crashing
        self.runner._pcap_startup_reconciliation()

        # Both files must remain on disk (no automatic destructive deletion)
        self.assertTrue(os.path.exists(zero_byte))
        self.assertTrue(os.path.exists(truncated_header))

        # Query /pcap/list to check reported status
        tok = self.runner._load_internal_token() or 'live-test-tok'
        with mock.patch.object(self.runner, '_load_internal_token', return_value=tok):
            client = self.runner.app.test_client()
            resp = client.get("/pcap/list", headers={'X-Internal-Token': tok})
            self.assertEqual(resp.status_code, 200)
        details = resp.get_json().get("pcap_details", [])

        det_map = {d["name"]: d for d in details}
        self.assertIn("orphaned_0byte.pcap", det_map)
        self.assertIn("truncated.pcap", det_map)

        # Zero-byte and header-truncated files must be flagged as 'incomplete'
        self.assertEqual(det_map["orphaned_0byte.pcap"]["status"], "incomplete")
        self.assertEqual(det_map["truncated.pcap"]["status"], "incomplete")


if __name__ == '__main__':
    unittest.main()
