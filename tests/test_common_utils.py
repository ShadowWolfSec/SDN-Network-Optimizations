"""
tests/test_common_utils.py
==========================
Unit tests for core/common_utils.py (Dependency-Free Foundation Module).
"""

import os
import tempfile
import time
import unittest

from core.common_utils import (
    parse_bool,
    parse_int,
    parse_float,
    parse_str,
    validate_ipv4,
    validate_mac,
    safe_resolve_path,
    resolve_safe_pcap_path,
    load_internal_token,
    CrossProcessFileLock,
)


class TestCommonUtils(unittest.TestCase):

    def test_parse_bool(self):
        # Truthy cases
        self.assertTrue(parse_bool(True))
        self.assertTrue(parse_bool(1))
        self.assertTrue(parse_bool(1.0))
        self.assertTrue(parse_bool("1"))
        self.assertTrue(parse_bool("true"))
        self.assertTrue(parse_bool("TRUE"))
        self.assertTrue(parse_bool("yes"))
        self.assertTrue(parse_bool("Y"))
        self.assertTrue(parse_bool("on"))
        self.assertTrue(parse_bool("  ON  "))

        # Falsy cases
        self.assertFalse(parse_bool(False))
        self.assertFalse(parse_bool(0))
        self.assertFalse(parse_bool(0.0))
        self.assertFalse(parse_bool("0"))
        self.assertFalse(parse_bool("false"))
        self.assertFalse(parse_bool("no"))
        self.assertFalse(parse_bool("off"))
        self.assertFalse(parse_bool(""))
        self.assertFalse(parse_bool(None))
        self.assertFalse(parse_bool("random_string"))

    def test_parse_int(self):
        self.assertEqual(parse_int(42), 42)
        self.assertEqual(parse_int(42.9), 42)
        self.assertEqual(parse_int(" 100 "), 100)
        self.assertEqual(parse_int("invalid", default=99), 99)
        self.assertEqual(parse_int(None, default=5), 5)

    def test_parse_float(self):
        self.assertEqual(parse_float(3.14), 3.14)
        self.assertEqual(parse_float(42), 42.0)
        self.assertEqual(parse_float(" 0.3 "), 0.3)
        self.assertEqual(parse_float("invalid", default=1.5), 1.5)
        self.assertEqual(parse_float(None, default=0.0), 0.0)

    def test_parse_str(self):
        self.assertEqual(parse_str(" hello "), "hello")
        self.assertEqual(parse_str(123), "123")
        self.assertEqual(parse_str(None, default="fallback"), "fallback")

    def test_validate_ipv4(self):
        self.assertEqual(validate_ipv4("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ipv4("  10.0.0.1  "), "10.0.0.1")
        self.assertIsNone(validate_ipv4("256.0.0.1"))
        self.assertIsNone(validate_ipv4("not_an_ip"))
        self.assertIsNone(validate_ipv4("::1"))  # IPv6 must be rejected
        self.assertIsNone(validate_ipv4("2001:db8::1"))
        self.assertIsNone(validate_ipv4(None))
        self.assertIsNone(validate_ipv4(12345))

    def test_validate_mac(self):
        self.assertEqual(validate_mac("00:11:22:33:44:55"), "00:11:22:33:44:55")
        self.assertEqual(validate_mac("00-11-22-33-44-55"), "00:11:22:33:44:55")
        self.assertEqual(validate_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(validate_mac("00:11:22:33:44"))
        self.assertIsNone(validate_mac("00:11:22:33:44:55:66"))
        self.assertIsNone(validate_mac("invalid_mac"))
        self.assertIsNone(validate_mac(None))

    def test_safe_resolve_path(self):
        with tempfile.TemporaryDirectory() as base_dir:
            # Valid subfile
            target = safe_resolve_path(base_dir, "test.txt")
            self.assertTrue(target.startswith(os.path.realpath(base_dir)))

            # Traversal attempts must raise ValueError
            with self.assertRaises(ValueError):
                safe_resolve_path(base_dir, "../outside.txt")
            with self.assertRaises(ValueError):
                safe_resolve_path(base_dir, "sub/../../outside.txt")
            with self.assertRaises(ValueError):
                safe_resolve_path(base_dir, "")

    def test_resolve_safe_pcap_path(self):
        with tempfile.TemporaryDirectory() as pcap_dir:
            target = resolve_safe_pcap_path(pcap_dir, "capture_1.pcap")
            self.assertTrue(target.endswith("capture_1.pcap"))

            # Invalid extension
            with self.assertRaises(ValueError):
                resolve_safe_pcap_path(pcap_dir, "script.py")
            # Path traversal
            with self.assertRaises(ValueError):
                resolve_safe_pcap_path(pcap_dir, "../capture.pcap")

    def test_cross_process_file_lock(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = os.path.join(tmpdir, "test.lock")
            # Acquire and release cleanly
            with CrossProcessFileLock(lock_path, timeout_sec=1.0) as lock:
                self.assertIsNotNone(lock.fd)
                # Second lock on same path with 0.1s timeout should fail
                with self.assertRaises(TimeoutError):
                    with CrossProcessFileLock(lock_path, timeout_sec=0.1):
                        pass

            # After exit, lock file should be acquirable again
            with CrossProcessFileLock(lock_path, timeout_sec=1.0) as lock2:
                self.assertIsNotNone(lock2.fd)


if __name__ == "__main__":
    unittest.main()
