"""
Verification of Topic 4 (F-33) User Notes.
Ensures:
1. request_id integrity and injection immunity (server & runner).
2. 4xx validation companion fields (whitelist, length, bad-pattern rejection).
3. log_tail sanitization vs disk log utility (Bearer token, password, Windows path, Linux path, internal URL, Traceback).
"""

import os
import sys
import tempfile
import types
import unittest
from flask import g, request

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Stub mininet if absent (e.g. on Windows development machines)
try:
    import mininet.net  # noqa: F401
except ImportError:
    mn_mod = types.ModuleType('mininet')
    mn_net = types.ModuleType('mininet.net')
    mn_net.Mininet = object
    mn_node = types.ModuleType('mininet.node')
    mn_node.RemoteController = object
    mn_node.OVSSwitch = object
    mn_link = types.ModuleType('mininet.link')
    mn_link.TCLink = object
    mn_log = types.ModuleType('mininet.log')
    mn_log.setLogLevel = lambda *a, **kw: None
    sys.modules.update({
        'mininet': mn_mod,
        'mininet.net': mn_net,
        'mininet.node': mn_node,
        'mininet.link': mn_link,
        'mininet.log': mn_log,
    })

from webapp.server import (
    app,
    _sanitize_log_text,
    _is_safe_detail_str,
    _sanitize_runner_detail_value,
    _sanitize_runner_error_payload,
    _proxy_ryu_post,
    _ALLOWED_RUNNER_DETAIL_KEYS,
    _ALLOWED_RUNNER_ERROR_CODES,
    _ALLOWED_RYU_400_ERRORS,
    _tail_file,
)
from labs.mininet_runner import (
    app as runner_app,
    _assign_runner_request_id,
    _runner_error,
    _runner_req_id,
)


class TestTopic4UserNotes(unittest.TestCase):

    # =========================================================================
    # Note 1: request_id Integrity
    # =========================================================================
    def test_note1_server_ignores_client_request_id(self):
        """The web server must generate request_id autonomously and ignore any client-supplied header."""
        with app.test_client() as client:
            resp = client.get('/api/settings', headers={'X-Request-ID': 'client-injected-id-12345'})
            self.assertEqual(resp.status_code, 401)
            data = resp.get_json()
            self.assertNotEqual(data.get('request_id'), 'client-injected-id-12345')
            self.assertEqual(len(data.get('request_id')), 12)
            int(data.get('request_id'), 16)  # must be hex

            with app.test_request_context('/api/controller/status', headers={'X-Request-ID': 'evil_client_id_999'}):
                app.preprocess_request()
                self.assertNotEqual(g.request_id, 'evil_client_id_999')
                self.assertEqual(len(g.request_id), 12)
                int(g.request_id, 16)

    def test_note1_runner_request_id_validation_and_sanitization(self):
        """Runner must enforce strict regex [A-Za-z0-9_.-]{4,32} and fallback if invalid."""
        with runner_app.test_request_context('/status', headers={'X-Request-ID': 'a1b2c3d4e5f6'}):
            runner_app.preprocess_request()
            self.assertEqual(g.request_id, 'a1b2c3d4e5f6')

        bad_ids = [
            'bad id with spaces',
            'drop_table;--',
            '../../../etc/passwd',
            'abc',         # len < 4
            'a' * 33,     # len > 32
            '<script>alert(1)</script>',
            'evil$var',
            'id!@#$',
        ]
        for bad in bad_ids:
            with runner_app.test_request_context('/status', headers={'X-Request-ID': bad}):
                runner_app.preprocess_request()
                self.assertNotEqual(g.request_id, bad, f"Runner accepted invalid ID: {bad!r}")
                self.assertEqual(len(g.request_id), 12)
                int(g.request_id, 16)

        from unittest.mock import patch
        with runner_app.test_request_context('/status'):
            with patch.object(request.headers, 'get', return_value='injected_id\r\nLog-Injection: true\n'):
                _assign_runner_request_id()
                self.assertNotEqual(g.request_id, 'injected_id\r\nLog-Injection: true\n')
                self.assertNotIn('\r', g.request_id)
                self.assertNotIn('\n', g.request_id)
                self.assertEqual(len(g.request_id), 12)

    # =========================================================================
    # Note 2: 4xx Validation and Companion Fields
    # =========================================================================
    def test_note2_runner_companion_fields_whitelisting_and_sanitization(self):
        """Companion fields must only allow whitelisted keys and reject paths, URLs, and exceptions."""
        malicious_runner_payload = {
            'error': 'attacker_blocked',
            'attacker': 'h3; rm -rf /; /home/ubuntu/evil.sh',
            'victim': 'h1',
            'ip': '10.0.0.5',
            'leaked_internal_key': 'secret_internal_val',
            'database_password': 'SuperSecretPassword',
            'traceback': 'Traceback (most recent call last)...',
        }

        safe_err, out_status, safe_extra = _sanitize_runner_error_payload(
            malicious_runner_payload, 400, 'test_op'
        )

        self.assertEqual(safe_err, 'attacker_blocked')
        self.assertEqual(out_status, 400)

        for k in safe_extra:
            self.assertIn(k, _ALLOWED_RUNNER_DETAIL_KEYS)

        self.assertNotIn('leaked_internal_key', safe_extra)
        self.assertNotIn('database_password', safe_extra)
        self.assertNotIn('traceback', safe_extra)
        self.assertNotIn('attacker', safe_extra)
        self.assertEqual(safe_extra['victim'], 'h1')
        self.assertEqual(safe_extra['ip'], '10.0.0.5')

    def test_note2_runner_ip_and_attacker_values_rejected_if_suspicious(self):
        """Values exceeding 64 chars or containing paths/URLs/newlines must be rejected."""
        suspicious_cases = [
            'http://internal-service.local/api',
            'https://192.168.1.100/admin',
            '/etc/shadow',
            'C:\\Windows\\System32\\cmd.exe',
            'exception in worker thread',
            'Traceback: line 42',
            '10.0.0.1\r\ninjected_header: val',
            'a' * 65,
        ]
        for val in suspicious_cases:
            self.assertFalse(
                _is_safe_detail_str(val),
                f"Value should have been rejected as unsafe: {val!r}"
            )
            self.assertIsNone(_sanitize_runner_detail_value(val))

    def test_note2_ryu_proxy_sanitizes_errors_and_message(self):
        """Ryu 400 errors dict and message must be redacted and sanitized."""
        from unittest.mock import patch, MagicMock

        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {
            'error': 'invalid_config',
            'message': 'Failed to bind socket http://127.0.0.1:8080 at /home/ubuntu/sdn-ddos-mitigation-ha with token=tok_secret_123',
            'errors': {
                'vip_ip': 'Invalid IP http://internal.net/vip',
                'secret_param': 'password=VerySecretPass999',
                'path_param': 'File not found: C:\\Users\\testuser\\Desktop\\test.py',
            }
        }

        with patch('webapp.server._ryu_post', return_value=mock_resp):
            with app.test_request_context('/api/dos/config', method='POST'):
                res, sc = _proxy_ryu_post('/dos/config', forward_400=True)
                data = res.get_json()

                self.assertEqual(sc, 400)
                self.assertEqual(data['error'], 'invalid_config')

                msg = data['message']
                self.assertNotIn('127.0.0.1:8080', msg)
                self.assertIn('[internal-url]', msg)
                self.assertNotIn('/home/ubuntu', msg)
                self.assertIn('[path]', msg)
                self.assertNotIn('tok_secret_123', msg)
                self.assertIn('token=[redacted]', msg)

                errs = data['errors']
                self.assertNotIn('http://internal.net', errs['vip_ip'])
                self.assertIn('[internal-url]', errs['vip_ip'])
                self.assertNotIn('VerySecretPass999', errs['secret_param'])
                self.assertIn('[redacted]', errs['secret_param'])
                self.assertNotIn('C:\\Users\\testuser', errs['path_param'])
                self.assertIn('[path]', errs['path_param'])

    # =========================================================================
    # Note 3: log_tail Sanitization vs Disk Log Utility
    # =========================================================================
    def test_note3_log_tail_sanitizes_all_sensitive_patterns(self):
        """
        Verify log_tail redaction with exact user-requested patterns:
        - Bearer Token
        - Password
        - Windows path
        - Linux path
        - Internal service URL
        - Traceback
        Ensures none appear in sanitized output, while disk log remains unredacted.
        """
        raw_log_content = (
            "2026-11-12 10:00:00 INFO [dos_guard] Worker starting on http://127.0.0.1:8080/dos/metrics\n"
            "2026-11-12 10:00:01 DEBUG [server] Connecting with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret\n"
            "2026-11-12 10:00:01 DEBUG [client] Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.standalone_token_leak\n"
            "2026-11-12 10:00:02 INFO [config] Loaded config from C:\\Users\\testuser\\Desktop\\sdn-ddos-mitigation-ha\\config.json\n"
            "2026-11-12 10:00:03 INFO [runner] Mininet topology started at /home/ubuntu/Desktop/sdn-ddos-mitigation-ha/labs/mininet_runner.py\n"
            "2026-11-12 10:00:04 DEBUG [auth] Database auth initialized with password=MySuperSecretPassword999!\n"
            "2026-11-12 10:00:05 ERROR [worker] Unexpected exception caught:\n"
            "Traceback (most recent call last):\n"
            '  File "/home/ubuntu/sdn-ddos-mitigation-ha/ryu_app/dos_guard.py", line 125, in handle_packet\n'
            '    data = fetch_url("http://192.168.1.50:9090/status")\n'
            '  File "C:\\Python312\\Lib\\urllib\\request.py", line 210, in urlopen\n'
            "    raise ConnectionRefusedError('Connection to 192.168.1.50:9090 failed')\n"
            "ConnectionRefusedError: Connection to 192.168.1.50:9090 failed\n"
            "2026-11-12 10:00:06 INFO [worker] Fallback to primary controller succeeded.\n"
        )

        with tempfile.NamedTemporaryFile('w+', delete=False, encoding='utf-8') as tf:
            tf.write(raw_log_content)
            tf_path = tf.name

        try:
            sanitized_tail = _tail_file(tf_path, max_lines=40, max_chars=4096)

            self.assertNotIn("Bearer eyJhbGci", sanitized_tail)
            self.assertNotIn("supersecret", sanitized_tail)
            self.assertNotIn("standalone_token_leak", sanitized_tail)
            self.assertNotIn("MySuperSecretPassword999!", sanitized_tail)
            self.assertNotIn("C:\\Users\\testuser", sanitized_tail)
            self.assertNotIn("/home/ubuntu/Desktop", sanitized_tail)
            self.assertNotIn("http://127.0.0.1:8080", sanitized_tail)
            self.assertNotIn("http://192.168.1.50:9090", sanitized_tail)
            self.assertNotIn("ConnectionRefusedError: Connection to 192.168.1.50", sanitized_tail)
            self.assertNotIn('File "/home/ubuntu/sdn-ddos-mitigation-ha/ryu_app/dos_guard.py"', sanitized_tail)

            self.assertIn("Authorization: [redacted]", sanitized_tail)
            self.assertIn("Bearer [redacted]", sanitized_tail)
            self.assertIn("password=[redacted]", sanitized_tail)
            self.assertIn("[path]", sanitized_tail)
            self.assertIn("[internal-url]", sanitized_tail)
            self.assertIn("[traceback redacted]", sanitized_tail)
            self.assertIn("[error detail redacted]", sanitized_tail)

            self.assertIn("Worker starting on [internal-url]", sanitized_tail)
            self.assertIn("Fallback to primary controller succeeded.", sanitized_tail)

            with open(tf_path, 'r', encoding='utf-8') as f:
                disk_content = f.read()

            self.assertIn("MySuperSecretPassword999!", disk_content)
            self.assertIn("http://127.0.0.1:8080/dos/metrics", disk_content)
            self.assertIn("C:\\Users\\testuser\\Desktop\\sdn-ddos-mitigation-ha\\config.json", disk_content)
            self.assertIn("/home/ubuntu/Desktop/sdn-ddos-mitigation-ha/labs/mininet_runner.py", disk_content)
            self.assertIn("ConnectionRefusedError: Connection to 192.168.1.50:9090 failed", disk_content)
            self.assertEqual(disk_content, raw_log_content)

        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


if __name__ == '__main__':
    unittest.main()
