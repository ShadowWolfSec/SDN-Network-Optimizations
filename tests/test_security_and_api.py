import csv
import html as html_lib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import requests
from werkzeug.security import generate_password_hash

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Ensure module import succeeds cleanly even if FLASK_DEBUG=0 is set in caller env
os.environ.setdefault('FLASK_DEBUG', '1')
os.environ.setdefault('FLASK_SECRET_KEY', 'unit-test-flask-secret-key-at-least-32-bytes')

from webapp import server as srv  # noqa: E402


class SecurityAndApiTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.test_users_file = os.path.join(self.tmpdir.name, 'users.json')
        with open(self.test_users_file, 'w', encoding='utf-8') as f:
            json.dump(
                {
                    'tester': {
                        'password': generate_password_hash('SecretPass123!'),
                        'role': 'admin',
                    }
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

        self.orig_ryu_base = srv.RYU_API_BASE
        self.orig_glances_cfg = (
            srv.GLANCES_API_BASE,
            srv.GLANCES_CACHE_TTL_SEC,
            srv.GLANCES_TIMEOUT_SEC,
            srv.GLANCES_CB_FAIL_THRESHOLD,
            srv.GLANCES_CB_COOLDOWN_SEC,
        )
        srv._reset_glances_state_for_tests()
        srv._reset_alerts_state_for_tests()
        self.client = srv.app.test_client()

    def tearDown(self):
        srv._reset_alerts_state_for_tests()
        srv.USERS_FILE = self.orig_users_file
        srv.RYU_API_BASE = self.orig_ryu_base
        (
            srv.GLANCES_API_BASE,
            srv.GLANCES_CACHE_TTL_SEC,
            srv.GLANCES_TIMEOUT_SEC,
            srv.GLANCES_CB_FAIL_THRESHOLD,
            srv.GLANCES_CB_COOLDOWN_SEC,
        ) = self.orig_glances_cfg
        srv._reset_glances_state_for_tests()
        with srv._users_cache_lock:
            srv._users_cache = {}
            srv._users_cache_mtime = 0.0
        with srv._rate_lock:
            srv._rate_state.clear()
        self.tmpdir.cleanup()

    def _extract_login_csrf(self, body_text: str) -> str:
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_text)
        self.assertIsNotNone(m, 'Missing hidden csrf_token input on login page')
        return html_lib.unescape(m.group(1))

    def _extract_app_csrf(self, body_text: str) -> str:
        m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', body_text)
        self.assertIsNotNone(m, 'Missing csrf-token meta tag on main UI page')
        return html_lib.unescape(m.group(1))

    def _login_tester(self, remote_addr: str = '127.0.0.1'):
        r_get = self.client.get('/login', environ_base={'REMOTE_ADDR': remote_addr})
        self.assertEqual(r_get.status_code, 200)
        csrf = self._extract_login_csrf(r_get.get_data(as_text=True))
        r_post = self.client.post(
            '/login',
            data={'username': 'tester', 'password': 'SecretPass123!', 'csrf_token': csrf},
            environ_base={'REMOTE_ADDR': remote_addr},
            follow_redirects=False,
        )
        self.assertEqual(r_post.status_code, 302)
        idx = self.client.get('/', environ_base={'REMOTE_ADDR': remote_addr})
        self.assertEqual(idx.status_code, 200)
        return self._extract_app_csrf(idx.get_data(as_text=True))

    def test_production_requires_secret_key(self):
        env = dict(os.environ)
        env['FLASK_DEBUG'] = '0'
        env['FLASK_SECRET_KEY'] = ''
        proc = subprocess.run(
            [sys.executable, '-B', '-c', 'import webapp.server'],
            cwd=PROJECT_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('FATAL: Set FLASK_SECRET_KEY', proc.stderr)

    def test_users_json_passwords_are_hashed(self):
        real_users_path = os.path.join(PROJECT_ROOT, 'webapp', 'users.json')
        with open(real_users_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)
        self.assertGreaterEqual(len(data), 1)
        for username, record in data.items():
            self.assertIsInstance(record, dict, f'Invalid user entry for {username}')
            pw = str(record.get('password') or '')
            self.assertTrue(
                srv._is_password_hash(pw),
                f'User {username} password in webapp/users.json must be hashed',
            )

    def test_unauthenticated_access_blocked(self):
        r_root = self.client.get('/', follow_redirects=False)
        self.assertEqual(r_root.status_code, 302)
        self.assertIn('/login', r_root.headers.get('Location', ''))

        r_api = self.client.get('/api/history')
        self.assertEqual(r_api.status_code, 401)
        self.assertEqual(r_api.get_json().get('error'), 'unauthorized')

        r_health = self.client.get('/health')
        self.assertEqual(r_health.status_code, 200)
        self.assertTrue(r_health.get_json().get('ok'))

    def test_security_headers_and_csp(self):
        r = self.client.get('/login')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(r.headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(r.headers.get('Cache-Control'), 'no-store')
        csp = r.headers.get('Content-Security-Policy', '')
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn('cdn.jsdelivr.net', csp)
        self.assertNotIn('fonts.googleapis.com', csp)

    def test_csrf_enforced_on_login_logout_and_api(self):
        # 1) POST /login without CSRF fails with 403
        r_nocsrf = self.client.post('/login', data={'username': 'tester', 'password': 'SecretPass123!'})
        self.assertEqual(r_nocsrf.status_code, 403)

        # 2) Authenticate properly
        csrf = self._login_tester()

        # 3) State-changing /api/* without CSRF fails with 403
        r_api_nocsrf = self.client.post('/api/settings', json={'ryu_api_base': 'http://127.0.0.1:8080'})
        self.assertEqual(r_api_nocsrf.status_code, 403)
        self.assertEqual(r_api_nocsrf.get_json().get('error'), 'csrf_invalid')

        # 4) State-changing /api/* with valid X-CSRF-Token succeeds
        r_api_ok = self.client.post(
            '/api/settings',
            json={'ryu_api_base': 'http://localhost:8080'},
            headers={'X-CSRF-Token': csrf},
        )
        self.assertEqual(r_api_ok.status_code, 200)
        self.assertEqual(r_api_ok.get_json().get('ryu_api_base'), 'http://localhost:8080')

        # 5) POST /logout requires CSRF
        r_logout_bad = self.client.post('/logout')
        self.assertEqual(r_logout_bad.status_code, 403)

        r_logout_ok = self.client.post('/logout', data={'csrf_token': csrf}, follow_redirects=False)
        self.assertEqual(r_logout_ok.status_code, 302)
        self.assertEqual(self.client.get('/api/history').status_code, 401)

    def test_login_brute_force_and_xff_spoof_resistance(self):
        r_get = self.client.get('/login', environ_base={'REMOTE_ADDR': '10.9.9.9'})
        csrf = self._extract_login_csrf(r_get.get_data(as_text=True))

        # 8 failed attempts from untrusted client 10.9.9.9 (varying spoofed XFF each time)
        for idx in range(8):
            r = self.client.post(
                '/login',
                data={'username': 'tester', 'password': 'WrongPassword', 'csrf_token': csrf},
                headers={'X-Forwarded-For': f'198.51.100.{idx + 1}'},
                environ_base={'REMOTE_ADDR': '10.9.9.9'},
            )
            self.assertEqual(r.status_code, 401)

        # 9th attempt must hit 429 even if attacker changes X-Forwarded-For again
        r_locked = self.client.post(
            '/login',
            data={'username': 'tester', 'password': 'SecretPass123!', 'csrf_token': csrf},
            headers={'X-Forwarded-For': '203.0.113.99'},
            environ_base={'REMOTE_ADDR': '10.9.9.9'},
        )
        self.assertEqual(r_locked.status_code, 429)

        # Trusted proxy peer propagation honors XFF only when TRUST_PROXY_HEADERS=1 and SDN_TRUSTED_PROXY=='1'
        with mock.patch.dict(os.environ, {'TRUST_PROXY_HEADERS': '1'}):
            with srv.app.test_request_context(
                '/login',
                headers={'X-Forwarded-For': '203.0.113.50, 127.0.0.1'},
                environ_base={'REMOTE_ADDR': '127.0.0.1', 'SDN_TRUSTED_PROXY': '1'},
            ):
                self.assertEqual(srv._rate_ip(), '203.0.113.50')
            with srv.app.test_request_context(
                '/login',
                headers={'X-Forwarded-For': '1.2.3.4'},
                environ_base={'REMOTE_ADDR': '10.9.9.9', 'SDN_TRUSTED_PROXY': '0'},
            ):
                self.assertEqual(srv._rate_ip(), '10.9.9.9')

    def test_ssrf_validation_in_settings(self):
        csrf = self._login_tester()
        bad_urls = [
            'http://169.254.169.254',
            'http://evil.example.com:8080',
            'ftp://127.0.0.1:8080',
            'http://user:pass@127.0.0.1:8080',
            'http://127.0.0.1:8080/extra/path',
            'not-a-url',
        ]
        for bad in bad_urls:
            r = self.client.post(
                '/api/settings',
                json={'ryu_api_base': bad},
                headers={'X-CSRF-Token': csrf},
            )
            self.assertEqual(r.status_code, 400, f'Expected 400 for {bad}')
            self.assertEqual(r.get_json().get('error'), 'invalid_ryu_api_base')

        r_ok = self.client.post(
            '/api/settings',
            json={'ryu_api_base': 'http://127.0.0.1:8080/'},
            headers={'X-CSRF-Token': csrf},
        )
        self.assertEqual(r_ok.status_code, 200)

    def test_pcap_download_path_traversal_blocked(self):
        self._login_tester()
        bad_names = ['bad.txt', '.hidden..pcap', '..etc.pcap', 'dir_only']
        slash_traversal = ['..%2fetc%2fpasswd.pcap']
        with mock.patch.object(srv, '_runner_get') as m_get:
            for bad in bad_names:
                r = self.client.get(f'/api/lab/pcap/download/{bad}')
                self.assertEqual(r.status_code, 400, f'Expected 400 for {bad}')
                self.assertEqual(r.get_json().get('error'), 'invalid_pcap_name')
            for bad in slash_traversal:
                r = self.client.get(f'/api/lab/pcap/download/{bad}')
                self.assertIn(r.status_code, (400, 404), f'Expected 400/404 for {bad}')
            m_get.assert_not_called()

    def test_hybrid_events_rotation_retention_and_history_endpoints(self):
        csrf = self._login_tester()
        orig_log_dir = srv.LOG_DIR
        orig_events_file = srv.EVENTS_LOG_FILE
        orig_last_ts = srv._events_last_ts
        orig_init = srv._events_ts_initialized
        orig_cleanup_day = srv._events_last_cleanup_day

        try:
            srv.LOG_DIR = os.path.join(self.tmpdir.name, 'logs')
            srv.EVENTS_LOG_FILE = os.path.join(srv.LOG_DIR, 'events.csv')
            srv._events_last_ts = 0.0
            srv._events_ts_initialized = False
            srv._events_last_cleanup_day = ''
            os.makedirs(srv.LOG_DIR, exist_ok=True)

            # Seed an expired daily log and a part file from year 2000 -> retention should remove them
            stale_main = os.path.join(srv.LOG_DIR, 'events-2000-01-01.csv')
            stale_part = os.path.join(srv.LOG_DIR, 'events-2000-01-01.1.csv')
            with open(stale_main, 'w', encoding='utf-8') as f:
                f.write('ts,type,src,reason,extra_json\n946684800,old,10.0.0.1,stale,{}\n')
            with open(stale_part, 'w', encoding='utf-8') as f:
                f.write('ts,type,src,reason,extra_json\n946684801,old2,10.0.0.1,stale,{}\n')

            now_ts = float(time.time())
            yesterday_ts = now_ts - 86400.0
            today_str = srv._events_date_str(now_ts)
            yday_str = srv._events_date_str(yesterday_ts)

            with mock.patch.dict(
                os.environ,
                {
                    'EVENTS_RETENTION_DAYS': '14',
                    'EVENTS_MAX_BYTES': '256',
                    'EVENTS_MAX_PARTS_PER_DAY': '2',
                },
            ):
                srv._append_event('lab_build', src='lab', reason='yesterday', ts_val=yesterday_ts)
                # Force multiple intra-day size rotations for today
                for idx in range(8):
                    srv._append_event(
                        'block',
                        src=f'10.0.0.{(idx % 5) + 1}',
                        reason='flood_event_' + ('X' * 40),
                        extra={'seq': idx},
                        ts_val=now_ts + idx,
                    )

            self.assertFalse(os.path.exists(stale_main))
            self.assertFalse(os.path.exists(stale_part))

            today_files = [
                fname
                for fname in os.listdir(srv.LOG_DIR)
                if fname.startswith(f'events-{today_str}.')
            ]
            # At most 2 rotated .<N>.csv parts + 1 active events-YYYY-MM-DD.csv file
            rotated_parts = [f for f in today_files if re.match(rf'^events-{today_str}\.\d+\.csv$', f)]
            self.assertLessEqual(len(rotated_parts), 2)
            self.assertIn(f'events-{today_str}.csv', today_files)

            # /api/history merges chronologically across yesterday + today parts
            r_hist = self.client.get('/api/history')
            self.assertEqual(r_hist.status_code, 200)
            events = r_hist.get_json().get('events', [])
            self.assertGreaterEqual(len(events), 2)
            self.assertEqual(events[0]['type'], 'lab_build')
            self.assertEqual(events[-1]['type'], 'block')

            # /api/history.csv returns single CSV header and today's rows
            r_csv = self.client.get('/api/history.csv')
            self.assertEqual(r_csv.status_code, 200)
            csv_lines = [ln for ln in r_csv.get_data(as_text=True).splitlines() if ln.strip()]
            self.assertEqual(csv_lines[0], 'ts,type,src,reason,extra_json')
            header_count = sum(1 for ln in csv_lines if ln == 'ts,type,src,reason,extra_json')
            self.assertEqual(header_count, 1)

            # /api/history.csv?date=<yesterday> filters properly
            r_yday = self.client.get(f'/api/history.csv?date={yday_str}')
            self.assertEqual(r_yday.status_code, 200)
            parsed = list(csv.DictReader(r_yday.get_data(as_text=True).splitlines()))
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0]['reason'], 'yesterday')

            # Invalid date parameter rejected cleanly with 400
            r_bad_date = self.client.get('/api/history.csv?date=../../etc')
            self.assertEqual(r_bad_date.status_code, 400)
            self.assertEqual(r_bad_date.get_json().get('error'), 'invalid_date')

            # Keep csrf referenced cleanly
            self.assertTrue(len(csrf) > 10)
        finally:
            srv.LOG_DIR = orig_log_dir
            srv.EVENTS_LOG_FILE = orig_events_file
            srv._events_last_ts = orig_last_ts
            srv._events_ts_initialized = orig_init
            srv._events_last_cleanup_day = orig_cleanup_day

    def test_frontend_html_js_integrity(self):
        index_path = os.path.join(PROJECT_ROOT, 'webapp', 'templates', 'index.html')
        app_js_path = os.path.join(PROJECT_ROOT, 'webapp', 'static', 'js', 'app.js')

        with open(index_path, 'r', encoding='utf-8') as f:
            index_html = f.read()
        with open(app_js_path, 'r', encoding='utf-8') as f:
            app_js = f.read()

        # 1) Offline Chart.js loaded locally; no uncommented external CDN script/font links
        html_no_comments = re.sub(r'<!--.*?-->', '', index_html, flags=re.S)
        self.assertIn('js/vendor/chart.umd.min.js', html_no_comments)
        self.assertNotIn('cdn.jsdelivr.net', html_no_comments)
        self.assertNotIn('fonts.googleapis.com', html_no_comments)

        # 2) Every static getElementById in app.js exists in index.html
        html_ids = set(re.findall(r'\bid="([A-Za-z0-9_-]+)"', index_html))
        js_ids = set(re.findall(r"document\.getElementById\(\s*['\"]([A-Za-z0-9_-]+)['\"]\s*\)", app_js))
        missing = sorted(i for i in js_ids if i not in html_ids)
        self.assertEqual(missing, [], f'Missing DOM IDs referenced by app.js: {missing}')

        # 3) Zero non-empty innerHTML XSS sinks in app.js
        sinks = re.findall(r'\.innerHTML\s*=\s*([^;\n]+)', app_js)
        non_empty_sinks = [s.strip() for s in sinks if s.strip() not in ("''", '""')]
        self.assertEqual(non_empty_sinks, [], f'Unsafe non-empty innerHTML assignment(s): {non_empty_sinks}')

        # 4) Visibility pause/resume present and redundant /api/lab/status poller removed
        self.assertIn('visibilitychange', app_js)
        self.assertIn('document.hidden', app_js)
        self.assertIn('resumePollers', app_js)
        self.assertNotIn('refreshScenarioHosts', app_js)

        # 5) Auto-save topology, Reset Default, Apply Live Changes, role separation, and preflight checks exist
        self.assertIn('btn-lab-apply-live', html_ids)
        self.assertIn('btn-topo-reset', html_ids)
        self.assertIn('scenario-requirements', html_ids)
        self.assertIn('scenario-hosts-note', html_ids)
        self.assertIn('saveTopologyState', app_js)
        self.assertIn('ensureDefaultTopology(true)', app_js)
        self.assertIn('getScenarioHostInventory', app_js)
        self.assertIn('attacker_reserved_role', app_js)
        self.assertIn('session_invalidated', app_js)

    def test_session_invalidated_on_server_boot_change(self):
        self._login_tester()
        self.assertEqual(self.client.get('/api/history').status_code, 200)

        orig_boot_id = srv._SERVER_BOOT_ID
        try:
            srv._SERVER_BOOT_ID = 'restarted-boot-id-999'
            r_api = self.client.get('/api/history')
            self.assertEqual(r_api.status_code, 401)
            self.assertEqual(r_api.get_json().get('error'), 'session_invalidated')

            r_page = self.client.get('/', follow_redirects=False)
            self.assertEqual(r_page.status_code, 302)
            self.assertIn('/login', r_page.headers.get('Location', ''))
        finally:
            srv._SERVER_BOOT_ID = orig_boot_id

    def test_topology_apply_endpoint_auth_and_forwarding(self):
        csrf = self._login_tester()

        # CSRF required
        r_nocsrf = self.client.post('/api/lab/topology/apply', json={'nodes': ['s1', 'h1'], 'links': ['h1-s1']})
        self.assertEqual(r_nocsrf.status_code, 403)
        self.assertEqual(r_nocsrf.get_json().get('error'), 'csrf_invalid')

        # 409 network_not_running forwarded accurately
        resp_409 = mock.MagicMock()
        resp_409.ok = False
        resp_409.status_code = 409
        resp_409.json.return_value = {'ok': False, 'error': 'network_not_running'}
        with mock.patch.object(srv, '_runner_post', return_value=resp_409):
            r_stopped = self.client.post(
                '/api/lab/topology/apply',
                json={'nodes': ['s1', 'h1'], 'links': ['h1-s1']},
                headers={'X-CSRF-Token': csrf},
            )
            self.assertEqual(r_stopped.status_code, 409)
            self.assertEqual(r_stopped.get_json().get('error'), 'network_not_running')

        # 202 accepted forwarded cleanly
        resp_202 = mock.MagicMock()
        resp_202.ok = True
        resp_202.status_code = 202
        resp_202.json.return_value = {'ok': True, 'accepted': True, 'busy': True}
        with mock.patch.object(srv, '_runner_post', return_value=resp_202):
            with mock.patch.object(srv, '_append_event') as m_log:
                r_ok = self.client.post(
                    '/api/lab/topology/apply',
                    json={'nodes': ['s1', 'h1', 'h2'], 'links': ['h1-s1', 'h2-s1']},
                    headers={'X-CSRF-Token': csrf},
                )
                self.assertEqual(r_ok.status_code, 202)
                self.assertTrue(r_ok.get_json().get('accepted'))
                m_log.assert_called_once()

    def test_scenario_preflight_injection_and_error_forwarding(self):
        csrf = self._login_tester()

        ryu_resp = mock.MagicMock()
        ryu_resp.ok = True
        ryu_resp.json.return_value = {
            'blocked_ips': ['10.0.0.1'],
            'config': {'ddos_source_threshold': 4},
        }
        runner_400 = mock.MagicMock()
        runner_400.ok = False
        runner_400.status_code = 400
        runner_400.headers = {'content-type': 'application/json'}
        runner_400.json.return_value = {'ok': False, 'error': 'attacker_blocked', 'attacker': 'h1', 'ip': '10.0.0.1'}

        with mock.patch.object(srv, '_safe_request', return_value=ryu_resp):
            with mock.patch.object(srv, '_runner_post', return_value=runner_400) as m_post:
                r = self.client.post(
                    '/api/lab/scenario',
                    json={'name': 'syn_flood', 'attackers': ['h1'], 'victim': 'h2'},
                    headers={'X-CSRF-Token': csrf},
                )
                self.assertEqual(r.status_code, 400)
                self.assertEqual(r.get_json().get('error'), 'attacker_blocked')
                sent_payload = m_post.call_args[1]['json_data']
                self.assertEqual(sent_payload['_preflight']['blocked_ips'], ['10.0.0.1'])
                self.assertEqual(sent_payload['_preflight']['ddos_source_threshold'], 4)
                self.assertTrue(sent_payload['_preflight']['ryu_running'])

    def test_topic1_ui_semantics_accessibility_and_english_unification(self):
        from collections import Counter
        index_path = os.path.join(PROJECT_ROOT, 'webapp', 'templates', 'index.html')
        login_path = os.path.join(PROJECT_ROOT, 'webapp', 'templates', 'login.html')
        css_path = os.path.join(PROJECT_ROOT, 'webapp', 'static', 'css', 'style.css')
        app_js_path = os.path.join(PROJECT_ROOT, 'webapp', 'static', 'js', 'app.js')

        ar_rx = re.compile(r'[\u0600-\u06FF]')
        for p in (index_path, login_path, css_path, app_js_path):
            with open(p, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIsNone(ar_rx.search(content), f'Unexpected Arabic characters in {p}')

        with open(index_path, 'r', encoding='utf-8') as f:
            index_html = f.read()
        with open(login_path, 'r', encoding='utf-8') as f:
            login_html = f.read()
        with open(app_js_path, 'r', encoding='utf-8') as f:
            app_js = f.read()

        self.assertIn('<html lang="en" dir="ltr">', index_html)
        self.assertIn('<html lang="en" dir="ltr">', login_html)
        self.assertIn('<ul id="alerts" class="alerts-list"></ul>', index_html)

        # Duplicate IDs removed
        ids = re.findall(r'\bid="([^"]+)"', index_html)
        dups = {k: v for k, v in Counter(ids).items() if v > 1}
        self.assertEqual(dups, {}, f'Duplicate IDs found in index.html: {dups}')
        for expected_id in (
            'lab-status', 'lab-status-card',
            'mitigation-status', 'mitigation-status-settings',
            'auto-failover-status', 'auto-failover-status-settings',
            'btn-unblock-all', 'btn-unblock-all-settings',
        ):
            self.assertIn(expected_id, ids)

        # Every visible form control has id + matching label[for]
        fors = set(re.findall(r'\bfor="([^"]+)"', index_html))
        id_set = set(ids)
        self.assertEqual([x for x in fors if x not in id_set], [])
        for tag, attrs in re.findall(r'<(input|select|textarea)\b([^>]*)>', index_html):
            if 'type="hidden"' in attrs:
                continue
            m = re.search(r'\bid="([^"]+)"', attrs)
            self.assertIsNotNone(m, f'{tag} missing id: {attrs}')
            self.assertIn(m.group(1), fors, f'{tag}#{m.group(1)} missing label[for]')

        # Sidebar nav items carry aria-label and title
        nav_buttons = re.findall(r'<button class="nav-item[^"]*"([^>]*)>', index_html)
        self.assertEqual(len(nav_buttons), 4)
        for attrs in nav_buttons:
            self.assertIn('aria-label=', attrs)
            self.assertIn('title=', attrs)

        # Demo & Blocked IP UI safeguards present in app.js
        self.assertIn('demoRunning', app_js)
        self.assertIn('connection_lost', app_js)
        self.assertIn('r.clone().json()', app_js)
        self.assertIn('renderBlockedIpCards', app_js)
        self.assertIn('copyTextToClipboard', app_js)
        self.assertIn('window.confirm(', app_js)

    def test_login_page_english_and_csrf_render(self):
        r = self.client.get('/login')
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn('<html lang="en" dir="ltr">', body)
        self.assertIn('for="login-username"', body)
        self.assertIn('for="login-password"', body)
        self.assertIn('Sign In', body)
        self.assertIn('name="csrf_token"', body)

    def test_controller_start_passes_learning_enabled_and_requires_csrf(self):
        # Unauthenticated rejected
        r_unauth = self.client.post('/api/controller/start', json={'learning_enabled': False})
        self.assertEqual(r_unauth.status_code, 401)

        csrf = self._login_tester()
        # Missing CSRF rejected
        r_nocsrf = self.client.post('/api/controller/start', json={'learning_enabled': False})
        self.assertEqual(r_nocsrf.status_code, 403)

        fake_proc = mock.MagicMock()
        fake_proc.pid = 43210
        m_open = mock.mock_open()
        with mock.patch.object(srv.os, 'name', 'posix'):
            with mock.patch.object(srv, '_controller_status', side_effect=[
                {'running': False, 'pid': None, 'ryu_api_base': srv.RYU_API_BASE, 'log_tail': ''},
                {'running': True, 'pid': 43210, 'ryu_api_base': srv.RYU_API_BASE, 'log_tail': ''},
            ]):
                with mock.patch('builtins.open', m_open):
                    with mock.patch.object(srv.subprocess, 'Popen', return_value=fake_proc) as m_popen:
                        r = self.client.post(
                            '/api/controller/start',
                            json={'learning_enabled': False},
                            headers={'X-CSRF-Token': csrf},
                        )
                        self.assertEqual(r.status_code, 200)
                        env_passed = m_popen.call_args[1]['env']
                        self.assertEqual(env_passed.get('LEARNING_ENABLE'), '0')

    def test_unblock_endpoints_csrf_and_forwarding(self):
        self.assertEqual(self.client.post('/api/unblock/ip', json={'ip': '10.0.0.5'}).status_code, 401)
        csrf = self._login_tester()
        self.assertEqual(self.client.post('/api/unblock/ip', json={'ip': '10.0.0.5'}).status_code, 403)

        ok_resp = mock.MagicMock()
        ok_resp.ok = True
        ok_resp.json.return_value = {'ok': True, 'unblocked': '10.0.0.5'}
        with mock.patch.object(srv, '_ryu_post', return_value=ok_resp) as m_post:
            r = self.client.post(
                '/api/unblock/ip',
                json={'ip': '10.0.0.5'},
                headers={'X-CSRF-Token': csrf},
            )
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.get_json().get('ok'))
            self.assertIn('/dos/unblock/ip/10.0.0.5', m_post.call_args[0][0])

        with mock.patch.object(srv, '_ryu_post', side_effect=ConnectionError('ryu down')):
            r_err = self.client.post(
                '/api/unblock/ip',
                json={'ip': '10.0.0.5'},
                headers={'X-CSRF-Token': csrf},
            )
            self.assertEqual(r_err.status_code, 502)
            self.assertFalse(r_err.get_json().get('ok'))

    def test_glances_parallel_fetch_and_ttl_cache(self):
        csrf = self._login_tester()
        self.assertTrue(csrf)
        srv.GLANCES_CACHE_TTL_SEC = 2.0
        srv.GLANCES_TIMEOUT_SEC = 2.0

        def fake_get(url, timeout=2.0):
            time.sleep(0.15)
            resp = mock.MagicMock()
            resp.raise_for_status.return_value = None
            if url.endswith('/api/3/quicklook'):
                resp.json.return_value = {'cpu': 18.4, 'mem': 51.2}
            elif url.endswith('/api/3/load'):
                resp.json.return_value = {'min1': 0.42, 'min5': 0.35, 'min15': 0.28}
            elif url.endswith('/api/3/fs'):
                resp.json.return_value = [{'size': 1000, 'used': 400}]
            elif url.endswith('/api/3/network'):
                resp.json.return_value = [{'rx': 100, 'tx': 200, 'rx_rate': 12, 'tx_rate': 34}]
            elif url.endswith('/api/3/processlist'):
                resp.json.return_value = [
                    {'cmdline': ['ryu-manager'], 'name': 'ryu-manager', 'cpu_percent': 3.5, 'memory_info': {'rss': 50 * 1024 * 1024}, 'num_threads': 4},
                    {'cmdline': ['ovs-vswitchd'], 'name': 'ovs-vswitchd', 'cpu_percent': 1.2, 'memory_info': {'rss': 20 * 1024 * 1024}, 'num_threads': 2},
                ]
            return resp

        with mock.patch.object(srv.requests, 'get', side_effect=fake_get) as m_get:
            t0 = time.monotonic()
            r1 = self.client.get('/api/vm/metrics')
            dt1 = time.monotonic() - t0
            self.assertEqual(r1.status_code, 200)
            d1 = r1.get_json()
            self.assertTrue(d1['ok'])
            self.assertFalse(d1['cached'])
            self.assertEqual(d1['service_state'], 'closed')
            self.assertAlmostEqual(d1['cpu_percent'], 18.4)
            self.assertLess(dt1, 0.45, f'Expected parallel 4-endpoint fetch <0.45s, got {dt1:.3f}s')
            self.assertEqual(m_get.call_count, 4)

            # Second call within TTL hits memory cache with zero upstream calls
            r2 = self.client.get('/api/vm/metrics')
            self.assertEqual(r2.status_code, 200)
            d2 = r2.get_json()
            self.assertTrue(d2['ok'])
            self.assertTrue(d2['cached'])
            self.assertEqual(m_get.call_count, 4)

            # Process list also cached within TTL
            p1 = self.client.get('/api/vm/proc')
            self.assertEqual(p1.status_code, 200)
            self.assertFalse(p1.get_json()['cached'])
            self.assertEqual(m_get.call_count, 5)

            p2 = self.client.get('/api/vm/proc')
            self.assertEqual(p2.status_code, 200)
            self.assertTrue(p2.get_json()['cached'])
            self.assertEqual(m_get.call_count, 5)

            # Expiring TTL triggers a fresh upstream fetch
            srv.GLANCES_CACHE_TTL_SEC = 0.02
            time.sleep(0.03)
            r3 = self.client.get('/api/vm/metrics')
            self.assertEqual(r3.status_code, 200)
            self.assertFalse(r3.get_json()['cached'])
            self.assertEqual(m_get.call_count, 9)

    def test_glances_cache_stampede_singleflight(self):
        srv.GLANCES_CACHE_TTL_SEC = 2.0
        srv.GLANCES_TIMEOUT_SEC = 2.0
        calls_lock = threading.Lock()
        quicklook_hits = {'n': 0}

        def fake_get(url, timeout=2.0):
            if url.endswith('/api/3/quicklook'):
                with calls_lock:
                    quicklook_hits['n'] += 1
                time.sleep(0.15)
            resp = mock.MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = (
                {'cpu': 22.0, 'mem': 44.0} if url.endswith('/quicklook')
                else ({'min1': 0.5} if url.endswith('/load') else [])
            )
            return resp

        base = srv.GLANCES_API_BASE.rstrip('/')
        barrier = threading.Barrier(10)
        results = []
        res_lock = threading.Lock()

        def worker():
            barrier.wait()
            st, body = srv._fetch_glances_cached(
                'vm_metrics',
                base,
                lambda t: srv._fetch_vm_metrics_live(base, t),
            )
            with res_lock:
                results.append((st, body))

        with mock.patch.object(srv.requests, 'get', side_effect=fake_get):
            threads = [threading.Thread(target=worker) for _ in range(10)]
            for th in threads:
                th.start()
            for th in threads:
                th.join(timeout=5.0)

        self.assertEqual(len(results), 10)
        self.assertTrue(all(st == 200 and body.get('ok') for st, body in results))
        self.assertEqual(quicklook_hits['n'], 1, f'Expected singleflight 1 upstream fetch, got {quicklook_hits["n"]}')
        cached_flags = [body.get('cached') for _, body in results]
        self.assertEqual(cached_flags.count(False), 1)
        self.assertEqual(cached_flags.count(True), 9)

    def test_glances_circuit_breaker_stale_preservation_and_half_open(self):
        self._login_tester()
        srv.GLANCES_CACHE_TTL_SEC = 0.02
        srv.GLANCES_TIMEOUT_SEC = 0.5
        srv.GLANCES_CB_FAIL_THRESHOLD = 2
        srv.GLANCES_CB_COOLDOWN_SEC = 10.0

        def healthy_get(url, timeout=2.0):
            resp = mock.MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = (
                {'cpu': 42.5, 'mem': 60.0} if url.endswith('/quicklook')
                else ({'min1': 1.1} if url.endswith('/load') else [])
            )
            return resp

        with mock.patch.object(srv.requests, 'get', side_effect=healthy_get):
            r_ok = self.client.get('/api/vm/metrics')
            self.assertEqual(r_ok.status_code, 200)
            self.assertAlmostEqual(r_ok.get_json()['cpu_percent'], 42.5)

        time.sleep(0.03)  # Expire TTL

        # Failure #1: still closed, preserves last_good
        with mock.patch.object(srv.requests, 'get', side_effect=requests.exceptions.ConnectionError('refused')):
            r_f1 = self.client.get('/api/vm/metrics')
            self.assertEqual(r_f1.status_code, 502)
            d_f1 = r_f1.get_json()
            self.assertTrue(d_f1['service_unhealthy'])
            self.assertEqual(d_f1['service_state'], 'closed')
            self.assertFalse(d_f1['circuit_open'])
            self.assertTrue(d_f1['stale_available'])
            self.assertAlmostEqual(d_f1['last_good']['cpu_percent'], 42.5)

            # Failure #2: trips circuit breaker OPEN
            r_f2 = self.client.get('/api/vm/metrics')
            self.assertEqual(r_f2.status_code, 502)
            d_f2 = r_f2.get_json()
            self.assertEqual(d_f2['service_state'], 'open')
            self.assertTrue(d_f2['circuit_open'])
            self.assertTrue(d_f2['stale_available'])
            self.assertAlmostEqual(d_f2['last_good']['cpu_percent'], 42.5)

        # /api/health/services reflects circuit open state
        h1 = self.client.get('/api/health/services')
        self.assertEqual(h1.status_code, 200)
        gl1 = h1.get_json()['services']['glances']
        self.assertFalse(gl1['healthy'])
        self.assertEqual(gl1['state'], 'open')
        self.assertTrue(gl1['circuit_open'])

        # While OPEN: fast-fails with ZERO upstream requests and preserves last_good
        with mock.patch.object(srv.requests, 'get', side_effect=AssertionError('must not hit Glances while open')) as m_open:
            r_fast = self.client.get('/api/vm/metrics')
            self.assertEqual(r_fast.status_code, 502)
            d_fast = r_fast.get_json()
            self.assertEqual(d_fast['error'], 'circuit_open')
            self.assertTrue(d_fast['circuit_open'])
            self.assertTrue(d_fast['stale_available'])
            self.assertAlmostEqual(d_fast['last_good']['cpu_percent'], 42.5)
            self.assertEqual(m_open.call_count, 0)

        # Expire cooldown -> Half-Open allows ONLY ONE concurrent test probe
        with srv._glances_cb_lock:
            srv._glances_cb_open_until = time.time() - 0.05

        probe_started = threading.Event()
        release_probe = threading.Event()
        base = srv.GLANCES_API_BASE.rstrip('/')

        def slow_failing_probe(url, timeout=2.0):
            if url.endswith('/quicklook'):
                probe_started.set()
                release_probe.wait(timeout=3.0)
            raise requests.exceptions.ConnectionError('still down')

        probe_results = {}

        def run_probe_req():
            probe_results['first'] = srv._fetch_glances_cached(
                'vm_metrics', base, lambda t: srv._fetch_vm_metrics_live(base, t)
            )

        with mock.patch.object(srv.requests, 'get', side_effect=slow_failing_probe):
            th = threading.Thread(target=run_probe_req)
            th.start()
            self.assertTrue(probe_started.wait(timeout=2.0))
            # Different endpoint (vm_proc) concurrent probe must be rejected by half-open single-probe guard
            st2, b2 = srv._fetch_glances_cached(
                'vm_proc', base, lambda t: srv._fetch_vm_proc_live(base, t)
            )
            self.assertEqual(st2, 502)
            self.assertEqual(b2['error'], 'half_open_probe_busy')
            release_probe.set()
            th.join(timeout=3.0)

        st1, b1 = probe_results['first']
        self.assertEqual(st1, 502)
        self.assertEqual(b1['service_state'], 'open')

        # Expire cooldown again -> probe succeeds -> circuit closes and /api/health/services recovers
        with srv._glances_cb_lock:
            srv._glances_cb_open_until = time.time() - 0.05

        def recovered_get(url, timeout=2.0):
            resp = mock.MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = (
                {'cpu': 19.0, 'mem': 35.0} if url.endswith('/quicklook')
                else ({'min1': 0.25} if url.endswith('/load') else [])
            )
            return resp

        with mock.patch.object(srv.requests, 'get', side_effect=recovered_get):
            r_rec = self.client.get('/api/vm/metrics')
            self.assertEqual(r_rec.status_code, 200)
            d_rec = r_rec.get_json()
            self.assertTrue(d_rec['ok'])
            self.assertEqual(d_rec['service_state'], 'closed')
            self.assertAlmostEqual(d_rec['cpu_percent'], 19.0)

        h2 = self.client.get('/api/health/services')
        gl2 = h2.get_json()['services']['glances']
        self.assertTrue(gl2['healthy'])
        self.assertEqual(gl2['state'], 'closed')
        self.assertFalse(gl2['circuit_open'])

    def test_topic2_frontend_unified_tab_aware_scheduler(self):
        app_js_path = os.path.join(PROJECT_ROOT, 'webapp', 'static', 'js', 'app.js')
        with open(app_js_path, 'r', encoding='utf-8') as f:
            app_js = f.read()

        # Exactly one unified scheduler setInterval loop
        self.assertEqual(len(re.findall(r'\bsetInterval\s*\(', app_js)), 1)
        self.assertNotIn('refreshInFlight', app_js)

        for sym in (
            'pollTasks',
            'registerPollTask',
            'runPollScheduler',
            'onTabActivated',
            'appliedSeq',
            'inFlight',
            'stale_available',
            'last_good',
            'formatGlancesFailureReason',
            '_demoWaitLabRunning',
            '_demoWaitAttackStopped',
        ):
            self.assertIn(sym, app_js)

        # Verify expected tab routing declarations exist
        self.assertRegex(app_js, r"registerPollTask\('vmMetrics',\s*\{[^}]*tabs:\s*\['settings'\]")
        self.assertRegex(app_js, r"registerPollTask\('vmProc',\s*\{[^}]*tabs:\s*\['settings'\]")
        self.assertRegex(app_js, r"registerPollTask\('history',\s*\{[^}]*tabs:\s*\['forensics'\]")
        self.assertRegex(app_js, r"registerPollTask\('flows',\s*\{[^}]*tabs:\s*\['dashboard',\s*'forensics'\]")
        self.assertRegex(app_js, r"registerPollTask\('controller',\s*\{[^}]*tabs:\s*\['lab'\],\s*bootstrapOnce:\s*true")
        self.assertRegex(app_js, r"registerPollTask\('attack',\s*\{[^}]*tabs:\s*\['lab'\],\s*bootstrapOnce:\s*true")
        self.assertRegex(app_js, r"registerPollTask\('ha',\s*\{[^}]*tabs:\s*\['lab'\],\s*bootstrapOnce:\s*true")
        self.assertRegex(app_js, r"registerPollTask\('alerts',\s*\{[^}]*tabs:\s*null")

    def test_topic4_settings_controller_status_and_metrics_no_internal_url_or_str_leak(self):
        csrf = self._login_tester()

        # 1. /api/settings preserves ryu_api_base for Settings UI, without leaking other internal config
        st_res = self.client.get('/api/settings')
        self.assertEqual(st_res.status_code, 200)
        st_json = st_res.get_json()
        self.assertEqual(set(st_json.keys()), {'ryu_api_base'})

        # 2. /api/controller/status preserves running, pid, log_tail and omits ryu_api_base
        cs_res = self.client.get('/api/controller/status')
        self.assertEqual(cs_res.status_code, 200)
        cs_json = cs_res.get_json()
        self.assertIn('running', cs_json)
        self.assertIn('pid', cs_json)
        self.assertIn('log_tail', cs_json)
        self.assertNotIn('ryu_api_base', cs_json)

        # 3. _safe_request secret-laden exceptions must not leak via _service_health, /api/health/services,
        #    /api/metrics, /api/alerts, /api/flows, or /api/lab/status
        secret_exc = requests.exceptions.ConnectionError(
            'http://127.0.0.1:8080/dos/metrics token=TopSecret999 /home/ubuntu/sdn-ddos-mitigation-ha/secret.key'
        )
        with srv._health_lock:
            srv._service_health['ryu'] = {'healthy': True, 'last_check': 0.0, 'error': None}
            srv._service_health['runner'] = {'healthy': True, 'last_check': 0.0, 'error': None}
            srv._service_health['glances'] = {'healthy': True, 'last_check': 0.0, 'error': None}

        with mock.patch.object(srv.requests, 'get', side_effect=secret_exc):
            for ep in ('/api/metrics', '/api/alerts', '/api/flows', '/api/lab/status'):
                res = self.client.get(ep)
                self.assertEqual(res.status_code, 502, ep)
                raw = res.get_data(as_text=True)
                data = res.get_json()
                self.assertFalse(data.get('ok', True))
                self.assertTrue(data.get('request_id'))
                self.assertTrue(res.headers.get('X-Request-ID'))
                for forbidden in (
                    'ryu_api_base',
                    'glances_api_base',
                    '127.0.0.1:8080',
                    '127.0.0.1:9090',
                    '127.0.0.1:61208',
                    'TopSecret999',
                    '/home/ubuntu',
                    'traceback',
                ):
                    self.assertNotIn(forbidden.lower(), raw.lower(), f'{ep} leaked {forbidden}: {raw}')
                self.assertNotIn('runner', data)
                self.assertNotIn('body', data)

        hs = self.client.get('/api/health/services')
        self.assertEqual(hs.status_code, 200)
        hs_raw = hs.get_data(as_text=True)
        for forbidden in ('TopSecret999', '/home/ubuntu', '127.0.0.1:8080', 'ConnectionError'):
            self.assertNotIn(forbidden, hs_raw)
        self.assertEqual(hs.get_json()['services']['ryu']['error'], 'connection_refused')
        self.assertEqual(hs.get_json()['services']['runner']['error'], 'connection_refused')

        # 4. Defense-in-depth: even if _service_health held an unexpected unsafe string, api_lab_status/api_flows reject it
        with srv._health_lock:
            srv._service_health['runner']['error'] = 'Traceback http://127.0.0.1:9090 secret=1'
            srv._service_health['ryu']['error'] = 'Exception /home/ubuntu/bad'
        with mock.patch.object(srv, '_safe_request', return_value=None):
            r_lab = self.client.get('/api/lab/status')
            self.assertEqual(r_lab.status_code, 502)
            self.assertEqual(r_lab.get_json()['error'], 'service_unavailable')
            r_fl = self.client.get('/api/flows')
            self.assertEqual(r_fl.status_code, 502)
            self.assertEqual(r_fl.get_json()['error'], 'service_unavailable')

        # 5. Glances error responses omit glances_api_base and raw exception strings
        with mock.patch.object(
            srv.requests,
            'get',
            side_effect=requests.exceptions.Timeout('http://127.0.0.1:61208/api/3/quicklook token=GSec1'),
        ):
            for gep in ('/api/vm/metrics', '/api/vm/proc'):
                gres = self.client.get(gep)
                self.assertEqual(gres.status_code, 502)
                gdata = gres.get_json()
                graw = gres.get_data(as_text=True)
                self.assertNotIn('glances_api_base', gdata)
                self.assertEqual(gdata.get('error'), 'timeout')
                self.assertTrue(gdata.get('request_id'))
                self.assertNotIn('GSec1', graw)
                self.assertNotIn('61208', graw)

        # 6. Controller start/stop errors return 500 internal_error with request_id and no str(e)/OS paths
        headers = {'X-CSRF-Token': csrf}
        tmp_ryu_log = os.path.join(self.tmpdir.name, 'ctrl_err.log')
        with mock.patch.object(srv.os, 'name', 'posix'), \
             mock.patch.object(srv, 'RYU_LOG_FILE', tmp_ryu_log), \
             mock.patch.object(srv, '_controller_status', return_value={'running': False, 'pid': None, 'log_tail': ''}), \
             mock.patch.object(srv.subprocess, 'Popen', side_effect=OSError('/home/ubuntu/secret/ryu-manager failed secret=abc')):
            r_st = self.client.post('/api/controller/start', headers=headers)
            self.assertEqual(r_st.status_code, 500)
            self.assertEqual(r_st.get_json()['error'], 'internal_error')
            self.assertTrue(r_st.get_json().get('request_id'))
            self.assertNotIn('/home/ubuntu', r_st.get_data(as_text=True))
            self.assertNotIn('secret=abc', r_st.get_data(as_text=True))

        with mock.patch.object(srv, '_read_pid', return_value=999999), \
             mock.patch.object(srv.os, 'killpg', side_effect=PermissionError('/proc/999999 denied'), create=True), \
             mock.patch.object(srv.os, 'kill', side_effect=PermissionError('/proc/999999 denied secret=stop')):
            r_sp = self.client.post('/api/controller/stop', headers=headers)
            self.assertEqual(r_sp.status_code, 500)
            self.assertEqual(r_sp.get_json()['error'], 'internal_error')
            self.assertNotIn('secret=stop', r_sp.get_data(as_text=True))

    def test_topic4_ryu_and_runner_proxy_error_sanitization_and_4xx_allowlist(self):
        csrf = self._login_tester()
        headers = {'X-CSRF-Token': csrf}

        # 1. Ryu proxy endpoints suppress str(e) and sanitize corrupted 400 JSON
        with mock.patch.object(
            srv,
            '_ryu_post',
            side_effect=requests.exceptions.Timeout('http://127.0.0.1:8080/dos/block token=RyuTok'),
        ):
            for ep, body in (
                ('/api/block/ip', {'ip': '10.0.0.10'}),
                ('/api/unblock/ip', {'ip': '10.0.0.10'}),
                ('/api/config', {'ewma_alpha': 0.3}),
                ('/api/whitelist/clear', {}),
                ('/api/flows/clear', {}),
            ):
                res = self.client.post(ep, json=body, headers=headers)
                self.assertEqual(res.status_code, 502, ep)
                data = res.get_json()
                self.assertEqual(data['error'], 'timeout')
                self.assertTrue(data.get('request_id'))
                self.assertNotIn('RyuTok', res.get_data(as_text=True))
                self.assertNotIn('8080', res.get_data(as_text=True))

        bad_ryu_400 = mock.MagicMock()
        bad_ryu_400.status_code = 400
        bad_ryu_400.json.return_value = {
            'ok': False,
            'error': 'Traceback /home/ubuntu/dos_guard.py secret=LeakMe',
            'errors': ['Authorization: Bearer VerySecretJWT at http://127.0.0.1:8080/x'],
        }
        with mock.patch.object(srv, '_ryu_post', return_value=bad_ryu_400):
            r_cfg = self.client.post('/api/config', json={'bad': 1}, headers=headers)
            self.assertEqual(r_cfg.status_code, 400)
            cfg_data = r_cfg.get_json()
            cfg_raw = r_cfg.get_data(as_text=True)
            self.assertEqual(cfg_data['error'], 'invalid_request')
            self.assertNotIn('LeakMe', cfg_raw)
            self.assertNotIn('VerySecretJWT', cfg_raw)
            self.assertNotIn('127.0.0.1:8080', cfg_raw)

        dict_ryu_400 = mock.MagicMock()
        dict_ryu_400.status_code = 400
        dict_ryu_400.json.return_value = {
            'ok': False,
            'error': 'invalid_config',
            'errors': {'alpha': 'must be between 0.01 and 1.0 (token=CfgTok)'},
            'changed': {},
        }
        with mock.patch.object(srv, '_ryu_post', return_value=dict_ryu_400):
            r_cfg2 = self.client.post('/api/config', json={'alpha': 999}, headers=headers)
            self.assertEqual(r_cfg2.status_code, 400)
            cfg2 = r_cfg2.get_json()
            self.assertEqual(cfg2['error'], 'invalid_config')
            self.assertIn('alpha', cfg2.get('errors', {}))
            self.assertNotIn('CfgTok', r_cfg2.get_data(as_text=True))

        # 2. Allowlisted runner 4xx codes and safe fields MUST still pass through for UI compatibility
        allowed_cases = [
            (
                '/api/lab/scenario',
                {'name': 'syn_flood'},
                400,
                {'ok': False, 'error': 'attacker_blocked', 'attacker': 'h1', 'ip': '10.0.0.1'},
                {'attacker': 'h1', 'ip': '10.0.0.1'},
            ),
            (
                '/api/lab/topology/apply',
                {'nodes': [], 'links': []},
                409,
                {'ok': False, 'error': 'network_not_running'},
                {},
            ),
            (
                '/api/lab/cmd/run',
                {'type': 'ping', 'src': 'h1', 'dst': 'h2'},
                400,
                {'ok': False, 'error': 'ping_failed'},
                {},
            ),
            (
                '/api/lab/build',
                {'nodes': [], 'links': []},
                400,
                {'ok': False, 'error': 'too_many_nodes_max_100'},
                {},
            ),
            (
                '/api/lab/link/update',
                {},
                400,
                {'ok': False, 'error': 'missing_endpoints'},
                {},
            ),
            (
                '/api/lab/attack/run',
                {'kind': 'ddos'},
                400,
                {
                    'ok': False,
                    'error': 'insufficient_attackers',
                    'required': 4,
                    'available': 2,
                    'available_hosts': ['h1', 'h3'],
                },
                {'required': 4, 'available': 2, 'available_hosts': ['h1', 'h3']},
            ),
        ]
        for ep, req_json, sc, upstream_json, expected_extra in allowed_cases:
            m_resp = mock.MagicMock()
            m_resp.ok = False
            m_resp.status_code = sc
            m_resp.json.return_value = upstream_json
            with mock.patch.object(srv, '_runner_post', return_value=m_resp), \
                 mock.patch.object(srv, '_safe_request', return_value=None):
                res = self.client.post(ep, json=req_json, headers=headers)
                self.assertEqual(res.status_code, sc, ep)
                data = res.get_json()
                self.assertEqual(data['error'], upstream_json['error'])
                self.assertTrue(data.get('request_id'))
                for k, v in expected_extra.items():
                    self.assertEqual(data.get(k), v)

        # 3. Unallowlisted raw runner 4xx errors/tracebacks/paths MUST be suppressed
        unsafe_400 = mock.MagicMock()
        unsafe_400.ok = False
        unsafe_400.status_code = 422
        unsafe_400.json.return_value = {
            'ok': False,
            'error': 'Traceback (most recent call last): token=RunnerSecret77',
            'victim': '/home/ubuntu/secret\nTraceback',
            'secret_leak': 'http://127.0.0.1:9090/internal',
        }
        with mock.patch.object(srv, '_runner_post', return_value=unsafe_400), \
             mock.patch.object(srv, '_safe_request', return_value=None):
            res_u = self.client.post('/api/lab/scenario', json={'name': 'syn_flood'}, headers=headers)
            self.assertEqual(res_u.status_code, 422)
            udata = res_u.get_json()
            uraw = res_u.get_data(as_text=True)
            self.assertEqual(udata['error'], 'invalid_request')
            self.assertNotIn('victim', udata)
            self.assertNotIn('secret_leak', udata)
            for bad in ('RunnerSecret77', 'Traceback', '/home/ubuntu', '127.0.0.1:9090'):
                self.assertNotIn(bad, uraw)

        # 4. Upstream HTTP 500 HTML/traceback -> safe 502 JSON with no HTML, body, or runner URL
        html_500 = mock.MagicMock()
        html_500.ok = False
        html_500.status_code = 500
        html_500.json.side_effect = ValueError('not json')
        html_500.text = '<html><body><h1>500</h1><pre>Traceback (most recent call last): password=pw1</pre></body></html>'
        for ep in ('/api/lab/topology/apply', '/api/lab/attack/stop', '/api/lab/scenario'):
            with mock.patch.object(srv, '_runner_post', return_value=html_500), \
                 mock.patch.object(srv, '_safe_request', return_value=None):
                r_h = self.client.post(ep, json={}, headers=headers)
                self.assertEqual(r_h.status_code, 502, ep)
                hdata = r_h.get_json()
                hraw = r_h.get_data(as_text=True)
                self.assertEqual(hdata['error'], 'runner_http_error')
                self.assertTrue(hdata.get('request_id'))
                self.assertNotIn('runner', hdata)
                self.assertNotIn('body', hdata)
                self.assertNotIn('<html>', hraw)
                self.assertNotIn('Traceback', hraw)
                self.assertNotIn('pw1', hraw)

        # 5. Runner connection error across remaining GET/POST routes -> 502 service_unavailable without runner URL/str(e)
        with mock.patch.object(srv, '_runner_get', side_effect=ConnectionError('http://127.0.0.1:9090 down token=R9090')), \
             mock.patch.object(srv, '_runner_post', side_effect=ConnectionError('http://127.0.0.1:9090 down token=R9090')):
            for m, ep in (
                ('GET', '/api/lab/ovs/flows'),
                ('GET', '/api/lab/attack/status'),
                ('GET', '/api/lab/pcap/list'),
                ('GET', '/api/lab/pcap/download/cap1.pcap'),
                ('GET', '/api/lab/ha/status'),
                ('GET', '/api/lab/ha/test'),
                ('POST', '/api/lab/stop'),
                ('POST', '/api/lab/ha/config'),
                ('POST', '/api/lab/cmd/run'),
            ):
                r_c = self.client.get(ep) if m == 'GET' else self.client.post(ep, json={}, headers=headers)
                self.assertEqual(r_c.status_code, 502, ep)
                cdata = r_c.get_json()
                craw = r_c.get_data(as_text=True)
                self.assertEqual(cdata['error'], 'service_unavailable')
                self.assertTrue(cdata.get('request_id'))
                self.assertNotIn('runner', cdata)
                self.assertNotIn('R9090', craw)
                self.assertNotIn('127.0.0.1:9090', craw)

    def test_topic4_global_error_handlers_http_vs_unhandled_and_runner_helper(self):
        csrf = self._login_tester()
        headers = {'X-CSRF-Token': csrf}

        # 1. HTTPException 404 & 405 return clean JSON for /api/* and never leak internals
        r_404 = self.client.get('/api/does_not_exist_topic4')
        self.assertEqual(r_404.status_code, 404)
        d_404 = r_404.get_json()
        self.assertEqual(d_404['error'], 'not_found')
        self.assertTrue(d_404.get('request_id'))

        r_405 = self.client.delete('/api/metrics', headers=headers)
        self.assertEqual(r_405.status_code, 405)
        d_405 = r_405.get_json()
        self.assertEqual(d_405['error'], 'method_not_allowed')
        self.assertTrue(d_405.get('request_id'))

        # 2. Unhandled Exception inside a route returns JSON 500 with request_id (not HTML traceback)
        orig_prop = srv.app.config.get('PROPAGATE_EXCEPTIONS')
        srv.app.config['PROPAGATE_EXCEPTIONS'] = False
        try:
            with mock.patch.object(
                srv,
                '_read_events',
                side_effect=RuntimeError('boom token=UnhandledSecret /home/ubuntu/secret.py'),
            ):
                r_500 = self.client.get('/api/history')
        finally:
            srv.app.config['PROPAGATE_EXCEPTIONS'] = orig_prop

        self.assertEqual(r_500.status_code, 500)
        d_500 = r_500.get_json()
        raw_500 = r_500.get_data(as_text=True)
        self.assertEqual(d_500['error'], 'internal_error')
        self.assertTrue(d_500.get('request_id'))
        self.assertNotIn('UnhandledSecret', raw_500)
        self.assertNotIn('/home/ubuntu', raw_500)
        self.assertNotIn('<!doctype', raw_500.lower())
        self.assertNotIn('traceback', raw_500.lower())

        # 3. Direct tests on labs.mininet_runner error sanitization & global handlers (stubbing mininet if absent)
        import importlib
        import types

        mn_stubs = {}
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
            mn_stubs = {
                'mininet': mn_mod,
                'mininet.net': mn_net,
                'mininet.node': mn_node,
                'mininet.link': mn_link,
                'mininet.log': mn_log,
            }

        with mock.patch.dict(sys.modules, mn_stubs):
            runner_mod = importlib.import_module('labs.mininet_runner')
            self.assertEqual(runner_mod._sanitize_runner_error_code('attacker_blocked'), 'attacker_blocked')
            self.assertEqual(
                runner_mod._sanitize_runner_error_code('Traceback secret=123', default_code='runner_internal_error'),
                'runner_internal_error',
            )

            rc = runner_mod.app.test_client()
            with mock.patch.object(runner_mod, '_load_internal_token', return_value='test-token-sec'):
                headers = {'X-Internal-Token': 'test-token-sec'}
                r_link = rc.post('/link/update', json={}, headers=headers)
                self.assertEqual(r_link.status_code, 400)
                self.assertEqual(r_link.get_json()['error'], 'missing_endpoints')
                self.assertTrue(r_link.get_json().get('request_id'))

                r_nf = rc.get('/no_such_runner_route', headers=headers)
                self.assertEqual(r_nf.status_code, 404)
                self.assertEqual(r_nf.get_json()['error'], 'not_found')

                orig_rp = runner_mod.app.config.get('PROPAGATE_EXCEPTIONS')
                runner_mod.app.config['PROPAGATE_EXCEPTIONS'] = False
                try:
                    with mock.patch.object(
                        runner_mod,
                        '_ha_status',
                        side_effect=RuntimeError('ha crash password=RunnerPw /home/ubuntu/ha.json'),
                    ):
                        r_r500 = rc.get('/ha/status', headers=headers)
                finally:
                    runner_mod.app.config['PROPAGATE_EXCEPTIONS'] = orig_rp

                self.assertEqual(r_r500.status_code, 500)
                rd = r_r500.get_json()
                rraw = r_r500.get_data(as_text=True)
                self.assertEqual(rd['error'], 'runner_internal_error')
                self.assertTrue(rd.get('request_id'))
                self.assertNotIn('RunnerPw', rraw)
                self.assertNotIn('/home/ubuntu', rraw)
                self.assertNotIn('Traceback', rraw)

    def test_topic4_log_tail_redaction_caps_auth_and_appjs_compat(self):
        # 1. Unauthenticated /api/controller/status must remain auth-gated (401)
        unauth = self.client.get('/api/controller/status')
        self.assertEqual(unauth.status_code, 401)

        csrf = self._login_tester()
        self.assertTrue(csrf)

        # 2. Realistic log containing secrets, Bearer JWTs, internal URLs, OS paths, multi-line traceback, & excess size
        log_path = os.path.join(self.tmpdir.name, 'ryu_test.log')
        lines = [f'2026-11-11 INFO steady line {i:03d} ' + ('x' * 300) for i in range(60)]
        lines.extend([
            'INFO connecting to http://127.0.0.1:9090/ha/active?secret=abc and https://10.0.0.5:8080/dos/metrics',
            'ERROR auth failed password=MySuperSecret999 token=tok_abc_777 SDN_INTERNAL_TOKEN=InternalTok888',
            'WARN header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature',
            r'WARN failed script /home/ubuntu/sdn-ddos-mitigation-ha/ryu_app/dos_guard.py and C:\Users\testuser\secret.py',
            'Traceback (most recent call last):',
            '  File "/home/ubuntu/sdn-ddos-mitigation-ha/webapp/server.py", line 123, in api_foo',
            '    raise ValueError("secret=TraceLeak123")',
            'ValueError: bad stuff password=TraceLeakPw',
            'INFO controller recovered cleanly',
        ])
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')

        orig_log_file = srv.RYU_LOG_FILE
        srv.RYU_LOG_FILE = log_path
        try:
            res = self.client.get('/api/controller/status')
        finally:
            srv.RYU_LOG_FILE = orig_log_file

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertNotIn('ryu_api_base', data)
        self.assertIn('running', data)
        self.assertIn('pid', data)
        tail = data.get('log_tail', '')
        self.assertLessEqual(len(tail.splitlines()), 40)
        self.assertLessEqual(len(tail), 4096)

        for leaked in (
            'MySuperSecret999',
            'tok_abc_777',
            'InternalTok888',
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
            '127.0.0.1:9090',
            '10.0.0.5:8080',
            '/home/ubuntu',
            'C:\\Users\\testuser',
            'TraceLeak123',
            'TraceLeakPw',
            'File "',
        ):
            self.assertNotIn(leaked, tail)

        self.assertIn('[redacted]', tail)
        self.assertIn('[internal-url]', tail)
        self.assertIn('[path]', tail)
        self.assertIn('[traceback redacted]', tail)
        self.assertIn('INFO controller recovered cleanly', tail)

        # 3. Frontend app.js retains expected UI field consumption without deleted error keys
        app_js_path = os.path.join(PROJECT_ROOT, 'webapp', 'static', 'js', 'app.js')
        with open(app_js_path, 'r', encoding='utf-8') as f:
            app_js = f.read()
        for sym in ('s.pid', 's.log_tail', 'ryu_api_base', 'formatScenarioError', 'errToShortText'):
            self.assertIn(sym, app_js)
        self.assertNotIn('glances_api_base', app_js)


if __name__ == '__main__':
    unittest.main()
