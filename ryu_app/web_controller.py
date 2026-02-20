"""
ryu_app/web_controller.py
========================
WSGI REST Presentation Controller for Ryu DoS Guard.
Encapsulates all 20 REST API endpoints registered with Ryu WSGI.
"""

import csv
import hmac
import io
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from ryu.app.wsgi import ControllerBase, route
    from webob import Response
except ImportError:
    try:
        from webob import Response
    except ImportError:
        class Response:
            def __init__(self, body=b"", status=200, content_type="text/plain", headers=None):
                self.body = body
                self.status = status
                self.status_code = int(status)
                self.content_type = content_type
                self.headers = headers or {}

    class ControllerBase:
        def __init__(self, req, link, data, **config):
            self.req = req
            self.link = link
            self.data = data
            self.config = config

        def __call__(self, req):
            return None

    def route(name, path, methods=None):
        def dec(fn):
            return fn
        return dec

from core.common_utils import (
    load_internal_token,
    parse_bool,
    validate_ipv4,
    validate_mac,
)

DOS_GUARD_INSTANCE_NAME = 'dos_guard_app'

_load_internal_token = load_internal_token
_parse_bool = parse_bool
_validate_ipv4 = validate_ipv4
_validate_mac = validate_mac

class DoSGuardWebController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(DoSGuardWebController, self).__init__(req, link, data, **config)
        d = data or {}
        self.app = d.get(DOS_GUARD_INSTANCE_NAME) or d.get('dos_guard_api_app') or d.get('app')

    def __call__(self, req):
        expected = _load_internal_token()
        if not expected:
            return Response(
                status=401,
                content_type='application/json; charset=utf-8',
                body=json.dumps({'ok': False, 'error': 'unauthorized', 'message': 'Internal token not configured'}).encode('utf-8'),
            )
        provided = (req.headers.get('X-Internal-Token') or '').strip()
        if not provided or not hmac.compare_digest(provided, expected):
            return Response(
                status=401,
                content_type='application/json; charset=utf-8',
                body=json.dumps({'ok': False, 'error': 'unauthorized'}).encode('utf-8'),
            )
        call_super = getattr(super(DoSGuardWebController, self), '__call__', None)
        if callable(call_super):
            try:
                res = call_super(req)
                if res is not None:
                    return res
            except Exception:
                pass
        return Response(status=200, content_type='application/json', body=b'{"ok": true}')

    @route('dos', '/dos/metrics', methods=['GET'])
    def get_metrics(self, req, **kwargs):
        app = self.app
        sem = getattr(app, '_whitelist_sem', None)
        if sem:
            with sem:
                wl_snapshot = sorted(list(app.whitelist_ips))
        else:
            wl_snapshot = list(app.whitelist_ips)
        body = {
            'time': time.time(),
            'measure_interval': app.measure_interval,
            'threshold_pps': app.pps_threshold,
            'alpha': app.alpha,
            'datapaths': list(app.datapaths.keys()),
            'blocked_ips': list(app.blocked_ips),
            'blocked_macs': list(app.blocked_macs),
            'rates': dict(app.rates),
            'ewma': dict(app.ewma),
            'total_packet_ins': app.total_packet_ins,
            'pktin_pps': float(getattr(app, '_last_pktin_pps', 0.0) or 0.0),
            'syn_rates': dict(app.syn_rates),
            'udp_rates': dict(app.udp_rates),
            'uniq_dports': dict(app.uniq_dports),
            'port_entropy': dict(getattr(app, 'port_entropy', {}) or {}),
            'port_stats': dict(app.port_stats_summary),
            'blocked_info': dict(app.blocked_info),
            'quarantined_ips': list(getattr(app, 'quarantined_ips', set()) or []),
            'quarantined_info': dict(getattr(app, 'quarantined_info', {}) or {}),
            'whitelist_ips': wl_snapshot,
            'whitelist_state_version': getattr(app, '_whitelist_state_version', 0),
            'last_packets': list(app.last_packets)[-50:],
            'alerts': list(app.alerts)[-50:],
            'ddos': dict(getattr(app, 'ddos_stats', {}) or {}),
            'vip_agg': dict(getattr(app, 'vip_agg_stats', {}) or {}),
            'vip_rl': {
                'active': bool(getattr(app, '_vip_rl_active', False)),
                'hold_sec': float(getattr(app, 'adaptive_vip_rl_hold_sec', 0.0) or 0.0),
                'enabled': bool(getattr(app, 'dp_vip_rate_limit_enabled', False)),
            },
            'failsafe': {
                'active': bool(getattr(app, '_failsafe_active', False)),
                'enabled': bool(getattr(app, 'ctrl_failsafe_enabled', False)),
                'pktin_pps_threshold': float(getattr(app, 'ctrl_failsafe_pktin_pps', 0.0) or 0.0),
                'hold_sec': float(getattr(app, 'ctrl_failsafe_hold_sec', 0.0) or 0.0),
            },
            'mac_table': { str(dpid): [{ 'mac': mac, 'port': port } for mac, port in app.mac_to_port.get(dpid, {}).items()] for dpid in list(app.mac_to_port.keys()) },
            'flow_stats': { str(dpid): app.flow_stats_summary.get(dpid, {}) for dpid in list(app.flow_stats_summary.keys()) },
            'meters': { str(dpid): dict(app._installed_meters.get(dpid, {})) for dpid in set(list(app.datapaths.keys()) + list(app._installed_meters.keys())) },
            'tracking': dict(getattr(app, '_tracking_stats', {}) or {
                'max_keys': int(getattr(app, 'tracking_max_keys', 2000) or 0),
                'ewma_keys': int(len(getattr(app, 'ewma', {}) or {})),
                'last_seen_keys': int(len(getattr(app, '_src_last_seen', {}) or {})),
                'rates_keys': int(len(getattr(app, 'rates', {}) or {})),
                'evictions_total': int(getattr(app, '_tracking_evictions_total', 0) or 0),
            }),
            'of_errors': list(app._of_errors)[-10:],
            'config': {
                'pps_threshold': app.pps_threshold,
                'threshold_pps': app.pps_threshold,
                'syn_threshold': app.syn_threshold,
                'udp_threshold': app.udp_threshold,
                'portscan_threshold': app.portscan_threshold,
                'block_duration_sec': app.block_duration_sec,
                'alpha': app.alpha,
                'measure_interval': app.measure_interval,
                'drop_priority': app.drop_priority,
                'mitigation_enabled': bool(getattr(app, 'mitigation_enabled', True)),
                'auto_failover_enabled': bool(getattr(app, 'auto_failover_enabled', False)),
                'ddos_source_threshold': int(getattr(app, 'ddos_source_threshold', 0) or 0),
                'ddos_min_pps_per_source': float(getattr(app, 'ddos_min_pps_per_source', 0.0) or 0.0),
                'ddos_vip_only': bool(getattr(app, 'ddos_vip_only', True)),
                'ddos_mitigation_enabled': bool(getattr(app, 'ddos_mitigation_enabled', True)),
                'ddos_block_top_n': int(getattr(app, 'ddos_block_top_n', 0) or 0),
                'ddos_block_duration_sec': float(getattr(app, 'ddos_block_duration_sec', 0.0) or 0.0),
                'vip_ip': str(getattr(app, 'vip_ip', '') or ''),
                'vip_agg_enabled': bool(getattr(app, 'vip_agg_enabled', True)),
                'vip_agg_pps_threshold': float(getattr(app, 'vip_agg_pps_threshold', 300.0) or 0.0),
                'vip_agg_min_unique_sources': int(getattr(app, 'vip_agg_min_unique_sources', 10) or 0),
                'vip_agg_low_rate_max_pps': float(getattr(app, 'vip_agg_low_rate_max_pps', 30.0) or 0.0),
                'vip_agg_window_sec': float(getattr(app, 'vip_agg_window_sec', 3.0) or 0.0),
                'vip_agg_sustain_intervals': int(getattr(app, 'vip_agg_sustain_intervals', 2) or 1),
                'vip_agg_cooldown_sec': float(getattr(app, 'vip_agg_cooldown_sec', 10.0) or 0.0),
                'vip_agg_baseline_enabled': bool(getattr(app, 'vip_agg_baseline_enabled', True)),
                'vip_agg_baseline_alpha': float(getattr(app, 'vip_agg_baseline_alpha', 0.15) or 0.0),
                'vip_agg_baseline_headroom': float(getattr(app, 'vip_agg_baseline_headroom', 1.0) or 0.0),
                'vip_agg_failover_enabled': bool(getattr(app, 'vip_agg_failover_enabled', False)),
                'tracking_max_keys': int(getattr(app, 'tracking_max_keys', 2000) or 0),
                'ewma_low_rate_ttl_sec': float(getattr(app, 'ewma_low_rate_ttl_sec', 3.0) or 0.0),
                'ewma_singleton_pps': float(getattr(app, 'ewma_singleton_pps', 5.0) or 0.0),
                'per_ip_port_history_cap': int(getattr(app, 'per_ip_port_history_cap', 1024) or 0),
                'quarantine_enabled': bool(getattr(app, 'quarantine_enabled', False)),
                'quarantine_pps': int(getattr(app, 'quarantine_pps', 0) or 0),
                'quarantine_duration_sec': float(getattr(app, 'quarantine_duration_sec', 0.0) or 0.0),
                'entropy_enabled': bool(getattr(app, 'entropy_enabled', False)),
                'entropy_threshold': float(getattr(app, 'entropy_threshold', 0.0) or 0.0),
                'entropy_min_ports': int(getattr(app, 'entropy_min_ports', 0) or 0),
                'dp_fastpath_enabled': bool(getattr(app, 'dp_fastpath_enabled', False)),
                'dp_mirror_vip_all': bool(getattr(app, 'dp_mirror_vip_all', False)),
                'dp_mirror_tcp_dports': list(getattr(app, 'dp_mirror_tcp_dports', []) or []),
                'dp_mirror_udp': bool(getattr(app, 'dp_mirror_udp', False)),
                'dp_mirror_icmp': bool(getattr(app, 'dp_mirror_icmp', False)),
                'dp_ctrl_meter_enabled': bool(getattr(app, 'dp_ctrl_meter_enabled', False)),
                'dp_ctrl_meter_pps': int(getattr(app, 'dp_ctrl_meter_pps', 0) or 0),
                'dp_vip_rl_enabled': bool(getattr(app, 'dp_vip_rate_limit_enabled', False)),
                'dp_vip_tcp_pps': int(getattr(app, 'dp_vip_tcp_pps', 0) or 0),
                'dp_vip_udp_pps': int(getattr(app, 'dp_vip_udp_pps', 0) or 0),
                'dp_vip_icmp_pps': int(getattr(app, 'dp_vip_icmp_pps', 0) or 0),
                'dp_vip_other_pps': int(getattr(app, 'dp_vip_other_pps', 0) or 0),
                'learning_enabled': bool(getattr(app, 'learning_enabled', True)),
            },
        }
        return Response(content_type='application/json', body=json.dumps(body).encode('utf-8'))

    @route('dos', '/dos/alerts.csv', methods=['GET'])
    def get_alerts_csv(self, req, **kwargs):
        app = self.app
        items = list(app.alerts)
        keys = []
        seen = set()
        for it in items:
            if isinstance(it, dict):
                for k in it.keys():
                    if k not in seen:
                        seen.add(k)
                        keys.append(k)
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=(keys or ['ts', 'type', 'src']), extrasaction='ignore')
        w.writeheader()
        for it in items:
            if isinstance(it, dict):
                w.writerow(it)
        return Response(content_type='text/csv', body=buf.getvalue().encode('utf-8'))

    @route('dos', '/dos/packets.csv', methods=['GET'])
    def get_packets_csv(self, req, **kwargs):
        app = self.app
        items = list(app.last_packets)
        keys = []
        seen = set()
        for it in items:
            if isinstance(it, dict):
                for k in it.keys():
                    if k not in seen:
                        seen.add(k)
                        keys.append(k)
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=(keys or ['ts', 'proto']), extrasaction='ignore')
        w.writeheader()
        for it in items:
            if isinstance(it, dict):
                w.writerow(it)
        return Response(content_type='text/csv', body=buf.getvalue().encode('utf-8'))

    @route('dos', '/dos/alerts', methods=['GET'])
    def get_alerts(self, req, **kwargs):
        app = self.app
        return Response(content_type='application/json', body=json.dumps(list(app.alerts)).encode('utf-8'))

    @route('dos', '/dos/alerts/clear', methods=['POST'])
    def clear_alerts(self, req, **kwargs):
        app = self.app
        app.alerts.clear()
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'cleared': True}).encode('utf-8'))

    @route('dos', '/dos/block/ip/{ip}', methods=['POST'])
    def block_ip(self, req, **kwargs):
        app = self.app
        ip_addr = _validate_ipv4(kwargs.get('ip'))
        if not ip_addr:
            return Response(status=400, content_type='application/json',
                           body=json.dumps({'ok': False, 'error': 'invalid_ip', 'message': 'Valid IPv4 address required'}).encode('utf-8'))
        if hasattr(app, '_is_protected_ip') and app._is_protected_ip(ip_addr):
            err_code = 'cannot_block_vip' if (app.vip_ip and ip_addr == str(app.vip_ip).strip()) else 'cannot_block_whitelisted_ip'
            msg = 'Cannot block protected VIP address' if err_code == 'cannot_block_vip' else 'Cannot block protected whitelisted IP'
            return Response(status=400, content_type='application/json',
                           body=json.dumps({'ok': False, 'error': err_code, 'message': msg}).encode('utf-8'))
        elif app.vip_ip and ip_addr == str(app.vip_ip).strip():
            return Response(status=400, content_type='application/json',
                           body=json.dumps({'ok': False, 'error': 'cannot_block_vip', 'message': 'Cannot block protected VIP address'}).encode('utf-8'))
        now = time.time()
        app._install_block_ip_all(ip_addr)
        app.blocked_ips.add(ip_addr)
        app.blocked_info[ip_addr] = {'ts': now, 'reason': 'manual_block', 'expires_at': None}
        app._emit_alert({
            'ts': now,
            'type': 'manual_block',
            'src': ip_addr,
        })
        try:
            app._security_log('manual_block', src=str(ip_addr))
        except Exception:
            pass
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'blocked': ip_addr}).encode('utf-8'))

    @route('dos', '/dos/unblock/ip/{ip}', methods=['POST'])
    def unblock_ip(self, req, **kwargs):
        app = self.app
        ip_addr = _validate_ipv4(kwargs.get('ip'))
        if not ip_addr:
            return Response(status=400, content_type='application/json',
                           body=json.dumps({'ok': False, 'error': 'invalid_ip', 'message': 'Valid IPv4 address required'}).encode('utf-8'))
        app._remove_block_ip_all(ip_addr)
        app.blocked_ips.discard(ip_addr)
        app.blocked_info.pop(ip_addr, None)
        app.ewma.pop(f"ip:{ip_addr}", None)
        app._emit_alert({
            'ts': time.time(),
            'type': 'manual_unblock',
            'src': ip_addr,
        })
        try:
            app._security_log('manual_unblock', src=str(ip_addr))
        except Exception:
            pass
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'unblocked': ip_addr}).encode('utf-8'))

    @route('dos', '/dos/unblock/all', methods=['POST'])
    def unblock_all(self, req, **kwargs):
        app = self.app
        for ip_addr in list(app.blocked_ips):
            app._remove_block_ip_all(ip_addr)
            app.ewma.pop(f"ip:{ip_addr}", None)
        app.blocked_ips.clear()
        app.blocked_info.clear()
        app._emit_alert({'ts': time.time(), 'type': 'manual_unblock_all'})
        try:
            app._security_log('manual_unblock_all')
        except Exception:
            pass
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'unblocked_all': True}).encode('utf-8'))

    @route('dos', '/dos/block/mac/{mac}', methods=['POST'])
    def block_mac(self, req, **kwargs):
        app = self.app
        mac_addr = _validate_mac(kwargs.get('mac'))
        if not mac_addr:
            return Response(status=400, content_type='application/json',
                           body=json.dumps({'ok': False, 'error': 'invalid_mac', 'message': 'Valid MAC required (e.g. aa:bb:cc:dd:ee:ff)'}).encode('utf-8'))
        for dp in list(app.datapaths.values()):
            app._install_block_mac(dp, mac_addr)
        app.blocked_macs.add(mac_addr)
        app._emit_alert({'ts': time.time(), 'type': 'manual_block_mac', 'src': mac_addr})
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'blocked_mac': mac_addr}).encode('utf-8'))

    @route('dos', '/dos/unblock/mac/{mac}', methods=['POST'])
    def unblock_mac(self, req, **kwargs):
        app = self.app
        mac_addr = _validate_mac(kwargs.get('mac'))
        if not mac_addr:
            return Response(status=400, content_type='application/json',
                           body=json.dumps({'ok': False, 'error': 'invalid_mac', 'message': 'Valid MAC required (e.g. aa:bb:cc:dd:ee:ff)'}).encode('utf-8'))
        for dp in list(app.datapaths.values()):
            app._remove_block_mac(dp, mac_addr)
        app.blocked_macs.discard(mac_addr)
        app._emit_alert({'ts': time.time(), 'type': 'manual_unblock_mac', 'src': mac_addr})
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'unblocked_mac': mac_addr}).encode('utf-8'))

    @route('dos', '/dos/unblock/mac/all', methods=['POST'])
    def unblock_mac_all(self, req, **kwargs):
        app = self.app
        for mac in list(app.blocked_macs):
            for dp in list(app.datapaths.values()):
                app._remove_block_mac(dp, mac)
        app.blocked_macs.clear()
        app._emit_alert({'ts': time.time(), 'type': 'manual_unblock_mac_all'})
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'unblocked_mac_all': True}).encode('utf-8'))

    @route('dos', '/dos/whitelist', methods=['GET'])
    def get_whitelist(self, req, **kwargs):
        app = self.app
        with app._whitelist_sem:
            ips = sorted(list(app.whitelist_ips))
            version = int(getattr(app, '_whitelist_state_version', 0))
            last_req_id = getattr(app, '_whitelist_last_request_id', None)
            last_ts = float(getattr(app, '_whitelist_last_updated_ts', 0.0) or 0.0)
            history = list(getattr(app, '_whitelist_history', []))
        body = {
            'ok': True,
            'state_version': version,
            'last_request_id': last_req_id,
            'last_updated_ts': last_ts,
            'count': len(ips),
            'whitelist_ips': ips,
            'recent_history': history,
        }
        return Response(content_type='application/json; charset=utf-8', body=json.dumps(body).encode('utf-8'))

    @route('dos', '/dos/whitelist/replace', methods=['POST'])
    def replace_whitelist(self, req, **kwargs):
        app = self.app
        try:
            body = json.loads(req.body.decode('utf-8')) if hasattr(req, 'body') and req.body else {}
        except Exception as e:
            return Response(status=400, content_type='application/json; charset=utf-8',
                           body=json.dumps({'ok': False, 'error': 'invalid_json', 'message': str(e)}).encode('utf-8'))
        if not isinstance(body, dict):
            return Response(status=400, content_type='application/json; charset=utf-8',
                           body=json.dumps({'ok': False, 'error': 'invalid_payload', 'message': 'JSON object required'}).encode('utf-8'))
        raw_ips = body.get('whitelist_ips')
        if not isinstance(raw_ips, list):
            return Response(status=400, content_type='application/json; charset=utf-8',
                           body=json.dumps({'ok': False, 'error': 'invalid_payload', 'message': 'whitelist_ips must be a list'}).encode('utf-8'))
        if len(raw_ips) > 256:
            return Response(status=422, content_type='application/json; charset=utf-8',
                           body=json.dumps({'ok': False, 'error': 'limit_exceeded', 'message': 'Maximum 256 IPs allowed'}).encode('utf-8'))
        req_id = str(body.get('request_id') or secrets.token_hex(8))

        # Stage 1: Pre-validation
        validated_set = set()
        for raw_ip in raw_ips:
            ip_clean = _validate_ipv4(raw_ip)
            if not ip_clean:
                return Response(status=400, content_type='application/json; charset=utf-8',
                               body=json.dumps({'ok': False, 'error': 'invalid_ip', 'message': f"Invalid IPv4: {raw_ip}"}).encode('utf-8'))
            validated_set.add(ip_clean)

        # Stage 2: Commit Point under Semaphore
        freed_blocked = set()
        freed_quarantined = set()
        now_ts = time.time()
        with app._whitelist_sem:
            freed_blocked = set(app.blocked_ips).intersection(validated_set)
            freed_quarantined = set(app.quarantined_ips).intersection(validated_set)

            app.whitelist_ips = set(validated_set)

            for ip in freed_blocked:
                app.blocked_ips.discard(ip)
                app.blocked_info.pop(ip, None)

            for ip in freed_quarantined:
                app.quarantined_ips.discard(ip)
                app.quarantined_info.pop(ip, None)

            for ip in (freed_blocked | freed_quarantined):
                app.ewma.pop(f"ip:{ip}", None)

            app._whitelist_state_version = int(getattr(app, '_whitelist_state_version', 0)) + 1
            app._whitelist_last_request_id = req_id
            app._whitelist_last_updated_ts = now_ts
            app._whitelist_history.append({
                'version': app._whitelist_state_version,
                'request_id': req_id,
                'ts': now_ts,
                'count': len(app.whitelist_ips),
            })
            committed_version = app._whitelist_state_version

        # Stage 3: Decoupled switch flow remediation
        remediation_warnings = []
        for ip in freed_blocked:
            try:
                app._remove_block_ip_all(ip)
            except Exception as ex:
                remediation_warnings.append({'ip': ip, 'type': 'block_removal_failed', 'detail': str(ex)})

        for ip in freed_quarantined:
            try:
                app._remove_quarantine_ip_all(ip)
            except Exception as ex:
                remediation_warnings.append({'ip': ip, 'type': 'quarantine_removal_failed', 'detail': str(ex)})

        resp_body = {
            'ok': True,
            'state_version': committed_version,
            'request_id': req_id,
            'count': len(validated_set),
            'freed_blocked': sorted(list(freed_blocked)),
            'freed_quarantined': sorted(list(freed_quarantined)),
            'remediation_warnings': remediation_warnings,
        }
        return Response(content_type='application/json; charset=utf-8', body=json.dumps(resp_body).encode('utf-8'))

    @route('dos', '/dos/whitelist/ip/{ip}', methods=['POST'])
    def whitelist_ip(self, req, **kwargs):
        app = self.app
        ip_addr = _validate_ipv4(kwargs.get('ip'))
        if not ip_addr:
            return Response(status=400, content_type='application/json',
                           body=json.dumps({'ok': False, 'error': 'invalid_ip', 'message': 'Valid IPv4 address required'}).encode('utf-8'))
        was_blocked = False
        was_quarantined = False
        with app._whitelist_sem:
            app.whitelist_ips.add(ip_addr)
            app._whitelist_state_version = int(getattr(app, '_whitelist_state_version', 0)) + 1
            app._whitelist_last_updated_ts = time.time()
            app._whitelist_history.append({
                'version': app._whitelist_state_version,
                'request_id': 'individual_add',
                'ts': app._whitelist_last_updated_ts,
                'count': len(app.whitelist_ips),
            })
            if ip_addr in app.blocked_ips:
                was_blocked = True
                app.blocked_ips.discard(ip_addr)
                app.blocked_info.pop(ip_addr, None)
            if ip_addr in app.quarantined_ips:
                was_quarantined = True
                app.quarantined_ips.discard(ip_addr)
                app.quarantined_info.pop(ip_addr, None)
            app.ewma.pop(f"ip:{ip_addr}", None)
            committed_ver = app._whitelist_state_version

        if was_blocked:
            try:
                app._remove_block_ip_all(ip_addr)
            except Exception:
                pass
        if was_quarantined:
            try:
                app._remove_quarantine_ip_all(ip_addr)
            except Exception:
                pass
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'whitelisted': ip_addr, 'state_version': committed_ver}).encode('utf-8'))

    @route('dos', '/dos/unwhitelist/ip/{ip}', methods=['POST'])
    def unwhitelist_ip(self, req, **kwargs):
        app = self.app
        ip_addr = _validate_ipv4(kwargs.get('ip'))
        if not ip_addr:
            return Response(status=400, content_type='application/json',
                           body=json.dumps({'ok': False, 'error': 'invalid_ip', 'message': 'Valid IPv4 address required'}).encode('utf-8'))
        with app._whitelist_sem:
            app.whitelist_ips.discard(ip_addr)
            app._whitelist_state_version = int(getattr(app, '_whitelist_state_version', 0)) + 1
            app._whitelist_last_updated_ts = time.time()
            app._whitelist_history.append({
                'version': app._whitelist_state_version,
                'request_id': 'individual_remove',
                'ts': app._whitelist_last_updated_ts,
                'count': len(app.whitelist_ips),
            })
            committed_ver = app._whitelist_state_version
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'unwhitelisted': ip_addr, 'state_version': committed_ver}).encode('utf-8'))

    @route('dos', '/dos/whitelist/clear', methods=['POST'])
    def whitelist_clear(self, req, **kwargs):
        app = self.app
        with app._whitelist_sem:
            app.whitelist_ips.clear()
            app._whitelist_state_version = int(getattr(app, '_whitelist_state_version', 0)) + 1
            app._whitelist_last_updated_ts = time.time()
            app._whitelist_history.append({
                'version': app._whitelist_state_version,
                'request_id': 'clear_all',
                'ts': app._whitelist_last_updated_ts,
                'count': 0,
            })
            committed_ver = app._whitelist_state_version
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'whitelist_cleared': True, 'state_version': committed_ver}).encode('utf-8'))

    @route('dos', '/dos/flows', methods=['GET'])
    def get_flows(self, req, **kwargs):
        app = self.app
        return Response(content_type='application/json', body=json.dumps(app.flow_stats_summary).encode('utf-8'))

    @route('dos', '/dos/flows/clear', methods=['POST'])
    def clear_flows(self, req, **kwargs):
        app = self.app
        cleared_count = 0
        app.blocked_ips.clear()
        app.blocked_macs.clear()
        app.blocked_info.clear()
        app.quarantined_ips.clear()
        app.quarantined_info.clear()
        app._vip_rl_active = False
        app._failsafe_active = False
        for dp in list(app.datapaths.values()):
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            dpid = app._dpid_of(dp)
            try:
                all_tables = getattr(ofproto, 'OFPTT_ALL', 0xff)
                for ck in app._app_flow_cookies():
                    app._delete_flows_by_cookie(dp, cookie=ck, table_id=all_tables)
                if dpid is not None:
                    app._clear_dpid_flow_specs(dpid)
                if hasattr(parser, 'OFPBarrierRequest'):
                    dp.send_msg(parser.OFPBarrierRequest(dp))
                # Restore base table-miss, ARP, and fastpath flows so the switch does not blackhole traffic
                app._install_base_flows(dp)
                cleared_count += 1
            except Exception as e:
                app.logger.warning('Failed to clear/restore flows on datapath %s: %s', getattr(dp, 'id', None), e)
        app._emit_alert({'ts': time.time(), 'type': 'flows_cleared', 'count': cleared_count})
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'cleared': cleared_count}).encode('utf-8'))

    @route('dos', '/dos/config', methods=['POST'])
    def update_config(self, req, **kwargs):
        app = self.app
        try:
            data = json.loads(req.body) if req.body else {}
        except Exception:
            return Response(status=400, content_type='application/json',
                            body=json.dumps({'ok': False, 'error': 'invalid_json'}).encode('utf-8'))
        if not isinstance(data, dict):
            return Response(status=400, content_type='application/json',
                            body=json.dumps({'ok': False, 'error': 'json_object_required'}).encode('utf-8'))

        errors = {}
        changed = {}

        def _parse_bool(val):
            if isinstance(val, str):
                return val.strip().lower() in ('1', 'true', 'yes', 'y', 'on')
            return bool(val)

        if 'learning_enabled' in data:
            prev_learning = bool(app.learning_enabled)
            app.learning_enabled = _parse_bool(data['learning_enabled'])
            changed['learning_enabled'] = bool(app.learning_enabled)
            if app.learning_enabled != prev_learning:
                for dp in list(app.datapaths.values()):
                    try:
                        app._install_base_flows(dp)
                    except Exception:
                        pass
        if 'mitigation_enabled' in data:
            app.mitigation_enabled = _parse_bool(data['mitigation_enabled'])
            changed['mitigation_enabled'] = bool(app.mitigation_enabled)
        if 'auto_failover_enabled' in data:
            app.auto_failover_enabled = _parse_bool(data['auto_failover_enabled'])
            changed['auto_failover_enabled'] = bool(app.auto_failover_enabled)
        if 'ddos_vip_only' in data:
            app.ddos_vip_only = _parse_bool(data['ddos_vip_only'])
            changed['ddos_vip_only'] = bool(app.ddos_vip_only)
        if 'ddos_mitigation_enabled' in data:
            app.ddos_mitigation_enabled = _parse_bool(data['ddos_mitigation_enabled'])
            changed['ddos_mitigation_enabled'] = bool(app.ddos_mitigation_enabled)

        if 'ddos_source_threshold' in data:
            try:
                v = int(data['ddos_source_threshold'])
                if v < 1:
                    errors['ddos_source_threshold'] = 'must be >= 1'
                else:
                    app.ddos_source_threshold = v
                    changed['ddos_source_threshold'] = v
            except Exception:
                errors['ddos_source_threshold'] = 'invalid integer'

        if 'ddos_min_pps_per_source' in data:
            try:
                v = float(data['ddos_min_pps_per_source'])
                if v < 0:
                    errors['ddos_min_pps_per_source'] = 'must be >= 0'
                else:
                    app.ddos_min_pps_per_source = v
                    changed['ddos_min_pps_per_source'] = v
            except Exception:
                errors['ddos_min_pps_per_source'] = 'invalid number'

        if 'ddos_block_top_n' in data:
            try:
                v = int(data['ddos_block_top_n'])
                if v < 0:
                    errors['ddos_block_top_n'] = 'must be >= 0'
                else:
                    app.ddos_block_top_n = v
                    changed['ddos_block_top_n'] = v
            except Exception:
                errors['ddos_block_top_n'] = 'invalid integer'

        if 'ddos_block_duration_sec' in data:
            try:
                v = float(data['ddos_block_duration_sec'])
                if v < 0:
                    errors['ddos_block_duration_sec'] = 'must be >= 0'
                else:
                    app.ddos_block_duration_sec = v
                    changed['ddos_block_duration_sec'] = v
            except Exception:
                errors['ddos_block_duration_sec'] = 'invalid number'

        if 'vip_ip' in data:
            raw_vip = str(data['vip_ip'] or '').strip()
            if raw_vip == '':
                app.vip_ip = ''
                changed['vip_ip'] = ''
            else:
                vip_val = _validate_ipv4(raw_vip)
                if not vip_val:
                    errors['vip_ip'] = 'invalid IPv4 address'
                else:
                    app.vip_ip = vip_val
                    changed['vip_ip'] = vip_val

        if 'threshold_pps' in data or 'pps_threshold' in data:
            try:
                raw_val = data['threshold_pps'] if 'threshold_pps' in data else data['pps_threshold']
                v = float(raw_val)
                if v < 1.0:
                    errors['threshold_pps'] = 'must be >= 1'
                else:
                    app.pps_threshold = v
                    changed['threshold_pps'] = v
                    changed['pps_threshold'] = v
            except Exception:
                errors['threshold_pps'] = 'invalid number'

        if 'alpha' in data:
            try:
                v = float(data['alpha'])
                if v <= 0.0 or v > 1.0:
                    errors['alpha'] = 'must be in (0, 1]'
                else:
                    app.alpha = v
                    changed['alpha'] = v
            except Exception:
                errors['alpha'] = 'invalid number'

        if 'measure_interval' in data:
            try:
                v = float(data['measure_interval'])
                if v < 0.1 or v > 300.0:
                    errors['measure_interval'] = 'must be between 0.1 and 300'
                else:
                    app.measure_interval = v
                    changed['measure_interval'] = v
            except Exception:
                errors['measure_interval'] = 'invalid number'

        if 'syn_threshold' in data:
            try:
                v = float(data['syn_threshold'])
                if v < 1.0:
                    errors['syn_threshold'] = 'must be >= 1'
                else:
                    app.syn_threshold = v
                    changed['syn_threshold'] = v
            except Exception:
                errors['syn_threshold'] = 'invalid number'

        if 'udp_threshold' in data:
            try:
                v = float(data['udp_threshold'])
                if v < 1.0:
                    errors['udp_threshold'] = 'must be >= 1'
                else:
                    app.udp_threshold = v
                    changed['udp_threshold'] = v
            except Exception:
                errors['udp_threshold'] = 'invalid number'

        if 'portscan_threshold' in data:
            try:
                v = int(data['portscan_threshold'])
                if v < 1:
                    errors['portscan_threshold'] = 'must be >= 1'
                else:
                    app.portscan_threshold = v
                    changed['portscan_threshold'] = v
            except Exception:
                errors['portscan_threshold'] = 'invalid integer'

        if 'block_duration_sec' in data:
            try:
                v = float(data['block_duration_sec'])
                if v < 0.0:
                    errors['block_duration_sec'] = 'must be >= 0'
                else:
                    app.block_duration_sec = v
                    changed['block_duration_sec'] = v
            except Exception:
                errors['block_duration_sec'] = 'invalid number'

        if 'drop_priority' in data:
            try:
                v = int(data['drop_priority'])
                if v < 1 or v > 65535:
                    errors['drop_priority'] = 'must be between 1 and 65535'
                else:
                    app.drop_priority = v
                    changed['drop_priority'] = v
            except Exception:
                errors['drop_priority'] = 'invalid integer'

        vip_rl_dirty = False
        if 'dp_vip_rl_enabled' in data:
            prev_rl = bool(app.dp_vip_rate_limit_enabled)
            app.dp_vip_rate_limit_enabled = _parse_bool(data['dp_vip_rl_enabled'])
            changed['dp_vip_rl_enabled'] = bool(app.dp_vip_rate_limit_enabled)
            if not app.dp_vip_rate_limit_enabled and app._vip_rl_active:
                for dp in list(app.datapaths.values()):
                    try:
                        app._remove_vip_rl(dp)
                    except Exception:
                        pass
                app._vip_rl_active = False
            if app.dp_vip_rate_limit_enabled != prev_rl:
                vip_rl_dirty = True

        for key, attr in (
            ('dp_vip_tcp_pps', 'dp_vip_tcp_pps'),
            ('dp_vip_udp_pps', 'dp_vip_udp_pps'),
            ('dp_vip_icmp_pps', 'dp_vip_icmp_pps'),
            ('dp_vip_other_pps', 'dp_vip_other_pps'),
        ):
            if key in data:
                try:
                    v = int(data[key])
                    if v < 1 or v > 1000000:
                        errors[key] = 'must be between 1 and 1000000'
                    else:
                        setattr(app, attr, v)
                        changed[key] = v
                        vip_rl_dirty = True
                except Exception:
                    errors[key] = 'invalid integer'

        for bkey in ('vip_agg_enabled', 'vip_agg_baseline_enabled', 'vip_agg_failover_enabled'):
            if bkey in data:
                val = _parse_bool(data[bkey])
                setattr(app, bkey, val)
                changed[bkey] = val
                if bkey == 'vip_agg_enabled' and not val:
                    app._vip_agg_consec = 0

        for ikey, lo, hi in (
            ('vip_agg_min_unique_sources', 1, 100000),
            ('vip_agg_sustain_intervals', 1, 60),
            ('tracking_max_keys', 50, 200000),
            ('per_ip_port_history_cap', 64, 65536),
        ):
            if ikey in data:
                try:
                    v = int(data[ikey])
                    if v < lo or v > hi:
                        errors[ikey] = f'must be between {lo} and {hi}'
                    else:
                        setattr(app, ikey, v)
                        changed[ikey] = v
                except Exception:
                    errors[ikey] = 'invalid integer'

        if 'tracking_max_keys' in changed:
            try:
                app._enforce_ewma_bounds(time.time())
            except Exception:
                pass

        for fkey, lo, hi in (
            ('vip_agg_pps_threshold', 1.0, 1000000.0),
            ('vip_agg_low_rate_max_pps', 0.0, 1000000.0),
            ('vip_agg_window_sec', 0.5, 60.0),
            ('vip_agg_cooldown_sec', 0.0, 3600.0),
            ('vip_agg_baseline_alpha', 0.01, 1.0),
            ('vip_agg_baseline_headroom', 0.0, 10.0),
            ('ewma_low_rate_ttl_sec', 0.5, 3600.0),
            ('ewma_singleton_pps', 0.1, 10000.0),
        ):
            if fkey in data:
                try:
                    v = float(data[fkey])
                    if v < lo or v > hi:
                        errors[fkey] = f'must be between {lo} and {hi}'
                    else:
                        setattr(app, fkey, v)
                        changed[fkey] = v
                except Exception:
                    errors[fkey] = 'invalid number'

        if vip_rl_dirty:
            for dp in list(app.datapaths.values()):
                try:
                    app._install_base_flows(dp)
                    if app._vip_rl_active and app.dp_vip_rate_limit_enabled:
                        app._remove_vip_rl(dp)
                        app._install_vip_rl(dp)
                except Exception:
                    pass

        if errors:
            return Response(status=400, content_type='application/json',
                            body=json.dumps({'ok': False, 'error': 'invalid_config', 'errors': errors, 'changed': changed}).encode('utf-8'))
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'changed': changed}).encode('utf-8'))

    @route('dos', '/dos/reset', methods=['POST'])
    def reset_runtime(self, req, **kwargs):
        app = self.app
        try:
            app.reset_runtime_counters()
        except Exception:
            pass
        return Response(content_type='application/json', body=json.dumps({'ok': True, 'reset': True}).encode('utf-8'))
