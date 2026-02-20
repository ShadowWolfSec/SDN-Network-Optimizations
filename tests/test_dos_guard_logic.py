import json
import logging
import os
import sys
import types
import unittest
from unittest import mock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class _StopMonitorLoop(BaseException):
    pass


def _build_ryu_stubs():
    modules = {}

    def _pkg(name):
        m = types.ModuleType(name)
        modules[name] = m
        return m

    ryu = _pkg('ryu')
    ryu_base = _pkg('ryu.base')
    ryu_app_mgr = _pkg('ryu.base.app_manager')

    class DummyRyuApp:
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger('dos_guard_test')

    ryu_app_mgr.RyuApp = DummyRyuApp
    ryu_base.app_manager = ryu_app_mgr
    ryu.base = ryu_base

    ryu_ctrl = _pkg('ryu.controller')
    ofp_event = _pkg('ryu.controller.ofp_event')
    for ev_name in (
        'EventOFPStateChange',
        'EventOFPSwitchFeatures',
        'EventOFPPacketIn',
        'EventOFPFlowStatsReply',
        'EventOFPPortStatsReply',
        'EventOFPMeterConfigStatsReply',
        'EventOFPBarrierReply',
        'EventOFPErrorMsg',
    ):
        setattr(ofp_event, ev_name, ev_name)

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
        sub_mod = _pkg(f'ryu.lib.packet.{sub}')
        setattr(ryu_pkt, sub, sub_mod)
    ryu_lib.packet = ryu_pkt
    ryu.lib = ryu_lib

    ryu_app_pkg = _pkg('ryu.app')
    wsgi = _pkg('ryu.app.wsgi')

    class DummyWSGIApplication:
        def __init__(self):
            self.mapper = None
            self.registory = {}

        def register(self, cls, data):
            return None

    class DummyControllerBase:
        def __init__(self, req, link, data, **config):
            self.req = req
            self.link = link
            self.data = data

        def __call__(self, req):
            return DummyResponse(status=200, content_type='application/json', body=b'{"ok":true}')

    class DummyResponse:
        def __init__(self, status=200, content_type='text/plain', body=b''):
            self.status_code = int(status)
            self.content_type = content_type
            self.body = body if isinstance(body, (bytes, bytearray)) else str(body).encode('utf-8')

    wsgi.WSGIApplication = DummyWSGIApplication
    wsgi.ControllerBase = DummyControllerBase
    wsgi.route = lambda *a, **kw: (lambda fn: fn)
    ryu_app_pkg.wsgi = wsgi
    ryu.app = ryu_app_pkg

    webob = _pkg('webob')
    webob.Response = DummyResponse
    return modules


class DoSGuardLogicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._stubs = _build_ryu_stubs()
        cls._saved_modules = {k: sys.modules.get(k) for k in cls._stubs}
        cls._saved_dg = sys.modules.pop('ryu_app.dos_guard', None)
        cls._saved_wc = sys.modules.pop('ryu_app.web_controller', None)
        sys.modules.update(cls._stubs)
        import ryu_app.dos_guard as dg
        cls.dg = dg

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop('ryu_app.dos_guard', None)
        sys.modules.pop('ryu_app.web_controller', None)
        if cls._saved_dg is not None:
            sys.modules['ryu_app.dos_guard'] = cls._saved_dg
        if cls._saved_wc is not None:
            sys.modules['ryu_app.web_controller'] = cls._saved_wc
        for name, orig in cls._saved_modules.items():
            if orig is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = orig

    def _new_guard(self):
        wsgi = self._stubs['ryu.app.wsgi'].WSGIApplication()
        return self.dg.DoSGuard(wsgi=wsgi)

    def test_defaults_aligned_with_measurements(self):
        guard = self._new_guard()
        self.assertEqual(guard.ctrl_failsafe_pktin_pps, 2000.0)
        self.assertEqual(guard.dp_ctrl_meter_pps, 2500)
        self.assertEqual(guard.portscan_threshold, 50)
        self.assertEqual(guard.syn_threshold, 200.0)

    def test_protected_ip_whitelist_and_vip(self):
        guard = self._new_guard()
        guard.vip_ip = '10.0.0.100'
        guard.whitelist_ips.add('10.0.0.5')
        self.assertTrue(guard._is_protected_ip('10.0.0.100'))
        self.assertTrue(guard._is_protected_ip('10.0.0.5'))
        self.assertFalse(guard._is_protected_ip('10.0.0.1'))
        self.assertFalse(guard._is_protected_ip(''))

    def test_decision_and_trigger_classification(self):
        guard = self._new_guard()
        guard.quarantine_enabled = False
        self.assertEqual(guard._decide_action('portscan_detected'), 'block')
        self.assertEqual(guard._decide_action('syn_rate_exceeded'), 'block')
        self.assertEqual(guard._decide_action('ddos_detected'), 'ddos')

        guard.quarantine_enabled = True
        self.assertEqual(guard._decide_action('portscan_detected'), 'quarantine')

        self.assertEqual(guard._classify_trigger('portscan_detected'), ('dos', 'port_scan'))
        self.assertEqual(guard._classify_trigger('syn_rate_exceeded'), ('dos', 'syn_flood'))
        self.assertEqual(guard._classify_trigger('ddos_detected'), ('ddos', 'multi_source_flood'))

    def test_monitor_ewma_decay_pruning_portscan_and_failsafe(self):
        guard = self._new_guard()
        guard.measure_interval = 1.0
        guard.alpha = 0.3
        guard.quarantine_enabled = False
        guard.mitigation_enabled = True

        # Seed decaying active host + below-cutoff stale entry + protected VIP + portscan attacker
        guard.ewma['ip:10.0.0.5'] = 100.0
        guard.ewma['ip:10.0.0.6'] = 0.04
        guard.pkt_counts['ip:10.0.0.100'] = 5000
        guard.pkt_counts['ip:10.0.0.1'] = 60
        guard.portscan_dports['10.0.0.1'] = set(range(1, 61))
        guard._pktin_interval_count = 2005  # > 2000.0 failsafe threshold

        sleep_calls = {'n': 0}

        def _fake_sleep(_sec):
            sleep_calls['n'] += 1
            if sleep_calls['n'] >= 2:
                raise _StopMonitorLoop()

        guard._install_block_ip_all = mock.MagicMock()
        guard._set_failsafe_active = mock.MagicMock()

        with mock.patch.object(self.dg.hub, 'sleep', side_effect=_fake_sleep):
            with self.assertRaises(_StopMonitorLoop):
                guard._monitor()

        # EWMA decayed cleanly and stale < 0.05 pruned
        self.assertAlmostEqual(guard.ewma['ip:10.0.0.5'], 70.0, places=4)
        self.assertNotIn('ip:10.0.0.6', guard.ewma)

        # VIP never blocked; portscan attacker blocked cleanly when quarantine=False
        self.assertNotIn('10.0.0.100', guard.blocked_ips)
        self.assertIn('10.0.0.1', guard.blocked_ips)
        guard._install_block_ip_all.assert_called_once_with('10.0.0.1')
        guard._set_failsafe_active.assert_called()

    def test_web_controller_auth_and_config_validation(self):
        guard = self._new_guard()
        data = {self.dg.DOS_GUARD_INSTANCE_NAME: guard}
        ctrl = self.dg.DoSGuardWebController(req=None, link=None, data=data)

        # 1) Token authentication guard
        with mock.patch.dict(os.environ, {'SDN_INTERNAL_TOKEN': 'secret-tok-xyz'}):
            bad_req = types.SimpleNamespace(headers={'X-Internal-Token': 'wrong'})
            resp_bad = ctrl(bad_req)
            self.assertEqual(resp_bad.status_code, 401)
            self.assertEqual(json.loads(resp_bad.body.decode('utf-8')).get('error'), 'unauthorized')

            ok_req = types.SimpleNamespace(headers={'X-Internal-Token': 'secret-tok-xyz'})
            resp_ok = ctrl(ok_req)
            self.assertEqual(resp_ok.status_code, 200)

        # 2) Invalid JSON & out-of-range parameters return 400
        resp_json_err = ctrl.update_config(types.SimpleNamespace(body=b'{not-json'))
        self.assertEqual(resp_json_err.status_code, 400)
        self.assertEqual(json.loads(resp_json_err.body.decode('utf-8')).get('error'), 'invalid_json')

        bad_cfg = {
            'ddos_source_threshold': 0,
            'portscan_threshold': -5,
            'drop_priority': 70000,
            'block_duration_sec': -1,
        }
        resp_bounds = ctrl.update_config(types.SimpleNamespace(body=json.dumps(bad_cfg).encode('utf-8')))
        self.assertEqual(resp_bounds.status_code, 400)
        payload = json.loads(resp_bounds.body.decode('utf-8'))
        self.assertEqual(payload.get('error'), 'invalid_config')
        for k in bad_cfg:
            self.assertIn(k, payload.get('errors', {}))

        # 3) Valid config update succeeds
        good_cfg = {'portscan_threshold': 65, 'learning_enabled': True}
        resp_good = ctrl.update_config(types.SimpleNamespace(body=json.dumps(good_cfg).encode('utf-8')))
        self.assertEqual(resp_good.status_code, 200)
        self.assertEqual(guard.portscan_threshold, 65)
        self.assertTrue(guard.learning_enabled)

    def test_meter_sync_ownership_barrier_and_error_handling(self):
        guard = self._new_guard()
        guard.dp_fastpath_enabled = False
        guard.dp_ctrl_meter_enabled = True
        guard.dp_ctrl_meter_id = 1
        guard.dp_ctrl_meter_pps = 2500
        guard.dp_vip_tcp_meter_id = 10
        guard.quarantine_meter_id = 20

        class FakeOfproto:
            OFPM_ALL = 0xffffffff
            OFPMPF_REPLY_MORE = 1
            OFPMF_PKTPS = 2
            OFPMF_KBPS = 1
            OFPMF_STATS = 8
            OFPMC_ADD = 0
            OFPMC_MODIFY = 1
            OFPET_METER_MOD_FAILED = 12
            OFPMMFC_METER_EXISTS = 1
            OFPMMFC_OUT_OF_METERS = 10
            OFPP_ANY = 0xffffffff
            OFPG_ANY = 0xffffffff
            OFPP_NORMAL = 0xfffffffa
            OFPP_FLOOD = 0xfffffffb
            OFPP_CONTROLLER = 0xfffffffd
            OFPCML_NO_BUFFER = 0xffff
            OFP_NO_BUFFER = 0xffffffff
            OFPIT_METER = 6
            OFPIT_APPLY_ACTIONS = 4

        xid_seq = {'n': 100}
        sent = []

        class FakeMsg:
            def __init__(self, kind, **kw):
                self.kind = kind
                self.xid = None
                for k, v in kw.items():
                    setattr(self, k, v)

        class FakeParser:
            def OFPMeterConfigStatsRequest(self, datapath, flags=0, meter_id=0):
                return FakeMsg('meter_stats_req', datapath=datapath, flags=flags, meter_id=meter_id)

            def OFPMeterMod(self, datapath, command=0, flags=0, meter_id=1, bands=None):
                return FakeMsg('meter_mod', datapath=datapath, command=command, flags=flags, meter_id=meter_id, bands=bands)

            def OFPMeterBandDrop(self, rate=0, burst_size=0):
                return types.SimpleNamespace(rate=rate, burst_size=burst_size)

            def OFPBarrierRequest(self, datapath):
                return FakeMsg('barrier_req', datapath=datapath)

            def OFPMatch(self, **kw):
                return dict(kw)

            def OFPActionOutput(self, port, max_len=0):
                return ('out', port, max_len)

            def OFPInstructionMeter(self, meter_id, type_=6):
                return ('meter', meter_id)

            def OFPInstructionActions(self, type_, actions):
                return ('actions', actions)

            def OFPFlowMod(self, **kw):
                return FakeMsg('flow_mod', **kw)

        dp = types.SimpleNamespace(id=1, ofproto=FakeOfproto, ofproto_parser=FakeParser())

        def fake_send(msg):
            xid_seq['n'] += 1
            msg.xid = xid_seq['n']
            sent.append(msg)

        dp.send_msg = fake_send

        # 1) switch_features_handler requests OFPMeterConfigStatsRequest (wait before installing base flows)
        guard.switch_features_handler(types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp)))
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].kind, 'meter_stats_req')
        self.assertEqual(sent[0].meter_id, FakeOfproto.OFPM_ALL)

        # 2) Multi-part OFPMeterConfigStatsReply: fragment 1 (REPLY_MORE=1) has meter=1 matching 2500pps,
        # fragment 2 (flags=0) has meter=10 with stale 500pps AND external unmanaged meter=999
        stat1 = types.SimpleNamespace(
            meter_id=1,
            flags=FakeOfproto.OFPMF_PKTPS | FakeOfproto.OFPMF_STATS,
            bands=[types.SimpleNamespace(rate=2500, burst_size=0)],
        )
        stat10 = types.SimpleNamespace(
            meter_id=10,
            flags=FakeOfproto.OFPMF_PKTPS | FakeOfproto.OFPMF_STATS,
            bands=[types.SimpleNamespace(rate=500, burst_size=0)],
        )
        stat999 = types.SimpleNamespace(
            meter_id=999,
            flags=FakeOfproto.OFPMF_KBPS | FakeOfproto.OFPMF_STATS,
            bands=[types.SimpleNamespace(rate=100, burst_size=0)],
        )
        guard._meter_config_stats_reply_handler(types.SimpleNamespace(
            msg=types.SimpleNamespace(datapath=dp, flags=FakeOfproto.OFPMPF_REPLY_MORE, body=[stat1])
        ))
        self.assertIn(1, guard._meter_sync_pending)  # Not yet finished until flags==0
        guard._meter_config_stats_reply_handler(types.SimpleNamespace(
            msg=types.SimpleNamespace(datapath=dp, flags=0, body=[stat10, stat999])
        ))
        self.assertNotIn(1, guard._meter_sync_pending)
        self.assertIn(999, guard._external_meters[1])

        # Base flows installed cleanly using synced meter=1 WITHOUT sending duplicate OFPMC_ADD for meter=1!
        meter_mods_after_sync = [m for m in sent if m.kind == 'meter_mod']
        self.assertEqual(meter_mods_after_sync, [])
        self.assertTrue(guard._installed_meters[1][1]['verified'])

        # 3) _ensure_meter refuses unmanaged external meter=999
        self.assertFalse(guard._ensure_meter(dp, 999, 500))

        # 4) Pre-existing managed meter=10 (was 500pps) updated to 800pps via OFPMC_MODIFY (NOT ADD)
        sent.clear()
        self.assertTrue(guard._ensure_meter(dp, 10, 800))
        m10_mods = [m for m in sent if m.kind == 'meter_mod']
        b10_reqs = [m for m in sent if m.kind == 'barrier_req']
        self.assertEqual(len(m10_mods), 1)
        self.assertEqual(m10_mods[0].command, FakeOfproto.OFPMC_MODIFY)
        self.assertEqual(len(b10_reqs), 1)
        # Not yet verified before BarrierReply!
        self.assertFalse(guard._installed_meters[1][10]['verified'])

        # BarrierReply confirms meter=10
        guard._barrier_reply_handler(types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp, xid=b10_reqs[0].xid)))
        self.assertTrue(guard._installed_meters[1][10]['verified'])

        # 5) Missing meter=20 sends OFPMC_ADD; simulate OFPMMFC_METER_EXISTS -> auto-retries OFPMC_MODIFY
        sent.clear()
        self.assertTrue(guard._ensure_meter(dp, 20, 150))
        m20_add = [m for m in sent if m.kind == 'meter_mod'][0]
        self.assertEqual(m20_add.command, FakeOfproto.OFPMC_ADD)
        sent.clear()
        guard._error_msg_handler(types.SimpleNamespace(msg=types.SimpleNamespace(
            datapath=dp,
            xid=m20_add.xid,
            type=FakeOfproto.OFPET_METER_MOD_FAILED,
            code=FakeOfproto.OFPMMFC_METER_EXISTS,
            data=b'',
        )))
        retry_mods = [m for m in sent if m.kind == 'meter_mod']
        self.assertEqual(len(retry_mods), 1)
        self.assertEqual(retry_mods[0].command, FakeOfproto.OFPMC_MODIFY)
        b20_req = [m for m in sent if m.kind == 'barrier_req'][0]
        guard._barrier_reply_handler(types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp, xid=b20_req.xid)))
        self.assertTrue(guard._installed_meters[1][20]['verified'])

        # 6) Non-recoverable error (OUT_OF_METERS) marks failed=True and records in _of_errors
        sent.clear()
        self.assertTrue(guard._ensure_meter(dp, 20, 300))
        m20_mod2 = [m for m in sent if m.kind == 'meter_mod'][0]
        guard._error_msg_handler(types.SimpleNamespace(msg=types.SimpleNamespace(
            datapath=dp,
            xid=m20_mod2.xid,
            type=FakeOfproto.OFPET_METER_MOD_FAILED,
            code=FakeOfproto.OFPMMFC_OUT_OF_METERS,
            data=b'',
        )))
        self.assertTrue(guard._installed_meters[1][20]['failed'])
        self.assertFalse(guard._installed_meters[1][20]['verified'])
        self.assertGreaterEqual(len(guard._of_errors), 2)
        self.assertFalse(guard._ensure_meter(dp, 20, 300))

        # 7) Pre-handshake disconnect (datapath.id is None) must not raise TypeError
        null_dp = types.SimpleNamespace(id=None)
        guard._state_change_handler(types.SimpleNamespace(datapath=null_dp, state=2))

    def test_strict_flow_deletion_and_cookie_ownership(self):
        guard = self._new_guard()
        guard.vip_ip = '10.0.0.100'
        guard.dp_fastpath_enabled = True
        guard.dp_vip_rate_limit_enabled = True
        guard.adaptive_vip_rl_enabled = True
        guard.ctrl_failsafe_enabled = True
        guard.drop_priority = 40000

        class FakeOfproto:
            OFPFC_ADD = 0
            OFPFC_DELETE = 3
            OFPFC_DELETE_STRICT = 4
            OFPTT_ALL = 0xff
            OFPP_ANY = 0xffffffff
            OFPG_ANY = 0xffffffff
            OFPP_NORMAL = 0xfffffffa
            OFPP_FLOOD = 0xfffffffb
            OFPP_CONTROLLER = 0xfffffffd
            OFPCML_NO_BUFFER = 0xffff
            OFP_NO_BUFFER = 0xffffffff
            OFPIT_METER = 6
            OFPIT_APPLY_ACTIONS = 4
            OFPMF_PKTPS = 2
            OFPMF_KBPS = 1
            OFPMF_STATS = 8
            OFPMC_ADD = 0
            OFPMC_MODIFY = 1

        sent = []

        class FakeMsg(dict):
            def __init__(self, kind, **kw):
                super().__init__(**kw)
                self.kind = kind
                self.xid = None

        class FakeParser:
            def OFPMatch(self, **kw):
                return ('match', tuple(sorted(kw.items())))

            def OFPActionOutput(self, port, max_len=0):
                return ('out', port, max_len)

            def OFPInstructionMeter(self, meter_id, type_=6):
                return ('meter', meter_id)

            def OFPInstructionActions(self, type_, actions):
                return ('actions', actions)

            def OFPMeterBandDrop(self, rate=0, burst_size=0):
                return types.SimpleNamespace(rate=rate, burst_size=burst_size)

            def OFPMeterMod(self, **kw):
                return FakeMsg('meter_mod', **kw)

            def OFPBarrierRequest(self, datapath):
                return FakeMsg('barrier_req', datapath=datapath)

            def OFPFlowMod(self, **kw):
                return FakeMsg('flow_mod', **kw)

        xseq = {'n': 1}
        dp = types.SimpleNamespace(id=1, ofproto=FakeOfproto, ofproto_parser=FakeParser())

        def fake_send(m):
            xseq['n'] += 1
            m.xid = xseq['n']
            sent.append(m)

        dp.send_msg = fake_send
        guard.datapaths[1] = dp

        # 1) Block IP at priority 40000, change drop_priority to 45000, unblock must STRICT-delete at 40000!
        guard._install_block_ip(dp, '10.0.0.1')
        guard.drop_priority = 45000
        sent.clear()
        guard._remove_block_ip(dp, '10.0.0.1')
        self.assertEqual(len(sent), 1)
        del_msg = sent[0]
        self.assertEqual(del_msg['command'], FakeOfproto.OFPFC_DELETE_STRICT)
        self.assertEqual(del_msg['table_id'], 0)
        self.assertEqual(del_msg['priority'], 40000)
        self.assertEqual(del_msg['cookie'], guard._block_ip_cookie)
        self.assertEqual(del_msg['cookie_mask'], 0xffffffffffffffff)

        # 2) Quarantine IP and Block MAC also use OFPFC_DELETE_STRICT with recorded priorities
        guard.drop_priority = 40000
        guard._install_quarantine_ip(dp, '10.0.0.2')
        guard._install_block_mac(dp, '00:11:22:33:44:55')
        sent.clear()
        guard._remove_quarantine_ip(dp, '10.0.0.2')
        guard._remove_block_mac(dp, '00:11:22:33:44:55')
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0]['command'], FakeOfproto.OFPFC_DELETE_STRICT)
        self.assertEqual(sent[0]['priority'], 39999)
        self.assertEqual(sent[0]['cookie'], guard._quarantine_cookie)
        self.assertEqual(sent[1]['command'], FakeOfproto.OFPFC_DELETE_STRICT)
        self.assertEqual(sent[1]['priority'], 40000)
        self.assertEqual(sent[1]['cookie'], guard._block_mac_cookie)

        # 3) VIP RL & Failsafe strict deletes
        guard._install_vip_rl(dp)
        guard._install_failsafe(dp)
        sent.clear()
        guard._remove_vip_rl(dp)
        guard._remove_failsafe(dp)
        self.assertGreaterEqual(len(sent), 7)
        for m in sent:
            self.assertEqual(m['command'], FakeOfproto.OFPFC_DELETE_STRICT)
            self.assertEqual(m['table_id'], 0)
            self.assertEqual(m['cookie_mask'], 0xffffffffffffffff)

        # 4) clear_flows uses ONLY cookie-scoped deletes (never unmasked cookie_mask=0)
        ctrl = self.dg.DoSGuardWebController(req=None, link=None, data={self.dg.DOS_GUARD_INSTANCE_NAME: guard})
        sent.clear()
        resp = ctrl.clear_flows(types.SimpleNamespace())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.body.decode('utf-8')).get('cleared'), 1)
        dels = [m for m in sent if m.kind == 'flow_mod' and m.get('command') == FakeOfproto.OFPFC_DELETE]
        self.assertEqual(len(dels), len(guard._app_flow_cookies()))
        deleted_cookies = set()
        for m in dels:
            self.assertEqual(m['table_id'], FakeOfproto.OFPTT_ALL)
            self.assertEqual(m['cookie_mask'], 0xffffffffffffffff)
            deleted_cookies.add(m['cookie'])
        self.assertEqual(deleted_cookies, set(guard._app_flow_cookies()))
        # Restored base flows carry _base_flow_cookie and all 7 base rules restore cleanly
        adds = [m for m in sent if m.kind == 'flow_mod' and m.get('command') is None]
        self.assertGreaterEqual(len(adds), 6)
        self.assertTrue(all(m['cookie'] == guard._base_flow_cookie for m in adds))

    def test_vip_rl_priority_isolation_and_failsafe_non_bypass(self):
        guard = self._new_guard()
        # User rule 2.a: default stays False pending measurement approval
        self.assertFalse(guard.dp_vip_rate_limit_enabled)
        self.assertEqual(guard.dp_vip_other_meter_id, 13)
        self.assertIn(13, guard._managed_meter_ids())

        guard.vip_ip = '10.0.0.100'
        guard.dp_fastpath_enabled = True
        guard.dp_ctrl_meter_enabled = True
        guard.dp_vip_rate_limit_enabled = True
        guard.adaptive_vip_rl_enabled = True
        guard.ctrl_failsafe_enabled = True

        class FakeOfproto:
            OFPFC_ADD = 0
            OFPFC_DELETE = 3
            OFPFC_DELETE_STRICT = 4
            OFPTT_ALL = 0xff
            OFPP_ANY = 0xffffffff
            OFPG_ANY = 0xffffffff
            OFPP_NORMAL = 0xfffffffa
            OFPP_FLOOD = 0xfffffffb
            OFPP_CONTROLLER = 0xfffffffd
            OFPCML_NO_BUFFER = 0xffff
            OFP_NO_BUFFER = 0xffffffff
            OFPIT_METER = 6
            OFPIT_APPLY_ACTIONS = 4
            OFPMF_PKTPS = 2
            OFPMF_KBPS = 1
            OFPMF_STATS = 8
            OFPMC_ADD = 0
            OFPMC_MODIFY = 1

        sent = []

        class FakeMsg(dict):
            def __init__(self, kind, **kw):
                super().__init__(**kw)
                self.kind = kind
                self.xid = None

        class FakeParser:
            def OFPMatch(self, **kw):
                return dict(kw)

            def OFPActionOutput(self, port, max_len=0):
                return ('out', port)

            def OFPInstructionMeter(self, meter_id, type_=6):
                return ('meter', meter_id)

            def OFPInstructionActions(self, type_, actions):
                return ('actions', actions)

            def OFPMeterBandDrop(self, rate=0, burst_size=0):
                return types.SimpleNamespace(rate=rate, burst_size=burst_size)

            def OFPMeterMod(self, **kw):
                return FakeMsg('meter_mod', **kw)

            def OFPBarrierRequest(self, datapath):
                return FakeMsg('barrier_req', datapath=datapath)

            def OFPFlowMod(self, **kw):
                return FakeMsg('flow_mod', **kw)

        xseq = {'n': 1}
        dp = types.SimpleNamespace(id=1, ofproto=FakeOfproto, ofproto_parser=FakeParser())

        def fake_send(m):
            xseq['n'] += 1
            m.xid = xseq['n']
            sent.append(m)

        dp.send_msg = fake_send
        guard.datapaths[1] = dp

        # Activate both failsafe and adaptive VIP RL
        guard._set_failsafe_active(True, 100.0, 'pktin_pps:2500')
        guard._set_vip_rl_active(True, 100.0, 'pktin_pps:2500')

        vip_adds = [
            m for m in sent
            if m.kind == 'flow_mod' and m.get('command') is None and m.get('cookie') == guard._vip_rl_cookie
        ]
        prio89 = [m for m in vip_adds if m['priority'] == 89]
        prio90 = [m for m in vip_adds if m['priority'] == 90]
        self.assertEqual(len(prio89), 1)
        self.assertEqual(prio89[0]['match'], {'eth_type': 0x0800, 'ipv4_dst': '10.0.0.100'})
        # Dedicated meter 13 (NOT TCP 10, UDP 11, or ICMP 12) and OFPP_NORMAL-only during failsafe
        self.assertEqual(prio89[0]['instructions'][0], ('meter', 13))
        self.assertEqual(prio89[0]['instructions'][1], ('actions', [('out', FakeOfproto.OFPP_NORMAL)]))
        self.assertEqual(len(prio90), 4)  # UDP, ICMP, TCP 80, TCP 443
        meters_used = {m['instructions'][0][1] for m in prio90}
        self.assertEqual(meters_used, {10, 11, 12})

        # Failsafe flows stay strictly below priority 89 (85..87)
        fs_adds = [
            m for m in sent
            if m.kind == 'flow_mod' and m.get('command') is None and m.get('cookie') == guard._failsafe_cookie
        ]
        self.assertTrue(all(m['priority'] in (85, 86, 87) for m in fs_adds))

        # Failsafe cooldown restores CONTROLLER+NORMAL mirroring on VIP RL rules (keeping meters!)
        sent.clear()
        guard._set_failsafe_active(False, 115.0, 'cooldown')
        reinstalled = [
            m for m in sent
            if m.kind == 'flow_mod' and m.get('command') is None and m.get('cookie') == guard._vip_rl_cookie
        ]
        self.assertEqual(len(reinstalled), 5)
        for m in reinstalled:
            outs = m['instructions'][1][1]
            self.assertIn(('out', FakeOfproto.OFPP_CONTROLLER), outs)
            self.assertIn(('out', FakeOfproto.OFPP_NORMAL), outs)

    def test_vip_aggregate_spoof_flood_detection_baseline_cooldown_and_failover(self):
        guard = self._new_guard()
        ctrl = self.dg.DoSGuardWebController(types.SimpleNamespace(), None, {self.dg.DOS_GUARD_INSTANCE_NAME: guard})

        # 1. Invalid vip_agg bounds return HTTP 400; valid tuning returns 200 and appears in /dos/metrics
        bad = ctrl.update_config(types.SimpleNamespace(body=json.dumps({
            'vip_agg_min_unique_sources': 0,
            'vip_agg_baseline_alpha': 2.0,
        }).encode('utf-8')))
        self.assertEqual(bad.status_code, 400)

        good = ctrl.update_config(types.SimpleNamespace(body=json.dumps({
            'dp_vip_rl_enabled': True,
            'vip_agg_enabled': True,
            'vip_agg_pps_threshold': 300.0,
            'vip_agg_min_unique_sources': 10,
            'vip_agg_low_rate_max_pps': 30.0,
            'vip_agg_window_sec': 3.0,
            'vip_agg_sustain_intervals': 2,
            'vip_agg_cooldown_sec': 10.0,
            'vip_agg_baseline_enabled': True,
            'vip_agg_baseline_alpha': 0.25,
            'vip_agg_baseline_headroom': 1.0,
        }).encode('utf-8')))
        self.assertEqual(good.status_code, 200)
        self.assertTrue(guard.vip_agg_enabled)
        self.assertFalse(guard.vip_agg_failover_enabled)

        # Fake datapath + spy on hub.spawn to verify HA failover stays decoupled by default
        spawned_failovers = []
        orig_spawn = self.dg.hub.spawn
        try:
            def spy_spawn(fn, *args, **kwargs):
                spawned_failovers.append((getattr(fn, '__name__', str(fn)), args))
                return None

            self.dg.hub.spawn = spy_spawn
            guard.dp_fastpath_enabled = True
            guard.auto_failover_enabled = True
            guard.failover_cooldown_sec = 0.0

            sent = []
            class FakeOfproto:
                OFPFC_ADD = 0
                OFPFC_DELETE = 3
                OFPFC_DELETE_STRICT = 4
                OFPP_CONTROLLER = 0xfffffffd
                OFPP_NORMAL = 0xfffffffa
                OFPCML_NO_BUFFER = 0xffff
                OFPM_ALL = 0xffffffff
                OFPTT_ALL = 0xff
                OFPMC_ADD = 0
                OFPMC_MODIFY = 1
                OFPMC_DELETE = 2
                OFPMF_PKTPS = 2
                OFPMF_STATS = 8

            class FakeMsg:
                def __init__(self, kind, **kw):
                    self.kind = kind
                    self.kw = kw
            class FakeParser:
                OFPActionOutput = staticmethod(lambda p, max_len=0: ('out', p))
                OFPInstructionMeter = staticmethod(lambda meter_id: ('meter', meter_id))
                OFPInstructionActions = staticmethod(lambda t, a: ('actions', a))
                OFPMatch = staticmethod(lambda **kw: dict(kw))
                OFPMeterBandDrop = staticmethod(lambda rate=0, burst_size=0: ('drop', rate))
                OFPMeterMod = staticmethod(lambda **kw: FakeMsg('meter_mod', **kw))
                OFPFlowMod = staticmethod(lambda **kw: FakeMsg('flow_mod', **kw))
                OFPBarrierRequest = staticmethod(lambda dp: FakeMsg('barrier'))

            dp = types.SimpleNamespace(id=1, ofproto=FakeOfproto, ofproto_parser=FakeParser(), send_msg=lambda m: sent.append(m))
            guard.datapaths[1] = dp

            # 2. Normal distributed VIP client baseline (15 clients x 4 pps = 60 pps) -> adapts baseline, never triggers
            normal_clients = {f"10.0.1.{i}": 4 for i in range(1, 16)}
            for t in (1.0, 2.0, 3.0, 4.0):
                st = guard._evaluate_vip_aggregate(now=t, interval=1.0, vip_counts=normal_clients, vip_total_pkts=60)
                self.assertFalse(st['active'])
            self.assertGreater(st['baseline_rate'], 30.0)
            self.assertEqual([a for a in guard.alerts if a.get('type') == 'spoof_flood'], [])
            self.assertFalse(guard._vip_rl_active)

            # 3. Single transient spike above effective threshold (150 sources x 4 pps = 600 pps) for ONE interval -> rejected
            spoof_burst = {f"198.51.100.{i}": 4 for i in range(1, 151)}
            st_spike = guard._evaluate_vip_aggregate(now=5.0, interval=1.0, vip_counts=spoof_burst, vip_total_pkts=600)
            self.assertFalse(st_spike['active'])
            self.assertEqual(st_spike['sustain_count'], 1)
            st_rec = guard._evaluate_vip_aggregate(now=6.0, interval=1.0, vip_counts=normal_clients, vip_total_pkts=60)
            self.assertFalse(st_rec['active'])
            self.assertEqual(st_rec['sustain_count'], 0)
            self.assertEqual([a for a in guard.alerts if a.get('type') == 'spoof_flood'], [])

            # 4. Sustained --rand-source spoof flood (450 unique low-rate IPs x 1 pps = 450 pps >= ~345 effective thr)
            spoof_t1 = {f"203.0.{i // 250}.{1 + (i % 250)}": 1 for i in range(450)}
            spoof_t2 = {f"203.1.{i // 250}.{1 + (i % 250)}": 1 for i in range(450)}
            st_1 = guard._evaluate_vip_aggregate(now=7.0, interval=1.0, vip_counts=spoof_t1, vip_total_pkts=450)
            self.assertFalse(st_1['active'])
            st_2 = guard._evaluate_vip_aggregate(now=8.0, interval=1.0, vip_counts=spoof_t2, vip_total_pkts=450)
            self.assertTrue(st_2['active'])
            self.assertIn('vip_agg_spoof_flood(', st_2['reason'])
            self.assertIn('uniq_src=450', st_2['reason'])
            self.assertTrue(guard._vip_rl_active)
            # Crucially: individual spoofed IPs are NEVER blocked or quarantined, and failover stays decoupled
            self.assertEqual(len(guard.blocked_ips), 0)
            self.assertEqual(len(guard.quarantined_ips), 0)
            self.assertEqual(spawned_failovers, [])

            spoof_alerts = [a for a in guard.alerts if a.get('type') == 'spoof_flood']
            self.assertEqual(len(spoof_alerts), 1)
            self.assertEqual(spoof_alerts[0]['unique_sources'], 450)
            self.assertEqual(spoof_alerts[0]['low_rate_sources'], 450)

            # 5. Cooldown suppresses duplicate alert at t=10.0, permits new alert after t=18.5
            guard._evaluate_vip_aggregate(now=10.0, interval=1.0, vip_counts=spoof_t1, vip_total_pkts=450)
            self.assertEqual(len([a for a in guard.alerts if a.get('type') == 'spoof_flood']), 1)

            # 6. Explicit opt-in vip_agg_failover_enabled=True spawns HA failover once cooldown expires
            ctrl.update_config(types.SimpleNamespace(body=json.dumps({'vip_agg_failover_enabled': True}).encode('utf-8')))
            guard._evaluate_vip_aggregate(now=19.0, interval=1.0, vip_counts=spoof_t2, vip_total_pkts=450)
            self.assertEqual(len([a for a in guard.alerts if a.get('type') == 'spoof_flood']), 2)
            self.assertEqual(len(spawned_failovers), 1)
            self.assertEqual(spawned_failovers[0][1], ('spoof_flood',))

            # Metrics exposure check
            metrics_resp = ctrl.get_metrics(types.SimpleNamespace())
            metrics_body = json.loads(metrics_resp.body.decode('utf-8'))
            self.assertIn('vip_agg', metrics_body)
            self.assertTrue(metrics_body['vip_agg']['active'])
            self.assertTrue(metrics_body['config']['vip_agg_failover_enabled'])
        finally:
            self.dg.hub.spawn = orig_spawn

    def test_bounded_tracking_preserves_heavy_hitters_and_exact_vip_agg_counts(self):
        guard = self._new_guard()
        ctrl = self.dg.DoSGuardWebController(types.SimpleNamespace(), None, {self.dg.DOS_GUARD_INSTANCE_NAME: guard})

        # Config validation for Stage 5 parameters
        bad = ctrl.update_config(types.SimpleNamespace(body=json.dumps({
            'tracking_max_keys': 5,
            'ewma_low_rate_ttl_sec': 0.1,
        }).encode('utf-8')))
        self.assertEqual(bad.status_code, 400)

        good = ctrl.update_config(types.SimpleNamespace(body=json.dumps({
            'tracking_max_keys': 200,
            'ewma_low_rate_ttl_sec': 3.0,
            'ewma_singleton_pps': 5.0,
            'per_ip_port_history_cap': 64,
        }).encode('utf-8')))
        self.assertEqual(good.status_code, 200)

        t0 = 1000.0
        # Inject 1 genuine heavy hitter (10.0.0.4, 400 pkts to VIP), 1 portscanner (10.0.0.5, 64 distinct ports),
        # interleaved with 10,000 single-packet spoofed sources targeting VIP & SYN!
        for i in range(10000):
            if i < 400:
                guard._track_packet_source('ip:10.0.0.4', '10.0.0.4', now_ts=t0)
                guard._record_transport_dport('10.0.0.4', 80, track_portscan=True, is_syn=True)
            if i < 120:
                guard._track_packet_source('ip:10.0.0.5', None, now_ts=t0)
                guard._record_transport_dport('10.0.0.5', 1000 + i, track_portscan=True, is_syn=True)

            spoof_ip = f"198.{(i // 65025) & 255}.{(i // 255) % 255}.{1 + (i % 254)}"
            # Make every IP unique in formatting so 10,000 unique strings hit dicts
            a = 10 + (i // 60000)
            b = (i // 250) % 240
            c = 1 + (i % 250)
            uniq_spoof = f"172.{a % 250}.{b}.{c}"
            if i >= 10000:
                uniq_spoof = spoof_ip
            guard._track_packet_source(f"ip:{uniq_spoof}", uniq_spoof, now_ts=t0)
            guard._record_transport_dport(uniq_spoof, 80, track_portscan=True, is_syn=True)

        # Every structure strictly bounded under high_water (int(200 * 1.25) = 250)
        self.assertLess(len(guard.pkt_counts), 250)
        self.assertLess(len(guard.vip_pkt_counts), 250)
        self.assertLess(len(guard.syn_counts), 250)
        self.assertLess(len(guard.portscan_dports), 250)
        self.assertLess(len(guard.dport_hist), 250)
        self.assertGreater(guard._tracking_evictions_total, 9000)

        # Genuine heavy hitter (10.0.0.4) & portscanner (10.0.0.5) are preserved intact!
        self.assertEqual(guard.pkt_counts.get('ip:10.0.0.4'), 400)
        self.assertEqual(guard.syn_counts.get('10.0.0.4'), 400)
        # Per-IP port history capped at 64 despite 120 distinct ports probed
        self.assertEqual(len(guard.portscan_dports.get('10.0.0.5', set())), 64)
        self.assertEqual(len(guard.dport_hist.get('10.0.0.5', {})), 64)

        # Scalar VIP aggregate totals remain 100% exact despite eviction!
        self.assertEqual(guard._vip_interval_total_pkts, 10400)
        st_agg = guard._evaluate_vip_aggregate(
            now=t0 + 1.0,
            interval=1.0,
            vip_counts=guard.vip_pkt_counts,
            vip_total_pkts=guard._vip_interval_total_pkts,
            extra_unique_sources=guard._vip_overflow_unique_srcs,
            extra_low_rate_sources=guard._vip_overflow_low_rate_srcs,
        )
        self.assertEqual(st_agg['total_rate'], 10400.0)
        self.assertEqual(st_agg['unique_sources'], 10001)
        # 10,000 spoofed low-rate IPs preserved via overflow counter; 10.0.0.4 is 400 pps (>30) so low_rate_sources == 10,000
        self.assertEqual(st_agg['low_rate_sources'], 10000)

        # Simulate EWMA ingestion & capping: heavy hitter 10.0.0.4 must survive cap=200 + retain > singleton_pps
        for idx in range(300):
            guard.ewma[f"ip:192.0.{idx // 200}.{1 + (idx % 200)}"] = 0.3
            guard._src_last_seen[f"ip:192.0.{idx // 200}.{1 + (idx % 200)}"] = t0
        guard.ewma['ip:10.0.0.4'] = 120.0
        guard._src_last_seen['ip:10.0.0.4'] = t0
        guard._enforce_ewma_bounds(t0 + 1.0)
        self.assertLessEqual(len(guard.ewma), 200)
        self.assertIn('ip:10.0.0.4', guard.ewma)
        self.assertEqual(guard.ewma['ip:10.0.0.4'], 120.0)

        # Fast TTL expiry: after 3.0s, stale singletons (< 5 pps) expire even before classic 6s EWMA decay
        guard.pkt_counts.clear()
        alpha_val = float(guard.alpha or 0.3)
        now_later = t0 + 3.5
        for k in list(guard.ewma.keys()):
            ew = (1.0 - alpha_val) * float(guard.ewma[k])
            if ew < guard.ewma_singleton_pps and (now_later - guard._src_last_seen.get(k, now_later)) >= guard.ewma_low_rate_ttl_sec:
                guard.ewma.pop(k, None)
                guard._src_last_seen.pop(k, None)
            else:
                guard.ewma[k] = ew
        self.assertNotIn('ip:192.0.0.1', guard.ewma)
        self.assertIn('ip:10.0.0.4', guard.ewma)

    def test_failover_error_alert_sanitized_no_secret_or_url_leak(self):
        import types
        import requests

        guard = self._new_guard()
        guard.alerts = []

        # 1) F-17 Decoupling: _failover_to_backup emits failover_requested with ZERO outbound HTTP calls
        with mock.patch.object(self.dg.requests, 'post') as mock_post:
            guard._failover_to_backup('spoof_flood')
            mock_post.assert_not_called()

        self.assertEqual(len(guard.alerts), 1)
        a1 = guard.alerts[-1]
        self.assertEqual(a1['type'], 'failover_requested')
        self.assertEqual(a1['target'], 'backup')
        self.assertEqual(a1['reason'], 'spoof_flood')
        self.assertTrue(a1.get('boot_id'))
        self.assertEqual(a1.get('seq'), 1)
        self.assertEqual(a1.get('id'), f"{a1['boot_id']}-1")

        # 2) Error classifier sanitization: Timeout exception with internal URL + token in str(e)
        timeout_exc = requests.exceptions.Timeout(
            'Read timed out at http://127.0.0.1:9090/ha/active token=SecretTok999 /home/ubuntu/key'
        )
        code1 = guard._classify_request_error(timeout_exc)
        self.assertEqual(code1, 'timeout')
        for bad in ('127.0.0.1:9090', 'SecretTok999', '/home/ubuntu', 'Read timed out'):
            self.assertNotIn(bad, code1)

        # 3) Error classifier sanitization: ConnectionError with OS path / internal URL
        conn_exc = requests.exceptions.ConnectionError(
            'Max retries exceeded with url: /ha/active (http://127.0.0.1:9090) C:\\Users\\testuser\\secret'
        )
        code2 = guard._classify_request_error(conn_exc)
        self.assertEqual(code2, 'connection_refused')
        for bad in ('127.0.0.1:9090', 'Max retries', 'C:\\Users\\testuser'):
            self.assertNotIn(bad, code2)

        # 4) Error classifier sanitization: SSLError and RequestException
        ssl_exc = requests.exceptions.SSLError('certificate verify failed at internal-ca.local')
        code3 = guard._classify_request_error(ssl_exc)
        self.assertEqual(code3, 'tls_error')

        req_exc = requests.exceptions.RequestException('arbitrary failure')
        code4 = guard._classify_request_error(req_exc)
        self.assertEqual(code4, 'request_failed')


if __name__ == '__main__':
    unittest.main()
