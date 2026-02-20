"""
tests/test_ryu_detection_pure.py
================================
Pure Python unit tests for ryu_app.detection and ryu_app.mitigation.
Validates math, EWMA, thresholds, LRU scores, and message builder structures
without requiring Ryu, Eventlet, or Mininet.
"""

import unittest
from unittest.mock import MagicMock

from ryu_app.detection import (
    calculate_ewma,
    calculate_pps,
    is_anomaly,
    evaluate_port_scan,
    classify_trigger,
    is_heavy_key,
    count_score_fn,
    enforce_ewma_bounds,
)
from ryu_app.mitigation import (
    build_ip_drop_match,
    build_mac_drop_match,
    build_flow_mod,
    build_meter_mod,
    build_delete_flow_strict,
    build_delete_flows_by_cookie,
)


class TestPureDetectionEngine(unittest.TestCase):
    """Tests for pure statistical and anomaly detection engine."""

    def test_calculate_ewma_standard_and_clamping(self):
        # Standard calculation: alpha=0.3, rate=100.0, prev=50.0 -> 0.3*100 + 0.7*50 = 30 + 35 = 65.0
        self.assertAlmostEqual(calculate_ewma(100.0, 50.0, 0.3), 65.0, places=5)
        # alpha=1.0 -> exactly current rate
        self.assertAlmostEqual(calculate_ewma(100.0, 50.0, 1.0), 100.0, places=5)
        # alpha=0.0 -> exactly prev EWMA
        self.assertAlmostEqual(calculate_ewma(100.0, 50.0, 0.0), 50.0, places=5)
        # alpha > 1.0 clamped to 1.0
        self.assertAlmostEqual(calculate_ewma(100.0, 50.0, 1.5), 100.0, places=5)
        # alpha < 0.0 clamped to 0.0
        self.assertAlmostEqual(calculate_ewma(100.0, 50.0, -0.5), 50.0, places=5)

    def test_calculate_pps(self):
        # 100 packets in 2.0 seconds -> 50.0 pps
        self.assertAlmostEqual(calculate_pps(100, 2.0), 50.0, places=5)
        # 0 time delta -> 0.0 (prevents division by zero)
        self.assertEqual(calculate_pps(100, 0.0), 0.0)
        # Negative time delta -> 0.0
        self.assertEqual(calculate_pps(100, -1.5), 0.0)

    def test_is_anomaly(self):
        self.assertTrue(is_anomaly(150.0, 100.0))
        self.assertTrue(is_anomaly(100.0, 100.0))
        self.assertFalse(is_anomaly(99.9, 100.0))

    def test_evaluate_port_scan(self):
        self.assertFalse(evaluate_port_scan(None, 10))
        self.assertFalse(evaluate_port_scan(set(), 10))
        self.assertFalse(evaluate_port_scan({80, 443, 22}, 5))
        self.assertTrue(evaluate_port_scan({80, 443, 22, 8080, 8443}, 5))
        self.assertTrue(evaluate_port_scan([1, 2, 3, 4, 5, 6], 5))

    def test_classify_trigger(self):
        self.assertEqual(classify_trigger('pps_threshold_exceeded'), ('dos', 'pps_flood'))
        self.assertEqual(classify_trigger('syn_rate_exceeded'), ('dos', 'syn_flood'))
        self.assertEqual(classify_trigger('udp_rate_exceeded'), ('dos', 'udp_flood'))
        self.assertEqual(classify_trigger('portscan_detected'), ('dos', 'port_scan'))
        self.assertEqual(classify_trigger('entropy_high'), ('dos', 'entropy_scan'))
        self.assertEqual(classify_trigger('ddos_detected'), ('ddos', 'multi_source_flood'))
        self.assertEqual(classify_trigger('spoof_flood'), ('ddos', 'spoof_flood'))
        # Unknown fallback
        self.assertEqual(classify_trigger('custom_unknown'), ('dos', 'custom_unknown'))
        self.assertEqual(classify_trigger(''), ('dos', 'unknown'))

    def test_is_heavy_key_protection_and_classification(self):
        ewma_map = {'ip:10.0.0.5': 25.0, 'ip:10.0.0.6': 2.0}
        protected = {'10.0.0.1'}
        blocked = {'10.0.0.2'}
        quarantined = {'10.0.0.3'}

        # Protected IP
        prot, heavy = is_heavy_key('10.0.0.1', ewma_map, singleton_thr=5.0, protected_ips=protected)
        self.assertEqual(prot, 1)

        # Blocked IP
        prot, heavy = is_heavy_key('10.0.0.2', ewma_map, singleton_thr=5.0, blocked_ips=blocked)
        self.assertEqual(prot, 1)

        # Quarantined IP
        prot, heavy = is_heavy_key('10.0.0.3', ewma_map, singleton_thr=5.0, quarantined_ips=quarantined)
        self.assertEqual(prot, 1)

        # Normal heavy IP (>= 5.0)
        prot, heavy = is_heavy_key('10.0.0.5', ewma_map, singleton_thr=5.0)
        self.assertEqual(prot, 0)
        self.assertEqual(heavy, 1)

        # Normal light IP (< 5.0)
        prot, heavy = is_heavy_key('10.0.0.6', ewma_map, singleton_thr=5.0)
        self.assertEqual(prot, 0)
        self.assertEqual(heavy, 0)

        # MAC key
        prot, heavy = is_heavy_key('mac:00:11:22:33:44:55', ewma_map, singleton_thr=5.0)
        self.assertEqual(prot, 0)

    def test_count_score_fn(self):
        score = count_score_fn('10.0.0.1', 42, 1, 1)
        self.assertEqual(score, (1, 1, 42))

        # Invalid count falls back to 0
        score_bad = count_score_fn('10.0.0.2', None, 0, 0)
        self.assertEqual(score_bad, (0, 0, 0))

    def test_enforce_ewma_bounds(self):
        ewma_map = {'a': 1.0, 'b': 2.0, 'c': 3.0}
        src_last_seen = {'a': 10.0, 'b': 20.0, 'c': 30.0, 'stale': 5.0}

        def mock_prune(store, cap, key_fn, on_evict=None, trim_to_cap=True):
            while len(store) > cap:
                evicted_key = sorted(store.keys())[0]
                store.pop(evicted_key)
                if on_evict:
                    on_evict(evicted_key, None)

        enforce_ewma_bounds(
            ewma_map=ewma_map,
            src_last_seen=src_last_seen,
            cap=2,
            is_heavy_fn=lambda k: (0, 0),
            prune_fn=mock_prune,
        )

        self.assertLessEqual(len(ewma_map), 2)
        # 'stale' key should be cleaned from src_last_seen because it wasn't in ewma_map
        self.assertNotIn('stale', src_last_seen)
        self.assertNotIn('a', src_last_seen)


class TestPureMitigationBuilders(unittest.TestCase):
    """Tests for OpenFlow 1.3 message builders in ryu_app.mitigation."""

    def setUp(self):
        self.mock_parser = MagicMock()
        self.mock_ofproto = MagicMock()
        self.mock_ofproto.OFP_VERSION = 0x04
        self.mock_ofproto.OFPFC_ADD = 0
        self.mock_ofproto.OFPFC_DELETE = 3
        self.mock_ofproto.OFPFC_DELETE_STRICT = 4
        self.mock_ofproto.OFPP_ANY = 0xFFFFFFFF
        self.mock_ofproto.OFPG_ANY = 0xFFFFFFFF
        self.mock_ofproto.OFPMF_PKTPS = 0x0002
        self.mock_ofproto.OFPMF_BURST = 0x0004
        self.mock_ofproto.OFPIT_APPLY_ACTIONS = 4

        self.mock_dp = MagicMock()
        self.mock_dp.ofproto = self.mock_ofproto
        self.mock_dp.ofproto_parser = self.mock_parser

    def test_build_ip_drop_match(self):
        build_ip_drop_match(self.mock_parser, self.mock_ofproto, '192.168.1.10')
        self.mock_parser.OFPMatch.assert_called_once_with(eth_type=0x0800, ipv4_src='192.168.1.10')

    def test_build_mac_drop_match(self):
        build_mac_drop_match(self.mock_parser, self.mock_ofproto, '00:AA:BB:CC:DD:EE')
        self.mock_parser.OFPMatch.assert_called_once_with(eth_src='00:aa:bb:cc:dd:ee')

    def test_build_flow_mod(self):
        match = MagicMock()
        build_flow_mod(
            dp=self.mock_dp,
            priority=100,
            match=match,
            table_id=0,
            idle_timeout=30,
            hard_timeout=60,
            cookie=0xCAFE,
        )
        self.mock_parser.OFPFlowMod.assert_called_once()
        _, kwargs = self.mock_parser.OFPFlowMod.call_args
        self.assertEqual(kwargs['priority'], 100)
        self.assertEqual(kwargs['table_id'], 0)
        self.assertEqual(kwargs['idle_timeout'], 30)
        self.assertEqual(kwargs['hard_timeout'], 60)
        self.assertEqual(kwargs['cookie'], 0xCAFE)

    def test_build_meter_mod(self):
        build_meter_mod(
            dp=self.mock_dp,
            meter_id=10,
            rate_pps=500,
            burst_size=50,
        )
        self.mock_parser.OFPMeterBandDrop.assert_called_once_with(rate=500, burst_size=50)
        self.mock_parser.OFPMeterMod.assert_called_once()
        _, kwargs = self.mock_parser.OFPMeterMod.call_args
        self.assertEqual(kwargs['meter_id'], 10)
        self.assertEqual(kwargs['flags'], 0x0002 | 0x0004)

    def test_build_delete_flow_strict(self):
        match = MagicMock()
        build_delete_flow_strict(
            dp=self.mock_dp,
            priority=100,
            match=match,
            table_id=0,
        )
        self.mock_parser.OFPFlowMod.assert_called_once()
        _, kwargs = self.mock_parser.OFPFlowMod.call_args
        self.assertEqual(kwargs['command'], 4)
        self.assertEqual(kwargs['priority'], 100)
        self.assertEqual(kwargs['out_port'], 0xFFFFFFFF)
        self.assertEqual(kwargs['out_group'], 0xFFFFFFFF)

    def test_build_delete_flows_by_cookie(self):
        build_delete_flows_by_cookie(
            dp=self.mock_dp,
            cookie=0xFEED,
            table_id=0,
        )
        self.mock_parser.OFPFlowMod.assert_called_once()
        _, kwargs = self.mock_parser.OFPFlowMod.call_args
        self.assertEqual(kwargs['command'], 3)
        self.assertEqual(kwargs['cookie'], 0xFEED)
        self.assertEqual(kwargs['cookie_mask'], 0xFFFFFFFFFFFFFFFF)


if __name__ == '__main__':
    unittest.main()
