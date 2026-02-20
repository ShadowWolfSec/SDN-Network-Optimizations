# Ryu app: DoS Guard with rate-based anomaly detection (EWMA) and dynamic blocking
# Tested with OpenFlow 1.3 (OVS in Mininet)

from collections import Counter, defaultdict, deque
import json
import os
import re
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, udp, icmp

# REST API
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response


DOS_GUARD_INSTANCE_NAME = 'dos_guard_app'
MININET_RUNNER_BASE = os.getenv('MININET_RUNNER_BASE', 'http://127.0.0.1:9090').rstrip('/')



# Modularized Level 2 Architecture Imports
from ryu_app.detection import (
    calculate_ewma,
    calculate_pps,
    enforce_ewma_bounds,
    is_anomaly,
    count_score_fn,
    is_heavy_key,
    evaluate_port_scan,
    classify_trigger,
)
from ryu_app.mitigation import (
    build_flow_mod,
    build_ip_drop_match,
    build_mac_drop_match,
    build_meter_mod,
    build_delete_flow_strict,
    build_delete_flows_by_cookie,
)
from core.common_utils import (
    load_internal_token,
    validate_ipv4,
    validate_mac,
    parse_bool,
)
# Helper Functions, Environment Parsers & Concurrency Semaphores (extracted to ryu_app/helpers.py)
from ryu_app.helpers import (
    _create_whitelist_semaphore,
    _load_internal_token,
    _internal_headers,
    _env_bool,
    _env_int,
    _env_float,
    _env_csv_ints,
    _validate_ipv4,
    _validate_mac,
)
from ryu_app.flow_manager import FlowManagerMixin
from ryu_app.traffic_tracker import TrafficTrackerMixin
from ryu_app.mitigation_manager import MitigationManagerMixin
from ryu_app.monitor_engine import MonitorEngineMixin


class DoSGuard(
    MonitorEngineMixin,
    MitigationManagerMixin,
    TrafficTrackerMixin,
    FlowManagerMixin,
    app_manager.RyuApp,
):
    """SDN DoS/DDoS Guard with EWMA-based anomaly detection and dynamic mitigation.
    
    This Ryu controller implements:
    - Rate-based anomaly detection using EWMA (Exponentially Weighted Moving Average)
    - SYN flood, UDP flood, and portscan detection
    - Dynamic IP blocking via OpenFlow rules
    - DDoS multi-source attack detection
    - VIP rate limiting and controller failsafe mechanisms
    - High-availability failover support
    
    Core detection logic uses PPS thresholds, entropy analysis, and port scanning detection.
    All network behavior (FlowMods/MeterMods) remains unchanged from original implementation.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication,
    }

    def __init__(self, *args, **kwargs):
        """Initialize DoS Guard with environment-based configuration."""
        super(DoSGuard, self).__init__(*args, **kwargs)
        self.name = 'dos_guard'
        self.datapaths: Dict[int, Any] = {}
        self.mac_to_port: Dict[int, Dict[str, int]] = defaultdict(dict)

        self.learning_enabled = _env_bool('LEARNING_ENABLE', False)

        self.dp_fastpath_enabled = _env_bool('DP_FASTPATH_ENABLE', False)
        self.dp_mirror_vip_all = _env_bool('DP_MIRROR_VIP_ALL', True)
        self.dp_mirror_tcp_dports = _env_csv_ints('DP_MIRROR_TCP_DPORTS', '80,443')
        self.dp_mirror_udp = _env_bool('DP_MIRROR_UDP', True)
        self.dp_mirror_icmp = _env_bool('DP_MIRROR_ICMP', True)

        self.dp_ctrl_meter_enabled = _env_bool('DP_CTRL_METER_ENABLE', False)
        self.dp_ctrl_meter_id = _env_int('DP_CTRL_METER_ID', 1)
        self.dp_ctrl_meter_pps = _env_int('DP_CTRL_METER_PPS', 2500)

        self.dp_vip_rate_limit_enabled = _env_bool('DP_VIP_RL_ENABLE', False)
        self.dp_vip_tcp_meter_id = _env_int('DP_VIP_TCP_METER_ID', 10)
        self.dp_vip_tcp_pps = _env_int('DP_VIP_TCP_PPS', 800)
        self.dp_vip_udp_meter_id = _env_int('DP_VIP_UDP_METER_ID', 11)
        self.dp_vip_udp_pps = _env_int('DP_VIP_UDP_PPS', 1200)
        self.dp_vip_icmp_meter_id = _env_int('DP_VIP_ICMP_METER_ID', 12)
        self.dp_vip_icmp_pps = _env_int('DP_VIP_ICMP_PPS', 200)
        self.dp_vip_other_meter_id = _env_int('DP_VIP_OTHER_METER_ID', 13)
        self.dp_vip_other_pps = _env_int('DP_VIP_OTHER_PPS', 500)

        self.adaptive_vip_rl_enabled = _env_bool('ADAPTIVE_VIP_RL_ENABLE', True)
        self.adaptive_vip_rl_hold_sec = _env_float('ADAPTIVE_VIP_RL_HOLD_SEC', 20.0)
        self._vip_rl_active = False
        self._vip_rl_last_ts = 0.0
        self._vip_rl_cookie = int(os.getenv('ADAPTIVE_VIP_RL_COOKIE', '424242') or '424242')

        self.ctrl_failsafe_enabled = _env_bool('CTRL_FAILSAFE_ENABLE', True)
        self.ctrl_failsafe_pktin_pps = _env_float('CTRL_FAILSAFE_PKTIN_PPS', 2000.0)
        self.ctrl_failsafe_hold_sec = _env_float('CTRL_FAILSAFE_HOLD_SEC', 10.0)
        self._failsafe_active = False
        self._failsafe_last_ts = 0.0
        self._failsafe_cookie = int(os.getenv('CTRL_FAILSAFE_COOKIE', '424243') or '424243')

        self._pktin_interval_count = 0
        self._last_pktin_pps = 0.0

        # Detection and control state
        self.measure_interval: float = 1.0
        self.pps_threshold: float = 300.0
        self.alpha: float = 0.3
        self.syn_threshold: float = 200.0
        self.udp_threshold: float = 400.0
        self.portscan_threshold: int = 50
        self.block_duration_sec: float = 120.0
        self.mitigation_enabled: bool = _env_bool('MITIGATION_ENABLE', True)

        self.quarantine_enabled: bool = _env_bool('QUARANTINE_ENABLE', False)
        self.quarantine_meter_id: int = _env_int('QUARANTINE_METER_ID', 20)
        self.quarantine_pps: int = _env_int('QUARANTINE_PPS', 150)
        self.quarantine_duration_sec: float = _env_float('QUARANTINE_DURATION_SEC', 60.0)
        self._base_flow_cookie: int = int(os.getenv('BASE_FLOW_COOKIE', '424240') or '424240')
        self._learned_flow_cookie: int = int(os.getenv('LEARNED_FLOW_COOKIE', '424241') or '424241')
        self._quarantine_cookie: int = int(os.getenv('QUARANTINE_COOKIE', '424244') or '424244')
        self._block_ip_cookie: int = int(os.getenv('BLOCK_IP_COOKIE', '424245') or '424245')
        self._block_mac_cookie: int = int(os.getenv('BLOCK_MAC_COOKIE', '424246') or '424246')
        self._installed_block_ip_specs: Dict[Tuple[int, str], Tuple[int, int]] = {}
        self._installed_quarantine_specs: Dict[Tuple[int, str], Tuple[int, int]] = {}
        self._installed_block_mac_specs: Dict[Tuple[int, str], Tuple[int, int]] = {}
        self._installed_vip_rl_specs: Dict[int, List[Tuple[int, int, Any]]] = defaultdict(list)
        self._installed_failsafe_specs: Dict[int, List[Tuple[int, int, Any]]] = defaultdict(list)
        self._installed_meters: Dict[int, Dict[int, Dict[str, Any]]] = defaultdict(dict)
        self._switch_meters: Dict[int, Dict[int, Dict[str, Any]]] = defaultdict(dict)
        self._external_meters: Dict[int, Dict[int, Dict[str, Any]]] = defaultdict(dict)
        self._meter_sync_pending: Dict[int, int] = {}
        self._meter_sync_buffer: Dict[int, Dict[int, Dict[str, Any]]] = defaultdict(dict)
        self._meter_sync_seq: int = 0
        self._pending_of_ops: Dict[Tuple[int, int], Dict[str, Any]] = {}
        self._pending_barriers: Dict[Tuple[int, int], Dict[str, Any]] = {}
        self._of_errors: deque = deque(maxlen=100)
        self.quarantined_ips: Set[str] = set()
        self.quarantined_info: Dict[str, Dict[str, Any]] = {}

        self.entropy_enabled: bool = _env_bool('ENTROPY_ENABLE', False)
        self.entropy_threshold: float = _env_float('ENTROPY_THRESHOLD', 3.5)
        self.entropy_min_ports: int = _env_int('ENTROPY_MIN_PORTS', 20)
        self.port_entropy: Dict[str, float] = {}

        self.auto_failover_enabled: bool = _env_bool('AUTO_FAILOVER_ENABLE', False)
        self.failover_cooldown_sec: float = 10.0
        self._last_failover_ts: float = 0.0

        self.ddos_source_threshold: int = _env_int('DDOS_SOURCE_THRESHOLD', 4)
        self.ddos_min_pps_per_source: float = _env_float('DDOS_MIN_PPS_PER_SOURCE', 30.0)
        self.ddos_alert_cooldown_sec: float = 5.0
        self._last_ddos_alert_ts: float = 0.0
        self.ddos_stats: Dict[str, Any] = {}

        self.vip_ip: str = (os.getenv('VIP_IP') or os.getenv('HA_VIP_IP') or '10.0.0.100').strip()
        self.ddos_vip_only: bool = _env_bool('DDOS_VIP_ONLY', True)
        self.ddos_mitigation_enabled: bool = _env_bool('DDOS_MITIGATION_ENABLE', True)
        self.ddos_block_top_n: int = _env_int('DDOS_BLOCK_TOP_N', 6)
        self.ddos_block_duration_sec: float = _env_float('DDOS_BLOCK_DURATION_SEC', self.block_duration_sec)

        # Aggregate VIP / spoofed-source detector (Stage 4 / F-13c: experimental configurable params)
        self.vip_agg_enabled: bool = _env_bool('VIP_AGG_ENABLE', True)
        self.vip_agg_pps_threshold: float = _env_float('VIP_AGG_PPS_THRESHOLD', 300.0)
        self.vip_agg_min_unique_sources: int = _env_int('VIP_AGG_MIN_SOURCES', 10)
        self.vip_agg_low_rate_max_pps: float = _env_float('VIP_AGG_LOW_RATE_MAX_PPS', 30.0)
        self.vip_agg_window_sec: float = _env_float('VIP_AGG_WINDOW_SEC', 3.0)
        self.vip_agg_sustain_intervals: int = _env_int('VIP_AGG_SUSTAIN_INTERVALS', 2)
        self.vip_agg_cooldown_sec: float = _env_float('VIP_AGG_COOLDOWN_SEC', 10.0)
        self.vip_agg_baseline_enabled: bool = _env_bool('VIP_AGG_BASELINE_ENABLE', True)
        self.vip_agg_baseline_alpha: float = _env_float('VIP_AGG_BASELINE_ALPHA', 0.15)
        self.vip_agg_baseline_headroom: float = _env_float('VIP_AGG_BASELINE_HEADROOM', 1.0)
        self.vip_agg_failover_enabled: bool = _env_bool('VIP_AGG_FAILOVER_ENABLE', False)
        self._vip_agg_window: deque = deque()
        self._vip_agg_consec: int = 0
        self._vip_agg_baseline_pps: float = 0.0
        self._last_vip_agg_alert_ts: float = 0.0
        self._last_vip_agg_reason: str = ''
        self._vip_interval_total_pkts: int = 0
        self.vip_agg_stats: Dict[str, Any] = {}

        # Bounded per-source tracking & heavy-hitter preservation (Stage 5 / F-13d)
        self.tracking_max_keys: int = _env_int('TRACKING_MAX_KEYS', 2000)
        self.ewma_low_rate_ttl_sec: float = _env_float('EWMA_LOW_RATE_TTL_SEC', 3.0)
        self.ewma_singleton_pps: float = _env_float('EWMA_SINGLETON_PPS', 5.0)
        self.per_ip_port_history_cap: int = _env_int('PER_IP_PORT_HISTORY_CAP', 1024)
        self._src_last_seen: Dict[str, float] = {}
        self._vip_overflow_unique_srcs: int = 0
        self._vip_overflow_low_rate_srcs: int = 0
        self._tracking_evictions_total: int = 0
        self._tracking_evictions_interval: int = 0
        self._tracking_stats: Dict[str, Any] = {}

        self.pkt_counts: Dict[str, int] = defaultdict(int)
        self.vip_pkt_counts: Dict[str, int] = defaultdict(int)
        self.syn_counts: Dict[str, int] = defaultdict(int)
        self.udp_counts: Dict[str, int] = defaultdict(int)
        self.portscan_dports: Dict[str, Set[int]] = defaultdict(set)
        self.dport_hist: Dict[str, Counter] = defaultdict(Counter)
        self.rates: Dict[str, float] = defaultdict(float)
        self.syn_rates: Dict[str, float] = defaultdict(float)
        self.udp_rates: Dict[str, float] = defaultdict(float)
        self.uniq_dports: Dict[str, int] = defaultdict(int)
        self.ewma: Dict[str, float] = defaultdict(float)
        self.blocked_ips: Set[str] = set()
        self.blocked_macs: Set[str] = set()
        self.blocked_info: Dict[str, Dict[str, Any]] = {}
        self.whitelist_ips: Set[str] = set()
        self._whitelist_sem = _create_whitelist_semaphore()
        self._whitelist_state_version: int = 0
        self._whitelist_last_request_id: Optional[str] = None
        self._whitelist_last_updated_ts: float = 0.0
        self._whitelist_history: deque = deque(maxlen=20)
        self.alerts: deque = deque(maxlen=200)
        self.boot_id: str = secrets.token_hex(16)
        self._alert_seq: int = 0
        self._alert_lock = threading.Lock()
        self.last_packets: deque = deque(maxlen=200)
        self.total_packet_ins: int = 0

        self.drop_priority: int = 40000  # higher than any learning rule

        self.stats_poll_interval_sec: float = _env_float('STATS_POLL_INTERVAL_SEC', 5.0)
        self._last_stats_poll_ts: float = 0.0

        # REST wiring
        wsgi = kwargs['wsgi']
        wsgi.registory = getattr(wsgi, 'registory', {})
        wsgi.registory[DOS_GUARD_INSTANCE_NAME] = self
        mapper = wsgi.mapper
        wsgi.register(DoSGuardWebController, {DOS_GUARD_INSTANCE_NAME: self})

        self.flow_stats_summary: Dict[int, Dict[str, Any]] = {}
        self.port_stats_summary: Dict[int, List[Dict[str, Any]]] = {}
        # Start monitor thread
        self.monitor_thread = hub.spawn(self._monitor)

    def _emit_alert(self, alert_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Emit alert with monotonic sequence ID and boot session ID under atomic lock."""
        if not isinstance(alert_dict, dict):
            return alert_dict
        with self._alert_lock:
            self._alert_seq += 1
            seq = self._alert_seq
            alert_dict['seq'] = seq
            alert_dict['boot_id'] = self.boot_id
            alert_dict['id'] = f"{self.boot_id}-{seq}"
            self.alerts.append(alert_dict)
            return alert_dict

    def _is_protected_ip(self, ip_addr: str) -> bool:
        """Return True if IP is whitelisted or matches the protected VIP."""
        if not ip_addr:
            return False
        s = str(ip_addr).strip()
        sem = getattr(self, '_whitelist_sem', None)
        if sem:
            with sem:
                if s in self.whitelist_ips:
                    return True
        else:
            if s in self.whitelist_ips:
                return True
        if self.vip_ip and s == str(self.vip_ip).strip():
            return True
        return False

    def reset_runtime_counters(self) -> None:
        """Reset all runtime counters and statistics.
        
        Used to clear accumulated metrics without changing configuration.
        """
        self.pkt_counts = defaultdict(int)
        self.vip_pkt_counts = defaultdict(int)
        self.syn_counts = defaultdict(int)
        self.udp_counts = defaultdict(int)
        self.portscan_dports = defaultdict(set)
        self.dport_hist = defaultdict(Counter)
        self.rates = defaultdict(float)
        self.syn_rates = defaultdict(float)
        self.udp_rates = defaultdict(float)
        self.uniq_dports = defaultdict(int)
        self.port_entropy = {}
        self.total_packet_ins = 0
        self._pktin_interval_count = 0
        self._last_pktin_pps = 0.0
        self.ddos_stats = {}
        self.vip_agg_stats = {}
        self._vip_agg_window.clear()
        self._vip_agg_consec = 0
        self._vip_agg_baseline_pps = 0.0
        self._last_vip_agg_alert_ts = 0.0
        self._last_vip_agg_reason = ''
        self._vip_interval_total_pkts = 0
        self._vip_overflow_unique_srcs = 0
        self._vip_overflow_low_rate_srcs = 0
        self._tracking_evictions_total = 0
        self._tracking_evictions_interval = 0
        self._tracking_stats = {}
        self._src_last_seen = {k: v for k, v in self._src_last_seen.items() if k in self.ewma}
        self.alerts.clear()
        self.last_packets.clear()
        self.flow_stats_summary = {}
        self.port_stats_summary = {}

    # OpenFlow Flow & Meter Operations provided by FlowManagerMixin (ryu_app/flow_manager.py)

    def _security_log(self, event: str, **fields):
        try:
            rec = {'event': str(event), 'ts': float(time.time())}
            for k, v in dict(fields or {}).items():
                rec[str(k)] = v
            fam = str(rec.get('family') or '').strip().lower()
            if not fam:
                ev = str(event or '').strip().lower()
                fam = 'ddos' if ev.startswith('ddos') else 'dos'
            tag = 'DDoS' if fam == 'ddos' else 'DoS'
            self.logger.warning('[%s] %s', tag, json.dumps(rec, ensure_ascii=False, sort_keys=True))
        except Exception:
            try:
                fam = str((fields or {}).get('family') or '').strip().lower()
                if not fam:
                    ev = str(event or '').strip().lower()
                    fam = 'ddos' if ev.startswith('ddos') else 'dos'
                tag = 'DDoS' if fam == 'ddos' else 'DoS'
                self.logger.warning('[%s] %s %s', tag, str(event), str(fields))
            except Exception:
                pass
# Re-export for backward compatibility
from ryu_app.web_controller import DoSGuardWebController
