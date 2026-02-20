"""
ryu_app/monitor_engine.py
Anomaly detection monitor loop, EWMA decay, and HA failover coordination.
"""

from collections import Counter, defaultdict
import math
import time
from typing import Any, Dict, List, Optional, Tuple

import sys

import requests
from ryu.lib import hub as _default_hub


def _get_hub():
    """Retrieve hub module, dynamically resolving to ryu_app.dos_guard.hub for mock compatibility."""
    dg = sys.modules.get('ryu_app.dos_guard')
    if dg is not None and hasattr(dg, 'hub'):
        return dg.hub
    return _default_hub


class MonitorEngineMixin:
    """Mixin providing periodic anomaly detection monitoring, EWMA tracking, and HA failover."""

    def _evaluate_vip_aggregate(
        self,
        now: float,
        interval: float,
        vip_counts: Dict[str, int],
        vip_total_pkts: int = 0,
        extra_unique_sources: int = 0,
        extra_low_rate_sources: int = 0,
    ) -> Dict[str, Any]:
        """Evaluate aggregate VIP packet rate and low-rate unique source spread (F-13c)."""
        dt = max(0.1, float(interval or 1.0))
        vip_ip = str(getattr(self, 'vip_ip', '') or '')
        enabled = bool(getattr(self, 'vip_agg_enabled', True)) and bool(vip_ip)
        if not enabled:
            self._vip_agg_consec = 0
            self.vip_agg_stats = {
                'time': float(now),
                'enabled': False,
                'active': False,
                'vip_ip': vip_ip,
                'total_rate': 0.0,
                'window_avg_rate': 0.0,
                'baseline_rate': float(getattr(self, '_vip_agg_baseline_pps', 0.0) or 0.0),
                'effective_threshold': float(getattr(self, 'vip_agg_pps_threshold', 300.0) or 0.0),
                'unique_sources': 0,
                'low_rate_sources': 0,
                'sustain_count': 0,
                'reason': '',
            }
            return self.vip_agg_stats

        protected_pkts = 0
        uniq_sources = max(0, int(extra_unique_sources or 0))
        low_rate_sources = max(0, int(extra_low_rate_sources or 0))
        low_max = max(0.0, float(getattr(self, 'vip_agg_low_rate_max_pps', 30.0) or 0.0))

        for ip_addr, cnt in (vip_counts or {}).items():
            ip_str = str(ip_addr or '')
            if not ip_str:
                continue
            try:
                c_val = int(cnt or 0)
            except Exception:
                c_val = 0
            if self._is_protected_ip(ip_str):
                protected_pkts += c_val
                continue
            uniq_sources += 1
            if c_val > 0 and (low_max <= 0.0 or (float(c_val) / dt) <= low_max):
                low_rate_sources += 1

        tracked_sum = 0
        for c in (vip_counts or {}).values():
            try:
                tracked_sum += int(c or 0)
            except Exception:
                pass
        raw_total = max(int(vip_total_pkts or 0), tracked_sum)
        agg_pkts = max(0, raw_total - protected_pkts)
        vip_pps = float(agg_pkts) / dt

        win_sec = max(0.5, float(getattr(self, 'vip_agg_window_sec', 3.0) or 3.0))
        self._vip_agg_window.append((float(now), float(vip_pps), int(uniq_sources), int(low_rate_sources)))
        while len(self._vip_agg_window) > 1 and (float(now) - float(self._vip_agg_window[0][0])) > win_sec:
            self._vip_agg_window.popleft()
        win_avg_pps = sum(s[1] for s in self._vip_agg_window) / float(len(self._vip_agg_window))

        baseline_enabled = bool(getattr(self, 'vip_agg_baseline_enabled', True))
        baseline = float(getattr(self, '_vip_agg_baseline_pps', 0.0) or 0.0)
        raw_thr = max(0.0, float(getattr(self, 'vip_agg_pps_threshold', 300.0) or 0.0))
        headroom = max(0.0, float(getattr(self, 'vip_agg_baseline_headroom', 1.0) or 0.0))
        eff_thr = raw_thr + (baseline * headroom if baseline_enabled else 0.0)

        min_uniq = max(1, int(getattr(self, 'vip_agg_min_unique_sources', 10) or 10))
        distributed_ok = (uniq_sources >= min_uniq) and (low_max <= 0.0 or low_rate_sources >= min_uniq)
        interval_anomalous = (raw_thr > 0.0) and distributed_ok and (vip_pps >= eff_thr)
        raw_anomalous = (raw_thr > 0.0) and distributed_ok and (vip_pps >= raw_thr)

        if interval_anomalous:
            self._vip_agg_consec = int(getattr(self, '_vip_agg_consec', 0) or 0) + 1
        else:
            self._vip_agg_consec = 0
            if not raw_anomalous and baseline_enabled:
                b_alpha = min(1.0, max(0.01, float(getattr(self, 'vip_agg_baseline_alpha', 0.15) or 0.15)))
                baseline = b_alpha * vip_pps + (1.0 - b_alpha) * baseline
                self._vip_agg_baseline_pps = baseline

        sustain_needed = max(1, int(getattr(self, 'vip_agg_sustain_intervals', 2) or 2))
        if sustain_needed <= 1:
            triggered = interval_anomalous and (win_avg_pps >= eff_thr)
        else:
            triggered = interval_anomalous and (self._vip_agg_consec >= sustain_needed)

        reason_str = ''
        if triggered:
            reason_str = (
                f"vip_agg_spoof_flood(pps={vip_pps:.1f},win_pps={win_avg_pps:.1f},"
                f"thr={eff_thr:.1f},uniq_src={uniq_sources},low_rate_src={low_rate_sources},"
                f"baseline={baseline:.1f},sustain={self._vip_agg_consec})"
            )
            self._last_vip_agg_reason = reason_str
            if self._should_enable_vip_rl_for_trigger('spoof_flood'):
                self._set_vip_rl_active(True, now, reason_str)

            cooldown = max(0.0, float(getattr(self, 'vip_agg_cooldown_sec', 10.0) or 0.0))
            last_alert_ts = float(getattr(self, '_last_vip_agg_alert_ts', 0.0) or 0.0)
            if last_alert_ts <= 0.0 or (float(now) - last_alert_ts) >= cooldown:
                self._last_vip_agg_alert_ts = float(now)
                alert_payload = {
                    'ts': float(now),
                    'type': 'spoof_flood',
                    'src': 'multiple',
                    'reason': reason_str,
                    'vip_ip': vip_ip,
                    'total_rate': float(vip_pps),
                    'window_avg_rate': float(win_avg_pps),
                    'effective_threshold': float(eff_thr),
                    'baseline_rate': float(baseline),
                    'unique_sources': int(uniq_sources),
                    'low_rate_sources': int(low_rate_sources),
                    'sustain_count': int(self._vip_agg_consec),
                }
                try:
                    self._emit_alert(alert_payload)
                except Exception:
                    pass
                self._security_log(
                    'spoof_flood',
                    family='ddos',
                    attack='spoof_flood',
                    vip_ip=vip_ip,
                    total_rate=float(vip_pps),
                    window_avg_rate=float(win_avg_pps),
                    effective_threshold=float(eff_thr),
                    baseline_rate=float(baseline),
                    unique_sources=int(uniq_sources),
                    low_rate_sources=int(low_rate_sources),
                    sustain_count=int(self._vip_agg_consec),
                    reason=reason_str,
                )
                if bool(getattr(self, 'auto_failover_enabled', False)) and bool(getattr(self, 'vip_agg_failover_enabled', False)):
                    try:
                        last_fo = float(self._last_failover_ts or 0.0)
                        if last_fo <= 0.0 or (float(now) - last_fo) >= float(self.failover_cooldown_sec or 0.0):
                            self._last_failover_ts = float(now)
                            _get_hub().spawn(self._failover_to_backup, 'spoof_flood')
                    except Exception:
                        pass

        self.vip_agg_stats = {
            'time': float(now),
            'enabled': True,
            'active': bool(triggered),
            'vip_ip': vip_ip,
            'total_rate': float(vip_pps),
            'window_avg_rate': float(win_avg_pps),
            'baseline_rate': float(baseline),
            'effective_threshold': float(eff_thr),
            'unique_sources': int(uniq_sources),
            'low_rate_sources': int(low_rate_sources),
            'sustain_count': int(self._vip_agg_consec),
            'failover_enabled': bool(getattr(self, 'vip_agg_failover_enabled', False)),
            'reason': reason_str if triggered else str(getattr(self, '_last_vip_agg_reason', '') or ''),
        }
        return self.vip_agg_stats

    def _monitor(self) -> None:
        """Main monitoring loop for anomaly detection.
        
        Runs periodically to:
        - Calculate packet rates and EWMA values
        - Detect PPS, SYN, UDP, and portscan anomalies
        - Apply blocking/quarantine actions
        - Handle DDoS detection and failover
        - Poll flow and port statistics
        """
        while True:
            interval = max(0.1, float(self.measure_interval or 1.0))
            _get_hub().sleep(interval)
            now = time.time()

            pktin_cnt = 0
            try:
                pktin_cnt = int(self._pktin_interval_count)
            except Exception:
                pktin_cnt = 0
            self._pktin_interval_count = 0
            try:
                pktin_pps = float(pktin_cnt) / interval
            except Exception:
                pktin_pps = 0.0
            try:
                self._last_pktin_pps = float(pktin_pps)
            except Exception:
                self._last_pktin_pps = 0.0
            counts = self.pkt_counts
            vip_counts = self.vip_pkt_counts
            try:
                vip_total_pkts = int(getattr(self, '_vip_interval_total_pkts', 0) or 0)
            except Exception:
                vip_total_pkts = 0
            self._vip_interval_total_pkts = 0
            try:
                vip_extra_uniq = int(getattr(self, '_vip_overflow_unique_srcs', 0) or 0)
                vip_extra_low = int(getattr(self, '_vip_overflow_low_rate_srcs', 0) or 0)
            except Exception:
                vip_extra_uniq = 0
                vip_extra_low = 0
            self._vip_overflow_unique_srcs = 0
            self._vip_overflow_low_rate_srcs = 0
            interval_evictions = int(getattr(self, '_tracking_evictions_interval', 0) or 0)
            self._tracking_evictions_interval = 0
            syn_counts = self.syn_counts
            udp_counts = self.udp_counts
            dport_sets = self.portscan_dports
            dport_hist = self.dport_hist
            self.pkt_counts = defaultdict(int)  # reset for next interval
            self.vip_pkt_counts = defaultdict(int)
            self.syn_counts = defaultdict(int)
            self.udp_counts = defaultdict(int)
            self.portscan_dports = defaultdict(set)
            portscan_sizes = {}
            self.dport_hist = defaultdict(Counter)

            track_cap = self._get_tracking_cap()
            interval_pkt_keys_raw = len(counts)
            interval_vip_keys_raw = len(vip_counts)
            if track_cap > 0 and len(counts) > track_cap:
                interval_evictions += self._prune_mapping_batch(
                    counts,
                    track_cap,
                    self._count_score_fn,
                    on_evict=lambda k, _v: self._src_last_seen.pop(k, None) if k not in self.ewma else None,
                    trim_to_cap=True,
                )

            new_rates = defaultdict(float)
            new_syn_rates = defaultdict(float)
            new_udp_rates = defaultdict(float)
            new_uniq_dports = defaultdict(int)
            new_port_entropy = {}

            ip_rates_map = {}
            vip_ip_rates_map = {}

            # Update EWMA for all active and previously tracked sources; fast-expire low-rate singletons
            alpha_val = min(1.0, max(0.01, float(self.alpha or 0.3)))
            low_rate_ttl = float(getattr(self, 'ewma_low_rate_ttl_sec', 3.0) or 0.0)
            singleton_pps = float(getattr(self, 'ewma_singleton_pps', 5.0) or 5.0)
            all_ewma_keys = set(counts.keys()) | set(self.ewma.keys())
            for src_key in all_ewma_keys:
                cnt = counts.get(src_key, 0)
                rate = float(cnt) / interval
                if cnt > 0:
                    new_rates[src_key] = rate
                    if src_key not in self._src_last_seen:
                        self._src_last_seen[src_key] = now
                prev = float(self.ewma.get(src_key, 0.0))
                ew = alpha_val * rate + (1.0 - alpha_val) * prev
                last_ts = float(self._src_last_seen.get(src_key, now) or now)
                is_singleton_stale = (
                    cnt == 0
                    and low_rate_ttl > 0.0
                    and ew < singleton_pps
                    and (now - last_ts) >= low_rate_ttl
                )
                if cnt == 0 and (ew < 0.05 or is_singleton_stale):
                    self.ewma.pop(src_key, None)
                    self._src_last_seen.pop(src_key, None)
                else:
                    self.ewma[src_key] = ew
            self._enforce_ewma_bounds(now)

            for src_key, cnt in counts.items():
                rate = new_rates.get(src_key, 0.0)
                ew = float(self.ewma.get(src_key, 0.0))

                # Only auto-block IPv4 speakers
                if src_key.startswith('ip:'):
                    ip_addr = src_key.split(':', 1)[1]
                    ip_rates_map[ip_addr] = float(rate)
                    if self._is_protected_ip(ip_addr):
                        continue
                    syn_rate = syn_counts.get(ip_addr, 0) / interval
                    udp_rate = udp_counts.get(ip_addr, 0) / interval
                    new_syn_rates[ip_addr] = syn_rate
                    new_udp_rates[ip_addr] = udp_rate
                    uniq_ports = len(dport_sets.get(ip_addr, set()))
                    portscan_sizes[ip_addr] = uniq_ports
                    new_uniq_dports[ip_addr] = uniq_ports

                    ent = 0.0
                    if self.entropy_enabled:
                        try:
                            hist = dport_hist.get(ip_addr) or Counter()
                            total = float(sum(hist.values()) or 0.0)
                            if total > 0:
                                for _p, c in hist.items():
                                    p = float(c) / total
                                    if p > 0:
                                        ent -= p * math.log(p, 2)
                        except Exception as e_ent:
                            logger.debug("Failed to calculate port entropy for %s: %s", ip_addr, e_ent)
                            ent = 0.0
                    new_port_entropy[ip_addr] = float(ent)

                    trigger = None
                    if syn_rate >= self.syn_threshold:
                        trigger = 'syn_rate_exceeded'
                    elif udp_rate >= self.udp_threshold:
                        trigger = 'udp_rate_exceeded'
                    elif uniq_ports >= self.portscan_threshold:
                        trigger = 'portscan_detected'
                    elif (rate >= self.pps_threshold) or (ew >= self.pps_threshold):
                        trigger = 'pps_threshold_exceeded'
                    elif self.entropy_enabled:
                        try:
                            if ent >= float(self.entropy_threshold) and int(uniq_ports) >= int(self.entropy_min_ports):
                                trigger = 'entropy_high'
                        except Exception:
                            pass

                    if trigger and ip_addr not in self.blocked_ips:
                        family, attack_type = self._classify_trigger(trigger)
                        action = self._decide_action(trigger)
                        if self._should_enable_vip_rl_for_trigger(trigger):
                            self._set_vip_rl_active(True, now, trigger)
                        if self.auto_failover_enabled:
                            try:
                                if (now - float(self._last_failover_ts or 0.0)) >= float(self.failover_cooldown_sec or 0.0):
                                    self._last_failover_ts = now
                                    _get_hub().spawn(self._failover_to_backup, trigger)
                            except Exception as e_fo:
                                logger.warning("Failed to spawn failover greenlet for trigger %s: %s", trigger, e_fo)
                        if action == 'quarantine' and self.mitigation_enabled and self.quarantine_enabled and ip_addr not in self.quarantined_ips:
                            self._install_quarantine_ip_all(ip_addr)
                            self.quarantined_ips.add(ip_addr)
                            expq = now + float(self.quarantine_duration_sec or 0.0) if float(self.quarantine_duration_sec or 0.0) > 0 else None
                            self.quarantined_info[ip_addr] = {'ts': now, 'reason': trigger, 'expires_at': expq}
                            try:
                                self._emit_alert({'ts': now, 'type': 'quarantine', 'src': ip_addr, 'reason': trigger, 'pps': float(self.quarantine_pps or 0)})
                            except Exception:
                                pass
                            self._security_log(
                                'quarantine',
                                family=family,
                                attack=attack_type,
                                src=str(ip_addr),
                                rate=float(rate),
                                ewma=float(ew),
                                syn_rate=float(syn_rate),
                                udp_rate=float(udp_rate),
                                uniq_dports=int(uniq_ports),
                                entropy=float(ent),
                                duration_sec=float(self.quarantine_duration_sec or 0.0),
                                pps=float(self.quarantine_pps or 0.0),
                                reason=str(trigger),
                            )
                        elif self.mitigation_enabled and self._should_block_for_trigger(trigger) and action == 'block':
                            self._install_block_ip_all(ip_addr)
                            self.blocked_ips.add(ip_addr)
                            exp = now + self.block_duration_sec if self.block_duration_sec > 0 else None
                            self.blocked_info[ip_addr] = {'ts': now, 'reason': trigger, 'expires_at': exp}
                            self._emit_alert({
                                'ts': now,
                                'type': 'block',
                                'src': ip_addr,
                                'rate': rate,
                                'ewma': ew,
                                'syn_rate': syn_rate,
                                'udp_rate': udp_rate,
                                'uniq_dports': uniq_ports,
                                'reason': trigger,
                            })
                            self._security_log(
                                'block',
                                family=family,
                                attack=attack_type,
                                src=str(ip_addr),
                                rate=float(rate),
                                ewma=float(ew),
                                syn_rate=float(syn_rate),
                                udp_rate=float(udp_rate),
                                uniq_dports=int(uniq_ports),
                                entropy=float(ent),
                                duration_sec=float(self.block_duration_sec or 0.0),
                                reason=str(trigger),
                            )
                        else:
                            self._emit_alert({
                                'ts': now,
                                'type': 'detect',
                                'src': ip_addr,
                                'rate': rate,
                                'ewma': ew,
                                'syn_rate': syn_rate,
                                'udp_rate': udp_rate,
                                'uniq_dports': uniq_ports,
                                'reason': trigger,
                            })
                            self._security_log(
                                'detect',
                                family=family,
                                attack=attack_type,
                                src=str(ip_addr),
                                rate=float(rate),
                                ewma=float(ew),
                                syn_rate=float(syn_rate),
                                udp_rate=float(udp_rate),
                                uniq_dports=int(uniq_ports),
                                entropy=float(ent),
                                reason=str(trigger),
                            )

            try:
                for ip_addr, cnt in vip_counts.items():
                    vip_ip_rates_map[str(ip_addr)] = float(cnt) / interval
            except Exception:
                vip_ip_rates_map = {}

            self.rates = new_rates
            self.syn_rates = new_syn_rates
            self.udp_rates = new_udp_rates
            self.uniq_dports = new_uniq_dports
            self.port_entropy = new_port_entropy

            try:
                base_map = vip_ip_rates_map if bool(self.ddos_vip_only) else ip_rates_map
                ddos_sources = [
                    ip for ip, r in base_map.items()
                    if float(r) >= float(self.ddos_min_pps_per_source or 0.0) and not self._is_protected_ip(ip)
                ]
                ddos_total_rate = float(sum([base_map.get(ip, 0.0) for ip in ddos_sources]))
                top_sources = sorted([(ip, float(base_map.get(ip, 0.0))) for ip in ddos_sources], key=lambda x: x[1], reverse=True)[:10]
                self.ddos_stats = {
                    'time': now,
                    'active_sources': len(ddos_sources),
                    'total_rate': ddos_total_rate,
                    'top_sources': [{'ip': ip, 'rate': r} for ip, r in top_sources],
                    'vip_ip': str(self.vip_ip or ''),
                    'vip_only': bool(self.ddos_vip_only),
                }

                is_ddos = (len(ddos_sources) >= int(self.ddos_source_threshold or 0)) and (ddos_total_rate >= float(self.pps_threshold or 0.0))
                if is_ddos and (now - float(self._last_ddos_alert_ts or 0.0)) >= float(self.ddos_alert_cooldown_sec or 0.0):
                    self._last_ddos_alert_ts = now
                    if self._should_enable_vip_rl_for_trigger('ddos_detected'):
                        self._set_vip_rl_active(True, now, 'ddos_detected')
                    self._emit_alert({
                        'ts': now,
                        'type': 'ddos',
                        'src': 'multiple',
                        'reason': 'ddos_detected',
                        'active_sources': len(ddos_sources),
                        'total_rate': ddos_total_rate,
                        'top_sources': [{'ip': ip, 'rate': r} for ip, r in top_sources],
                    })
                    self._security_log(
                        'ddos_detected',
                        family='ddos',
                        attack='multi_source_flood',
                        active_sources=int(len(ddos_sources)),
                        total_rate=float(ddos_total_rate),
                        top_sources=[{'ip': ip, 'rate': float(r)} for ip, r in top_sources],
                        vip_only=bool(self.ddos_vip_only),
                        vip_ip=str(self.vip_ip or ''),
                    )

                    if self.mitigation_enabled and self.ddos_mitigation_enabled:
                        try:
                            n = int(self.ddos_block_top_n or 0)
                        except Exception:
                            n = 0
                        if n > 0:
                            for ip_addr, r in list(top_sources)[:n]:
                                ip_addr = str(ip_addr)
                                if not ip_addr:
                                    continue
                                if self._is_protected_ip(ip_addr):
                                    continue
                                if ip_addr in self.blocked_ips:
                                    continue
                                self._install_block_ip_all(ip_addr)
                                self.blocked_ips.add(ip_addr)
                                exp = now + float(self.ddos_block_duration_sec or 0.0) if float(self.ddos_block_duration_sec or 0.0) > 0 else None
                                self.blocked_info[ip_addr] = {'ts': now, 'reason': 'ddos_mitigation', 'expires_at': exp}
                                self._emit_alert({'ts': now, 'type': 'ddos_block', 'src': ip_addr, 'rate': float(r)})
                                self._security_log(
                                    'ddos_block',
                                    family='ddos',
                                    attack='multi_source_flood',
                                    src=str(ip_addr),
                                    rate=float(r),
                                    duration_sec=float(self.ddos_block_duration_sec or 0.0),
                                    reason='ddos_mitigation',
                                 )

                    if self.auto_failover_enabled:
                        try:
                            if (now - float(self._last_failover_ts or 0.0)) >= float(self.failover_cooldown_sec or 0.0):
                                self._last_failover_ts = now
                                _get_hub().spawn(self._failover_to_backup, 'ddos_detected')
                        except Exception as e_fo:
                            logger.warning("Failed to spawn DDoS failover greenlet: %s", e_fo)
            except Exception:
                pass

            try:
                self._evaluate_vip_aggregate(
                    now=now,
                    interval=interval,
                    vip_counts=vip_counts,
                    vip_total_pkts=vip_total_pkts,
                    extra_unique_sources=vip_extra_uniq,
                    extra_low_rate_sources=vip_extra_low,
                )
            except Exception:
                pass

            self._tracking_stats = {
                'time': float(now),
                'max_keys': int(track_cap),
                'ewma_keys': int(len(self.ewma)),
                'last_seen_keys': int(len(self._src_last_seen)),
                'rates_keys': int(len(self.rates)),
                'last_interval_pkt_keys': int(interval_pkt_keys_raw),
                'last_interval_vip_keys': int(interval_vip_keys_raw),
                'vip_overflow_unique_sources': int(vip_extra_uniq),
                'vip_overflow_low_rate_sources': int(vip_extra_low),
                'evictions_interval': int(interval_evictions),
                'evictions_total': int(getattr(self, '_tracking_evictions_total', 0) or 0),
                'low_rate_ttl_sec': float(low_rate_ttl),
                'singleton_pps': float(singleton_pps),
                'per_ip_port_history_cap': int(getattr(self, 'per_ip_port_history_cap', 1024) or 1024),
            }

            # Auto-unblock expired
            if self.block_duration_sec > 0:
                to_unblock = []
                for ip_addr, info in list(self.blocked_info.items()):
                    exp = info.get('expires_at')
                    if exp and now >= exp:
                        to_unblock.append(ip_addr)
                for ip_addr in to_unblock:
                    self._remove_block_ip_all(ip_addr)
                    if ip_addr in self.blocked_ips:
                        self.blocked_ips.remove(ip_addr)
                    self.blocked_info.pop(ip_addr, None)
                    self.ewma.pop(f"ip:{ip_addr}", None)
                    self._emit_alert({'ts': now, 'type': 'auto_unblock', 'src': ip_addr})
                    self._security_log('auto_unblock', src=str(ip_addr))

            if self.quarantine_duration_sec > 0:
                to_unq = []
                for ip_addr, info in list(self.quarantined_info.items()):
                    exp = info.get('expires_at')
                    if exp and now >= exp:
                        to_unq.append(ip_addr)
                for ip_addr in to_unq:
                    self._remove_quarantine_ip_all(ip_addr)
                    if ip_addr in self.quarantined_ips:
                        self.quarantined_ips.remove(ip_addr)
                    self.quarantined_info.pop(ip_addr, None)
                    try:
                        self._emit_alert({'ts': now, 'type': 'auto_unquarantine', 'src': ip_addr})
                    except Exception:
                        pass
                    self._security_log('auto_unquarantine', src=str(ip_addr))

            if self._vip_rl_active and self.adaptive_vip_rl_hold_sec > 0:
                try:
                    if (now - float(self._vip_rl_last_ts or 0.0)) >= float(self.adaptive_vip_rl_hold_sec or 0.0):
                        self._set_vip_rl_active(False, now, 'cooldown')
                except Exception:
                    pass

            if self.ctrl_failsafe_enabled and self.ctrl_failsafe_pktin_pps > 0:
                try:
                    if float(pktin_pps) >= float(self.ctrl_failsafe_pktin_pps):
                        self._set_vip_rl_active(True, now, f'pktin_pps:{float(pktin_pps):.1f}')
                        self._set_failsafe_active(True, now, f'pktin_pps:{float(pktin_pps):.1f}')
                    elif self._failsafe_active and self.ctrl_failsafe_hold_sec > 0:
                        if (now - float(self._failsafe_last_ts or 0.0)) >= float(self.ctrl_failsafe_hold_sec or 0.0):
                            self._set_failsafe_active(False, now, 'cooldown')
                except Exception:
                    pass

            try:
                poll_int = float(self.stats_poll_interval_sec or 0.0)
            except Exception:
                poll_int = 0.0
            if poll_int <= 0:
                poll_int = 0.0

            do_poll = True
            if poll_int > 0:
                do_poll = (now - float(self._last_stats_poll_ts or 0.0)) >= poll_int
            if do_poll:
                self._last_stats_poll_ts = now

                # Poll flow stats from each datapath
                for dp in list(self.datapaths.values()):
                    try:
                        req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
                        dp.send_msg(req)
                    except Exception:
                        pass

                # Poll port stats from each datapath
                for dp in list(self.datapaths.values()):
                    try:
                        reqp = dp.ofproto_parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
                        dp.send_msg(reqp)
                    except Exception:
                        pass

    @staticmethod
    def _classify_request_error(exc: Exception) -> str:
        """Classify outbound HTTP exceptions into short safe reason codes."""
        if isinstance(exc, requests.exceptions.Timeout):
            return 'timeout'
        if isinstance(exc, requests.exceptions.SSLError):
            return 'tls_error'
        if isinstance(exc, requests.exceptions.ConnectionError):
            return 'connection_refused'
        if isinstance(exc, requests.exceptions.RequestException):
            return 'request_failed'
        return 'failover_error'

    def _failover_to_backup(self, reason: str) -> None:
        """Trigger HA failover by emitting a failover_requested alert."""
        now = time.time()
        try:
            self._emit_alert({
                'ts': now,
                'type': 'failover_requested',
                'target': 'backup',
                'reason': str(reason),
            })
        except Exception:
            pass
        self._security_log('failover_requested', reason=str(reason), target='backup')
