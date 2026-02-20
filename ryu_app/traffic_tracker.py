"""
ryu_app/traffic_tracker.py
Traffic accounting and OpenFlow PacketIn processing mixin.
"""

import time
from typing import Any, Dict, List, Optional, Set, Tuple

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp


class TrafficTrackerMixin:
    """Mixin providing packet tracking, bounded LRU pruning, and PacketIn handling."""

    def _is_heavy_key(self, raw_key: str) -> Tuple[int, int]:
        """Return (protected_or_blocked_flag, known_heavy_ewma_flag) for eviction priority."""
        s = str(raw_key or '')
        if s.startswith('ip:'):
            ew_key = s
            ip_only = s[3:]
        elif s.startswith('mac:'):
            ew_key = s
            ip_only = ''
        else:
            ew_key = f'ip:{s}'
            ip_only = s
        prot = 1 if (
            ip_only and (
                ip_only in self.blocked_ips
                or ip_only in self.quarantined_ips
                or self._is_protected_ip(ip_only)
            )
        ) else 0
        try:
            singleton_thr = float(getattr(self, 'ewma_singleton_pps', 5.0) or 5.0)
            heavy = 1 if float(self.ewma.get(ew_key, 0.0) or 0.0) >= singleton_thr else 0
        except Exception:
            heavy = 0
        return prot, heavy

    def _count_score_fn(self, key: str, count_val: Any) -> Tuple[int, int, int]:
        """Priority-preserving score tuple: evict low-count non-heavy singletons first."""
        prot, heavy = self._is_heavy_key(key)
        try:
            cnt = int(count_val or 0)
        except Exception:
            cnt = 0
        return prot, heavy, cnt

    def _prune_mapping_batch(self, mapping, max_keys: int, score_fn, on_evict=None, trim_to_cap: bool = False) -> int:
        """Evict lowest-priority entries in amortized batches (F-13d)."""
        try:
            cap = int(max_keys or 0)
        except Exception:
            cap = 0
        if cap <= 0:
            return 0
        if trim_to_cap:
            if len(mapping) <= cap:
                return 0
            keep_n = cap
        else:
            high_water = max(cap + 1, int(cap * 1.25))
            if len(mapping) < high_water:
                return 0
            keep_n = max(1, min(cap, int(cap * 0.75)))
        n_evict = len(mapping) - keep_n
        if n_evict <= 0:
            return 0
        ranked = sorted(mapping.items(), key=lambda kv: score_fn(kv[0], kv[1]))
        evicted = 0
        for k, val in ranked[:n_evict]:
            mapping.pop(k, None)
            if on_evict is not None:
                try:
                    on_evict(k, val)
                except Exception:
                    pass
            evicted += 1
        self._tracking_evictions_total = int(getattr(self, '_tracking_evictions_total', 0) or 0) + evicted
        self._tracking_evictions_interval = int(getattr(self, '_tracking_evictions_interval', 0) or 0) + evicted
        return evicted

    def _record_vip_overflow(self, ip_str: str, cnt: int) -> None:
        """Preserve aggregate VIP source counts when per-IP tracking entries are evicted."""
        ip_val = str(ip_str or '')
        if not ip_val or self._is_protected_ip(ip_val):
            return
        self._vip_overflow_unique_srcs = int(getattr(self, '_vip_overflow_unique_srcs', 0) or 0) + 1
        dt = max(0.1, float(getattr(self, 'measure_interval', 1.0) or 1.0))
        low_max = max(0.0, float(getattr(self, 'vip_agg_low_rate_max_pps', 30.0) or 0.0))
        try:
            c_val = int(cnt or 0)
        except Exception:
            c_val = 0
        if c_val > 0 and (low_max <= 0.0 or (float(c_val) / dt) <= low_max):
            self._vip_overflow_low_rate_srcs = int(getattr(self, '_vip_overflow_low_rate_srcs', 0) or 0) + 1

    def _get_tracking_cap(self) -> int:
        raw = getattr(self, 'tracking_max_keys', 2000)
        if raw is None:
            return 2000
        try:
            return int(raw)
        except Exception:
            return 2000

    def _track_packet_source(self, src_key: str, vip_src_ip: Optional[str], now_ts: Optional[float] = None) -> None:
        """Record per-source and scalar VIP packet counts under bounded dict caps."""
        ts = time.time() if now_ts is None else float(now_ts)
        cap = self._get_tracking_cap()
        self.pkt_counts[src_key] += 1
        self._src_last_seen[src_key] = ts
        self._prune_mapping_batch(
            self.pkt_counts,
            cap,
            self._count_score_fn,
            on_evict=lambda k, _v: self._src_last_seen.pop(k, None) if k not in self.ewma else None,
        )
        if vip_src_ip:
            vip_key = str(vip_src_ip)
            self.vip_pkt_counts[vip_key] += 1
            self._vip_interval_total_pkts += 1
            self._prune_mapping_batch(
                self.vip_pkt_counts,
                cap,
                self._count_score_fn,
                on_evict=self._record_vip_overflow,
            )

    def _record_transport_dport(self, ip_src: str, dport: int, track_portscan: bool = True, is_syn: bool = False, is_udp: bool = False) -> None:
        """Record bounded SYN/UDP/portscan/histogram counters without per-protocol duplication."""
        ip_s = str(ip_src)
        dp_int = int(dport)
        cap = self._get_tracking_cap()
        port_cap = max(1, int(getattr(self, 'per_ip_port_history_cap', 1024) or 1024))
        if is_syn:
            self.syn_counts[ip_s] += 1
            self._prune_mapping_batch(self.syn_counts, cap, self._count_score_fn)
        if is_udp:
            self.udp_counts[ip_s] += 1
            self._prune_mapping_batch(self.udp_counts, cap, self._count_score_fn)
        if track_portscan:
            pset = self.portscan_dports[ip_s]
            if len(pset) < port_cap:
                pset.add(dp_int)
            self._prune_mapping_batch(
                self.portscan_dports,
                cap,
                lambda k, s: (*self._is_heavy_key(k), len(s)),
            )
        hist = self.dport_hist[ip_s]
        if dp_int in hist or len(hist) < port_cap:
            hist[dp_int] += 1
        self._prune_mapping_batch(
            self.dport_hist,
            cap,
            lambda k, c: (*self._is_heavy_key(k), sum(c.values())),
        )

    def _enforce_ewma_bounds(self, now: float) -> None:
        """Cap multi-interval EWMA and last-seen maps while retaining heavy hitters."""
        cap = self._get_tracking_cap()
        if cap > 0 and len(self.ewma) > cap:
            self._prune_mapping_batch(
                self.ewma,
                cap,
                lambda k, ew: (*self._is_heavy_key(k), float(ew or 0.0), float(self._src_last_seen.get(k, 0.0) or 0.0)),
                on_evict=lambda k, _v: self._src_last_seen.pop(k, None),
                trim_to_cap=True,
            )
        stale_last_seen = [k for k in self._src_last_seen if k not in self.ewma and k not in self.pkt_counts]
        for k in stale_last_seen:
            self._src_last_seen.pop(k, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        try:
            self._pktin_interval_count += 1
        except Exception:
            pass

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dpid = datapath.id
        src = eth.src
        dst = eth.dst

        # Detection accounting
        self.total_packet_ins += 1
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4:
            src_key = f"ip:{ip4.src}"
        else:
            src_key = f"mac:{src}"
        vip_src = str(ip4.src) if (ip4 and self.vip_ip and str(ip4.dst) == str(self.vip_ip)) else None
        self._track_packet_source(src_key, vip_src)

        if self.dp_fastpath_enabled and getattr(msg, 'reason', None) == ofproto.OFPR_ACTION:
            if ip4 and ip4.src in self.blocked_ips:
                self._install_block_ip_all(ip4.src)
            self._record_packet(datapath, in_port, pkt, src, dst, ip4)
            return

        # Immediate active defense: if IP or MAC is already blocked, re-install drop flow without forwarding
        if src in self.blocked_macs:
            for dp in list(self.datapaths.values()):
                self._install_block_mac(dp, src)
            self._record_packet(datapath, in_port, pkt, src, dst, ip4)
            return
        if ip4 and ip4.src in self.blocked_ips:
            self._install_block_ip_all(ip4.src)
            self._record_packet(datapath, in_port, pkt, src, dst, ip4)
            return

        out_port = ofproto.OFPP_FLOOD
        if self.learning_enabled:
            # L2 learning
            self.mac_to_port[dpid][src] = in_port

            # Default output port selection (learning switch)
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to avoid future packet-ins
        if self.learning_enabled and out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, priority=10, match=match, actions=actions,
                               cookie=int(self._learned_flow_cookie), buffer_id=msg.buffer_id)
                self._record_packet(datapath, in_port, pkt, src, dst, ip4)
                return
            else:
                self._add_flow(datapath, priority=10, match=match, actions=actions,
                               cookie=int(self._learned_flow_cookie))

        # Send the packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        self._record_packet(datapath, in_port, pkt, src, dst, ip4)

    def _record_packet(self, datapath, in_port, pkt, src, dst, ip4):
        # Protocol-specific accounting
        if ip4:
            t = pkt.get_protocol(tcp.tcp)
            u = pkt.get_protocol(udp.udp)
            if t:
                is_syn = bool((t.bits & 0x02) and not (t.bits & 0x10))
                try:
                    self._record_transport_dport(ip4.src, t.dst_port, track_portscan=is_syn, is_syn=is_syn, is_udp=False)
                except Exception:
                    pass
                self.last_packets.append({
                    'ts': time.time(), 'dpid': datapath.id, 'in_port': in_port,
                    'proto': 'tcp', 'src': ip4.src, 'dst': ip4.dst,
                    'sport': t.src_port, 'dport': t.dst_port, 'syn': bool(t.bits & 0x02), 'ack': bool(t.bits & 0x10)
                })
            elif u:
                try:
                    self._record_transport_dport(ip4.src, u.dst_port, track_portscan=True, is_syn=False, is_udp=True)
                except Exception:
                    pass
                self.last_packets.append({
                    'ts': time.time(), 'dpid': datapath.id, 'in_port': in_port,
                    'proto': 'udp', 'src': ip4.src, 'dst': ip4.dst,
                    'sport': u.src_port, 'dport': u.dst_port
                })
            else:
                ic = pkt.get_protocol(icmp.icmp)
                if ic:
                    self.last_packets.append({
                        'ts': time.time(), 'dpid': datapath.id, 'in_port': in_port,
                        'proto': 'icmp', 'src': ip4.src, 'dst': ip4.dst
                    })
                else:
                    self.last_packets.append({
                        'ts': time.time(), 'dpid': datapath.id, 'in_port': in_port,
                        'proto': 'ip', 'src': ip4.src, 'dst': ip4.dst
                    })
        else:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                self.last_packets.append({
                    'ts': time.time(), 'dpid': datapath.id, 'in_port': in_port,
                    'proto': 'arp', 'src_mac': src, 'dst_mac': dst,
                    'arp_spa': arp_pkt.src_ip, 'arp_tpa': arp_pkt.dst_ip
                })
            else:
                self.last_packets.append({
                    'ts': time.time(), 'dpid': datapath.id, 'in_port': in_port,
                    'proto': 'l2', 'src_mac': src, 'dst_mac': dst
                })
