"""
ryu_app/mitigation_manager.py
Mitigation policy decisions, rate limiting, and defensive OpenFlow installation.
"""

import time
from typing import Any, Dict, List, Optional, Tuple


class MitigationManagerMixin:
    """Mixin providing mitigation policy decisions, rate-limiting, and defensive flow management."""

    # --------------------------------------------------------------------------
    # Trigger Classification & Action Decisions
    # --------------------------------------------------------------------------
    def _should_enable_vip_rl_for_trigger(self, trigger: str) -> bool:
        if not trigger:
            return False
        if trigger in ('pps_threshold_exceeded', 'syn_rate_exceeded', 'udp_rate_exceeded'):
            return True
        if trigger in ('ddos_detected', 'spoof_flood'):
            return True
        return False

    def _should_block_for_trigger(self, trigger: str) -> bool:
        if not trigger:
            return False
        return trigger in (
            'pps_threshold_exceeded',
            'syn_rate_exceeded',
            'udp_rate_exceeded',
            'portscan_detected',
        )

    def _decide_action(self, trigger: str) -> str:
        t = str(trigger or '')
        if t == 'portscan_detected':
            return 'quarantine' if self.quarantine_enabled else 'block'
        if t == 'entropy_high':
            return 'quarantine'
        if t in ('pps_threshold_exceeded', 'syn_rate_exceeded', 'udp_rate_exceeded'):
            return 'block'
        if t == 'ddos_detected':
            return 'ddos'
        if t == 'spoof_flood':
            return 'vip_rl'
        return 'detect'

    def _classify_trigger(self, trigger: str) -> Tuple[str, str]:
        m = {
            'pps_threshold_exceeded': ('dos', 'pps_flood'),
            'syn_rate_exceeded': ('dos', 'syn_flood'),
            'udp_rate_exceeded': ('dos', 'udp_flood'),
            'portscan_detected': ('dos', 'port_scan'),
            'entropy_high': ('dos', 'entropy_scan'),
            'ddos_detected': ('ddos', 'multi_source_flood'),
            'spoof_flood': ('ddos', 'spoof_flood'),
        }
        return m.get(str(trigger or ''), ('dos', str(trigger or 'unknown')))

    # --------------------------------------------------------------------------
    # VIP Rate Limiting (Dataplane Protection)
    # --------------------------------------------------------------------------
    def _install_vip_rl(self, datapath):
        if not self.vip_ip:
            return
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = self._dpid_of(datapath)

        actions_base = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        if self.dp_ctrl_meter_enabled and not self._failsafe_active:
            actions_base = [
                parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL),
            ]

        specs = []
        if int(getattr(self, 'dp_vip_other_meter_id', 0) or 0) > 0 and int(getattr(self, 'dp_vip_other_pps', 0) or 0) > 0:
            match_vip_all = parser.OFPMatch(eth_type=0x0800, ipv4_dst=str(self.vip_ip))
            self._add_flow(
                datapath,
                priority=89,
                match=match_vip_all,
                actions=actions_base,
                meter_id=self.dp_vip_other_meter_id,
                meter_pps=self.dp_vip_other_pps,
                cookie=self._vip_rl_cookie,
            )
            specs.append((0, 89, match_vip_all))

        match_udp = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=str(self.vip_ip))
        self._add_flow(datapath, priority=90, match=match_udp, actions=actions_base,
                       meter_id=self.dp_vip_udp_meter_id, meter_pps=self.dp_vip_udp_pps, cookie=self._vip_rl_cookie)
        specs.append((0, 90, match_udp))

        match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_dst=str(self.vip_ip))
        self._add_flow(datapath, priority=90, match=match_icmp, actions=actions_base,
                       meter_id=self.dp_vip_icmp_meter_id, meter_pps=self.dp_vip_icmp_pps, cookie=self._vip_rl_cookie)
        specs.append((0, 90, match_icmp))

        for dport in list(self.dp_mirror_tcp_dports or []):
            try:
                dport = int(dport)
            except Exception:
                continue
            match_tcp = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=str(self.vip_ip), tcp_dst=dport)
            self._add_flow(datapath, priority=90, match=match_tcp, actions=actions_base,
                           meter_id=self.dp_vip_tcp_meter_id, meter_pps=self.dp_vip_tcp_pps, cookie=self._vip_rl_cookie)
            specs.append((0, 90, match_tcp))

        if dpid is not None:
            self._installed_vip_rl_specs[dpid] = specs

    def _remove_vip_rl(self, datapath):
        dpid = self._dpid_of(datapath)
        specs = self._installed_vip_rl_specs.pop(dpid, []) if dpid is not None else []
        try:
            if specs:
                for table_id, prio, match in specs:
                    self._delete_flow_strict(
                        datapath,
                        table_id=table_id,
                        priority=prio,
                        match=match,
                        cookie=int(self._vip_rl_cookie),
                    )
            else:
                self._delete_flows_by_cookie(
                    datapath,
                    cookie=int(self._vip_rl_cookie),
                    table_id=0,
                )
        except Exception:
            return

    def _set_vip_rl_active(self, active: bool, now: float, reason: str):
        if not (self.dp_fastpath_enabled and self.adaptive_vip_rl_enabled and self.dp_vip_rate_limit_enabled):
            return
        if active:
            self._vip_rl_last_ts = float(now)
            if self._vip_rl_active:
                return
            for dp in list(self.datapaths.values()):
                try:
                    self._install_vip_rl(dp)
                except Exception:
                    pass
            self._vip_rl_active = True
            try:
                self._emit_alert({'ts': float(now), 'type': 'vip_rl_on', 'reason': str(reason)})
            except Exception:
                pass
            self._security_log('vip_rl_on', mode='dataplane', reason=str(reason))
        else:
            if not self._vip_rl_active:
                return
            for dp in list(self.datapaths.values()):
                try:
                    self._remove_vip_rl(dp)
                except Exception:
                    pass
            self._vip_rl_active = False
            try:
                self._emit_alert({'ts': float(now), 'type': 'vip_rl_off', 'reason': str(reason)})
            except Exception:
                pass
            self._security_log('vip_rl_off', mode='dataplane', reason=str(reason))

    # --------------------------------------------------------------------------
    # Controller Failsafe (Fast-Path Bypass)
    # --------------------------------------------------------------------------
    def _install_failsafe(self, datapath):
        if not self.vip_ip:
            return
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = self._dpid_of(datapath)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        specs = []

        if self.dp_mirror_vip_all:
            match_vip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=str(self.vip_ip))
            self._add_flow(datapath, priority=85, match=match_vip, actions=actions, cookie=self._failsafe_cookie)
            specs.append((0, 85, match_vip))

        if self.dp_mirror_udp:
            match_udp = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=str(self.vip_ip))
            self._add_flow(datapath, priority=86, match=match_udp, actions=actions, cookie=self._failsafe_cookie)
            specs.append((0, 86, match_udp))

        if self.dp_mirror_icmp:
            match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_dst=str(self.vip_ip))
            self._add_flow(datapath, priority=86, match=match_icmp, actions=actions, cookie=self._failsafe_cookie)
            specs.append((0, 86, match_icmp))

        for dport in list(self.dp_mirror_tcp_dports or []):
            try:
                dport = int(dport)
            except Exception:
                continue
            match_tcp = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=str(self.vip_ip), tcp_dst=dport)
            self._add_flow(datapath, priority=87, match=match_tcp, actions=actions, cookie=self._failsafe_cookie)
            specs.append((0, 87, match_tcp))

        if dpid is not None:
            self._installed_failsafe_specs[dpid] = specs

    def _remove_failsafe(self, datapath):
        dpid = self._dpid_of(datapath)
        specs = self._installed_failsafe_specs.pop(dpid, []) if dpid is not None else []
        try:
            if specs:
                for table_id, prio, match in specs:
                    self._delete_flow_strict(
                        datapath,
                        table_id=table_id,
                        priority=prio,
                        match=match,
                        cookie=int(self._failsafe_cookie),
                    )
            else:
                self._delete_flows_by_cookie(
                    datapath,
                    cookie=int(self._failsafe_cookie),
                    table_id=0,
                )
        except Exception:
            return

    def _set_failsafe_active(self, active: bool, now: float, reason: str):
        if not (self.dp_fastpath_enabled and self.ctrl_failsafe_enabled):
            return
        if active:
            self._failsafe_last_ts = float(now)
            if self._failsafe_active:
                return
            self._failsafe_active = True
            for dp in list(self.datapaths.values()):
                try:
                    if self._vip_rl_active and self.adaptive_vip_rl_enabled and self.dp_vip_rate_limit_enabled:
                        self._install_vip_rl(dp)
                        if getattr(dp, 'ofproto_parser', None) is not None and hasattr(dp.ofproto_parser, 'OFPBarrierRequest'):
                            dp.send_msg(dp.ofproto_parser.OFPBarrierRequest(dp))
                    self._install_failsafe(dp)
                except Exception:
                    pass
            try:
                self._emit_alert({'ts': float(now), 'type': 'failsafe_on', 'reason': str(reason)})
            except Exception:
                pass
            self._security_log('failsafe_on', mode='controller', reason=str(reason))
        else:
            if not self._failsafe_active:
                return
            self._failsafe_active = False
            for dp in list(self.datapaths.values()):
                try:
                    self._remove_failsafe(dp)
                    if self._vip_rl_active and self.adaptive_vip_rl_enabled and self.dp_vip_rate_limit_enabled:
                        self._install_vip_rl(dp)
                except Exception:
                    pass
            try:
                self._emit_alert({'ts': float(now), 'type': 'failsafe_off', 'reason': str(reason)})
            except Exception:
                pass
            self._security_log('failsafe_off', mode='controller', reason=str(reason))

    # --------------------------------------------------------------------------
    # Flow Programming: Block & Quarantine Rules
    # --------------------------------------------------------------------------
    def _install_block_ip_all(self, ip_addr: str) -> None:
        """Install block rule for IP on all datapaths."""
        for dp in list(self.datapaths.values()):
            self._install_block_ip(dp, ip_addr)

    def _install_block_ip(self, datapath, ip_addr: str) -> None:
        """Install drop flow for specific IPv4 address."""
        parser = datapath.ofproto_parser
        prio = int(self.drop_priority)
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_addr)
        self._add_flow(datapath, priority=prio, match=match, actions=None,
                       cookie=int(self._block_ip_cookie))
        dpid = self._dpid_of(datapath)
        if dpid is not None:
            self._installed_block_ip_specs[(dpid, str(ip_addr))] = (0, prio)

    def _install_quarantine_ip_all(self, ip_addr) -> None:
        for dp in list(self.datapaths.values()):
            self._install_quarantine_ip(dp, ip_addr)

    def _install_quarantine_ip(self, datapath, ip_addr) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        prio = max(1, int(self.drop_priority) - 1)
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=str(ip_addr))
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self._add_flow(
            datapath,
            priority=prio,
            match=match,
            actions=actions,
            meter_id=int(self.quarantine_meter_id or 0),
            meter_pps=int(self.quarantine_pps or 0),
            cookie=int(self._quarantine_cookie),
        )
        dpid = self._dpid_of(datapath)
        if dpid is not None:
            self._installed_quarantine_specs[(dpid, str(ip_addr))] = (0, prio)

    def _remove_quarantine_ip_all(self, ip_addr) -> None:
        for dp in list(self.datapaths.values()):
            self._remove_quarantine_ip(dp, ip_addr)

    def _remove_quarantine_ip(self, datapath, ip_addr) -> None:
        parser = datapath.ofproto_parser
        dpid = self._dpid_of(datapath)
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=str(ip_addr))
        spec = self._installed_quarantine_specs.pop((dpid, str(ip_addr)), None) if dpid is not None else None
        if spec is not None:
            table_id, prio = spec
            self._delete_flow_strict(
                datapath,
                table_id=table_id,
                priority=prio,
                match=match,
                cookie=int(self._quarantine_cookie),
            )
        else:
            self._delete_flows_by_cookie(
                datapath,
                cookie=int(self._quarantine_cookie),
                table_id=0,
                match=match,
            )

    def _remove_block_ip_all(self, ip_addr) -> None:
        for dp in list(self.datapaths.values()):
            self._remove_block_ip(dp, ip_addr)

    def _remove_block_ip(self, datapath, ip_addr) -> None:
        parser = datapath.ofproto_parser
        dpid = self._dpid_of(datapath)
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_addr)
        spec = self._installed_block_ip_specs.pop((dpid, str(ip_addr)), None) if dpid is not None else None
        if spec is not None:
            table_id, prio = spec
            self._delete_flow_strict(
                datapath,
                table_id=table_id,
                priority=prio,
                match=match,
                cookie=int(self._block_ip_cookie),
            )
        else:
            self._delete_flows_by_cookie(
                datapath,
                cookie=int(self._block_ip_cookie),
                table_id=0,
                match=match,
            )

    def _install_block_mac(self, datapath, mac_addr) -> None:
        parser = datapath.ofproto_parser
        prio = int(self.drop_priority)
        match = parser.OFPMatch(eth_src=mac_addr)
        self._add_flow(datapath, priority=prio, match=match, actions=None,
                       cookie=int(self._block_mac_cookie))
        dpid = self._dpid_of(datapath)
        if dpid is not None:
            self._installed_block_mac_specs[(dpid, str(mac_addr))] = (0, prio)

    def _remove_block_mac(self, datapath, mac_addr) -> None:
        parser = datapath.ofproto_parser
        dpid = self._dpid_of(datapath)
        match = parser.OFPMatch(eth_src=mac_addr)
        spec = self._installed_block_mac_specs.pop((dpid, str(mac_addr)), None) if dpid is not None else None
        if spec is not None:
            table_id, prio = spec
            self._delete_flow_strict(
                datapath,
                table_id=table_id,
                priority=prio,
                match=match,
                cookie=int(self._block_mac_cookie),
            )
        else:
            self._delete_flows_by_cookie(
                datapath,
                cookie=int(self._block_mac_cookie),
                table_id=0,
                match=match,
            )
