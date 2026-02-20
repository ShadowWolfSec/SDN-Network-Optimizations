"""
SDN DoS/DDoS Guard - OpenFlow Flow & Meter Manager (FlowManagerMixin)
=====================================================================
Encapsulates:
- OpenFlow 1.3 flow rule addition, strict deletion, and cookie-based deletion
- Managed PKTPS meter creation, modification, sync buffer, and watchdog timeout
- Barrier request/reply tracking and error message classification
- Switch connection lifecycle (StateChange, SwitchFeatures)
- Base table-miss, ARP flood, and VIP mirroring / fastpath flow setup
- Port and Flow statistics reply collection and ranking
"""

import time
from typing import Any, Dict, List, Optional, Set, Tuple

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3


class FlowManagerMixin:
    """OpenFlow 1.3 flow, meter, barrier, and error handling capabilities for DoSGuard."""

    def _managed_meter_ids(self) -> Set[int]:
        """Return positive meter IDs explicitly managed by DoSGuard."""
        ids = set()
        for raw_id in (
            getattr(self, 'dp_ctrl_meter_id', 0),
            getattr(self, 'dp_vip_tcp_meter_id', 0),
            getattr(self, 'dp_vip_udp_meter_id', 0),
            getattr(self, 'dp_vip_icmp_meter_id', 0),
            getattr(self, 'dp_vip_other_meter_id', 0),
            getattr(self, 'quarantine_meter_id', 0),
        ):
            try:
                mid = int(raw_id or 0)
            except Exception:
                mid = 0
            if mid > 0:
                ids.add(mid)
        return ids

    @staticmethod
    def _ofp_error_names(ofproto, err_type: int, err_code: int) -> Tuple[str, str]:
        tname = f'0x{int(err_type):02x}'
        cname = f'0x{int(err_code):02x}'
        for attr in dir(ofproto):
            if attr.startswith('OFPET_') and getattr(ofproto, attr, None) == err_type:
                tname = attr
                break
        prefix_map = {
            getattr(ofproto, 'OFPET_METER_MOD_FAILED', 12): 'OFPMMFC_',
            getattr(ofproto, 'OFPET_FLOW_MOD_FAILED', 5): 'OFPFMFC_',
            getattr(ofproto, 'OFPET_BAD_ACTION', 2): 'OFPBAC_',
            getattr(ofproto, 'OFPET_BAD_INSTRUCTION', 3): 'OFPBIC_',
            getattr(ofproto, 'OFPET_BAD_MATCH', 4): 'OFPBMC_',
            getattr(ofproto, 'OFPET_BAD_REQUEST', 1): 'OFPBRC_',
        }
        cprefix = prefix_map.get(err_type, '')
        if cprefix:
            for attr in dir(ofproto):
                if attr.startswith(cprefix) and getattr(ofproto, attr, None) == err_code:
                    cname = attr
                    break
        return tname, cname

    def _prune_pending_of_state(self, now: Optional[float] = None) -> None:
        cur = float(now if now is not None else time.time())
        for store in (self._pending_of_ops, self._pending_barriers):
            for k in list(store.keys()):
                if (cur - float(store[k].get('ts') or 0.0)) > 60.0:
                    store.pop(k, None)

    @staticmethod
    def _dpid_of(datapath) -> Optional[int]:
        raw = getattr(datapath, 'id', None) if datapath is not None else None
        if raw is None:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        dpid = self._dpid_of(datapath)
        if dpid is None:
            return
        if ev.state == MAIN_DISPATCHER:
            if dpid not in self.datapaths:
                self.logger.info('Register datapath: %016x', dpid)
                self.datapaths[dpid] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                self.logger.info('Unregister datapath: %016x', dpid)
                del self.datapaths[dpid]
            self._installed_meters.pop(dpid, None)
            self._switch_meters.pop(dpid, None)
            self._external_meters.pop(dpid, None)
            self._meter_sync_pending.pop(dpid, None)
            self._meter_sync_buffer.pop(dpid, None)
            self._clear_dpid_flow_specs(dpid)
            for k in [k for k in self._pending_of_ops if k[0] == dpid]:
                self._pending_of_ops.pop(k, None)
            for k in [k for k in self._pending_barriers if k[0] == dpid]:
                self._pending_barriers.pop(k, None)

    def _meter_sync_watchdog(self, datapath, dpid: int, sync_token: int) -> None:
        hub.sleep(1.5)
        if self._meter_sync_pending.get(dpid) != sync_token:
            return
        self._meter_sync_pending.pop(dpid, None)
        self._meter_sync_buffer.pop(dpid, None)
        self.logger.warning(
            'OFPMeterConfigStatsReply timed out on datapath %016x; installing base flows without pre-sync',
            dpid,
        )
        try:
            self._install_base_flows(datapath)
        except Exception as e:
            self.logger.warning('Fallback _install_base_flows failed on datapath %016x: %s', dpid, e)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = self._dpid_of(datapath)
        if dpid is None:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[dpid] = datapath
        self._installed_meters.pop(dpid, None)
        self._switch_meters.pop(dpid, None)
        self._external_meters.pop(dpid, None)
        self._meter_sync_buffer.pop(dpid, None)

        if hasattr(parser, 'OFPMeterConfigStatsRequest'):
            self._meter_sync_seq += 1
            sync_token = self._meter_sync_seq
            self._meter_sync_pending[dpid] = sync_token
            self._meter_sync_buffer[dpid] = {}
            try:
                req = parser.OFPMeterConfigStatsRequest(
                    datapath=datapath,
                    flags=0,
                    meter_id=getattr(ofproto, 'OFPM_ALL', 0xffffffff),
                )
                datapath.send_msg(req)
                rxid = getattr(req, 'xid', None)
                if isinstance(rxid, int):
                    self._pending_of_ops[(dpid, rxid)] = {
                        'kind': 'meter_stats_sync',
                        'dpid': dpid,
                        'sync_token': sync_token,
                        'ts': time.time(),
                    }
                hub.spawn(self._meter_sync_watchdog, datapath, dpid, sync_token)
                return
            except Exception as e:
                self._meter_sync_pending.pop(dpid, None)
                self._meter_sync_buffer.pop(dpid, None)
                self.logger.warning('Failed to request meter stats on datapath %016x: %s', dpid, e)

        self._install_base_flows(datapath)

    @set_ev_cls(ofp_event.EventOFPMeterConfigStatsReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def _meter_config_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = self._dpid_of(datapath)
        if dpid is None:
            return
        ofproto = datapath.ofproto

        buf = self._meter_sync_buffer.setdefault(dpid, {})
        for stat in (getattr(msg, 'body', None) or []):
            try:
                mid = int(getattr(stat, 'meter_id', 0) or 0)
            except Exception:
                continue
            if mid <= 0:
                continue
            flags = int(getattr(stat, 'flags', 0) or 0)
            rate = 0
            burst = 0
            bands = list(getattr(stat, 'bands', None) or [])
            if bands:
                b0 = bands[0]
                try:
                    rate = int(getattr(b0, 'rate', 0) or 0)
                except Exception:
                    rate = 0
                try:
                    burst = int(getattr(b0, 'burst_size', 0) or 0)
                except Exception:
                    burst = 0
            buf[mid] = {'flags': flags, 'rate': rate, 'burst': burst}

        more_flag = int(getattr(ofproto, 'OFPMPF_REPLY_MORE', 1))
        if (int(getattr(msg, 'flags', 0) or 0) & more_flag) != 0:
            return

        committed = dict(self._meter_sync_buffer.pop(dpid, {}))
        managed = self._managed_meter_ids()
        self._switch_meters[dpid] = committed
        self._external_meters[dpid] = {m: dict(v) for m, v in committed.items() if m not in managed}

        dp_installed = self._installed_meters[dpid]
        for mid, info in committed.items():
            if mid in managed:
                dp_installed[mid] = {
                    'rate': int(info['rate']),
                    'flags': int(info['flags']),
                    'burst': int(info['burst']),
                    'verified': True,
                    'failed': False,
                    'last_error': None,
                    'source': 'switch_stats',
                }

        if self._meter_sync_pending.pop(dpid, None) is not None:
            self._install_base_flows(datapath)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def _barrier_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = self._dpid_of(datapath)
        if dpid is None:
            return
        bxid = getattr(msg, 'xid', None)
        if not isinstance(bxid, int):
            return
        binfo = self._pending_barriers.pop((dpid, bxid), None)
        if not binfo:
            return
        dp_installed = self._installed_meters[dpid]
        dp_sw = self._switch_meters[dpid]
        for mid, op_xid in (binfo.get('meter_ops') or []):
            if isinstance(op_xid, int):
                self._pending_of_ops.pop((dpid, op_xid), None)
            entry = dp_installed.get(mid)
            if not entry:
                continue
            if entry.get('xid') == op_xid and not entry.get('failed'):
                entry['verified'] = True
                dp_sw[mid] = {
                    'flags': int(entry['flags']),
                    'rate': int(entry['rate']),
                    'burst': int(entry['burst']),
                }

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def _error_msg_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = self._dpid_of(datapath)
        if dpid is None:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        err_type = int(getattr(msg, 'type', 0) or 0)
        err_code = int(getattr(msg, 'code', 0) or 0)
        xid = getattr(msg, 'xid', None)
        tname, cname = self._ofp_error_names(ofproto, err_type, err_code)

        pending = self._pending_of_ops.pop((dpid, xid), None) if isinstance(xid, int) else None
        rec = {
            'ts': time.time(),
            'dpid': dpid,
            'xid': xid,
            'type': err_type,
            'code': err_code,
            'type_name': tname,
            'code_name': cname,
            'kind': (pending.get('kind') if pending else 'unknown'),
            'meter_id': (pending.get('meter_id') if pending else None),
        }
        self._of_errors.append(rec)
        self.logger.warning(
            'OFPErrorMsg on datapath %016x xid=%s type=%s(%d) code=%s(%d) kind=%s meter_id=%s',
            dpid, xid, tname, err_type, cname, err_code, rec['kind'], rec['meter_id'],
        )

        if pending and pending.get('kind') == 'meter_stats_sync':
            if self._meter_sync_pending.pop(dpid, None) is not None:
                self._meter_sync_buffer.pop(dpid, None)
                self._install_base_flows(datapath)
            return

        if err_type == getattr(ofproto, 'OFPET_METER_MOD_FAILED', 12) and pending and pending.get('kind') == 'meter_mod':
            mid = int(pending.get('meter_id') or 0)
            rate_pps = int(pending.get('rate') or 0)
            dp_installed = self._installed_meters[dpid]
            exists_code = int(getattr(ofproto, 'OFPMMFC_METER_EXISTS', 1))
            if (
                err_code == exists_code
                and pending.get('cmd') == ofproto.OFPMC_ADD
                and mid in self._managed_meter_ids()
                and rate_pps > 0
                and not pending.get('retried')
            ):
                self.logger.info(
                    'Meter %s already exists on datapath %016x; retrying with OFPMC_MODIFY',
                    mid, dpid,
                )
                self._switch_meters[dpid].setdefault(mid, {
                    'flags': int(pending.get('flags') or 0),
                    'rate': 0,
                    'burst': 0,
                })
                self._send_meter_mod(
                    datapath, mid, rate_pps, command=ofproto.OFPMC_MODIFY, retried=True
                )
                return

            if mid in dp_installed:
                dp_installed[mid]['verified'] = False
                dp_installed[mid]['failed'] = True
                dp_installed[mid]['last_error'] = f'{tname}:{cname}'
            if pending.get('cmd') == ofproto.OFPMC_ADD:
                self._switch_meters[dpid].pop(mid, None)

    def _vip_mirror_params(self, datapath, vip_meter_id: int, vip_meter_pps: int):
        """Return (actions, meter_id, meter_pps) for VIP fastpath rules."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        meter_id = 0
        meter_pps = 0
        if self.dp_ctrl_meter_enabled:
            actions = [
                parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL),
            ]
            meter_id = int(self.dp_ctrl_meter_id or 0)
            meter_pps = int(self.dp_ctrl_meter_pps or 0)
        if self.dp_vip_rate_limit_enabled and vip_meter_id > 0:
            meter_id = int(vip_meter_id)
            meter_pps = int(vip_meter_pps or 0)
        return actions, meter_id, meter_pps

    def _install_base_flows(self, datapath) -> None:
        """Install base table-miss, ARP, fastpath/mirror, and active block/failsafe flows."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        base_ck = int(self._base_flow_cookie)
        if self.dp_fastpath_enabled:
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self._add_flow(datapath, priority=0, match=match, actions=actions, cookie=base_ck)

            match_arp = parser.OFPMatch(eth_type=0x0806)
            actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self._add_flow(datapath, priority=1, match=match_arp, actions=actions_arp, cookie=base_ck)

            if self.vip_ip:
                if self.dp_mirror_vip_all:
                    actions_vip, meter_id, meter_pps = self._vip_mirror_params(
                        datapath, int(self.dp_vip_other_meter_id or 0), int(self.dp_vip_other_pps or 0)
                    )
                    match_vip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=str(self.vip_ip))
                    self._add_flow(datapath, priority=50, match=match_vip, actions=actions_vip,
                                   meter_id=meter_id, meter_pps=meter_pps, cookie=base_ck)

                if self.dp_mirror_udp:
                    actions_udp, meter_id, meter_pps = self._vip_mirror_params(
                        datapath, int(self.dp_vip_udp_meter_id or 0), int(self.dp_vip_udp_pps or 0)
                    )
                    match_udp = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=str(self.vip_ip))
                    self._add_flow(datapath, priority=60, match=match_udp, actions=actions_udp,
                                   meter_id=meter_id, meter_pps=meter_pps, cookie=base_ck)

                if self.dp_mirror_icmp:
                    actions_icmp, meter_id, meter_pps = self._vip_mirror_params(
                        datapath, int(self.dp_vip_icmp_meter_id or 0), int(self.dp_vip_icmp_pps or 0)
                    )
                    match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_dst=str(self.vip_ip))
                    self._add_flow(datapath, priority=60, match=match_icmp, actions=actions_icmp,
                                   meter_id=meter_id, meter_pps=meter_pps, cookie=base_ck)

                for dport in list(self.dp_mirror_tcp_dports or []):
                    try:
                        dport_i = int(dport)
                    except Exception:
                        continue
                    match_tcp = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=str(self.vip_ip), tcp_dst=dport_i)
                    actions_tcp, meter_id, meter_pps = self._vip_mirror_params(
                        datapath, int(self.dp_vip_tcp_meter_id or 0), int(self.dp_vip_tcp_pps or 0)
                    )
                    self._add_flow(datapath, priority=70, match=match_tcp, actions=actions_tcp,
                                   meter_id=meter_id, meter_pps=meter_pps, cookie=base_ck)
        else:
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self._add_flow(datapath, priority=0, match=match, actions=actions,
                           meter_id=(int(self.dp_ctrl_meter_id or 0) if self.dp_ctrl_meter_enabled else 0),
                           meter_pps=(int(self.dp_ctrl_meter_pps or 0) if self.dp_ctrl_meter_enabled else 0),
                           cookie=base_ck)

            match_arp = parser.OFPMatch(eth_type=0x0806)
            actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self._add_flow(datapath, priority=1, match=match_arp, actions=actions_arp, cookie=base_ck)

        # Re-apply existing block/quarantine rules to connected switch
        for ip_addr in list(self.blocked_ips):
            self._install_block_ip(datapath, ip_addr)
        for mac_addr in list(self.blocked_macs):
            self._install_block_mac(datapath, mac_addr)
        for ip_addr in list(self.quarantined_ips):
            self._install_quarantine_ip(datapath, ip_addr)

        if self.dp_fastpath_enabled and self.adaptive_vip_rl_enabled and self._vip_rl_active:
            self._install_vip_rl(datapath)

        if self.dp_fastpath_enabled and self.ctrl_failsafe_enabled and self._failsafe_active:
            self._install_failsafe(datapath)

    def _send_meter_mod(self, datapath, mid: int, rate_pps: int, *, command: int, retried: bool = False) -> bool:
        dpid = int(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        desired_flags = int(ofproto.OFPMF_PKTPS | ofproto.OFPMF_STATS)
        burst = max(1, int(rate_pps) * 2)
        try:
            self._prune_pending_of_state()
            bands = [parser.OFPMeterBandDrop(rate=int(rate_pps), burst_size=burst)]
            mod = parser.OFPMeterMod(
                datapath=datapath,
                command=int(command),
                flags=desired_flags,
                meter_id=int(mid),
                bands=bands,
            )
            datapath.send_msg(mod)
            op_xid = getattr(mod, 'xid', None)
            if isinstance(op_xid, int):
                self._pending_of_ops[(dpid, op_xid)] = {
                    'kind': 'meter_mod',
                    'dpid': dpid,
                    'meter_id': int(mid),
                    'cmd': int(command),
                    'rate': int(rate_pps),
                    'flags': desired_flags,
                    'burst': burst,
                    'retried': bool(retried),
                    'ts': time.time(),
                }
            self._installed_meters[dpid][int(mid)] = {
                'rate': int(rate_pps),
                'flags': desired_flags,
                'burst': burst,
                'cmd': int(command),
                'xid': (op_xid if isinstance(op_xid, int) else None),
                'verified': False,
                'failed': False,
                'last_error': None,
                'source': 'meter_mod',
            }
            if hasattr(parser, 'OFPBarrierRequest'):
                barrier = parser.OFPBarrierRequest(datapath)
                datapath.send_msg(barrier)
                bxid = getattr(barrier, 'xid', None)
                if isinstance(bxid, int):
                    self._pending_barriers[(dpid, bxid)] = {
                        'dpid': dpid,
                        'meter_ops': [(int(mid), op_xid)],
                        'ts': time.time(),
                    }
            return True
        except Exception as e:
            self.logger.warning('Failed to configure meter %s on datapath %016x: %s', mid, dpid, e)
            return False

    def _ensure_meter(self, datapath, meter_id: int, pps: int) -> bool:
        """Create or update a managed OpenFlow 1.3 PKTPS meter using switch sync & Barrier verification."""
        if not meter_id or int(meter_id) <= 0 or not pps or int(pps) <= 0:
            return False
        dpid = int(datapath.id)
        mid = int(meter_id)
        rate_pps = int(pps)

        if mid not in self._managed_meter_ids():
            self.logger.warning('Refusing to modify unmanaged meter %s on datapath %016x', mid, dpid)
            return False

        ofproto = datapath.ofproto
        desired_flags = int(ofproto.OFPMF_PKTPS | ofproto.OFPMF_STATS)
        flag_mask = int(ofproto.OFPMF_PKTPS | ofproto.OFPMF_KBPS | ofproto.OFPMF_STATS)

        sw_entry = self._switch_meters[dpid].get(mid)
        cur_entry = self._installed_meters[dpid].get(mid)

        if sw_entry is not None:
            if int(sw_entry.get('rate') or 0) == rate_pps and (int(sw_entry.get('flags') or 0) & flag_mask) == desired_flags:
                if not cur_entry or not cur_entry.get('failed'):
                    self._installed_meters[dpid][mid] = {
                        'rate': rate_pps,
                        'flags': int(sw_entry.get('flags') or desired_flags),
                        'burst': int(sw_entry.get('burst') or 0),
                        'verified': True,
                        'failed': False,
                        'last_error': None,
                        'source': (cur_entry.get('source') if cur_entry else 'switch_stats'),
                    }
                    return True

        if cur_entry and cur_entry.get('rate') == rate_pps and (int(cur_entry.get('flags') or 0) & flag_mask) == desired_flags:
            if cur_entry.get('failed'):
                return False
            if cur_entry.get('verified') or cur_entry.get('xid') is not None:
                return True

        cmd = ofproto.OFPMC_MODIFY if (sw_entry is not None or mid in self._installed_meters[dpid]) else ofproto.OFPMC_ADD
        return self._send_meter_mod(datapath, mid, rate_pps, command=cmd)

    def _app_flow_cookies(self) -> Tuple[int, ...]:
        """Return all OpenFlow flow cookies owned by DoSGuard."""
        return (
            int(self._base_flow_cookie),
            int(self._learned_flow_cookie),
            int(self._vip_rl_cookie),
            int(self._failsafe_cookie),
            int(self._quarantine_cookie),
            int(self._block_ip_cookie),
            int(self._block_mac_cookie),
        )

    def _clear_dpid_flow_specs(self, dpid: int) -> None:
        self._installed_vip_rl_specs.pop(dpid, None)
        self._installed_failsafe_specs.pop(dpid, None)
        for store in (
            self._installed_block_ip_specs,
            self._installed_quarantine_specs,
            self._installed_block_mac_specs,
        ):
            for k in [k for k in store if k[0] == dpid]:
                store.pop(k, None)

    def _delete_flow_strict(self, datapath, *, table_id: int, priority: int, match, cookie: int) -> None:
        """Delete an exact single OpenFlow rule using OFPFC_DELETE_STRICT and full cookie ownership mask."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        strict_cmd = int(getattr(ofproto, 'OFPFC_DELETE_STRICT', 4))
        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=int(table_id),
            command=strict_cmd,
            priority=int(priority),
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=int(cookie),
            cookie_mask=0xffffffffffffffff,
            match=match,
        )
        datapath.send_msg(mod)
        dpid = self._dpid_of(datapath)
        fxid = getattr(mod, 'xid', None)
        if dpid is not None and isinstance(fxid, int):
            self._pending_of_ops[(dpid, fxid)] = {'kind': 'flow_delete_strict', 'dpid': dpid, 'ts': time.time()}

    def _delete_flows_by_cookie(self, datapath, *, cookie: int, table_id: Optional[int] = None, match=None) -> None:
        """Delete controller-owned flows matching exact cookie (never wildcard cookie_mask=0)."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        tid = int(table_id) if table_id is not None else int(getattr(ofproto, 'OFPTT_ALL', 0xff))
        kwargs = {
            'datapath': datapath,
            'table_id': tid,
            'command': ofproto.OFPFC_DELETE,
            'out_port': ofproto.OFPP_ANY,
            'out_group': ofproto.OFPG_ANY,
            'cookie': int(cookie),
            'cookie_mask': 0xffffffffffffffff,
        }
        if match is not None:
            kwargs['match'] = match
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
        dpid = self._dpid_of(datapath)
        fxid = getattr(mod, 'xid', None)
        if dpid is not None and isinstance(fxid, int):
            self._pending_of_ops[(dpid, fxid)] = {'kind': 'flow_delete_cookie', 'dpid': dpid, 'ts': time.time()}

    def _add_flow(self, datapath, priority: int, match, actions=None, meter_id: int = 0,
                  meter_pps: int = 0, cookie: int = 0, buffer_id: Optional[int] = None,
                  table_id: int = 0, idle_timeout: int = 0) -> None:
        """Install an OpenFlow flow entry.

        Args:
            datapath: Ryu datapath object
            priority: Flow rule priority
            match: OpenFlow match object
            actions: List of actions (None for drop)
            meter_id: Meter ID for rate limiting (0 or None for none)
            meter_pps: PPS threshold for meter
            cookie: Flow cookie for identification
            buffer_id: Optional switch buffer_id for buffered PacketIn flows
            table_id: Explicit OpenFlow table_id (default 0)
            idle_timeout: Flow idle timeout in seconds (default 0 for permanent)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = []
        mid = int(meter_id) if meter_id is not None else 0
        mpps = int(meter_pps) if meter_pps is not None else 0
        if mid > 0 and mpps > 0:
            if self._ensure_meter(datapath, mid, mpps):
                inst.append(parser.OFPInstructionMeter(mid, ofproto.OFPIT_METER))
        if actions:
            inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))

        kwargs = {
            'datapath': datapath,
            'table_id': int(table_id),
            'priority': int(priority),
            'match': match,
            'instructions': inst,
            'cookie': (int(cookie) if cookie is not None else int(self._base_flow_cookie)),
            'idle_timeout': int(idle_timeout),
        }
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs['buffer_id'] = buffer_id
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
        dpid = self._dpid_of(datapath)
        fxid = getattr(mod, 'xid', None)
        if dpid is not None and isinstance(fxid, int):
            self._pending_of_ops[(dpid, fxid)] = {'kind': 'flow_add', 'dpid': dpid, 'ts': time.time()}

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        stats = ev.msg.body
        total = len(stats)
        drops = 0
        top = []
        for s in stats:
            try:
                if s.priority == self.drop_priority:
                    drops += 1
                top.append({
                    'priority': getattr(s, 'priority', None),
                    'packet_count': getattr(s, 'packet_count', None),
                    'byte_count': getattr(s, 'byte_count', None),
                    'table_id': getattr(s, 'table_id', None),
                    'duration_sec': getattr(s, 'duration_sec', None),
                    'match': str(getattr(s, 'match', '')),
                    'actions': str(getattr(s, 'instructions', '')),
                })
            except Exception:
                pass
        try:
            top_sorted = sorted(top, key=lambda x: (x['packet_count'] or 0), reverse=True)[:10]
        except Exception:
            top_sorted = top[:10]
        self.flow_stats_summary[dpid] = {
            'total_flows': total,
            'drop_flows': drops,
            'top': top_sorted,
        }

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        ports = []
        for p in body:
            try:
                ports.append({
                    'port_no': getattr(p, 'port_no', None),
                    'rx_packets': getattr(p, 'rx_packets', None),
                    'tx_packets': getattr(p, 'tx_packets', None),
                    'rx_bytes': getattr(p, 'rx_bytes', None),
                    'tx_bytes': getattr(p, 'tx_bytes', None),
                    'rx_dropped': getattr(p, 'rx_dropped', None),
                    'tx_dropped': getattr(p, 'tx_dropped', None),
                    'rx_errors': getattr(p, 'rx_errors', None),
                    'tx_errors': getattr(p, 'tx_errors', None),
                })
            except Exception:
                pass
        self.port_stats_summary[dpid] = ports
