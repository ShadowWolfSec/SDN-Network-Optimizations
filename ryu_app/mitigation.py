"""
ryu_app/mitigation.py
OpenFlow 1.3 message builder helpers for flow-mod and meter rules.
"""

from typing import Any, List, Optional


def build_ip_drop_match(parser: Any, ofproto: Any, ip_addr: str) -> Any:
    """Builds OpenFlow 1.3 match structure for dropping traffic by IPv4 source address."""
    return parser.OFPMatch(eth_type=0x0800, ipv4_src=str(ip_addr).strip())


def build_mac_drop_match(parser: Any, ofproto: Any, mac_addr: str) -> Any:
    """Builds OpenFlow 1.3 match structure for dropping traffic by Ethernet MAC address."""
    return parser.OFPMatch(eth_src=str(mac_addr).strip().lower())


def build_flow_mod(
    dp: Any,
    priority: int,
    match: Any,
    instructions: Optional[List[Any]] = None,
    actions: Optional[List[Any]] = None,
    table_id: int = 0,
    idle_timeout: int = 0,
    hard_timeout: int = 0,
    cookie: int = 0,
    buffer_id: Optional[int] = None,
    command: Optional[int] = None,
) -> Any:
    """Constructs OpenFlow 1.3 OFPFlowMod message object without sending it."""
    parser = dp.ofproto_parser
    ofproto = dp.ofproto

    inst = list(instructions or [])
    if actions and not inst:
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))

    cmd = ofproto.OFPFC_ADD if command is None else int(command)

    kwargs = {
        'datapath': dp,
        'table_id': int(table_id),
        'command': cmd,
        'priority': int(priority),
        'match': match,
        'instructions': inst,
        'idle_timeout': int(idle_timeout),
        'hard_timeout': int(hard_timeout),
        'cookie': int(cookie),
    }
    if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
        kwargs['buffer_id'] = buffer_id

    return parser.OFPFlowMod(**kwargs)


def build_meter_mod(
    dp: Any,
    meter_id: int,
    rate_pps: int,
    burst_size: int = 0,
    command: Optional[int] = None,
) -> Any:
    """Constructs OpenFlow 1.3 OFPMeterMod message object without sending it."""
    parser = dp.ofproto_parser
    ofproto = dp.ofproto

    cmd = ofproto.OFPMC_ADD if command is None else int(command)
    flags = ofproto.OFPMF_PKTPS
    if burst_size > 0:
        flags |= ofproto.OFPMF_BURST

    bands = [
        parser.OFPMeterBandDrop(
            rate=int(rate_pps),
            burst_size=int(burst_size),
        )
    ]
    return parser.OFPMeterMod(
        datapath=dp,
        command=cmd,
        flags=flags,
        meter_id=int(meter_id),
        bands=bands,
    )


def build_delete_flow_strict(
    dp: Any,
    priority: int,
    match: Any,
    table_id: int = 0,
    out_port: Optional[int] = None,
    out_group: Optional[int] = None,
) -> Any:
    """Constructs strict flow delete message (OFPFC_DELETE_STRICT)."""
    parser = dp.ofproto_parser
    ofproto = dp.ofproto

    port = ofproto.OFPP_ANY if out_port is None else int(out_port)
    group = ofproto.OFPG_ANY if out_group is None else int(out_group)

    return parser.OFPFlowMod(
        datapath=dp,
        table_id=int(table_id),
        command=ofproto.OFPFC_DELETE_STRICT,
        priority=int(priority),
        match=match,
        out_port=port,
        out_group=group,
    )


def build_delete_flows_by_cookie(
    dp: Any,
    cookie: int,
    cookie_mask: int = 0xFFFFFFFFFFFFFFFF,
    table_id: int = 0,
) -> Any:
    """Constructs cookie-based bulk flow delete message (OFPFC_DELETE)."""
    parser = dp.ofproto_parser
    ofproto = dp.ofproto

    return parser.OFPFlowMod(
        datapath=dp,
        table_id=int(table_id),
        command=ofproto.OFPFC_DELETE,
        out_port=ofproto.OFPP_ANY,
        out_group=ofproto.OFPG_ANY,
        cookie=int(cookie),
        cookie_mask=int(cookie_mask),
    )
