"""
ryu_app/detection.py
Anomaly detection algorithms: EWMA rate calculation, Shannon entropy,
and threshold classification.
"""

from typing import Any, Dict, List, Optional, Set, Tuple


def calculate_ewma(current_rate: float, prev_ewma: float, alpha: float) -> float:
    """Calculates Exponentially Weighted Moving Average (EWMA).
    
    Formula:
        EWMA_t = alpha * current_rate + (1.0 - alpha) * prev_ewma
    """
    a = min(1.0, max(0.0, float(alpha)))
    return a * float(current_rate) + (1.0 - a) * float(prev_ewma)


def calculate_pps(delta_packets: int, delta_time: float) -> float:
    """Calculates packets per second (PPS) given packet count delta and time delta."""
    dt = float(delta_time)
    if dt <= 0.0:
        return 0.0
    return float(delta_packets) / dt


def is_anomaly(rate: float, threshold: float) -> bool:
    """Verifies whether measured packet rate strictly equals or exceeds detection threshold."""
    return float(rate) >= float(threshold)


def evaluate_port_scan(target_ports: Any, threshold: int) -> bool:
    """Evaluates whether distinct target ports contacted exceed portscan threshold."""
    if not target_ports:
        return False
    return len(target_ports) >= int(threshold)


def classify_trigger(trigger: str) -> Tuple[str, str]:
    """Classifies trigger name into (family, attack_type) tuple."""
    mapping = {
        'pps_threshold_exceeded': ('dos', 'pps_flood'),
        'syn_rate_exceeded': ('dos', 'syn_flood'),
        'udp_rate_exceeded': ('dos', 'udp_flood'),
        'portscan_detected': ('dos', 'port_scan'),
        'entropy_high': ('dos', 'entropy_scan'),
        'ddos_detected': ('ddos', 'multi_source_flood'),
        'spoof_flood': ('ddos', 'spoof_flood'),
    }
    t = str(trigger or '').strip()
    return mapping.get(t, ('dos', t or 'unknown'))


def is_heavy_key(
    raw_key: str,
    ewma_map: Dict[str, float],
    singleton_thr: float = 5.0,
    protected_ips: Optional[Set[str]] = None,
    blocked_ips: Optional[Set[str]] = None,
    quarantined_ips: Optional[Set[str]] = None,
) -> Tuple[int, int]:
    """Returns priority eviction tuple: (protected_or_blocked_flag, known_heavy_ewma_flag)."""
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

    prot = 0
    if ip_only:
        if blocked_ips and ip_only in blocked_ips:
            prot = 1
        elif quarantined_ips and ip_only in quarantined_ips:
            prot = 1
        elif protected_ips and ip_only in protected_ips:
            prot = 1

    try:
        heavy = 1 if float(ewma_map.get(ew_key, 0.0) or 0.0) >= float(singleton_thr) else 0
    except Exception:
        heavy = 0
    return prot, heavy


def count_score_fn(
    key: str,
    count_val: Any,
    prot: int,
    heavy: int,
) -> Tuple[int, int, int]:
    """Priority-preserving score tuple: evict low-count non-heavy singletons first."""
    try:
        cnt = int(count_val or 0)
    except Exception:
        cnt = 0
    return prot, heavy, cnt


def enforce_ewma_bounds(
    ewma_map: Dict[str, float],
    src_last_seen: Dict[str, float],
    cap: int,
    is_heavy_fn: Any,
    prune_fn: Any,
) -> None:
    """Enforces bounding and amortized batch eviction on EWMA and last-seen dictionaries."""
    if cap > 0 and len(ewma_map) > cap:
        prune_fn(
            ewma_map,
            cap,
            lambda k, ew: (*is_heavy_fn(k), float(ew or 0.0), float(src_last_seen.get(k, 0.0) or 0.0)),
            on_evict=lambda k, _v: src_last_seen.pop(k, None),
            trim_to_cap=True,
        )
    stale_last_seen = [k for k in src_last_seen if k not in ewma_map]
    for k in stale_last_seen:
        src_last_seen.pop(k, None)
