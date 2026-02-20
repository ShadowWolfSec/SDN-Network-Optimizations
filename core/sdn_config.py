"""
core/sdn_config.py - Unified Configuration Management Architecture
F-18 Phase C Implementation
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple, Union
from enum import Enum
import os
import json
import logging
import tempfile

logger = logging.getLogger('sdn.config')


class ConfigSource(str, Enum):
    DEFAULT = "default"
    FILE = "file"
    ENVIRONMENT = "env"
    CLI = "cli"
    RUNTIME_EPHEMERAL = "runtime_ephemeral"


class ConfigMutability(str, Enum):
    STARTUP_ONLY = "startup_only"
    RUNTIME_MUTABLE = "runtime_mutable"
    HARDCODED_READONLY = "readonly"


@dataclass(frozen=True)
class ConfigField:
    name: str
    canonical_env: str
    legacy_envs: List[str]
    type_fn: type
    default_value: Any
    mutability: ConfigMutability
    description: str
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None


from core.common_utils import (
    parse_bool,
    parse_int,
    parse_float,
    parse_str,
)

# Backward-compatibility aliases
_parse_bool = parse_bool
_parse_int = parse_int
_parse_float = parse_float
_parse_str = parse_str


class SDNConfigSchema:
    """Canonical schema for all SDN parameters across Bash, Flask, and Ryu."""

    FIELDS: Dict[str, ConfigField] = {
        # 1. Network & Binding
        "wsapi_host": ConfigField(
            name="wsapi_host",
            canonical_env="SDN_WSAPI_HOST",
            legacy_envs=["RYU_REST_HOST"],
            type_fn=_parse_str,
            default_value="127.0.0.1",
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Ryu WSAPI REST listening host",
        ),
        "wsapi_port": ConfigField(
            name="wsapi_port",
            canonical_env="SDN_WSAPI_PORT",
            legacy_envs=["RYU_REST_PORT"],
            type_fn=_parse_int,
            default_value=8080,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Ryu WSAPI REST listening port",
            min_value=1024,
            max_value=65535,
        ),
        "ofp_port": ConfigField(
            name="ofp_port",
            canonical_env="SDN_OFP_PORT",
            legacy_envs=["RYU_OFP_PORT", "OFP_TCP_LISTEN_PORT"],
            type_fn=_parse_int,
            default_value=6653,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Ryu OpenFlow 1.3 TCP listening port",
            min_value=0,
            max_value=65535,
        ),
        "vip_ip": ConfigField(
            name="vip_ip",
            canonical_env="SDN_VIP_IP",
            legacy_envs=["VIP_IP", "HA_VIP_IP"],
            type_fn=_parse_str,
            default_value="10.0.0.100",
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Virtual IP protected target",
        ),

        # 2. Datapath Controls (Strictly False Defaults for Protection)
        "fastpath_enable": ConfigField(
            name="fastpath_enable",
            canonical_env="SDN_FASTPATH_ENABLE",
            legacy_envs=["DP_FASTPATH_ENABLE"],
            type_fn=_parse_bool,
            default_value=False,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Fastpath L2 switch bypass (False=Full inspection)",
        ),
        "ctrl_meter_enable": ConfigField(
            name="ctrl_meter_enable",
            canonical_env="SDN_CTRL_METER_ENABLE",
            legacy_envs=["DP_CTRL_METER_ENABLE"],
            type_fn=_parse_bool,
            default_value=False,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="OpenFlow meter on controller path",
        ),
        "ctrl_meter_pps": ConfigField(
            name="ctrl_meter_pps",
            canonical_env="SDN_CTRL_METER_PPS",
            legacy_envs=["DP_CTRL_METER_PPS"],
            type_fn=_parse_int,
            default_value=2500,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Controller meter rate limit in PPS",
            min_value=100,
            max_value=1000000,
        ),
        "learning_enable": ConfigField(
            name="learning_enable",
            canonical_env="SDN_LEARNING_ENABLE",
            legacy_envs=["LEARNING_ENABLE"],
            type_fn=_parse_bool,
            default_value=False,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="L2 MAC learning mode (False=Inspect all packets)",
        ),

        # 3. Detection Thresholds (Runtime Mutable)
        "threshold_pps": ConfigField(
            name="threshold_pps",
            canonical_env="SDN_THRESHOLD_PPS",
            legacy_envs=["THRESHOLD_PPS", "PPS_THRESHOLD"],
            type_fn=_parse_float,
            default_value=300.0,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="EWMA Baseline traffic anomaly threshold (PPS)",
            min_value=1.0,
            max_value=1000000.0,
        ),
        "alpha": ConfigField(
            name="alpha",
            canonical_env="SDN_ALPHA",
            legacy_envs=["ALPHA"],
            type_fn=_parse_float,
            default_value=0.3,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="EWMA Smoothing factor alpha",
            min_value=0.01,
            max_value=1.0,
        ),
        "measure_interval": ConfigField(
            name="measure_interval",
            canonical_env="SDN_MEASURE_INTERVAL",
            legacy_envs=["MEASURE_INTERVAL"],
            type_fn=_parse_float,
            default_value=1.0,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Rate calculation interval in seconds",
            min_value=0.1,
            max_value=300.0,
        ),
        "syn_threshold": ConfigField(
            name="syn_threshold",
            canonical_env="SDN_SYN_THRESHOLD",
            legacy_envs=["SYN_THRESHOLD"],
            type_fn=_parse_float,
            default_value=200.0,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="TCP SYN flood detection threshold (PPS)",
            min_value=1.0,
            max_value=1000000.0,
        ),
        "udp_threshold": ConfigField(
            name="udp_threshold",
            canonical_env="SDN_UDP_THRESHOLD",
            legacy_envs=["UDP_THRESHOLD"],
            type_fn=_parse_float,
            default_value=400.0,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="UDP flood detection threshold (PPS)",
            min_value=1.0,
            max_value=1000000.0,
        ),
        "portscan_threshold": ConfigField(
            name="portscan_threshold",
            canonical_env="SDN_PORTSCAN_THRESHOLD",
            legacy_envs=["PORTSCAN_THRESHOLD"],
            type_fn=_parse_int,
            default_value=50,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Portscan unique ports threshold",
            min_value=1,
            max_value=65535,
        ),

        # 4. Mitigation & HA Controls
        "mitigation_enable": ConfigField(
            name="mitigation_enable",
            canonical_env="SDN_MITIGATION_ENABLE",
            legacy_envs=["MITIGATION_ENABLE"],
            type_fn=_parse_bool,
            default_value=True,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Automated IP/MAC blocking on attack detection",
        ),
        "auto_failover_enable": ConfigField(
            name="auto_failover_enable",
            canonical_env="SDN_AUTO_FAILOVER_ENABLE",
            legacy_envs=["AUTO_FAILOVER_ENABLE"],
            type_fn=_parse_bool,
            default_value=False,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="HA automatic failover coordination (False by default)",
        ),
        "block_duration_sec": ConfigField(
            name="block_duration_sec",
            canonical_env="SDN_BLOCK_DURATION_SEC",
            legacy_envs=["DDOS_BLOCK_DURATION_SEC"],
            type_fn=_parse_float,
            default_value=120.0,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Temporary attack block duration (0=permanent)",
            min_value=0.0,
            max_value=86400.0,
        ),
        "drop_priority": ConfigField(
            name="drop_priority",
            canonical_env="SDN_DROP_PRIORITY",
            legacy_envs=["DROP_PRIORITY"],
            type_fn=_parse_int,
            default_value=200,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="OpenFlow flow drop priority",
            min_value=1,
            max_value=65535,
        ),
        "stats_poll_interval_sec": ConfigField(
            name="stats_poll_interval_sec",
            canonical_env="SDN_STATS_POLL_INTERVAL_SEC",
            legacy_envs=["STATS_POLL_INTERVAL_SEC"],
            type_fn=_parse_float,
            default_value=5.0,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Ryu switch stats polling interval in seconds",
            min_value=1.0,
            max_value=60.0,
        ),
        # 11. Log Rotation & PCAP Lifecycle (F-30)
        "log_max_bytes": ConfigField(
            name="log_max_bytes",
            canonical_env="SDN_LOG_MAX_BYTES",
            legacy_envs=["LOG_MAX_BYTES"],
            type_fn=_parse_int,
            default_value=10 * 1024 * 1024,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Max bytes per log file before rotation (default 10MB)",
            min_value=100 * 1024,
            max_value=100 * 1024 * 1024,
        ),
        "log_backup_count": ConfigField(
            name="log_backup_count",
            canonical_env="SDN_LOG_BACKUP_COUNT",
            legacy_envs=["LOG_BACKUP_COUNT"],
            type_fn=_parse_int,
            default_value=5,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Number of rotated log backups to retain",
            min_value=1,
            max_value=30,
        ),
        "log_tail_max_bytes": ConfigField(
            name="log_tail_max_bytes",
            canonical_env="SDN_LOG_TAIL_MAX_BYTES",
            legacy_envs=["LOG_TAIL_MAX_BYTES"],
            type_fn=_parse_int,
            default_value=256 * 1024,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Max bytes read backward during log tailing (safety ceiling)",
            min_value=16 * 1024,
            max_value=2 * 1024 * 1024,
        ),
        "pcap_max_files": ConfigField(
            name="pcap_max_files",
            canonical_env="SDN_PCAP_MAX_FILES",
            legacy_envs=["MAX_PCAP_FILES"],
            type_fn=_parse_int,
            default_value=30,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Max PCAP files retained in logs/pcaps",
            min_value=5,
            max_value=200,
        ),
        "pcap_max_total_mb": ConfigField(
            name="pcap_max_total_mb",
            canonical_env="SDN_PCAP_MAX_TOTAL_MB",
            legacy_envs=["MAX_PCAP_TOTAL_MB"],
            type_fn=_parse_int,
            default_value=200,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Max total storage allocated for PCAP files in MB",
            min_value=20,
            max_value=5000,
        ),
        "pcap_single_file_max_mb": ConfigField(
            name="pcap_single_file_max_mb",
            canonical_env="SDN_PCAP_SINGLE_FILE_MAX_MB",
            legacy_envs=["PCAP_MAX_MB"],
            type_fn=_parse_int,
            default_value=25,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Max MB per attack capture file to prevent disk flooding",
            min_value=1,
            max_value=200,
        ),
        "pcap_snaplen": ConfigField(
            name="pcap_snaplen",
            canonical_env="SDN_PCAP_SNAPLEN",
            legacy_envs=["PCAP_SNAPLEN"],
            type_fn=_parse_int,
            default_value=96,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Snaplen bytes captured per packet by tcpdump",
            min_value=64,
            max_value=65535,
        ),
        "events_max_file_mb": ConfigField(
            name="events_max_file_mb",
            canonical_env="SDN_EVENTS_MAX_FILE_MB",
            legacy_envs=["EVENTS_MAX_FILE_MB"],
            type_fn=_parse_int,
            default_value=10,
            mutability=ConfigMutability.STARTUP_ONLY,
            description="Max size in MB of daily event CSV file before part rotation",
            min_value=1,
            max_value=100,
        ),
        "events_retention_days": ConfigField(
            name="events_retention_days",
            canonical_env="SDN_EVENTS_RETENTION_DAYS",
            legacy_envs=["EVENTS_RETENTION_DAYS"],
            type_fn=_parse_int,
            default_value=14,
            mutability=ConfigMutability.RUNTIME_MUTABLE,
            description="Retention days for daily event CSV files",
            min_value=1,
            max_value=180,
        ),
    }


SDN_CONFIG_ALIASES: Dict[str, str] = {
    'ewma_alpha': 'alpha',
    'block_duration': 'block_duration_sec',
    'dp_ctrl_meter_enable': 'ctrl_meter_enable',
    'controller_meter_enable': 'ctrl_meter_enable',
    'dp_fastpath_enable': 'fastpath_enable',
    'pcap_max_mb': 'pcap_single_file_max_mb',
    'max_pcap_files': 'pcap_max_files',
    'max_pcap_total_mb': 'pcap_max_total_mb',
}


class SDNConfigManager:
    """Manages the 5-layer configuration hierarchy and persistence for SDN."""

    def __init__(self, config_file: Optional[str] = None):
        if config_file:
            self._config_file = config_file
        else:
            run_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.run'))
            os.makedirs(run_dir, exist_ok=True)
            self._config_file = os.path.join(run_dir, 'sdn_config.json')

        self._startup_config: Dict[str, Any] = {}
        self._runtime_overrides: Dict[str, Any] = {}
        self._provenance: Dict[str, ConfigSource] = {}
        self.load_startup()

    @property
    def config_file(self) -> str:
        return self._config_file

    def load_startup(self) -> Dict[str, Any]:
        """Loads configuration honoring strict 4-layer startup hierarchy."""
        effective: Dict[str, Any] = {}
        provenance: Dict[str, ConfigSource] = {}

        # Layer 1: Baseline Defaults
        for name, field_spec in SDNConfigSchema.FIELDS.items():
            effective[name] = field_spec.default_value
            provenance[name] = ConfigSource.DEFAULT

        # Layer 2: Persistent Configuration File
        file_cfg = self._read_config_file()
        for name, field_spec in SDNConfigSchema.FIELDS.items():
            if name in file_cfg:
                try:
                    val = field_spec.type_fn(file_cfg[name])
                    if self._check_bounds(field_spec, val):
                        effective[name] = val
                        provenance[name] = ConfigSource.FILE
                except Exception as ex:
                    logger.warning("Ignoring invalid config file field %s: %s", name, ex)

        # Layer 3: Environment Variables (Canonical > Legacy)
        for name, field_spec in SDNConfigSchema.FIELDS.items():
            raw_val = None
            source_found = None
            if field_spec.canonical_env in os.environ:
                raw_val = os.environ[field_spec.canonical_env]
                source_found = ConfigSource.ENVIRONMENT
            else:
                for leg in field_spec.legacy_envs:
                    if leg in os.environ:
                        raw_val = os.environ[leg]
                        source_found = ConfigSource.ENVIRONMENT
                        break

            if raw_val is not None:
                try:
                    val = field_spec.type_fn(raw_val)
                    if self._check_bounds(field_spec, val):
                        effective[name] = val
                        provenance[name] = source_found
                except Exception as ex:
                    logger.warning("Ignoring invalid environment variable for %s: %s", name, ex)

        self._startup_config = effective
        self._provenance = provenance
        self._runtime_overrides.clear()
        return dict(self._startup_config)

    def _read_config_file(self) -> Dict[str, Any]:
        if not os.path.isfile(self._config_file):
            return {}
        try:
            with open(self._config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception as ex:
            logger.warning("Failed to read config file %s: %s", self._config_file, ex)
            return {}

    def _check_bounds(self, field_spec: ConfigField, val: Any) -> bool:
        if field_spec.min_value is not None and val < field_spec.min_value:
            return False
        if field_spec.max_value is not None and val > field_spec.max_value:
            return False
        return True

    def get_effective(self, name: str) -> Any:
        """Returns the effective value respecting priority: Runtime Override > Startup."""
        canonical = SDN_CONFIG_ALIASES.get(name, name)
        if canonical in self._runtime_overrides:
            return self._runtime_overrides[canonical]
        if canonical in self._startup_config:
            return self._startup_config[canonical]
        if canonical in SDNConfigSchema.FIELDS:
            return SDNConfigSchema.FIELDS[canonical].default_value
        return None

    def get_all_effective(self) -> Dict[str, Any]:
        result = dict(self._startup_config)
        result.update(self._runtime_overrides)
        return result

    def get_metadata(self) -> Dict[str, Dict[str, Any]]:
        meta: Dict[str, Dict[str, Any]] = {}
        for name, field_spec in SDNConfigSchema.FIELDS.items():
            eff = self.get_effective(name)
            src = ConfigSource.RUNTIME_EPHEMERAL if name in self._runtime_overrides else self._provenance.get(name, ConfigSource.DEFAULT)
            meta[name] = {
                "value": eff,
                "default": field_spec.default_value,
                "mutability": field_spec.mutability.value,
                "source": src.value,
                "min": field_spec.min_value,
                "max": field_spec.max_value,
                "canonical_env": field_spec.canonical_env,
                "legacy_envs": field_spec.legacy_envs,
                "description": field_spec.description,
            }
        return meta

    def apply_runtime_override(
        self,
        updates: Dict[str, Any],
        persist: bool = False,
    ) -> Tuple[Dict[str, Any], Dict[str, str], bool]:
        """Applies dynamic updates in-memory. If persist=True, executes atomic two-phase write."""
        changed: Dict[str, Any] = {}
        errors: Dict[str, str] = {}

        for raw_k, raw_v in updates.items():
            if raw_k == 'persist':
                continue
            k = SDN_CONFIG_ALIASES.get(raw_k, raw_k)
            if k not in SDNConfigSchema.FIELDS:
                if persist:
                    errors[raw_k] = "unknown_configuration_field"
                continue

            field_spec = SDNConfigSchema.FIELDS[k]
            try:
                typed_v = field_spec.type_fn(raw_v)
            except Exception:
                errors[raw_k] = f"invalid_type_expected_{field_spec.type_fn.__name__}"
                continue

            if not self._check_bounds(field_spec, typed_v):
                errors[raw_k] = f"out_of_bounds_range_[{field_spec.min_value}_{field_spec.max_value}]"
                continue

            changed[k] = typed_v

        if errors:
            return {}, errors, False

        # Apply in memory
        for k, v in changed.items():
            self._runtime_overrides[k] = v

        persisted = False
        if persist and changed:
            persisted = self._atomic_persist_to_file(changed)

        return changed, {}, persisted

    def _atomic_persist_to_file(self, new_values: Dict[str, Any]) -> bool:
        """Executes atomic staging and rename to guarantee persistence durability."""
        existing = self._read_config_file()
        merged = dict(existing)
        merged.update(new_values)

        dir_name = os.path.dirname(self._config_file)
        os.makedirs(dir_name, exist_ok=True)
        tmp_path = f"{self._config_file}.tmp"

        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(merged, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self._config_file)
            for k in new_values:
                self._startup_config[k] = new_values[k]
                self._provenance[k] = ConfigSource.FILE
            return True
        except Exception as ex:
            logger.error("Failed to atomically persist config file %s: %s", self._config_file, ex)
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            return False

    def export_for_subprocess(self) -> Dict[str, str]:
        """Exports string environment dictionary for Popen, mapping canonical AND legacy aliases."""
        env_dict: Dict[str, str] = {}
        for name, field_spec in SDNConfigSchema.FIELDS.items():
            val = self.get_effective(name)
            str_val = "1" if val is True else ("0" if val is False else str(val))
            # Set canonical
            env_dict[field_spec.canonical_env] = str_val
            # Set legacy aliases for 100% backwards compatibility
            for leg in field_spec.legacy_envs:
                env_dict[leg] = str_val
        return env_dict


# Global Singleton for webapp and runners
_GLOBAL_CONFIG_MANAGER: Optional[SDNConfigManager] = None


def get_config_manager() -> SDNConfigManager:
    global _GLOBAL_CONFIG_MANAGER
    if _GLOBAL_CONFIG_MANAGER is None:
        _GLOBAL_CONFIG_MANAGER = SDNConfigManager()
    return _GLOBAL_CONFIG_MANAGER
