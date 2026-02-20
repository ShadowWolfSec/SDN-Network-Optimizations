"""SDN DDoS Mitigation Lab - Web Application Server.

Entry point for the web application. Constructs the Flask app instance via
`create_app()`, which mounts all 7 domain blueprints:
- dashboard: Core UI routes, auth views, health checks
- monitoring: Glances metrics, circuit breaker, system alerts
- events: History logs and CSV export
- controller: Ryu controller process management (status, start, stop)
- lab_proxy: Mininet runner proxy routes (topology, attacks, PCAP, HA)
- mitigation: Ryu REST mitigation proxy routes (block, unblock, whitelist, flows)
- whitelist: Persistent whitelist management (save, restore, status, delete)

Maintains 100% backward compatibility by re-exporting all interfaces and variables.
"""

import atexit
import copy
import ctypes
import datetime
import errno
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from flask import (
    Flask,
    Response,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
)
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# Path configuration: ensure PROJECT_ROOT is at sys.path[0] and webapp/ is removed from sys.path
# to prevent webapp/core from shadowing root-level core/ packages when executed as a script.
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, '..'))
while _CURRENT_DIR in sys.path:
    sys.path.remove(_CURRENT_DIR)
while _PROJECT_ROOT in sys.path:
    sys.path.remove(_PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)

APP_HOST = os.getenv('APP_HOST', '0.0.0.0')
APP_PORT = int(os.getenv('APP_PORT', '5000'))
FLASK_DEBUG = os.getenv('FLASK_DEBUG', '1').strip().lower() in ('1', 'true', 'yes', 'y', 'on')

from core.sdn_config import get_config_manager

# Core infrastructure re-exports
from webapp.core import (
    PROJECT_ROOT,
    RUN_DIR,
    LOG_DIR,
    WEBAPP_DIR,
    USERS_FILE,
    EVENTS_LOG_FILE,
    CONFIGS_DIR,
    WHITELIST_STORAGE_PATH,
    WHITELIST_LOCK_PATH,
    RYU_PID_FILE,
    RYU_PID_META_FILE,
    RYU_LOG_FILE,
    RYU_MANAGER_CMD,
    RYU_APP_PATH,
    RYU_API_BASE,
    MININET_RUNNER_BASE,
    GLANCES_API_BASE,
    GLANCES_CACHE_TTL_SEC,
    GLANCES_TIMEOUT_SEC,
    GLANCES_CB_FAIL_THRESHOLD,
    GLANCES_CB_COOLDOWN_SEC,
    AlertsSyncWorker,
    CrossProcessFileLock,
    HEALTH_CHECK_INTERVAL,
    SecurityError,
    USERS_CACHE_TTL,
    VALID_HA_TARGETS,
    _ALLOWED_RUNNER_DETAIL_KEYS,
    _ALLOWED_RUNNER_ERROR_CODES,
    _ALLOWED_RYU_400_ERRORS,
    _BEARER_RX,
    _PATH_RX,
    _SECRET_KV_RX,
    _SERVER_BOOT_ID,
    _TB_START_RX,
    _TrustedProxyMiddleware,
    _URL_RX,
    _access_allowed,
    _access_guard,
    _alerts_snapshot,
    _alerts_sync_lifecycle_lock,
    _alerts_sync_started,
    _alerts_sync_stop_event,
    _alerts_sync_thread,
    _alerts_sync_worker_loop,
    _append_event,
    _assign_request_id,
    _audit_log_whitelist,
    _auth_guard,
    _bootstrap_seen_alerts_from_csv,
    _classify_backend_exception,
    _cleanup_old_event_files,
    _coordinate_failover_request,
    _csrf_guard,
    _current_request_id,
    _ensure_events_last_ts,
    _error_json,
    _events_date_str,
    _events_file_for_date,
    _events_last_cleanup_day,
    _events_last_ts,
    _events_lock,
    _events_max_bytes,
    _events_max_parts,
    _events_retention_days,
    _events_ts_initialized,
    _failover_execution_lock,
    _failover_history,
    _failover_states,
    _failover_states_lock,
    _forward_runner_response,
    _get_csrf_token,
    _get_service_health,
    _handle_backend_exception,
    _handle_http_exception,
    _handle_unhandled_exception,
    _health_lock,
    _inject_csrf_token,
    _internal_headers,
    _is_logged_in,
    _is_password_hash,
    _is_safe_detail_str,
    _last_seen_boot_id,
    _last_seen_seq,
    _list_event_files,
    _load_internal_token,
    _load_users,
    _log_backend_exception,
    _login_fail_allowed,
    _login_fail_clear,
    _login_fail_record,
    _poll_and_sync_alerts_once,
    _process_and_archive_alerts,
    _proxy_ryu_post,
    _ryu_post,
    _rate_check,
    _rate_ip,
    _rate_limit_guard,
    _rate_lock,
    _rate_state,
    _read_events,
    _record_sync_failure,
    _redact_secrets,
    _require_admin_role,
    require_admin,
    _reset_alerts_state_for_tests,
    _rotate_daily_event_file_if_needed,
    _safe_request,
    _sanitize_log_text,
    _sanitize_runner_detail_value,
    _sanitize_runner_error_payload,
    _security_headers,
    _seen_alert_ids_deque,
    _seen_alert_ids_set,
    _seen_ids_lock,
    _service_health,
    _snapshot_lock,
    _start_alerts_sync_worker,
    _stop_alerts_sync_worker,
    _tail_file,
    _update_service_health,
    _users_cache,
    _users_cache_lock,
    _users_cache_mtime,
    _validate_ipv4_api,
    _validate_mac_api,
    _validate_service_url,
    _verify_password,
    create_app,
)

# Blueprint route and helper re-exports
from webapp.blueprints.dashboard import (
    api_service_health,
    health,
    index,
    login_get,
    login_post,
    logout,
)
from webapp.blueprints.monitoring import (
    _fetch_glances_cached,
    _fetch_vm_metrics_live,
    _fetch_vm_proc_live,
    _glances_caches,
    _glances_cb_lock,
    _glances_cb_open_until,
    _glances_cb_snapshot,
    _reset_glances_state_for_tests,
    api_alerts,
    api_get_settings,
    api_metrics,
    api_set_settings,
    api_vm_metrics,
    api_vm_proc,
)
from webapp.blueprints.events import (
    api_history,
    api_history_csv,
)
from webapp.blueprints.controller import (
    _check_ofp_listener,
    _controller_process_lock,
    _controller_status,
    _read_pid,
    _read_pid_meta,
    _verify_process_identity,
    _write_pid_meta,
    api_controller_start,
    api_controller_status,
    api_controller_stop,
)
from webapp.blueprints.lab_proxy import (
    _proxy_runner,
    _runner_get,
    _runner_post,
    _runner_delete,
    api_lab_attack_run,
    api_lab_attack_status,
    api_lab_attack_stop,
    api_lab_build,
    api_lab_cmd_run,
    api_lab_ha_active,
    api_lab_ha_config,
    api_lab_ha_failover_status,
    api_lab_ha_service_start,
    api_lab_ha_service_stop,
    api_lab_ha_status,
    api_lab_ha_test,
    api_lab_link_update,
    api_lab_ovs_flows,
    api_lab_pcap_delete,
    api_lab_pcap_download,
    api_lab_pcap_list,
    api_lab_pcap_pin,
    api_lab_pcap_storage,
    api_lab_pcap_unpin,
    api_lab_scenario,
    api_lab_status,
    api_lab_stop,
    api_lab_topology_apply,
)
from webapp.blueprints.mitigation import (
    api_alerts_clear,
    api_block_ip,
    api_block_mac,
    api_flows,
    api_flows_clear,
    api_get_config,
    api_unblock_all,
    api_unblock_ip,
    api_unblock_mac,
    api_unblock_mac_all,
    api_update_config,
    api_whitelist_clear,
    api_whitelist_ip,
    api_unwhitelist_ip,
)
from webapp.blueprints.whitelist import (
    _validate_whitelist_json_payload,
    api_whitelist_delete_persistent,
    api_whitelist_restore,
    api_whitelist_save,
    api_whitelist_status,
)

# Application factory creation
app = create_app()

atexit.register(_stop_alerts_sync_worker)


if __name__ == '__main__':
    if os.getenv('SDN_ALERTS_SYNC_WORKER_ENABLED', '1').strip().lower() in ('1', 'true', 'yes', 'on'):
        _start_alerts_sync_worker()

    def _sig_handler(signum, frame):
        app.logger.info("Received signal %s, stopping alerts sync worker...", signum)
        _stop_alerts_sync_worker(timeout=3.0)
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, _sig_handler)
        signal.signal(signal.SIGINT, _sig_handler)
    except Exception:
        pass

    try:
        app.run(host=APP_HOST, port=APP_PORT, debug=FLASK_DEBUG)
    finally:
        _stop_alerts_sync_worker(timeout=3.0)
