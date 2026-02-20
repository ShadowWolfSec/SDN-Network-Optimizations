import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_WEBAPP_DIR = os.path.join(PROJECT_ROOT, 'webapp')
while _WEBAPP_DIR in sys.path:
    sys.path.remove(_WEBAPP_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

RUN_DIR = os.path.join(PROJECT_ROOT, '.run')
LOG_DIR = os.path.join(PROJECT_ROOT, 'logs')
WEBAPP_DIR = os.path.join(PROJECT_ROOT, 'webapp')
USERS_FILE = os.path.join(WEBAPP_DIR, 'users.json')
EVENTS_LOG_FILE = os.path.join(LOG_DIR, 'events.csv')
CONFIGS_DIR = os.path.realpath(os.path.abspath(os.path.join(PROJECT_ROOT, 'configs')))
WHITELIST_STORAGE_PATH = os.path.join(CONFIGS_DIR, 'sdn_whitelist.json')
WHITELIST_LOCK_PATH = os.path.join(CONFIGS_DIR, '.sdn_whitelist.lock')
RYU_PID_FILE = os.path.join(RUN_DIR, 'ryu.pid')
RYU_PID_META_FILE = os.path.join(RUN_DIR, 'ryu.pid.meta')
RYU_LOG_FILE = os.path.join(LOG_DIR, 'ryu.log')
RYU_MANAGER_CMD = os.getenv('RYU_MANAGER_CMD', 'ryu-manager')
RYU_APP_PATH = os.getenv('RYU_APP_PATH', os.path.join(PROJECT_ROOT, 'ryu_app', 'dos_guard.py'))

RYU_API_BASE = os.getenv('RYU_API_BASE', 'http://127.0.0.1:8080')
MININET_RUNNER_BASE = os.getenv('MININET_RUNNER_BASE', 'http://127.0.0.1:9090')
GLANCES_API_BASE = os.getenv('GLANCES_API_BASE', 'http://127.0.0.1:61208')
GLANCES_CACHE_TTL_SEC = float(os.getenv('GLANCES_CACHE_TTL_SEC', '3.5') or 3.5)
GLANCES_TIMEOUT_SEC = float(os.getenv('GLANCES_TIMEOUT_SEC', '2.0') or 2.0)
GLANCES_CB_FAIL_THRESHOLD = int(os.getenv('GLANCES_CB_FAIL_THRESHOLD', '2') or 2)
GLANCES_CB_COOLDOWN_SEC = float(os.getenv('GLANCES_CB_COOLDOWN_SEC', '10.0') or 10.0)

from webapp.core.tail_utils import (
    _tail_file,
    _sanitize_log_text,
    _redact_secrets,
    _SECRET_KV_RX,
    _BEARER_RX,
    _URL_RX,
    _PATH_RX,
    _TB_START_RX,
)
from webapp.core.security import (
    SecurityError,
    CrossProcessFileLock,
    _is_password_hash,
    _verify_password,
    _load_users,
    _is_logged_in,
    _get_csrf_token,
    _inject_csrf_token,
    _login_fail_allowed,
    _login_fail_record,
    _login_fail_clear,
    _rate_ip,
    _rate_check,
    _access_allowed,
    _validate_ipv4_api,
    _validate_mac_api,
    _validate_service_url,
    _current_request_id,
    _assign_request_id,
    _load_internal_token,
    _internal_headers,
    _log_backend_exception,
    _classify_backend_exception,
    _error_json,
    _handle_backend_exception,
    _is_safe_detail_str,
    _sanitize_runner_detail_value,
    _sanitize_runner_error_payload,
    _ALLOWED_RUNNER_ERROR_CODES,
    _ALLOWED_RUNNER_DETAIL_KEYS,
    _ALLOWED_RYU_400_ERRORS,
    _forward_runner_response,
    _proxy_ryu_post,
    _ryu_post,
    _handle_http_exception,
    _handle_unhandled_exception,
    _rate_limit_guard,
    _access_guard,
    _auth_guard,
    _csrf_guard,
    _security_headers,
    _require_admin_role,
    require_admin,
    _audit_log_whitelist,
    _TrustedProxyMiddleware,
    _rate_lock,
    _rate_state,
    _users_cache,
    _users_cache_lock,
    _users_cache_mtime,
    _SERVER_BOOT_ID,
    USERS_FILE,
    USERS_CACHE_TTL,
)
from webapp.core.alerts_sync import (
    AlertsSyncWorker,
    _alerts_snapshot,
    _snapshot_lock,
    _seen_alert_ids_set,
    _seen_alert_ids_deque,
    _seen_ids_lock,
    _last_seen_boot_id,
    _last_seen_seq,
    _alerts_sync_thread,
    _alerts_sync_stop_event,
    _alerts_sync_started,
    _alerts_sync_lifecycle_lock,
    VALID_HA_TARGETS,
    _failover_states,
    _failover_states_lock,
    _failover_execution_lock,
    _failover_history,
    _events_last_ts,
    _events_ts_initialized,
    _events_lock,
    _events_last_cleanup_day,
    _service_health,
    _health_lock,
    HEALTH_CHECK_INTERVAL,
    _update_service_health,
    _get_service_health,
    _safe_request,
    _reset_alerts_state_for_tests,
    _events_date_str,
    _events_retention_days,
    _events_max_bytes,
    _events_max_parts,
    _events_file_for_date,
    _list_event_files,
    _cleanup_old_event_files,
    _rotate_daily_event_file_if_needed,
    _ensure_events_last_ts,
    _append_event,
    _bootstrap_seen_alerts_from_csv,
    _coordinate_failover_request,
    _process_and_archive_alerts,
    _record_sync_failure,
    _poll_and_sync_alerts_once,
    _alerts_sync_worker_loop,
    _start_alerts_sync_worker,
    _stop_alerts_sync_worker,
    _read_events,
)
from webapp.core.app_factory import (
    create_app,
)

__all__ = [
    '_tail_file',
    '_sanitize_log_text',
    '_redact_secrets',
    'SecurityError',
    'CrossProcessFileLock',
    '_is_password_hash',
    '_verify_password',
    '_load_users',
    '_is_logged_in',
    '_get_csrf_token',
    '_inject_csrf_token',
    '_rate_check',
    '_access_allowed',
    '_validate_ipv4_api',
    '_validate_mac_api',
    '_validate_service_url',
    '_current_request_id',
    '_assign_request_id',
    '_internal_headers',
    '_log_backend_exception',
    '_classify_backend_exception',
    '_error_json',
    '_handle_backend_exception',
    '_forward_runner_response',
    '_proxy_ryu_post',
    '_handle_http_exception',
    '_handle_unhandled_exception',
    '_rate_limit_guard',
    '_access_guard',
    '_auth_guard',
    '_csrf_guard',
    '_security_headers',
    '_require_admin_role',
    'require_admin',
    '_audit_log_whitelist',
    'AlertsSyncWorker',
    '_alerts_snapshot',
    '_reset_alerts_state_for_tests',
    '_append_event',
    '_read_events',
    '_bootstrap_seen_alerts_from_csv',
    '_coordinate_failover_request',
    '_process_and_archive_alerts',
    '_start_alerts_sync_worker',
    '_stop_alerts_sync_worker',
    'create_app',
]
