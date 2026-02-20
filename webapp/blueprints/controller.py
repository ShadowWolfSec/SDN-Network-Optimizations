"""Ryu Controller Process Management Blueprint.

Handles controller status checks, starting, and stopping Ryu manager process
with PID metadata validation and TOCTOU protection.
Routes:
- GET  /api/controller/status -> api_controller_status()
- POST /api/controller/start -> api_controller_start()
- POST /api/controller/stop -> api_controller_stop()
"""

import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, current_app, jsonify, request

from core.sdn_config import get_config_manager
from webapp.core import (
    PROJECT_ROOT,
    RYU_APP_PATH,
    RYU_LOG_FILE,
    RYU_PID_FILE,
    RYU_PID_META_FILE,
    RYU_MANAGER_CMD,
    RYU_API_BASE,
)
from webapp.core.tail_utils import _tail_file
from webapp.core.security import (
    _handle_backend_exception,
    _load_internal_token,
    _SERVER_BOOT_ID,
    require_admin,
)
from webapp.core.alerts_sync import _safe_request

controller_bp = Blueprint('controller', __name__)

_controller_process_lock = threading.RLock()


def _get_subprocess_module():
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'subprocess'):
        return srv.subprocess
    return subprocess


def _call_safe_request(*args, **kwargs):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_safe_request'):
        return srv._safe_request(*args, **kwargs)
    return _safe_request(*args, **kwargs)


def _read_pid(pid_file: str) -> Optional[int]:
    try:
        with open(pid_file, 'r', encoding='utf-8') as f:
            return int(f.read().strip())
    except Exception:
        return None


def _pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _parse_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val != 0
    if isinstance(val, str):
        return val.strip().lower() in ('true', '1', 'yes', 'on')
    return False


def _get_kernel_boot_id() -> str:
    try:
        with open('/proc/sys/kernel/random/boot_id', 'r', encoding='utf-8') as f:
            return f.read().strip()
    except Exception:
        return _SERVER_BOOT_ID


def _get_ryu_log_file() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'RYU_LOG_FILE'):
        return str(srv.RYU_LOG_FILE or '')
    return RYU_LOG_FILE


def _get_ryu_pid_file() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'RYU_PID_FILE'):
        return str(srv.RYU_PID_FILE or '')
    return RYU_PID_FILE


def _get_ryu_pid_meta_file() -> str:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, 'RYU_PID_META_FILE'):
        return str(srv.RYU_PID_META_FILE or '')
    return RYU_PID_META_FILE


def _read_pid_meta() -> Optional[Dict[str, Any]]:
    try:
        meta_file = _get_ryu_pid_meta_file()
        if os.path.isfile(meta_file):
            with open(meta_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return None


def _write_pid_meta(pid: int, starttime: int) -> None:
    try:
        meta_file = _get_ryu_pid_meta_file()
        os.makedirs(os.path.dirname(meta_file), exist_ok=True)
        meta = {
            'pid': pid,
            'starttime': starttime,
            'boot_id': _get_kernel_boot_id(),
            'created_at': time.time(),
        }
        with open(f"{meta_file}.tmp", 'w', encoding='utf-8') as f:
            json.dump(meta, f)
        os.replace(f"{meta_file}.tmp", meta_file)
    except Exception as ex:
        try:
            current_app.logger.warning("Failed to write PID metadata: %s", ex)
        except Exception:
            pass


def _read_proc_starttime(pid: int) -> Optional[int]:
    try:
        stat_path = f"/proc/{pid}/stat"
        if os.path.isfile(stat_path):
            with open(stat_path, 'r', encoding='utf-8') as f:
                content = f.read()
            rparen = content.rfind(')')
            if rparen != -1:
                fields = content[rparen + 1:].strip().split()
                if len(fields) >= 20:
                    return int(fields[19])
    except Exception:
        pass
    return None


def _verify_process_identity(pid: Optional[int]) -> Tuple[str, bool, Optional[Dict[str, Any]]]:
    """Verify process exists, matches boot_id, starttime, and cmdline to prevent PID reuse issues."""
    if not pid or pid <= 0:
        return 'stopped', False, None

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return 'stopped', False, None
    except PermissionError:
        return 'uncertain_eperm', False, None
    except Exception:
        return 'uncertain_unverifiable', False, None

    meta = _read_pid_meta()
    if meta and meta.get('pid') == pid:
        if meta.get('boot_id'):
            curr_boot = _get_kernel_boot_id()
            if meta['boot_id'] != curr_boot:
                return 'stale_pid_reused', False, None

    if os.name == 'posix' and os.path.isdir(f"/proc/{pid}"):
        curr_starttime = _read_proc_starttime(pid)
        if meta and meta.get('pid') == pid and meta.get('starttime') is not None and curr_starttime is not None:
            if int(curr_starttime) != int(meta['starttime']):
                return 'stale_pid_reused', False, None

        try:
            with open(f"/proc/{pid}/cmdline", 'rb') as f:
                raw_cmd = f.read().decode('utf-8', errors='ignore')
            if 'dos_guard' in raw_cmd or 'ryu' in raw_cmd:
                if curr_starttime is not None and (not meta or meta.get('pid') != pid):
                    _write_pid_meta(pid, curr_starttime)
                    meta = _read_pid_meta()
                return 'verified_running', True, meta
            else:
                return 'stale_pid_reused', False, None
        except PermissionError:
            return 'uncertain_eperm', False, None
        except Exception:
            return 'running_unverified', False, meta

    return 'running_unverified', False, meta


def _pidfd_kill(pid: int, sig: int = signal.SIGTERM) -> bool:
    """Send signal mitigating TOCTOU race using Linux pidfd or atomic double-check."""
    try:
        SYS_pidfd_open = 434
        libc = ctypes.CDLL(None, use_errno=True)
        pidfd = libc.syscall(SYS_pidfd_open, ctypes.c_int(pid), ctypes.c_uint(0))
        if pidfd >= 0:
            try:
                SYS_pidfd_send_signal = 424
                res = libc.syscall(SYS_pidfd_send_signal, ctypes.c_int(pidfd), ctypes.c_int(sig), None, ctypes.c_uint(0))
                return (res == 0)
            finally:
                os.close(pidfd)
    except Exception:
        pass

    try:
        os.killpg(pid, sig)
    except Exception:
        os.kill(pid, sig)
    return True


def _check_ofp_listener(ofp_port: int, ryu_pid: Optional[int]) -> Tuple[bool, str]:
    """Verify OpenFlow listener zero-side-effect: inspects /proc/net/tcp without sending packets."""
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_check_ofp_listener') and srv._check_ofp_listener != _check_ofp_listener:
        return srv._check_ofp_listener(ofp_port, ryu_pid)

    if ofp_port <= 0:
        return True, 'bypassed_headless'

    hex_port = f"{ofp_port:04X}"
    port_found = False

    for tcp_path in ('/proc/net/tcp', '/proc/net/tcp6'):
        if os.path.isfile(tcp_path):
            try:
                with open(tcp_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                for l in lines[1:]:
                    parts = l.strip().split()
                    if len(parts) >= 4:
                        local_addr = parts[1]
                        st = parts[3]
                        if local_addr.endswith(f":{hex_port}") and st == '0A':  # 0A = TCP_LISTEN
                            port_found = True
                            break
                if port_found:
                    break
            except Exception:
                pass

    if port_found:
        return True, 'bound_listening'

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        res = s.connect_ex(('127.0.0.1', ofp_port))
        s.close()
        if res == 0:
            return True, 'connect_succeeded'
    except Exception:
        pass

    return False, 'port_closed'


def _call_read_pid(pid_file: str) -> Optional[int]:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_read_pid'):
        return srv._read_pid(pid_file)
    return _read_pid(pid_file)


def _call_verify_process_identity(pid: Optional[int]) -> Tuple[str, bool, Optional[Dict[str, Any]]]:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_verify_process_identity'):
        return srv._verify_process_identity(pid)
    return _verify_process_identity(pid)


def _call_check_ofp_listener(ofp_port: int, ryu_pid: Optional[int]) -> Tuple[bool, str]:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_check_ofp_listener'):
        return srv._check_ofp_listener(ofp_port, ryu_pid)
    return _check_ofp_listener(ofp_port, ryu_pid)


def _call_controller_status() -> Dict[str, Any]:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_controller_status'):
        return srv._controller_status()
    return _controller_status()


def _controller_status() -> Dict[str, Any]:
    with _controller_process_lock:
        pid_file = _get_ryu_pid_file()
        meta_file = _get_ryu_pid_meta_file()
        pid = _call_read_pid(pid_file)
        ident_state, verified, meta = _call_verify_process_identity(pid)

        if ident_state == 'stopped' and pid:
            try:
                os.remove(pid_file)
                if os.path.exists(meta_file):
                    os.remove(meta_file)
            except Exception:
                pass
            pid = None

    running = (ident_state in ('verified_running', 'running_unverified'))

    mgr = get_config_manager()
    ofp_port = mgr.get_effective('ofp_port') or 6653
    ofp_ready, ofp_status = _call_check_ofp_listener(ofp_port, pid) if running else (False, 'controller_stopped')

    rest_ready = False
    datapaths = []
    if running:
        try:
            srv = sys.modules.get('webapp.server')
            ryu_base = str(getattr(srv, 'RYU_API_BASE', RYU_API_BASE) or RYU_API_BASE)
            r = _call_safe_request(f"{ryu_base}/dos/metrics", method='GET', timeout=0.5, service_name='ryu')
            if r and r.ok:
                rest_ready = True
                d = r.json() or {}
                datapaths = list(d.get('datapaths') or [])
        except Exception:
            rest_ready = False

    datapath_ready = (len(datapaths) >= 1)

    if not running:
        overall_state = 'uncertain_eperm' if ident_state == 'uncertain_eperm' else 'stopped'
    elif verified and rest_ready and ofp_ready and datapath_ready:
        overall_state = 'ready'
    elif verified and not (rest_ready and ofp_ready and datapath_ready):
        overall_state = 'degraded'
    else:
        overall_state = 'starting'

    return {
        'ok': True,
        'running': running,
        'pid': pid,
        'process_verified': verified,
        'overall_state': overall_state,
        'readiness': {
            'process_started': verified,
            'rest_ready': rest_ready,
            'openflow_listener_ready': ofp_ready,
            'datapath_ready': datapath_ready,
            'datapaths_count': len(datapaths),
            'datapaths': datapaths,
        },
        'ofp_probe': ofp_status,
        'log_tail': _tail_file(_get_ryu_log_file(), max_lines=40, max_chars=4096),
    }


@controller_bp.get('/api/controller/status')
def api_controller_status():
    return jsonify(_call_controller_status())


@controller_bp.post('/api/controller/start')
@require_admin
def api_controller_start():
    with _controller_process_lock:
        st = _call_controller_status()
        if st.get('running'):
            return jsonify({'ok': True, 'state': 'already_running', **st})
        if st.get('overall_state') == 'uncertain_eperm':
            return jsonify({'ok': False, 'error': 'process_unverified_eperm', 'message': 'Process running under elevated/foreign user. Cannot start duplicate.'}), 409

        pid_file = _get_ryu_pid_file()
        meta_file = _get_ryu_pid_meta_file()
        log_file = _get_ryu_log_file()

        if os.name != 'posix':
            return jsonify({'ok': False, 'error': 'controller_start_supported_on_linux_only'}), 400

        payload = request.get_json(silent=True) or {}
        mgr = get_config_manager()

        if isinstance(payload, dict):
            if 'learning_enabled' in payload:
                mgr.apply_runtime_override({'learning_enable': payload['learning_enabled']}, persist=False)
            if 'config_overrides' in payload and isinstance(payload['config_overrides'], dict):
                mgr.apply_runtime_override(payload['config_overrides'], persist=False)

        log_f = None
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            log_f = open(log_file, 'a', encoding='utf-8')
            wsapi_host = str(mgr.get_effective('wsapi_host') or '127.0.0.1')
            wsapi_port = str(mgr.get_effective('wsapi_port') or 8080)
            ofp_port = str(mgr.get_effective('ofp_port') or 6653)

            ryu_flags = [
                '--wsapi-host', wsapi_host,
                '--wsapi-port', wsapi_port,
                '--ofp-tcp-listen-port', ofp_port,
            ]
            cmd = [RYU_MANAGER_CMD, *ryu_flags, RYU_APP_PATH]

            env = os.environ.copy()
            env.update(mgr.export_for_subprocess())
            tok = _load_internal_token()
            if tok:
                env['SDN_INTERNAL_TOKEN'] = tok

            sub_mod = _get_subprocess_module()
            try:
                p = sub_mod.Popen(
                    cmd,
                    cwd=PROJECT_ROOT,
                    stdout=log_f,
                    stderr=log_f,
                    env=env,
                    start_new_session=True,
                )
            except FileNotFoundError:
                p = sub_mod.Popen(
                    [sys.executable, '-m', 'ryu.cmd.manager', *ryu_flags, RYU_APP_PATH],
                    cwd=PROJECT_ROOT,
                    stdout=log_f,
                    stderr=log_f,
                    env=env,
                    start_new_session=True,
                )

            with open(pid_file, 'w', encoding='utf-8') as f:
                f.write(str(p.pid))

            st_time = _read_proc_starttime(p.pid) or int(time.time() * 100)
            _write_pid_meta(p.pid, st_time)

        except Exception as e:
            return _handle_backend_exception('controller_start', e, upstream='local', status_override=500)
        finally:
            if log_f is not None:
                try:
                    log_f.close()
                except Exception:
                    pass

    return jsonify({'ok': True, **_call_controller_status()})


@controller_bp.post('/api/controller/stop')
@require_admin
def api_controller_stop():
    with _controller_process_lock:
        pid_file = _get_ryu_pid_file()
        meta_file = _get_ryu_pid_meta_file()
        pid = _call_read_pid(pid_file)
        if not pid:
            return jsonify({'ok': True, **_call_controller_status()})

        ident_state, verified, _ = _call_verify_process_identity(pid)

        if ident_state == 'stopped':
            try:
                os.remove(pid_file)
                if os.path.exists(meta_file):
                    os.remove(meta_file)
            except Exception:
                pass
            return jsonify({'ok': True, **_call_controller_status()})

        if ident_state == 'uncertain_eperm':
            return _handle_backend_exception('controller_stop', PermissionError("Permission denied accessing process"), upstream='local', status_override=500)

        if not verified:
            return jsonify({
                'ok': False,
                'error': 'process_identity_unverified',
                'state': ident_state,
                'message': 'Refusing to send SIGTERM to unverified process to protect foreign host processes.',
            }), 409

        try:
            _pidfd_kill(pid, signal.SIGTERM)
        except Exception as e:
            return _handle_backend_exception('controller_stop', e, upstream='local', status_override=500)

        try:
            os.remove(pid_file)
            if os.path.exists(meta_file):
                os.remove(meta_file)
        except Exception:
            pass

    return jsonify({'ok': True, **_call_controller_status()})
