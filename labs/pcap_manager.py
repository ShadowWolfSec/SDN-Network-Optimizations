"""
labs/pcap_manager.py
PCAP packet capture, quota rotation, and storage lifecycle manager.
"""

import collections
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger('pcap_manager')

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PCAP_DIR = os.path.join(PROJECT_ROOT, 'logs', 'pcaps')
os.makedirs(PCAP_DIR, exist_ok=True)

_MANIFEST_FILE = os.path.join(PCAP_DIR, '.pinned_manifest.json')

PCAP_SNAPLEN = int(os.getenv('PCAP_SNAPLEN', '96'))
MAX_PCAP_FILES = int(os.getenv('MAX_PCAP_FILES', '30'))
MAX_PCAP_TOTAL_MB = int(os.getenv('MAX_PCAP_TOTAL_MB', '200'))
PCAP_SINGLE_FILE_MAX_MB = int(os.getenv('PCAP_SINGLE_FILE_MAX_MB', '20'))

# Dedicated Locks
_pcap_lock = threading.RLock()
_readers_lock = threading.Lock()
_pcap_prune_lock = threading.Lock()
_manifest_lock = threading.Lock()

_active_readers: Dict[str, int] = collections.defaultdict(int)
_active_pcap_name: Optional[str] = None
_finalizing_pcaps: Set[str] = set()
_pcap_proc: Optional[subprocess.Popen] = None
_last_pcap_name: Optional[str] = None


def _get_runner_attr(attr: str, fallback: Any) -> Any:
    mod = sys.modules.get('labs.mininet_runner')
    if mod is not None and hasattr(mod, attr):
        return getattr(mod, attr)
    return fallback


def current_pcap_dir() -> str:
    return str(_get_runner_attr('PCAP_DIR', PCAP_DIR))


def current_manifest_file() -> str:
    return str(_get_runner_attr('_MANIFEST_FILE', _MANIFEST_FILE))


def current_active_readers() -> Dict[str, int]:
    return _get_runner_attr('_active_readers', _active_readers)


def current_active_pcap_name() -> Optional[str]:
    return _get_runner_attr('_active_pcap_name', _active_pcap_name)


def get_pcap_proc() -> Optional[subprocess.Popen]:
    return _get_runner_attr('_pcap_proc', _pcap_proc)


def get_active_pcap_name() -> Optional[str]:
    return current_active_pcap_name()


def get_last_pcap_name() -> Optional[str]:
    return _get_runner_attr('_last_pcap_name', _last_pcap_name)


def current_finalizing_pcaps() -> Set[str]:
    return _get_runner_attr('_finalizing_pcaps', _finalizing_pcaps)


def pcap_snaplen() -> int:
    try:
        from core.sdn_config import get_config_manager
        mgr = get_config_manager()
        return mgr.get_int('PCAP_SNAPLEN', PCAP_SNAPLEN, 64, 65535)
    except Exception:
        return PCAP_SNAPLEN


def pcap_max_files() -> int:
    runner_val = _get_runner_attr('MAX_PCAP_FILES', None)
    if runner_val is not None and int(runner_val) != 30:
        return int(runner_val)
    try:
        from core.sdn_config import get_config_manager
        mgr = get_config_manager()
        return mgr.get_int('MAX_PCAP_FILES', MAX_PCAP_FILES, 1, 500)
    except Exception:
        return MAX_PCAP_FILES


def pcap_max_total_mb() -> int:
    runner_val = _get_runner_attr('MAX_PCAP_TOTAL_MB', None)
    if runner_val is not None and int(runner_val) != 200:
        return int(runner_val)
    try:
        from core.sdn_config import get_config_manager
        mgr = get_config_manager()
        return mgr.get_int('MAX_PCAP_TOTAL_MB', MAX_PCAP_TOTAL_MB, 10, 50000)
    except Exception:
        return MAX_PCAP_TOTAL_MB


def pcap_single_file_max_mb() -> int:
    try:
        from core.sdn_config import get_config_manager
        mgr = get_config_manager()
        return mgr.get_int('PCAP_SINGLE_FILE_MAX_MB', PCAP_SINGLE_FILE_MAX_MB, 1, 1000)
    except Exception:
        return PCAP_SINGLE_FILE_MAX_MB


def resolve_safe_pcap_path(name: str) -> str:
    """Strictly validates pcap filename and enforces directory containment."""
    if not name or not isinstance(name, str):
        raise ValueError("invalid_pcap_name")
    bn = os.path.basename(name.strip())
    if bn != name or '..' in name or '/' in name or '\\' in name:
        raise ValueError("path_traversal_attempt")
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:pcap|pcapng|cap)', bn):
        raise ValueError("invalid_pcap_extension")
    cur_dir = current_pcap_dir()
    real_dir = os.path.realpath(cur_dir)
    target = os.path.realpath(os.path.join(cur_dir, bn))
    if not (target.startswith(real_dir + os.sep) and os.path.dirname(target) == real_dir):
        raise ValueError("path_outside_pcap_dir")
    return target


def safe_basename(name: str) -> str:
    try:
        path = resolve_safe_pcap_path(name)
        return os.path.basename(path)
    except Exception:
        return ''


def human_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{num_bytes / (1024 * 1024 * 1024):.1f} GB"


def save_pinned_manifest_unlocked(pinned_set: Set[str]) -> bool:
    cur_dir = current_pcap_dir()
    manifest_file = current_manifest_file()
    tmp_name = f".pinned_manifest.tmp.{os.getpid()}.{int(time.time() * 1000)}"
    tmp_path = os.path.join(cur_dir, tmp_name)
    try:
        payload = {
            'pinned_files': sorted(list(pinned_set)),
            'version': 1,
            'updated_at': time.time(),
        }
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, manifest_file)
        try:
            os.chmod(manifest_file, 0o644)
            sudo_uid = os.getenv('SUDO_UID')
            sudo_gid = os.getenv('SUDO_GID')
            if sudo_uid and sudo_gid:
                os.chown(manifest_file, int(sudo_uid), int(sudo_gid))
        except Exception:
            pass
        return True
    except Exception as e:
        logger.error("Failed to save pinned manifest: %s", e)
        try:
            if os.path.isfile(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False


def load_pinned_manifest() -> Set[str]:
    manifest_file = current_manifest_file()
    with _manifest_lock:
        if not os.path.isfile(manifest_file):
            return set()
        try:
            with open(manifest_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict) and 'pinned_files' in data and isinstance(data['pinned_files'], list):
                return set(data['pinned_files'])
            elif isinstance(data, list):
                return set(data)
            return set()
        except Exception as e:
            logger.warning("Failed to load pinned manifest %s (corrupt JSON?): %s", manifest_file, e)
            return set()


def save_pinned_manifest(pinned_set: Set[str]) -> bool:
    with _manifest_lock:
        return save_pinned_manifest_unlocked(pinned_set)


def pcap_prune(state_lock: Optional[Any] = None) -> Dict[str, Any]:
    """Prunes ephemeral unpinned PCAP files exceeding max count or total size."""
    with _pcap_prune_lock:
        stats = {
            'deleted_count': 0,
            'freed_bytes': 0,
            'remaining_count': 0,
            'remaining_bytes': 0,
            'pinned_count': 0,
            'pinned_bytes': 0,
            'quota_exceeded': False,
        }
        try:
            cur_dir = current_pcap_dir()
            if not os.path.isdir(cur_dir):
                return stats

            pinned = load_pinned_manifest()
            readers_dict = current_active_readers()
            with _readers_lock:
                active_readers_set = {fn for fn, count in readers_dict.items() if count > 0}

            protected_names = set(pinned)
            act_name = current_active_pcap_name()
            fin_names = current_finalizing_pcaps()
            with _pcap_lock:
                if act_name:
                    protected_names.add(act_name)
                protected_names.update(fin_names)
            protected_names.update(active_readers_set)

            max_files = pcap_max_files()
            max_bytes = pcap_max_total_mb() * 1024 * 1024

            real_pcap_dir = os.path.realpath(cur_dir)
            all_files = []
            for fn in os.listdir(cur_dir):
                if not fn.endswith('.pcap'):
                    continue
                fpath = os.path.join(cur_dir, fn)
                try:
                    real_target = os.path.realpath(fpath)
                    if not (real_target.startswith(real_pcap_dir + os.sep) and os.path.dirname(real_target) == real_pcap_dir):
                        continue
                    st = os.stat(fpath)
                except Exception:
                    continue
                is_pinned = fn in pinned
                is_protected = fn in protected_names
                all_files.append({
                    'name': fn,
                    'path': fpath,
                    'size': int(st.st_size),
                    'mtime': float(st.st_mtime),
                    'pinned': is_pinned,
                    'protected': is_protected,
                })

            total_bytes = sum(f['size'] for f in all_files)
            pinned_bytes = sum(f['size'] for f in all_files if f['pinned'])
            pinned_count = sum(1 for f in all_files if f['pinned'])
            stats['pinned_count'] = pinned_count
            stats['pinned_bytes'] = pinned_bytes

            eligible = [f for f in all_files if not f['protected']]
            eligible.sort(key=lambda x: x['mtime'])

            current_count = len(all_files)
            for f in list(eligible):
                if current_count <= max_files:
                    break
                try:
                    os.remove(f['path'])
                    eligible.remove(f)
                    all_files.remove(f)
                    current_count -= 1
                    total_bytes -= f['size']
                    stats['deleted_count'] += 1
                    stats['freed_bytes'] += f['size']
                except Exception as e:
                    logger.warning("Failed to remove PCAP during count prune %s: %s", f['name'], e)

            for f in list(eligible):
                if total_bytes <= max_bytes:
                    break
                try:
                    os.remove(f['path'])
                    eligible.remove(f)
                    all_files.remove(f)
                    total_bytes -= f['size']
                    stats['deleted_count'] += 1
                    stats['freed_bytes'] += f['size']
                except Exception as e:
                    logger.warning("Failed to remove PCAP during size prune %s: %s", f['name'], e)

            stats['remaining_count'] = len(all_files)
            stats['remaining_bytes'] = total_bytes
            if total_bytes > max_bytes:
                stats['quota_exceeded'] = True
                logger.warning(
                    "PCAP quota exceeded (%d bytes > %d max bytes) but remaining files are protected or pinned",
                    total_bytes, max_bytes
                )

            return stats
        except Exception as ex:
            logger.error("Exception in _pcap_prune: %s", ex)
            return stats


def terminate_pcap_proc(proc: Optional[subprocess.Popen]) -> None:
    if not proc:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except Exception:
                pass
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=0.5)
                except Exception:
                    pass
    except Exception as e:
        logger.warning("Error terminating pcap proc: %s", e)


def finalize_pcap(fname: str, path: str, state_lock: Optional[Any] = None) -> None:
    global _pcap_proc, _active_pcap_name
    fin_set = current_finalizing_pcaps()
    with _pcap_lock:
        if _active_pcap_name == fname:
            _active_pcap_name = None
        fin_set.add(fname)
        _pcap_proc = None

    try:
        time.sleep(0.1)
        if os.path.isfile(path):
            try:
                os.chmod(path, 0o644)
                sudo_uid = os.getenv('SUDO_UID')
                sudo_gid = os.getenv('SUDO_GID')
                if sudo_uid and sudo_gid:
                    os.chown(path, int(sudo_uid), int(sudo_gid))
            except Exception:
                pass
            try:
                sz = os.path.getsize(path)
                if sz == 0:
                    logger.warning("PCAP file %s is empty (0 bytes) after capture stop", fname)
            except Exception:
                pass
    finally:
        with _pcap_lock:
            fin_set.discard(fname)
        pcap_prune()


def stop_active_pcap(state_lock: Optional[Any] = None) -> None:
    global _pcap_proc, _active_pcap_name
    proc = None
    fname = None
    cur_dir = current_pcap_dir()
    act_name = current_active_pcap_name()
    with _pcap_lock:
        proc = _pcap_proc
        fname = act_name
    if proc:
        terminate_pcap_proc(proc)
    if fname:
        fpath = os.path.join(cur_dir, fname)
        finalize_pcap(fname, fpath)


def start_pcap(duration: int, *, victim_ip: Optional[str] = None, state_lock: Optional[Any] = None) -> str:
    global _pcap_proc, _last_pcap_name, _active_pcap_name
    if not shutil.which('tcpdump'):
        raise RuntimeError('tcpdump_not_installed')

    cur_dir = current_pcap_dir()
    pcap_prune()

    with _pcap_lock:
        if _pcap_proc and _pcap_proc.poll() is None:
            raise RuntimeError('pcap_already_running')

        pinned = load_pinned_manifest()
        max_total = pcap_max_total_mb() * 1024 * 1024
        try:
            pinned_storage = sum(
                os.path.getsize(os.path.join(cur_dir, f))
                for f in pinned
                if os.path.isfile(os.path.join(cur_dir, f))
            )
        except Exception:
            pinned_storage = 0

        if max_total > 0 and pinned_storage >= (0.95 * max_total):
            raise RuntimeError('pcap_storage_quota_exhausted')

        ts = time.strftime('%Y%m%d_%H%M%S')
        fname = f"attack_{ts}.pcap"
        path = os.path.join(cur_dir, fname)
        snaplen = pcap_snaplen()
        cmd = ['tcpdump', '-i', 'any', '-s', str(max(64, int(snaplen))), '-w', path]
        if victim_ip:
            cmd += ['host', str(victim_ip)]
        _pcap_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _last_pcap_name = fname
        _active_pcap_name = fname

    max_file_bytes = pcap_single_file_max_mb() * 1024 * 1024
    dur = max(1, int(duration))

    def _pcap_watchdog():
        t_start = time.time()
        while True:
            time.sleep(0.5)
            with _pcap_lock:
                proc = _pcap_proc
                if not proc or proc.poll() is not None:
                    break
                try:
                    if os.path.isfile(path) and os.path.getsize(path) >= max_file_bytes:
                        logger.warning(
                            "PCAP capture %s exceeded single file limit (%d MB), terminating tcpdump",
                            fname, pcap_single_file_max_mb()
                        )
                        terminate_pcap_proc(proc)
                        break
                except Exception:
                    pass
                if (time.time() - t_start) >= dur:
                    terminate_pcap_proc(proc)
                    break

        finalize_pcap(fname, path)

    threading.Thread(target=_pcap_watchdog, daemon=True).start()
    return fname


def pcap_startup_reconciliation() -> None:
    """Startup reconciliation for PCAP storage:
    - Cleans up orphaned temporary manifest files (.pinned_manifest.tmp.*)
    - Verifies directory permissions (0755)
    - Logs warning for any 0-byte PCAP files left behind by killed runner
    - Pre-seeds manifest if missing to protect pre-existing files
    - Runs initial pcap_prune()
    """
    cur_dir = current_pcap_dir()
    manifest_file = current_manifest_file()
    try:
        os.makedirs(cur_dir, exist_ok=True)
        try:
            os.chmod(cur_dir, 0o755)
            sudo_uid = os.getenv('SUDO_UID')
            sudo_gid = os.getenv('SUDO_GID')
            if sudo_uid and sudo_gid:
                os.chown(cur_dir, int(sudo_uid), int(sudo_gid))
        except Exception:
            pass
        if os.path.isdir(cur_dir):
            for fn in os.listdir(cur_dir):
                if fn.startswith('.pinned_manifest.tmp.'):
                    try:
                        os.remove(os.path.join(cur_dir, fn))
                    except Exception:
                        pass
                elif fn.endswith('.pcap'):
                    fpath = os.path.join(cur_dir, fn)
                    try:
                        if os.path.isfile(fpath) and os.path.getsize(fpath) == 0:
                            logger.warning("Found orphaned 0-byte PCAP on startup: %s", fn)
                    except Exception:
                        pass
        if not os.path.isfile(manifest_file):
            try:
                if os.path.isdir(cur_dir):
                    existing_baseline = {
                        fn for fn in os.listdir(cur_dir)
                        if fn.endswith('.pcap') and os.path.isfile(os.path.join(cur_dir, fn))
                    }
                    if existing_baseline:
                        save_pinned_manifest(existing_baseline)
            except Exception:
                pass
        pcap_prune()
    except Exception as e:
        logger.warning("Error in _pcap_startup_reconciliation: %s", e)


# Backward Compatibility Aliases
_resolve_safe_pcap_path = resolve_safe_pcap_path
_safe_basename = safe_basename
_human_size = human_size
_save_pinned_manifest_unlocked = save_pinned_manifest_unlocked
_load_pinned_manifest = load_pinned_manifest
_save_pinned_manifest = save_pinned_manifest
_pcap_prune = pcap_prune
_terminate_pcap_proc = terminate_pcap_proc
_finalize_pcap = finalize_pcap
_stop_active_pcap = stop_active_pcap
_start_pcap = start_pcap
_pcap_startup_reconciliation = pcap_startup_reconciliation
_pcap_snaplen = pcap_snaplen
_pcap_max_files = pcap_max_files
_pcap_max_total_mb = pcap_max_total_mb
_pcap_single_file_max_mb = pcap_single_file_max_mb
