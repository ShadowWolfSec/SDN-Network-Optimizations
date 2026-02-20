"""
labs/routes_pcap.py
Flask route endpoints for PCAP capture management, downloads, and storage.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Set

from flask import Flask, Response, abort, current_app, jsonify, request

from labs.pcap_manager import (
    current_active_pcap_name,
    current_active_readers,
    current_finalizing_pcaps,
    current_pcap_dir,
    get_last_pcap_name,
    human_size,
    load_pinned_manifest,
    pcap_max_files,
    pcap_max_total_mb,
    pcap_prune,
    resolve_safe_pcap_path,
    save_pinned_manifest,
    _readers_lock,
)
from labs.topology import _state_lock

logger = logging.getLogger('pcap_routes')


def _log_warning(msg: str, *args):
    try:
        current_app.logger.warning(msg, *args)
    except Exception:
        logger.warning(msg, *args)


def _log_error(msg: str, *args):
    try:
        current_app.logger.error(msg, *args)
    except Exception:
        logger.error(msg, *args)


def pcap_list():
    """Returns sorted catalog of PCAPs with size, timestamps, capturing state, and pinned status."""
    items = []
    pinned = load_pinned_manifest()
    cur_pcap_dir = current_pcap_dir()
    real_pcap_dir = os.path.realpath(cur_pcap_dir)
    try:
        if os.path.isdir(cur_pcap_dir):
            active_pcap = current_active_pcap_name()
            try:
                fin_set = set(current_finalizing_pcaps())
            except Exception:
                fin_set = set()
            for fn in os.listdir(cur_pcap_dir):
                if not fn.endswith('.pcap'):
                    continue
                fpath = os.path.join(cur_pcap_dir, fn)
                try:
                    real_target = os.path.realpath(fpath)
                    if not (real_target.startswith(real_pcap_dir + os.sep) and os.path.dirname(real_target) == real_pcap_dir):
                        continue
                    st = os.stat(fpath)
                    sz = int(st.st_size)
                    mt = float(st.st_mtime)
                except Exception:
                    continue

                is_active = (fn == active_pcap)
                is_finalizing = (fn in fin_set)

                status = 'capturing' if is_active else ('finalizing' if is_finalizing else 'completed')
                if status == 'completed' and sz < 24:
                    status = 'incomplete'

                items.append({
                    'name': fn,
                    'size_bytes': sz,
                    'size_human': human_size(sz),
                    'mtime': mt,
                    'status': status,
                    'pinned': (fn in pinned),
                })
    except Exception as e:
        _log_warning("Error listing pcaps: %s", e)

    items.sort(key=lambda x: x['mtime'], reverse=True)
    names_only = [item['name'] for item in items]
    return jsonify({
        'ok': True,
        'pcaps': names_only,
        'pcap_details': items,
        'last': get_last_pcap_name(),
        'active_pcap': current_active_pcap_name(),
    })


def pcap_download(name: str):
    """Streams PCAP binary safely, tracking active readers to prevent premature deletion."""
    try:
        path = resolve_safe_pcap_path(name)
    except ValueError as ve:
        abort(400, description=str(ve))

    active_pcap = current_active_pcap_name()
    finalizing = current_finalizing_pcaps()
    with _state_lock:
        if name == active_pcap or name in finalizing:
            return jsonify({'ok': False, 'error': 'pcap_capture_in_progress'}), 409

    if not os.path.isfile(path):
        abort(404)

    readers = current_active_readers()
    with _readers_lock:
        readers[name] += 1

    def _stream_pcap():
        try:
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    yield chunk
        finally:
            with _readers_lock:
                readers[name] = max(0, readers[name] - 1)

    return Response(
        _stream_pcap(),
        mimetype='application/vnd.tcpdump.pcap',
        headers={
            'Content-Disposition': f'attachment; filename="{name}"',
            'Content-Type': 'application/vnd.tcpdump.pcap',
        }
    )


def pcap_pin(name: str):
    """Marks capture as pinned evidence in persistent manifest."""
    try:
        path = resolve_safe_pcap_path(name)
    except ValueError as ve:
        abort(400, description=str(ve))
    if not os.path.isfile(path):
        abort(404)
    pinned = load_pinned_manifest()
    pinned.add(name)
    ok = save_pinned_manifest(pinned)
    return jsonify({'ok': ok, 'pinned': True, 'name': name})


def pcap_unpin(name: str):
    """Removes pinned status from capture and triggers quota pruning if necessary."""
    try:
        path = resolve_safe_pcap_path(name)
    except ValueError as ve:
        abort(400, description=str(ve))
    pinned = load_pinned_manifest()
    if name in pinned:
        pinned.remove(name)
        ok = save_pinned_manifest(pinned)
        pcap_prune()
    else:
        ok = True
    return jsonify({'ok': ok, 'pinned': False, 'name': name})


def pcap_delete(name: str):
    """Safely deletes completed capture file if not active or currently downloading."""
    try:
        path = resolve_safe_pcap_path(name)
    except ValueError as ve:
        abort(400, description=str(ve))
    active_pcap = current_active_pcap_name()
    finalizing = current_finalizing_pcaps()
    with _state_lock:
        if name == active_pcap or name in finalizing:
            return jsonify({'ok': False, 'error': 'cannot_delete_active_capture'}), 409
    readers = current_active_readers()
    with _readers_lock:
        if readers.get(name, 0) > 0:
            return jsonify({'ok': False, 'error': 'cannot_delete_downloading_file'}), 409
    if not os.path.isfile(path):
        abort(404)
    try:
        os.remove(path)
        pinned = load_pinned_manifest()
        if name in pinned:
            pinned.remove(name)
            save_pinned_manifest(pinned)
        pcap_prune()
        return jsonify({'ok': True, 'deleted': name})
    except Exception as ex:
        _log_error("Failed to delete pcap %s: %s", name, ex)
        return jsonify({'ok': False, 'error': str(ex)}), 500


def pcap_storage():
    """Computes disk usage, quota consumption, and pinned breakdown for dashboard clients."""
    pinned = load_pinned_manifest()
    cur_pcap_dir = current_pcap_dir()
    real_pcap_dir = os.path.realpath(cur_pcap_dir)
    total_bytes = 0
    pinned_bytes = 0
    file_count = 0
    pinned_count = 0
    if os.path.isdir(cur_pcap_dir):
        for fn in os.listdir(cur_pcap_dir):
            if not fn.endswith('.pcap'):
                continue
            fpath = os.path.join(cur_pcap_dir, fn)
            try:
                real_target = os.path.realpath(fpath)
                if not (real_target.startswith(real_pcap_dir + os.sep) and os.path.dirname(real_target) == real_pcap_dir):
                    continue
                sz = os.path.getsize(fpath)
                total_bytes += sz
                file_count += 1
                if fn in pinned:
                    pinned_bytes += sz
                    pinned_count += 1
            except Exception:
                continue

    max_mb = pcap_max_total_mb()
    max_bytes = max_mb * 1024 * 1024
    storage_ratio = round(total_bytes / max_bytes, 4) if max_bytes > 0 else 0
    return jsonify({
        'ok': True,
        'total_bytes': total_bytes,
        'total_human': human_size(total_bytes),
        'pinned_bytes': pinned_bytes,
        'pinned_human': human_size(pinned_bytes),
        'ephemeral_bytes': max(0, total_bytes - pinned_bytes),
        'ephemeral_human': human_size(max(0, total_bytes - pinned_bytes)),
        'max_bytes': max_bytes,
        'max_mb': max_mb,
        'total_files': file_count,
        'pinned_files': pinned_count,
        'max_files': pcap_max_files(),
        'pinned_quota_ratio': round(pinned_bytes / max_bytes, 4) if max_bytes > 0 else 0,
        'storage_quota_ratio': storage_ratio,
        # Normalized alias keys for UI & client dashboards
        'used_bytes': total_bytes,
        'used_mb': round(total_bytes / (1024 * 1024), 2),
        'limit_mb': max_mb,
        'pinned_count': pinned_count,
        'unpinned_count': max(0, file_count - pinned_count),
        'percent_used': round(storage_ratio * 100, 1),
    })


def register_pcap_routes(app: Flask) -> None:
    """Registers PCAP endpoints directly onto the Flask application instance."""
    app.add_url_rule('/pcap/list', 'pcap_list', pcap_list, methods=['GET'])
    app.add_url_rule('/pcap/download/<name>', 'pcap_download', pcap_download, methods=['GET'])
    app.add_url_rule('/pcap/pin/<name>', 'pcap_pin', pcap_pin, methods=['POST'])
    app.add_url_rule('/pcap/unpin/<name>', 'pcap_unpin', pcap_unpin, methods=['POST'])
    app.add_url_rule('/pcap/delete/<name>', 'pcap_delete', pcap_delete, methods=['DELETE', 'POST'])
    app.add_url_rule('/pcap/storage', 'pcap_storage', pcap_storage, methods=['GET'])
