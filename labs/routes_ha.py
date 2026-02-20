"""
labs/routes_ha.py
Flask route endpoints for High Availability (HA) cluster and VIP failover.
"""

import logging
import re
import sys
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request

from labs.cmd_console import safe_name
from labs.ha_manager import (
    _ha_state,
    ha_apply_active,
    ha_ensure_hosts,
    ha_start_service,
    ha_status as get_ha_status,
    ha_stop_service,
    ha_test_vip,
)
from labs.topology import (
    _state_lock,
    acquire_lock,
    get_net,
    require_net,
)

logger = logging.getLogger('ha_routes')


def _runner_ha_func(name: str, fallback: Any) -> Any:
    """Dynamically resolves function from mininet_runner to honor test mocks/patches."""
    mod = sys.modules.get('labs.mininet_runner')
    if mod is not None and hasattr(mod, name):
        return getattr(mod, name)
    return fallback


def _get_runner_error_fn():
    from labs.mininet_runner import _runner_error
    return _runner_error


def _get_busy_resp_fn():
    from labs.mininet_runner import _busy_resp
    return _busy_resp


def _runner_error(err_or_exc, status=500, default_code='runner_internal_error', op='runner', extra=None):
    return _get_runner_error_fn()(err_or_exc, status=status, default_code=default_code, op=op, extra=extra)


def _busy_resp():
    return _get_busy_resp_fn()()


def ha_status():
    """Returns current HA cluster state, active node, running services, and last probe."""
    fn = _runner_ha_func('_ha_status', get_ha_status)
    return jsonify(fn())


def ha_config():
    """Updates HA configuration parameters and reapplies active VIP if network is live."""
    data = request.get_json(silent=True) or {}
    if not acquire_lock(1.5):
        return _busy_resp()
    try:
        if 'enabled' in data:
            _ha_state['enabled'] = bool(data['enabled'])
        if 'vip_ip' in data:
            v = str(data['vip_ip'] or '').strip()
            if v and re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', v):
                _ha_state['vip_ip'] = v
        if 'service_port' in data:
            try:
                p = int(data['service_port'])
                if 1 <= p <= 65535:
                    _ha_state['service_port'] = p
            except Exception:
                pass
        if 'primary' in data:
            name = safe_name(str(data['primary'] or ''))
            if name:
                _ha_state['primary'] = name
        if 'backup' in data:
            name = safe_name(str(data['backup'] or ''))
            if name:
                _ha_state['backup'] = name
        if 'auto_test' in data:
            _ha_state['auto_test'] = bool(data['auto_test'])

        applied = None
        net = get_net()
        if net is not None:
            try:
                apply_fn = _runner_ha_func('_ha_apply_active', ha_apply_active)
                applied = apply_fn(net)
            except Exception:
                applied = None
        return jsonify({'ok': True, 'ha': dict(_ha_state), 'applied': applied})
    finally:
        _state_lock.release()


def ha_active():
    """Switches active cluster node between primary and backup, with optional verification and rollback."""
    data = request.get_json(silent=True) or {}
    target = str(data.get('target') or data.get('active') or '').strip().lower()
    if target not in ('primary', 'backup'):
        return _runner_error('active_must_be_primary_or_backup', status=400, default_code='active_must_be_primary_or_backup', op='ha_active')

    if not acquire_lock(1.5):
        return _busy_resp()
    net = None
    try:
        try:
            net = require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='ha_active')

        ensure_fn = _runner_ha_func('_ha_ensure_hosts', ha_ensure_hosts)
        try:
            ensure_fn(net)
        except Exception as e:
            return _runner_error(e, status=400, default_code='ha_service_error', op='ha_active')

        previous_target = str(_ha_state.get('active') or 'primary')
        _ha_state['active'] = target
        apply_fn = _runner_ha_func('_ha_apply_active', ha_apply_active)
        out = apply_fn(net)
    finally:
        _state_lock.release()

    vip_test = {}
    if net is not None:
        try:
            test_fn = _runner_ha_func('_ha_test_vip', ha_test_vip)
            vip_test = test_fn(net)
        except Exception:
            pass

    if data.get('enforce_verification') and vip_test and not vip_test.get('vip_ok'):
        with _state_lock:
            _ha_state['active'] = previous_target
            apply_fn = _runner_ha_func('_ha_apply_active', ha_apply_active)
            apply_fn(net)
        return _runner_error('ha_test_failed', status=502, default_code='ha_test_failed', op='ha_active', extra={'rolled_back': True, 'previous': previous_target})

    return jsonify({'ok': True, 'active': target, 'applied': out, 'vip_test': vip_test})


def ha_service_start():
    """Starts HTTP service on HA cluster nodes."""
    if not acquire_lock(1.5):
        return _busy_resp()
    try:
        try:
            net = require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='ha_service_start')
        start_fn = _runner_ha_func('_ha_start_service', ha_start_service)
        out = start_fn(net)
        return jsonify(out)
    finally:
        _state_lock.release()


def ha_service_stop():
    """Stops HTTP service on HA cluster nodes."""
    if not acquire_lock(1.5):
        return _busy_resp()
    try:
        stop_fn = _runner_ha_func('_ha_stop_service', ha_stop_service)
        out = stop_fn()
        return jsonify(out)
    finally:
        _state_lock.release()


def ha_test():
    """Executes VIP reachability and HTTP response validation test."""
    if not acquire_lock(1.5):
        return _busy_resp()
    try:
        try:
            net = require_net()
        except Exception as e:
            return _runner_error(e, status=400, default_code='network_not_built', op='ha_test')
        test_fn = _runner_ha_func('_ha_test_vip', ha_test_vip)
        res = test_fn(net)
        return jsonify({'ok': True, 'test': res})
    finally:
        _state_lock.release()


def register_ha_routes(app: Flask) -> None:
    """Registers HA endpoints directly onto the Flask application instance."""
    app.add_url_rule('/ha/status', 'ha_status', ha_status, methods=['GET'])
    app.add_url_rule('/ha/config', 'ha_config', ha_config, methods=['POST'])
    app.add_url_rule('/ha/active', 'ha_active', ha_active, methods=['POST'])
    app.add_url_rule('/ha/service/start', 'ha_service_start', ha_service_start, methods=['POST'])
    app.add_url_rule('/ha/service/stop', 'ha_service_stop', ha_service_stop, methods=['POST'])
    app.add_url_rule('/ha/test', 'ha_test', ha_test, methods=['GET', 'POST'])
