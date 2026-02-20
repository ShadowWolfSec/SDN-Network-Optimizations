"""Dashboard and UI Blueprint.

Handles top-level routes, service health reporting, login/logout, and index UI.
Routes:
- GET  /health -> health()
- GET  /api/health/services -> api_service_health()
- GET  /login -> login_get()
- POST /login -> login_post()
- POST /logout -> logout()
- GET  / -> index()
"""

import re
import secrets
import sys
import time
from typing import Any, Dict

from flask import Blueprint, jsonify, redirect, render_template, request, session

from webapp.core.security import (
    _get_csrf_token,
    _rate_ip,
    _login_fail_allowed,
    _login_fail_record,
    _login_fail_clear,
    _load_users,
    _verify_password,
    _SERVER_BOOT_ID,
)
from webapp.core.alerts_sync import (
    _health_lock,
    _service_health,
)

dashboard_bp = Blueprint('dashboard', __name__)


def _get_glances_cb_snapshot() -> Dict[str, Any]:
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_glances_cb_snapshot'):
        return srv._glances_cb_snapshot()
    try:
        from webapp.blueprints.monitoring import _glances_cb_snapshot
        return _glances_cb_snapshot()
    except Exception:
        return {'state': 'closed', 'fail_count': 0, 'cooldown_remaining_sec': 0.0}


@dashboard_bp.get('/health')
def health():
    return jsonify({'ok': True})


@dashboard_bp.get('/api/health/services')
def api_service_health():
    """Return health status of all backend services for graceful degradation UI."""
    cb_snap = _get_glances_cb_snapshot()
    with _health_lock:
        services_copy = {k: dict(v) for k, v in _service_health.items()}
    gl = services_copy.get('glances') or {}
    gl['state'] = cb_snap.get('state', 'closed')
    gl['fail_count'] = cb_snap.get('fail_count', 0)
    gl['cooldown_remaining_sec'] = cb_snap.get('cooldown_remaining_sec', 0.0)
    gl['circuit_open'] = (gl['state'] == 'open')
    services_copy['glances'] = gl
    return jsonify({'ok': True, 'services': services_copy})


@dashboard_bp.get('/login')
def login_get():
    _get_csrf_token()
    return render_template('login.html')


@dashboard_bp.post('/login')
def login_post():
    """Secure login with rate limiting and input sanitization."""
    client_ip = _rate_ip()
    if not _login_fail_allowed(client_ip):
        return render_template('login.html', error='Too many failed login attempts. Try again later.'), 429

    username = (request.form.get('username') or '').strip()
    password = (request.form.get('password') or '').strip()

    # Input validation
    if not username or not password:
        _login_fail_record(client_ip)
        return render_template('login.html', error='Missing username/password'), 401

    # Username sanitization (alphanumeric only)
    if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
        _login_fail_record(client_ip)
        return render_template('login.html', error='Invalid username format'), 401

    users = _load_users()
    u = users.get(username) if isinstance(users, dict) else None
    stored_pw = str(u.get('password') or '') if isinstance(u, dict) else ''

    if not isinstance(u, dict) or not _verify_password(stored_pw, password):
        _login_fail_record(client_ip)
        return render_template('login.html', error='Invalid credentials'), 401

    _login_fail_clear(client_ip)
    # Prevent session fixation while rotating CSRF token for authenticated session
    session.clear()
    session['user'] = username
    session['role'] = u.get('role', 'user') if isinstance(u, dict) else 'user'
    session['csrf_token'] = secrets.token_urlsafe(32)
    session['boot_id'] = _SERVER_BOOT_ID
    session.permanent = True  # Use configured lifetime
    session['login_ts'] = int(time.time())

    return redirect('/')


@dashboard_bp.post('/logout')
def logout():
    """Secure logout with session cleanup."""
    session.clear()
    return redirect('/login')


@dashboard_bp.get('/')
def index():
    _get_csrf_token()
    user = session.get('user')
    if user:
        users = _load_users()
        u = users.get(user) or users.get(str(user).lower())
        if isinstance(u, dict):
            session['role'] = u.get('role', 'user')
        elif str(user).lower() == 'admin':
            session['role'] = 'admin'
        else:
            session['role'] = 'user'
    return render_template('index.html')
