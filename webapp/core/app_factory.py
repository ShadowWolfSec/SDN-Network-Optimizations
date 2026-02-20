"""Flask application factory.

Configures application security, session cookie properties, reverse proxy handling,
security hooks (CSRF, authentication, rate limiting, request IDs, security headers),
error handlers, and context processors.
"""

import os
import sys
from datetime import timedelta
from typing import Optional, Dict, Any

from flask import Flask
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from webapp.core.security import (
    _assign_request_id,
    _rate_limit_guard,
    _access_guard,
    _auth_guard,
    _csrf_guard,
    _security_headers,
    _inject_csrf_token,
    _handle_http_exception,
    _handle_unhandled_exception,
    _TrustedProxyMiddleware,
    _DEFAULT_SECRET_KEY,
)
from webapp.core.alerts_sync import (
    _start_alerts_sync_worker,
    _stop_alerts_sync_worker,
    _alerts_sync_started,
)

_WEBAPP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def _ensure_alerts_sync_worker_started():
    if os.getenv('SDN_ALERTS_SYNC_WORKER_ENABLED', '1').strip().lower() in ('1', 'true', 'yes', 'on'):
        if not _alerts_sync_started:
            _start_alerts_sync_worker()


def create_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    """Create and configure the Flask application instance."""
    app = Flask(
        'webapp.server',
        root_path=_WEBAPP_DIR,
        template_folder=os.path.join(_WEBAPP_DIR, 'templates'),
        static_folder=os.path.join(_WEBAPP_DIR, 'static'),
    )

    flask_debug = os.getenv('FLASK_DEBUG', '1').strip().lower() in ('1', 'true', 'yes', 'y', 'on')
    secret_key = os.getenv('FLASK_SECRET_KEY', '').strip() or _DEFAULT_SECRET_KEY
    if not flask_debug and (secret_key == _DEFAULT_SECRET_KEY or not os.getenv('FLASK_SECRET_KEY')):
        if not (test_config and test_config.get('TESTING')):
            print('FATAL: Set FLASK_SECRET_KEY in production. Do not use the default key.', file=sys.stderr)
            sys.exit(1)

    app.secret_key = secret_key

    session_cookie_secure = os.getenv('SESSION_COOKIE_SECURE', '0').strip().lower() in ('1', 'true', 'yes', 'y', 'on')
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=session_cookie_secure,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_COOKIE_NAME='sdn_guard_sid',
    )

    if test_config:
        app.config.update(test_config)

    # Trusted proxy fix middleware
    if os.getenv('TRUST_PROXY_HEADERS', '0').strip().lower() in ('1', 'true', 'yes', 'y', 'on'):
        raw_app = app.wsgi_app
        fixed_app = ProxyFix(raw_app, x_for=1, x_proto=1, x_host=1, x_port=1)
        app.wsgi_app = _TrustedProxyMiddleware(raw_app, fixed_app)

    # Request hooks
    app.before_request(_assign_request_id)
    app.before_request(_rate_limit_guard)
    app.before_request(_access_guard)
    app.before_request(_auth_guard)
    app.before_request(_csrf_guard)
    app.before_request(_ensure_alerts_sync_worker_started)

    # Response hook
    app.after_request(_security_headers)

    # Context processors
    app.context_processor(_inject_csrf_token)

    # Error handlers
    app.errorhandler(HTTPException)(_handle_http_exception)
    app.errorhandler(Exception)(_handle_unhandled_exception)

    # Register all 7 domain blueprints
    from webapp.blueprints import (
        dashboard_bp,
        monitoring_bp,
        events_bp,
        controller_bp,
        lab_proxy_bp,
        mitigation_bp,
        whitelist_bp,
    )
    for bp in (
        dashboard_bp,
        monitoring_bp,
        events_bp,
        controller_bp,
        lab_proxy_bp,
        mitigation_bp,
        whitelist_bp,
    ):
        app.register_blueprint(bp)

    return app
