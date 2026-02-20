"""Events and History Blueprint.

Handles history queries and daily CSV exports for security events.
Routes:
- GET /api/history -> api_history()
- GET /api/history.csv -> api_history_csv()
"""

import os
import re
import sys
from flask import Blueprint, Response, jsonify, request

from webapp.core.alerts_sync import (
    _events_lock,
    _read_events,
    _list_event_files,
    _events_date_str,
)

events_bp = Blueprint('events', __name__)


def _call_read_events(limit: int = 500):
    srv = sys.modules.get('webapp.server')
    if srv and hasattr(srv, '_read_events'):
        return srv._read_events(limit)
    return _read_events(limit)


@events_bp.get('/api/history')
def api_history():
    return jsonify({'ok': True, 'events': _call_read_events(500)})


@events_bp.get('/api/history.csv')
def api_history_csv():
    date_q = (request.args.get('date') or '').strip()
    if date_q and not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date_q):
        return jsonify({'ok': False, 'error': 'invalid_date'}), 400

    header = 'ts,type,src,reason,extra_json\n'
    with _events_lock:
        files = _list_event_files()
        target_date = date_q or _events_date_str()
        prefix = f"events-{target_date}."
        selected = [p for p in files if os.path.basename(p).startswith(prefix)]
        if not date_q and not selected and files:
            selected = [files[-1]]

        if not selected:
            return Response(header, mimetype='text/csv')

        chunks = [header]
        for fpath in selected:
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except Exception:
                continue
            if lines and lines[0].strip().lower().startswith('ts,type,'):
                lines = lines[1:]
            if lines:
                chunks.extend(lines)
                if not lines[-1].endswith('\n'):
                    chunks.append('\n')

    return Response(''.join(chunks), mimetype='text/csv')
