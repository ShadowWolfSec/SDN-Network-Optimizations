"""Flask Blueprints Package for SDN DDoS Mitigation Web Application.

Organizes the 59 application routes into 7 domain-specific blueprints:
- dashboard: Core UI routes, auth views, health checks
- monitoring: Glances metrics, circuit breaker, system alerts
- events: History logs and CSV export
- controller: Ryu controller process management (status, start, stop)
- lab_proxy: Mininet runner proxy routes (topology, attacks, PCAP, HA)
- mitigation: Ryu REST mitigation proxy routes (block, unblock, whitelist, flows)
- whitelist: Persistent whitelist management (save, restore, status, delete)
"""

from webapp.blueprints.dashboard import dashboard_bp
from webapp.blueprints.monitoring import monitoring_bp
from webapp.blueprints.events import events_bp
from webapp.blueprints.controller import controller_bp
from webapp.blueprints.lab_proxy import lab_proxy_bp
from webapp.blueprints.mitigation import mitigation_bp
from webapp.blueprints.whitelist import whitelist_bp

ALL_BLUEPRINTS = [
    dashboard_bp,
    monitoring_bp,
    events_bp,
    controller_bp,
    lab_proxy_bp,
    mitigation_bp,
    whitelist_bp,
]

__all__ = [
    'dashboard_bp',
    'monitoring_bp',
    'events_bp',
    'controller_bp',
    'lab_proxy_bp',
    'mitigation_bp',
    'whitelist_bp',
    'ALL_BLUEPRINTS',
]
