/**
 * OVS Flows & Attack Scenarios Module (SDNApp.OvsFlows).
 * Handles OpenFlow table inspection, attack execution, and PCAP forensics.
 */

(function (global) {
  'use strict';

  /**
   * Render OpenFlow rules per switch into the #ovs-flows container.
   * Sorts flows descending by priority.
   */
  function renderOvsFlows(data) {
    const host = document.getElementById('ovs-flows');
    if (!host) return;
    host.innerHTML = '';
    const sws = (data && data.switches) ? data.switches : [];
    if (!sws.length) {
      const empty = document.createElement('div');
      empty.className = 'msg';
      empty.textContent = 'No data (network may not be running)';
      host.appendChild(empty);
      return;
    }

    sws.forEach(sw => {
      const div = document.createElement('div');
      div.style.marginBottom = '12px';
      const title = document.createElement('div');
      title.className = 'msg';
      const swName = document.createElement('strong');
      swName.textContent = String(sw.switch || '');
      title.appendChild(swName);
      if (sw.error) {
        title.appendChild(document.createTextNode(' '));
        const errSpan = document.createElement('span');
        errSpan.style.color = '#ff7a3a';
        errSpan.textContent = String(sw.error);
        title.appendChild(errSpan);
      }
      div.appendChild(title);

      const flows = (sw.flows || []).slice();
      flows.sort((a, b) => (Number(b.priority) || 0) - (Number(a.priority) || 0));

      const table = document.createElement('table');
      table.style.width = '100%';
      table.style.borderCollapse = 'collapse';
      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');
      ['Priority', 'Match', 'Actions'].forEach(col => {
        const th = document.createElement('th');
        th.style.textAlign = 'left';
        th.style.borderBottom = '1px solid #1d2a44';
        th.style.padding = '6px';
        th.style.color = '#9fb3c8';
        th.textContent = col;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      const tbody = document.createElement('tbody');
      const monoFont = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace";
      flows.slice(0, 200).forEach(f => {
        const tr = document.createElement('tr');
        const tdPrio = document.createElement('td');
        tdPrio.style.verticalAlign = 'top';
        tdPrio.style.borderBottom = '1px dashed #22324f';
        tdPrio.style.padding = '6px';
        tdPrio.textContent = String(f.priority ?? '');

        const tdMatch = document.createElement('td');
        tdMatch.style.verticalAlign = 'top';
        tdMatch.style.borderBottom = '1px dashed #22324f';
        tdMatch.style.padding = '6px';
        tdMatch.style.fontFamily = monoFont;
        tdMatch.style.fontSize = '12px';
        tdMatch.textContent = String(f.match || '');

        const tdAct = document.createElement('td');
        tdAct.style.verticalAlign = 'top';
        tdAct.style.borderBottom = '1px dashed #22324f';
        tdAct.style.padding = '6px';
        tdAct.style.fontFamily = monoFont;
        tdAct.style.fontSize = '12px';
        tdAct.textContent = String(f.actions || '');

        tr.appendChild(tdPrio);
        tr.appendChild(tdMatch);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      div.appendChild(table);
      host.appendChild(div);
    });
  }

  /**
   * Resolves the current scenario host inventory with role classification,
   * switch link status, and Ryu blocking/quarantine state.
   */
  function getScenarioHostInventory(opts = {}) {
    const s = opts.lastLabStatus !== undefined
      ? opts.lastLabStatus
      : ((global.SDNApp && global.SDNApp.getLastLabStatus) ? global.SDNApp.getLastLabStatus() : global.lastLabStatus);
    const m = opts.lastMetrics !== undefined
      ? opts.lastMetrics
      : ((global.SDNApp && global.SDNApp.getLastMetrics) ? global.SDNApp.getLastMetrics() : global.lastMetrics);

    const ha = (s && s.ha) ? s.ha : {};
    const haActive = !!(ha && (ha.enabled || ha.running || ha.active));
    const primary = haActive ? String(ha.primary || 'h2').trim() : '';
    const backup = haActive ? String(ha.backup || 'h3').trim() : '';
    const blocked = new Set(Array.isArray(m && m.blocked_ips) ? m.blocked_ips.map(String) : []);
    const quarantined = new Set(Array.isArray(m && m.quarantined_ips) ? m.quarantined_ips.map(String) : []);

    let rawHosts = [];
    const hostList = (s && (Array.isArray(s.hosts_info) ? s.hosts_info : (Array.isArray(s.hosts) ? s.hosts : null))) || [];
    if (hostList.length > 0) {
      rawHosts = hostList.map(h => ({
        name: String(h.name || ''),
        ip: h.ip ? String(h.ip) : null,
        linked: h.linked !== false && !!h.ip,
        role: String(h.role || ((primary && h.name === primary) ? 'ha_primary' : ((backup && h.name === backup) ? 'ha_backup' : 'client'))),
      }));
    } else {
      const topo = (s && s.topology && typeof s.topology === 'object') ? s.topology : {};
      const nodes = (s && Array.isArray(s.nodes)) ? s.nodes : ((topo && Array.isArray(topo.nodes)) ? topo.nodes : []);
      rawHosts = nodes.map(n => typeof n === 'string' ? n : (n && n.name ? n.name : '')).filter(name => name.startsWith('h')).map(name => ({
        name,
        ip: null,
        linked: true,
        role: (primary && name === primary) ? 'ha_primary' : ((backup && name === backup) ? 'ha_backup' : 'client'),
      }));
    }

    return rawHosts.filter(h => h.name).map(h => ({
      ...h,
      blocked: !!(h.ip && blocked.has(h.ip)),
      quarantined: !!(h.ip && quarantined.has(h.ip)),
    }));
  }

  /**
   * Returns validation requirements, minimum host count, and description for a scenario.
   */
  function getScenarioRequirementSpec(name, opts = {}) {
    const m = opts.lastMetrics !== undefined
      ? opts.lastMetrics
      : ((global.SDNApp && global.SDNApp.getLastMetrics) ? global.SDNApp.getLastMetrics() : global.lastMetrics);
    const cfg = (m && m.config && typeof m.config === 'object') ? m.config : {};
    const ddosThresh = Math.max(1, Number(cfg.ddos_source_threshold || 4));
    const synThresh = Number(cfg.syn_threshold || 200);
    const udpThresh = Number(cfg.udp_threshold || 400);
    const ppsThresh = Number(cfg.pps_threshold || 300);
    const psThresh = Number(cfg.portscan_threshold || 50);

    switch (String(name || '')) {
      case 'demo_normal':
      case 'normal':
        return { autoSelect: false, isNormal: true, minAttackers: 1, idealAttackers: 1, label: 'Normal Traffic (Ping)', detail: 'Requires: at least 1 linked client host and 1 linked Victim host.' };
      case 'demo_dos':
        return { autoSelect: false, isNormal: false, minAttackers: 1, idealAttackers: 1, label: 'DoS (Single Attacker)', detail: `Requires: 1+ unblocked selected client attacker + linked Victim (pps_threshold=${ppsThresh} pps).` };
      case 'demo_ddos_medium':
        return { autoSelect: false, isNormal: false, minAttackers: Math.max(4, ddosThresh), idealAttackers: Math.max(4, ddosThresh), label: 'DDoS Medium', detail: `Requires: at least ${Math.max(4, ddosThresh)} unblocked selected client attackers + linked Victim (sends high-rate SYN flood).` };
      case 'demo_ddos_massive':
        return { autoSelect: false, isNormal: false, minAttackers: Math.max(6, ddosThresh), idealAttackers: Math.max(6, ddosThresh), label: 'DDoS Massive', detail: `Requires: at least ${Math.max(6, ddosThresh)} unblocked selected client attackers + linked Victim (maximum DDoS load to VIP).` };
      case 'syn_flood':
        return { autoSelect: false, isNormal: false, minAttackers: 1, idealAttackers: 1, label: 'SYN Flood', detail: `Requires: 1+ unblocked selected client attacker + linked Victim (syn_threshold=${synThresh} pps).` };
      case 'udp_flood':
        return { autoSelect: false, isNormal: false, minAttackers: 1, idealAttackers: 1, label: 'UDP Flood', detail: `Requires: 1+ unblocked selected client attacker + linked Victim (udp_threshold=${udpThresh} pps).` };
      case 'icmp_flood':
        return { autoSelect: false, isNormal: false, minAttackers: 1, idealAttackers: 1, label: 'ICMP Flood', detail: `Requires: 1+ unblocked selected client attacker + linked Victim (pps_threshold=${ppsThresh} pps).` };
      case 'portscan':
        return { autoSelect: false, isNormal: false, minAttackers: 1, idealAttackers: 1, label: 'Portscan', detail: `Requires: 1+ unblocked selected client attacker + linked Victim (portscan_threshold=${psThresh} ports/s; sends ~125 ports/s).` };
      default:
        return { autoSelect: false, isNormal: false, minAttackers: 1, idealAttackers: 1, label: 'Attack Scenario', detail: 'Requires: 1+ eligible client attacker and a valid Victim host.' };
    }
  }

  /**
   * Maps backend error codes to user-facing descriptive messages.
   */
  function formatScenarioError(e, fallback) {
    const data = (e && (e.data || e.bodyJson) && typeof (e.data || e.bodyJson) === 'object') ? (e.data || e.bodyJson) : {};
    const code = String(data.error || '');
    if (code === 'network_not_built') return 'Error: Network is not built — click Build Network first.';
    if (code === 'attack_already_running') return 'Warning: An attack is currently running — click Stop Attack first.';
    if (code === 'victim_not_linked') return `Error: Victim (${data.victim || ''}) is not linked to a switch.`;
    if (code === 'victim_in_attackers') return 'Error: Victim cannot be selected as an attacker.';
    if (code === 'attacker_reserved_role') return `Error: Host (${data.attacker || ''}) is reserved as an HA server and cannot be an attacker.`;
    if (code === 'attacker_not_linked') return `Error: Host (${data.attacker || ''}) is not linked to a switch and has no IP.`;
    if (code === 'attacker_blocked') return `Error: Attacker ${data.attacker || ''} (${data.ip || ''}) is currently blocked — unblock it first.`;
    if (code === 'insufficient_attackers') {
      const req = data.required || 4;
      const avail = data.available ?? 0;
      const list = Array.isArray(data.available_hosts) && data.available_hosts.length ? data.available_hosts.join(', ') : 'none';
      return `Error: Insufficient clean attackers — need at least ${req}, currently available: ${avail} (${list}).`;
    }
    return fallback || 'Operation failed.';
  }

  /**
   * Initializes attack scenario UI, OVS table refresh, PCAP controls, and polling.
   */
  function initAttackAndOvs(opts = {}) {
    const getJSON = opts.getJSON || global.getJSON;
    const errToShortText = opts.errToShortText || global.errToShortText || String;
    const getLastLabStatus = opts.getLastLabStatus || (() => (global.SDNApp && global.SDNApp.getLastLabStatus ? global.SDNApp.getLastLabStatus() : global.lastLabStatus));
    const getLastMetrics = opts.getLastMetrics || (() => (global.SDNApp && global.SDNApp.getLastMetrics ? global.SDNApp.getLastMetrics() : global.lastMetrics));
    const isLabBusy = opts.isLabBusy || (() => (global.SDNApp && global.SDNApp.isLabBusy ? global.SDNApp.isLabBusy() : global.labBusy));
    const isLastAttackRunning = opts.isLastAttackRunning || (() => (global.SDNApp && global.SDNApp.isLastAttackRunning ? global.SDNApp.isLastAttackRunning() : global.lastAttackRunning));
    const setLastAttackRunning = opts.setLastAttackRunning || ((val) => {
      if (global.SDNApp && global.SDNApp.setLastAttackRunning) global.SDNApp.setLastAttackRunning(val);
      global.lastAttackRunning = val;
    });
    const labStatusCallbacks = opts.labStatusCallbacks || (global.SDNApp && global.SDNApp.getLabStatusCallbacks ? global.SDNApp.getLabStatusCallbacks() : global.labStatusCallbacks) || [];
    const metricsCallbacks = opts.metricsCallbacks || (global.SDNApp && global.SDNApp.getMetricsCallbacks ? global.SDNApp.getMetricsCallbacks() : global.metricsCallbacks) || [];
    const pollTasks = opts.pollTasks || (global.SDNApp && global.SDNApp.getPollTasks ? global.SDNApp.getPollTasks() : global.pollTasks) || {};

    const btnOvs = document.getElementById('btn-ovs-refresh');
    const ovsMsg = document.getElementById('ovs-msg');

    const scenarioNameEl = document.getElementById('scenario-name');
    const scenarioReqsEl = document.getElementById('scenario-requirements');
    const scenarioAttackersEl = document.getElementById('scenario-attackers');
    const scenarioHostsNoteEl = document.getElementById('scenario-hosts-note');
    const scenarioVictimEl = document.getElementById('scenario-victim');
    const btnScenarioStop = document.getElementById('btn-scenario-stop');
    const scenarioMsg = document.getElementById('scenario-msg');

    const elRunning = document.getElementById('attack-running');
    const elKind = document.getElementById('attack-kind');
    const elProfile = document.getElementById('attack-profile');
    const elAtk = document.getElementById('attack-attackers');
    const elLeg = document.getElementById('attack-legit');
    const elDur = document.getElementById('attack-elapsed');

    const pcapStatus = document.getElementById('pcap-status');
    const pcapList = document.getElementById('pcap-list');
    const pcapStorageSummary = document.getElementById('pcap-storage-summary');
    const btnPcapRefresh = document.getElementById('btn-pcap-refresh');

    let lastScenarioUIKey = null;

    function updateScenarioRequirements(inv, curVic) {
      if (!scenarioReqsEl) return;
      const scName = scenarioNameEl ? scenarioNameEl.value : 'demo_normal';
      const spec = getScenarioRequirementSpec(scName, { lastMetrics: getLastMetrics() });
      const curLab = getLastLabStatus();
      const labRunning = !!(curLab && curLab.running);

      const eligibleAll = inv.filter(h => h.role === 'client' && h.name !== curVic && h.linked);
      const eligibleClean = eligibleAll.filter(h => !h.blocked);
      const readyCount = spec.isNormal ? eligibleAll.length : eligibleClean.length;

      const lines = [spec.detail];
      if (!labRunning) {
        lines.push('Status: Network is stopped (click Build Network first).');
        scenarioReqsEl.style.borderColor = '#475569';
      } else {
        const targetStr = spec.autoSelect
          ? `Auto-eligible clean clients: ${readyCount} / ${spec.idealAttackers} (minimum ${spec.minAttackers})`
          : `Eligible clean attackers: ${readyCount}`;
        lines.push(targetStr);
        if (isLastAttackRunning()) {
          lines.push('Warning: Another attack is running — stop it before launching a new one.');
          scenarioReqsEl.style.borderColor = '#f59e0b';
        } else if (readyCount < spec.minAttackers) {
          lines.push(`Warning: Fewer available hosts than required (${spec.minAttackers}) — add hosts or unblock IPs.`);
          scenarioReqsEl.style.borderColor = '#ef4444';
        } else if (!getLastMetrics()) {
          lines.push('Warning: Ryu controller is currently offline (traffic will run without detection/blocking).');
          scenarioReqsEl.style.borderColor = '#f59e0b';
        } else {
          scenarioReqsEl.style.borderColor = '#10b981';
        }
      }
      scenarioReqsEl.innerText = lines.join('\n');
    }

    function renderScenarioSelectors() {
      if (!scenarioAttackersEl || !scenarioVictimEl) return;
      try {
        const curLab = getLastLabStatus();
        const curMetrics = getLastMetrics();
        const inv = getScenarioHostInventory({ lastLabStatus: curLab, lastMetrics: curMetrics });
        const scName = scenarioNameEl ? scenarioNameEl.value : '';
        const spec = getScenarioRequirementSpec(scName, { lastMetrics: curMetrics });
        const linkedHosts = inv.filter(h => h.linked);

        const curVicPrev = scenarioVictimEl.value || '';
        const validVicNames = linkedHosts.map(h => h.name);
        let nextVic = validVicNames.includes(curVicPrev) ? curVicPrev : '';
        if (!nextVic) {
          const haPrim = linkedHosts.find(h => h.role === 'ha_primary');
          nextVic = haPrim ? haPrim.name : (validVicNames[0] || '');
        }

        const uiKey = JSON.stringify({
          inv: inv.map(h => [h.name, h.ip, h.linked, h.role, h.blocked, h.quarantined]),
          vic: nextVic,
          sc: scName,
          labRunning: !!(curLab && curLab.running),
          atkRunning: isLastAttackRunning(),
          ryuUp: !!curMetrics,
        });

        updateScenarioRequirements(inv, nextVic);
        if (uiKey === lastScenarioUIKey) return;
        lastScenarioUIKey = uiKey;

        const prevChecked = new Set();
        try {
          scenarioAttackersEl.querySelectorAll('input[type="checkbox"][data-host]').forEach(cb => {
            if (cb && cb.checked) prevChecked.add(String(cb.getAttribute('data-host') || ''));
          });
        } catch (e) {}

        scenarioVictimEl.innerHTML = '';
        const defOpt = document.createElement('option');
        defOpt.value = '';
        defOpt.textContent = linkedHosts.length ? 'Victim (Select Target)' : 'No linked hosts available';
        scenarioVictimEl.appendChild(defOpt);

        linkedHosts.forEach(h => {
          const ov = document.createElement('option');
          ov.value = h.name;
          const roleTag = h.role === 'ha_primary' ? ' - HA Primary' : (h.role === 'ha_backup' ? ' - HA Backup' : '');
          const ipTag = h.ip ? ` (${h.ip}${roleTag})` : (roleTag ? ` (${roleTag.slice(3)})` : '');
          ov.innerText = `${h.name}${ipTag}`;
          scenarioVictimEl.appendChild(ov);
        });
        if (nextVic && validVicNames.includes(nextVic)) {
          scenarioVictimEl.value = nextVic;
        }

        const eligible = inv.filter(h => h.role === 'client' && h.name !== nextVic && h.linked);
        const excludedHA = inv.filter(h => h.role === 'ha_primary' || h.role === 'ha_backup');
        const excludedUnlinked = inv.filter(h => !h.linked);

        scenarioAttackersEl.innerHTML = '';
        if (!curLab || !curLab.running) {
          const sp = document.createElement('span');
          sp.style.color = 'var(--text-muted)';
          sp.style.fontSize = '11px';
          sp.innerText = 'Waiting for lab startup (Build Network)...';
          scenarioAttackersEl.appendChild(sp);
        } else if (spec.autoSelect) {
          const cleanAuto = eligible.filter(h => !h.blocked).map(h => h.ip ? `${h.name} (${h.ip})` : h.name);
          const box = document.createElement('span');
          box.style.color = cleanAuto.length >= spec.minAttackers ? '#93c5fd' : '#fca5a5';
          box.style.fontSize = '11px';
          box.innerText = cleanAuto.length
            ? `Auto-selecting ${cleanAuto.length} eligible host(s): ${cleanAuto.join(', ')}`
            : 'No unblocked eligible client hosts available for this auto scenario.';
          scenarioAttackersEl.appendChild(box);
        } else if (eligible.length === 0) {
          const sp = document.createElement('span');
          sp.style.color = '#fca5a5';
          sp.style.fontSize = '11px';
          sp.innerText = 'No client attackers available (all linked hosts are reserved for Victim or HA).';
          scenarioAttackersEl.appendChild(sp);
        } else {
          let anyChecked = false;
          eligible.forEach(h => {
            const wrap = document.createElement('label');
            wrap.style.display = 'inline-flex';
            wrap.style.alignItems = 'center';
            wrap.style.gap = '6px';
            wrap.style.padding = '4px 8px';
            wrap.style.border = h.blocked ? '1px solid #ef4444' : '1px solid #284061';
            wrap.style.borderRadius = '999px';
            wrap.style.background = h.blocked ? 'rgba(239, 68, 68, 0.12)' : '#0b1220';
            wrap.style.color = '#e6ecf2';

            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.setAttribute('data-host', h.name);
            const shouldCheck = prevChecked.has(h.name);
            cb.checked = shouldCheck;
            if (shouldCheck) anyChecked = true;

            const text = document.createElement('span');
            const statusSuffix = h.blocked ? ' [Blocked]' : (h.quarantined ? ' [Quarantine]' : '');
            text.innerText = (h.ip ? `${h.name} (${h.ip})` : h.name) + statusSuffix;

            wrap.appendChild(cb);
            wrap.appendChild(text);
            scenarioAttackersEl.appendChild(wrap);
          });

          if (!anyChecked && prevChecked.size === 0) {
            const firstClean = eligible.find(h => spec.isNormal || !h.blocked) || eligible[0];
            if (firstClean) {
              const cb = scenarioAttackersEl.querySelector(`input[type="checkbox"][data-host="${firstClean.name}"]`);
              if (cb) cb.checked = true;
            }
          }
        }

        if (scenarioHostsNoteEl) {
          const notes = [];
          if (excludedHA.length) {
            notes.push('Excluded HA servers: ' + excludedHA.map(h => `${h.name} (${h.role === 'ha_primary' ? 'Primary' : 'Backup'})`).join(', '));
          }
          if (excludedUnlinked.length) {
            notes.push('Unlinked hosts: ' + excludedUnlinked.map(h => h.name).join(', '));
          }
          const blockedClients = eligible.filter(h => h.blocked);
          if (blockedClients.length) {
            notes.push('Currently blocked in Ryu: ' + blockedClients.map(h => h.name).join(', '));
          }
          scenarioHostsNoteEl.innerText = notes.join(' | ');
        }
      } catch (e) {}
    }

    function updateScenarioHostsFromStatus(_s) {
      renderScenarioSelectors();
    }

    if (scenarioNameEl) {
      scenarioNameEl.addEventListener('change', () => renderScenarioSelectors());
    }
    if (scenarioVictimEl) {
      scenarioVictimEl.addEventListener('change', () => renderScenarioSelectors());
    }
    metricsCallbacks.push(() => renderScenarioSelectors());

    async function refreshOvs() {
      if (isLabBusy()) return;
      if (ovsMsg) ovsMsg.innerText = '';
      try {
        const d = await getJSON('/api/lab/ovs/flows');
        renderOvsFlows(d);
      } catch (e) {
        if (ovsMsg) ovsMsg.innerText = 'Failed to load OVS flows.';
      }
    }

    let lastAttackState = null;

    async function pollAttack(reqSeq = null, task = null) {
      if (isLabBusy()) return;
      if (document.hidden && (!task || reqSeq === null || !task.forcing)) return;
      const t = task || (pollTasks && pollTasks.attack);
      const seq = (reqSeq !== null && reqSeq !== undefined) ? reqSeq : (t ? ++t.seq : 1);
      try {
        const s = await getJSON('/api/lab/attack/status');
        if (t && seq < t.appliedSeq) return;
        if (t) t.appliedSeq = seq;
        const a = s.attack || {};
        const wasRunning = isLastAttackRunning();
        const nowRunning = !!s.running;
        setLastAttackRunning(nowRunning);
        if (wasRunning !== nowRunning) {
          renderScenarioSelectors();
        }

        const currentAttackKey = JSON.stringify({
          running: s.running,
          name: a.name,
          victim: a.victim,
          victim_ip: a.victim_ip,
          attackers: a.attackers,
          attacker_ips: a.attacker_ips
        });
        const attackChanged = (currentAttackKey !== lastAttackState);
        lastAttackState = currentAttackKey;

        if (elRunning) elRunning.innerText = s.running ? 'Running' : 'Stopped';
        if (elKind) {
          const kind = (a.kind || '').toString();
          if (kind === 'scenario') {
            const nm = a.name || 'scenario';
            const pr = a.proto ? String(a.proto).toUpperCase() : '';
            const readableName = {
              'demo_normal': 'Normal Traffic',
              'demo_dos': 'DoS (Single Attacker)',
              'demo_ddos_medium': 'DDoS Medium',
              'demo_ddos_massive': 'DDoS Massive',
              'syn_flood': 'SYN Flood',
              'udp_flood': 'UDP Flood',
              'portscan': 'Portscan',
              'icmp_flood': 'ICMP Flood'
            }[nm] || nm;
            elKind.innerText = pr ? `${readableName} (${pr})` : readableName;
          } else {
            const pr = a.proto ? String(a.proto).toUpperCase() : '';
            elKind.innerText = pr ? `${kind} (${pr})` : (kind || '-');
          }
        }
        if (elProfile) elProfile.innerText = (a.kind === 'scenario') ? '-' : (a.profile || '-');
        if (elAtk) elAtk.innerText = Array.isArray(a.attackers) ? String(a.attackers.length) : '-';
        if (elLeg) elLeg.innerText = Array.isArray(a.legitimate) ? String(a.legitimate.length) : '-';
        if (elDur) {
          const st = Number(a.started_at || 0);
          const dur = Number(a.duration || 0);
          if (st && dur) {
            const el = Math.max(0, Math.round(Date.now() / 1000 - st));
            elDur.innerText = `${el}/${dur}`;
          } else {
            elDur.innerText = a.duration ? String(a.duration) : '-';
          }
        }

        const elVictim = document.getElementById('attack-victim');
        const elVictimIp = document.getElementById('attack-victim-ip');
        const elAttackerIps = document.getElementById('attack-attacker-ips');

        if (elVictim) {
          if (s.running || attackChanged) {
            elVictim.innerText = s.running ? (a.victim || '-') : '-';
          }
        }
        if (elVictimIp) {
          if (s.running || attackChanged) {
            elVictimIp.innerText = s.running ? (a.victim_ip || '-') : '-';
          }
        }
        if (elAttackerIps) {
          if (s.running || attackChanged) {
            if (s.running) {
              if (Array.isArray(a.attacker_ips) && a.attacker_ips.length > 0) {
                elAttackerIps.innerText = a.attacker_ips.join(', ');
              } else if (Array.isArray(a.attackers) && a.attackers.length > 0) {
                elAttackerIps.innerText = a.attackers.join(', ');
              } else {
                elAttackerIps.innerText = '-';
              }
            } else {
              elAttackerIps.innerText = '-';
            }
          }
        }

        const liveChart = (global.SDNApp && global.SDNApp.Charts && global.SDNApp.Charts.getLiveChart)
          ? global.SDNApp.Charts.getLiveChart()
          : global.chartLive;
        if (liveChart) {
          if (s.running && a.name) {
            const readableName = {
              'demo_normal': 'Normal Traffic',
              'demo_dos': 'DoS (Single Attacker)',
              'demo_ddos_medium': 'DDoS Medium',
              'demo_ddos_massive': 'DDoS Massive',
              'syn_flood': 'SYN Flood',
              'udp_flood': 'UDP Flood',
              'portscan': 'Portscan',
              'icmp_flood': 'ICMP Flood'
            }[a.name] || a.name;
            liveChart.options.plugins.title = {
              display: true,
              text: `Live Traffic Rate - ${readableName}`,
              color: '#9fb3c8'
            };
          } else {
            liveChart.options.plugins.title = {
              display: true,
              text: 'Live Traffic Rate',
              color: '#9fb3c8'
            };
          }
          liveChart.update();
        }

        if (pcapStatus) {
          const p = s.last_pcap || '-';
          const pr = s.pcap_running ? 'Recording' : 'Idle';
          pcapStatus.innerText = `PCAP: ${pr} / ${p}`;
        }
      } catch (e) {
        console.error('Error polling attack status:', e);
      }
    }

    async function refreshPcapList(reqSeq = null, task = null) {
      if (isLabBusy()) return;
      if (document.hidden && (!task || reqSeq === null || !task.forcing)) return;
      if (!pcapList) return;
      const t = task || (pollTasks && pollTasks.pcap);
      const seq = (reqSeq !== null && reqSeq !== undefined) ? reqSeq : (t ? ++t.seq : 1);
      try {
        const [d, dStorage] = await Promise.all([
          getJSON('/api/lab/pcap/list'),
          getJSON('/api/lab/pcap/storage').catch(() => null),
        ]);
        if (t && seq < t.appliedSeq) return;
        if (t) t.appliedSeq = seq;

        if (pcapStorageSummary && dStorage && dStorage.ok) {
          pcapStorageSummary.innerText = `${dStorage.used_mb} / ${dStorage.limit_mb} MB (${dStorage.pinned_count} pinned)`;
          pcapStorageSummary.title = `Total Storage: ${dStorage.used_mb} MB of ${dStorage.limit_mb} MB limit (${dStorage.pinned_count} pinned evidence, ${dStorage.unpinned_count} ephemeral)`;
        }

        const details = (d && Array.isArray(d.pcap_details)) ? d.pcap_details : null;
        const items = (d && Array.isArray(d.pcaps)) ? d.pcaps : [];
        pcapList.innerHTML = '';

        if (details) {
          if (details.length === 0) {
            const emptySpan = document.createElement('span');
            emptySpan.style.fontSize = '12px';
            emptySpan.style.color = 'var(--text-secondary)';
            emptySpan.style.padding = '4px 0';
            emptySpan.innerText = 'No PCAP captures recorded yet.';
            pcapList.appendChild(emptySpan);
            return;
          }
          details.slice(0, 15).forEach(item => {
            const card = document.createElement('div');
            card.className = 'pcap-item-card';

            const info = document.createElement('div');
            info.className = 'pcap-item-info';

            const a = document.createElement('a');
            a.className = 'pcap-item-link';
            a.href = `/api/lab/pcap/download/${encodeURIComponent(item.name)}`;
            a.target = '_blank';
            a.rel = 'noopener';
            a.innerText = item.name;
            a.title = `Download ${item.name}`;

            const meta = document.createElement('div');
            meta.className = 'pcap-meta';

            const sz = document.createElement('span');
            sz.className = 'pcap-badge-size';
            sz.innerText = item.size_human || `${Math.round(item.size_bytes / 1024)} KB`;

            const st = document.createElement('span');
            st.className = `pcap-badge-status pcap-status-${item.status}`;
            st.innerText = item.status;

            meta.appendChild(sz);
            meta.appendChild(st);

            if (item.pinned) {
              const pinBadge = document.createElement('span');
              pinBadge.className = 'pcap-badge-pinned';
              pinBadge.innerText = '📌 Pinned';
              pinBadge.title = 'Pinned forensic evidence (protected from auto-pruning)';
              meta.appendChild(pinBadge);
            }

            info.appendChild(a);
            info.appendChild(meta);
            card.appendChild(info);

            const actions = document.createElement('div');
            actions.className = 'pcap-actions';

            const btnPin = document.createElement('button');
            btnPin.className = 'pcap-btn-action';
            if (item.pinned) {
              btnPin.innerText = 'Unpin';
              btnPin.title = 'Unpin this capture (make it eligible for auto-pruning)';
              btnPin.addEventListener('click', async (e) => {
                e.preventDefault();
                btnPin.disabled = true;
                try {
                  await getJSON(`/api/lab/pcap/unpin/${encodeURIComponent(item.name)}`, { method: 'POST' });
                  await refreshPcapList();
                } catch (err) {
                  console.error('Error unpinning PCAP:', err);
                  btnPin.disabled = false;
                }
              });
            } else {
              btnPin.innerText = '📌 Pin';
              btnPin.title = 'Pin this capture as forensic evidence (protects from auto-pruning)';
              btnPin.addEventListener('click', async (e) => {
                e.preventDefault();
                btnPin.disabled = true;
                try {
                  await getJSON(`/api/lab/pcap/pin/${encodeURIComponent(item.name)}`, { method: 'POST' });
                  await refreshPcapList();
                } catch (err) {
                  console.error('Error pinning PCAP:', err);
                  btnPin.disabled = false;
                }
              });
            }
            actions.appendChild(btnPin);

            const btnDel = document.createElement('button');
            btnDel.className = 'pcap-btn-action pcap-btn-delete';
            btnDel.innerText = '🗑️';
            btnDel.title = 'Delete PCAP capture';

            if (item.pinned || item.status === 'capturing' || item.status === 'finalizing') {
              btnDel.disabled = true;
              btnDel.title = item.pinned ? 'Cannot delete: file is pinned evidence (unpin first)' : 'Cannot delete: capture is actively running or finalizing';
            } else {
              btnDel.addEventListener('click', async (e) => {
                e.preventDefault();
                if (!confirm(`Are you sure you want to delete "${item.name}"? This action cannot be undone.`)) return;
                btnDel.disabled = true;
                try {
                  await getJSON(`/api/lab/pcap/delete/${encodeURIComponent(item.name)}`, { method: 'DELETE' });
                  await refreshPcapList();
                } catch (err) {
                  console.error('Error deleting PCAP:', err);
                  btnDel.disabled = false;
                }
              });
            }
            actions.appendChild(btnDel);

            card.appendChild(actions);
            pcapList.appendChild(card);
          });
        } else {
          items.slice(0, 10).forEach(name => {
            const a = document.createElement('a');
            a.className = 'pill gray';
            a.href = `/api/lab/pcap/download/${encodeURIComponent(name)}`;
            a.target = '_blank';
            a.rel = 'noopener';
            a.innerText = name;
            pcapList.appendChild(a);
          });
        }
      } catch (e) {
        console.warn('Error refreshing PCAP captures:', e);
      }
    }
    global.refreshPcapList = refreshPcapList;

    if (btnOvs) btnOvs.addEventListener('click', refreshOvs);

    if (btnPcapRefresh) btnPcapRefresh.addEventListener('click', async () => {
      await refreshPcapList();
      await pollAttack();
    });

    if (btnScenarioStop) btnScenarioStop.addEventListener('click', async () => {
      if (scenarioMsg) scenarioMsg.innerText = '';
      try {
        let lastErr = null;
        for (let i = 0; i < 3; i++) {
          try {
            await getJSON('/api/lab/attack/stop', { method: 'POST' });
            lastErr = null;
            break;
          } catch (e) {
            lastErr = e;
            await new Promise(r => setTimeout(r, 600 + (i * 600)));
          }
        }
        if (lastErr) throw lastErr;
        if (scenarioMsg) scenarioMsg.innerText = 'Stopped.';
        if (scenarioMsg) setTimeout(() => { if (scenarioMsg.innerText === 'Stopped.') scenarioMsg.innerText = ''; }, 2000);
        await pollAttack();
        await refreshPcapList();
      } catch (e) {
        const t = errToShortText(e);
        if (scenarioMsg) scenarioMsg.innerText = t ? `Stop failed (${t})` : 'Stop failed (ensure lab is Running)';
        if (scenarioMsg) setTimeout(() => { scenarioMsg.innerText = ''; }, 3000);
      }
    });

    labStatusCallbacks.push(updateScenarioHostsFromStatus);
    const curLab = getLastLabStatus();
    if (curLab) updateScenarioHostsFromStatus(curLab);

    return {
      pollAttack,
      refreshPcapList,
      refreshOvs,
      renderScenarioSelectors,
      syncScenarioUI: renderScenarioSelectors,
    };
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  const OvsFlowsModule = {
    renderOvsFlows,
    getScenarioHostInventory,
    getScenarioRequirementSpec,
    formatScenarioError,
    initAttackAndOvs,
  };

  global.SDNApp = global.SDNApp || {};
  global.SDNApp.OvsFlows = OvsFlowsModule;

  // Global backwards compatibility bindings
  global.renderOvsFlows = renderOvsFlows;
  global.getScenarioHostInventory = getScenarioHostInventory;
  global.getScenarioRequirementSpec = getScenarioRequirementSpec;
  global.formatScenarioError = formatScenarioError;
  global.initAttackAndOvs = initAttackAndOvs;

})(typeof window !== 'undefined' ? window : this);
