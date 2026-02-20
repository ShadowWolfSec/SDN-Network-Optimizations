/**
 * Forensics & Event History Module (SDNApp.Forensics).
 * Fetches and renders historical audit logs and attack timeline events.
 */

(function (global) {
  'use strict';

  let lastHistoryUpdate = 0;

  function resolveGetJSON(opts) {
    if (opts && typeof opts.getJSON === 'function') return opts.getJSON;
    if (global.SDNApp && global.SDNApp.Monitoring && typeof global.SDNApp.Monitoring.getJSON === 'function') {
      return global.SDNApp.Monitoring.getJSON;
    }
    if (global.SDNApp && global.SDNApp.Utils && typeof global.SDNApp.Utils.getJSON === 'function') {
      return global.SDNApp.Utils.getJSON;
    }
    if (typeof global.getJSON === 'function') return global.getJSON;
    return async (url, o) => {
      const res = await fetch(url, o);
      return await res.json();
    };
  }

  function formatHistoryLine(ev) {
    if (!ev) return '';
    const t = ev.ts ? new Date(ev.ts * 1000).toLocaleString() : '';
    const ty = ev.type || '';
    const src = ev.src || '';
    const reason = ev.reason || '';
    let extra = '';
    try {
      const raw = ev.extra_json;
      if (raw) {
        const x = (typeof raw === 'string') ? JSON.parse(raw) : raw;
        if (x && typeof x === 'object') {
          if (ty === 'lab_build') {
            const n = (x.nodes !== undefined && x.nodes !== null) ? `nodes=${x.nodes}` : '';
            const l = (x.links !== undefined && x.links !== null) ? `links=${x.links}` : '';
            extra = [n, l].filter(Boolean).join(' ');
          } else if (ty === 'scenario') {
            const nm = x.name ? `name=${x.name}` : '';
            const pr = x.proto ? `proto=${String(x.proto).toUpperCase()}` : '';
            const du = x.duration ? `dur=${x.duration}s` : '';
            const cp = (x.capture === true) ? 'pcap=on' : '';
            extra = [nm, pr, du, cp].filter(Boolean).join(' ');
          } else if (ty === 'attack_run') {
            const k = x.kind ? `kind=${x.kind}` : '';
            const prf = x.profile ? `profile=${x.profile}` : '';
            const pr = x.proto ? `proto=${String(x.proto).toUpperCase()}` : '';
            const du = x.duration ? `dur=${x.duration}s` : '';
            const mx = (x.mixed === true) ? 'mixed=on' : '';
            const cp = (x.capture === true) ? 'pcap=on' : '';
            extra = [k, prf, pr, du, mx, cp].filter(Boolean).join(' ');
          }
        }
      }
    } catch (e) {
    }
    return `[${t}] ${ty} ${src} ${reason} ${extra}`.trim();
  }

  async function refreshHistory(force = false, reqSeq = null, task = null, opts = {}) {
    const box = document.getElementById('history-view');
    const msg = document.getElementById('history-msg');
    if (!box) return;
    const now = Date.now();
    if (!force && now - lastHistoryUpdate < 4000) return;
    lastHistoryUpdate = now;
    if (msg) msg.innerText = '';

    const pollTasks = (opts && opts.pollTasks) || global.pollTasks || {};
    const t = task || pollTasks.history;
    const seq = (reqSeq !== null && reqSeq !== undefined) ? reqSeq : (t ? ++t.seq : 1);
    const getJSON = resolveGetJSON(opts);

    try {
      const r = await getJSON('/api/history');
      if (t && seq < t.appliedSeq) return;
      if (t) t.appliedSeq = seq;
      if (!r || r.ok !== true) {
        if (msg) msg.innerText = 'History unavailable';
        return;
      }
      const events = (r.events || []).slice(-120);
      box.textContent = events.map(formatHistoryLine).join('\n');
    } catch (e) {
      if (t && seq < t.appliedSeq) return;
      if (t) t.appliedSeq = seq;
      if (msg) msg.innerText = 'History failed';
    }
  }

  function initHistory(opts = {}) {
    const btn = document.getElementById('btn-history-refresh');
    if (btn) {
      btn.addEventListener('click', async () => {
        await refreshHistory(true, null, null, opts);
      });
    }
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  global.SDNApp = global.SDNApp || {};
  global.SDNApp.Forensics = {
    formatHistoryLine,
    refreshHistory,
    initHistory,
    getLastUpdate: () => lastHistoryUpdate,
  };

  global.formatHistoryLine = formatHistoryLine;
  global.refreshHistory = (force, reqSeq, task) => refreshHistory(force, reqSeq, task);
  global.initHistory = initHistory;

})(typeof window !== 'undefined' ? window : this);
