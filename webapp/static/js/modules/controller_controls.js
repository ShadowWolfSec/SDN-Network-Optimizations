/**
 * Controller Controls Module (SDNApp.Controller).
 * Manages Ryu controller lifecycle and status indicators.
 */

(function (global) {
  'use strict';

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

  function resolveShowToast(opts) {
    if (opts && typeof opts.showToast === 'function') return opts.showToast;
    if (global.SDNApp && global.SDNApp.Utils && typeof global.SDNApp.Utils.showToast === 'function') {
      return global.SDNApp.Utils.showToast;
    }
    if (typeof global.showToast === 'function') return global.showToast;
    return () => {};
  }

  function resolveErrToShortText(opts) {
    if (opts && typeof opts.errToShortText === 'function') return opts.errToShortText;
    if (global.SDNApp && global.SDNApp.Utils && typeof global.SDNApp.Utils.errToShortText === 'function') {
      return global.SDNApp.Utils.errToShortText;
    }
    if (typeof global.errToShortText === 'function') return global.errToShortText;
    return (e) => (e && e.message) || 'error';
  }

  function initControllerControls(opts = {}) {
    const getJSON = resolveGetJSON(opts);
    const showToast = resolveShowToast(opts);
    const errToShortText = resolveErrToShortText(opts);
    const pollTasks = (opts && opts.pollTasks) || global.pollTasks || {};

    const statusEl = document.getElementById('controller-status');
    const logEl = document.getElementById('controller-log');
    const btnStart = document.getElementById('btn-controller-start');
    const btnStop = document.getElementById('btn-controller-stop');
    const btnRestartNoLearning = document.getElementById('btn-controller-restart-no-learning');
    const btnFlowsClear = document.getElementById('btn-flows-clear');
    const learningToggle = document.getElementById('learning-toggle');
    const learningStatus = document.getElementById('learning-status');

    async function poll(reqSeq = null, task = null) {
      if (document.hidden && task && reqSeq !== null && !task.forcing) return;
      const t = task || pollTasks.controller;
      const seq = (reqSeq !== null && reqSeq !== undefined) ? reqSeq : (t ? ++t.seq : 1);
      try {
        const s = await getJSON('/api/controller/status');
        if (t && seq < t.appliedSeq) return;
        if (t) t.appliedSeq = seq;
        const running = !!s.running;
        const overall = s.overall_state || (running ? 'running' : 'stopped');
        if (statusEl) {
          statusEl.classList.remove('green', 'red', 'gray', 'yellow');
          if (overall === 'ready') statusEl.classList.add('green');
          else if (overall === 'degraded' || overall === 'starting') statusEl.classList.add('yellow');
          else if (overall === 'uncertain_eperm') statusEl.classList.add('red');
          else statusEl.classList.add(running ? 'green' : 'gray');
          statusEl.innerText = running ? `${overall.toUpperCase()} (PID ${s.pid})` : (overall === 'uncertain_eperm' ? 'Uncertain (EPERM)' : 'Stopped');
        }

        // Update 4-stage decoupled readiness indicators
        const r = s.readiness || {};
        const stProc = document.getElementById('stage-process');
        const stRest = document.getElementById('stage-rest');
        const stOfp = document.getElementById('stage-ofp');
        const stDp = document.getElementById('stage-datapath');

        if (stProc) {
          stProc.innerText = s.process_verified ? 'Verified' : (running ? 'Unverified' : 'Stopped');
          stProc.className = s.process_verified ? 'badge badge-success' : (running ? 'badge badge-warning' : 'badge badge-secondary');
        }
        if (stRest) {
          stRest.innerText = r.rest_ready ? 'Ready' : (running ? 'Down' : 'Inactive');
          stRest.className = r.rest_ready ? 'badge badge-success' : (running ? 'badge badge-danger' : 'badge badge-secondary');
        }
        if (stOfp) {
          stOfp.innerText = r.openflow_listener_ready ? 'Listening' : (running ? 'Closed' : 'Inactive');
          stOfp.className = r.openflow_listener_ready ? 'badge badge-success' : (running ? 'badge badge-danger' : 'badge badge-secondary');
        }
        if (stDp) {
          const dpCount = r.datapaths_count || (r.datapaths ? r.datapaths.length : 0);
          stDp.innerText = r.datapath_ready ? `Active (${dpCount})` : '0 Switches';
          stDp.className = r.datapath_ready ? 'badge badge-success' : (running ? 'badge badge-warning' : 'badge badge-secondary');
        }

        // Backend safety enforcement: disable stop/restart if process identity cannot be verified
        if (btnStop) {
          btnStop.disabled = running && !s.process_verified;
          btnStop.title = (running && !s.process_verified) ? 'Action disabled: Process identity cannot be verified (protected from signaling host processes)' : '';
        }
        if (btnRestartNoLearning) {
          btnRestartNoLearning.disabled = running && !s.process_verified;
        }

        if (logEl) logEl.textContent = s.log_tail || s.log || '';
      } catch (e) {
        if (t && seq < t.appliedSeq) return;
        if (t) t.appliedSeq = seq;
        if (statusEl) {
          statusEl.classList.remove('green', 'red', 'gray', 'yellow');
          statusEl.classList.add('red');
          statusEl.innerText = 'Error';
        }
      }
    }

    if (btnStart) {
      btnStart.addEventListener('click', async () => {
        try {
          await getJSON('/api/controller/start', { method: 'POST' });
        } catch (e) {
          showToast(`Failed to start controller (${errToShortText(e) || 'error'})`, 'error');
        }
        poll();
      });
    }

    if (btnStop) {
      btnStop.addEventListener('click', async () => {
        try {
          await getJSON('/api/controller/stop', { method: 'POST' });
        } catch (e) {
          showToast(`Failed to stop controller (${errToShortText(e) || 'error'})`, 'error');
        }
        poll();
      });
    }

    if (btnRestartNoLearning) {
      btnRestartNoLearning.addEventListener('click', async () => {
        try {
          await getJSON('/api/controller/stop', { method: 'POST' });
          for (let i = 0; i < 8; i++) {
            await new Promise(r => setTimeout(r, 300));
            try {
              const st = await getJSON('/api/controller/status');
              if (st && !st.running) break;
            } catch (errPoll) {
              break;
            }
          }
          await getJSON('/api/controller/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ learning_enabled: false })
          });
          if (learningToggle) learningToggle.checked = false;
          if (learningStatus) {
            learningStatus.classList.remove('green', 'red', 'gray');
            learningStatus.classList.add('gray');
            learningStatus.innerText = 'OFF';
          }
          try {
            await getJSON('/api/config', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ learning_enabled: false })
            });
          } catch (errCfg) {}
          showToast('Controller restarted with Learning Mode OFF.', 'success');
          poll();
        } catch (e) {
          console.error('Failed to restart controller:', e);
          showToast(`Failed to restart controller (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    if (btnFlowsClear) {
      btnFlowsClear.addEventListener('click', async () => {
        if (!window.confirm('Clear all OpenFlow switch rules? Base connectivity flows will be restored automatically.')) {
          return;
        }
        try {
          await getJSON('/api/flows/clear', { method: 'POST' });
          showToast('OpenFlow rules cleared and base flows restored.', 'success');
        } catch (e) {
          console.error('Failed to clear flows:', e);
          showToast(`Failed to clear flows (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    if (learningToggle) {
      learningToggle.addEventListener('change', async () => {
        try {
          await getJSON('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ learning_enabled: learningToggle.checked })
          });
        } catch (e) {
          console.error('Failed to update learning mode:', e);
        }
      });
    }

    return { poll };
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  global.SDNApp = global.SDNApp || {};
  global.SDNApp.Controller = {
    initControllerControls,
  };

  global.initControllerControls = initControllerControls;

})(typeof window !== 'undefined' ? window : this);
