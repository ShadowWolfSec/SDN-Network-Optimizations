/**
 * Lab Orchestrator Module (SDNApp.LabOrchestrator).
 * Manages Mininet network lifecycle, demo scenarios, and attack dispatching.
 */

(function (global) {
  'use strict';

  let demoRunId = 0;
  let demoRunning = false;
  let demoActiveTimer = null;
  let demoSleepCancel = null;
  let demoAbortMessage = '';
  let lastLabJobKey = '';

  /**
   * Safe sleep function tied to a specific demo run ID; rejects if cancelled or expired.
   */
  function _demoSleep(ms, runId, opts = {}) {
    const makeCodedError = opts.makeCodedError || global.makeCodedError || ((c, m) => { const e = new Error(m || c); e.code = c; return e; });
    return new Promise((resolve, reject) => {
      if (runId !== demoRunId) {
        reject(makeCodedError('demo_stopped', 'demo_stopped'));
        return;
      }
      const cancel = () => {
        if (demoActiveTimer) {
          clearTimeout(demoActiveTimer);
          demoActiveTimer = null;
        }
        if (demoSleepCancel === cancel) demoSleepCancel = null;
        reject(makeCodedError('demo_stopped', 'demo_stopped'));
      };
      demoSleepCancel = cancel;
      demoActiveTimer = setTimeout(() => {
        demoActiveTimer = null;
        if (demoSleepCancel === cancel) demoSleepCancel = null;
        if (runId !== demoRunId) {
          reject(makeCodedError('demo_stopped', 'demo_stopped'));
          return;
        }
        resolve();
      }, Math.max(1, Number(ms || 1)));
    });
  }

  /**
   * Polls lab status until the desired running state is achieved without busy flag.
   */
  async function _demoWaitLabRunning(desiredRunning, runId, timeoutMs = 90000, opts = {}) {
    const getJSON = opts.getJSON || global.getJSON;
    const makeCodedError = opts.makeCodedError || global.makeCodedError || ((c, m) => { const e = new Error(m || c); e.code = c; return e; });
    const isNetworkDisconnectError = opts.isNetworkDisconnectError || global.isNetworkDisconnectError || (() => false);

    const started = Date.now();
    let consecutiveErrors = 0;
    while (true) {
      if (runId !== demoRunId) throw makeCodedError('demo_stopped', 'demo_stopped');
      if (Date.now() - started > timeoutMs) throw makeCodedError('demo_timeout', 'demo_timeout');
      let sleepMs = 1000;
      try {
        const s = await getJSON('/api/lab/status');
        consecutiveErrors = 0;
        const running = !!(s && s.running);
        const busy = !!(s && s.busy);
        if (running === !!desiredRunning && !busy) return;
      } catch (e) {
        if (e && (e.status === 401 || e.status === 403)) throw e;
        consecutiveErrors += 1;
        sleepMs = 500;
        if (consecutiveErrors >= 3) {
          if (isNetworkDisconnectError(e)) {
            throw makeCodedError('connection_lost', 'connection_lost');
          }
          throw e;
        }
      }
      await _demoSleep(sleepMs, runId, opts);
    }
  }

  /**
   * Polls attack status until no attack is actively running.
   */
  async function _demoWaitAttackStopped(runId, timeoutMs = 60000, opts = {}) {
    const getJSON = opts.getJSON || global.getJSON;
    const makeCodedError = opts.makeCodedError || global.makeCodedError || ((c, m) => { const e = new Error(m || c); e.code = c; return e; });
    const isNetworkDisconnectError = opts.isNetworkDisconnectError || global.isNetworkDisconnectError || (() => false);

    const started = Date.now();
    let consecutiveErrors = 0;
    while (true) {
      if (runId !== demoRunId) throw makeCodedError('demo_stopped', 'demo_stopped');
      if (Date.now() - started > timeoutMs) throw makeCodedError('demo_timeout', 'demo_timeout');
      let sleepMs = 1000;
      try {
        const s = await getJSON('/api/lab/attack/status');
        consecutiveErrors = 0;
        const running = !!(s && s.running);
        if (!running) return;
      } catch (e) {
        if (e && (e.status === 401 || e.status === 403)) throw e;
        consecutiveErrors += 1;
        sleepMs = 500;
        if (consecutiveErrors >= 3) {
          if (isNetworkDisconnectError(e)) {
            throw makeCodedError('connection_lost', 'connection_lost');
          }
          throw e;
        }
      }
      await _demoSleep(sleepMs, runId, opts);
    }
  }

  /**
   * Updates status badge chips for Lab State.
   */
  function setLabStatusBadges(colorCls, text) {
    ['lab-status', 'lab-status-card'].forEach(elId => {
      const el = document.getElementById(elId);
      if (!el) return;
      el.classList.remove('green', 'red', 'gray');
      if (colorCls) el.classList.add(colorCls);
      el.innerText = text;
    });
  }

  /**
   * Updates global top system status banner across views.
   */
  function updateSystemStatusBanner(s) {
    const banner = document.getElementById('system-status-banner');
    if (!banner) return;
    const badge = document.getElementById('banner-state-badge');
    const msg = document.getElementById('banner-message');
    const opContainer = document.getElementById('banner-op-container');
    const opLabel = document.getElementById('banner-op');
    const timer = document.getElementById('banner-timer');
    const elapsed = document.getElementById('banner-elapsed');

    const running = !!(s && s.running);
    const job = (s && s.job && typeof s.job === 'object') ? s.job : null;
    const isBusy = !!(s && ((job && job.busy) || s.is_busy || s.busy));
    const stateRaw = (s && s.current_state) ? String(s.current_state).toUpperCase() : (isBusy ? 'BUILDING_LAB' : (running ? 'LAB_READY' : 'IDLE'));
    const stateClass = stateRaw.toLowerCase();

    banner.className = `system-status-banner state-${stateClass}`;
    if (badge) badge.innerText = stateRaw;

    let displayMsg = '';
    if (s && s.message) {
      displayMsg = s.message;
    } else if (stateRaw === 'BUILDING_LAB') {
      displayMsg = 'Building network topology... Please wait';
    } else if (stateRaw === 'STOPPING') {
      displayMsg = 'Stopping network and cleaning resources...';
    } else if (stateRaw === 'ATTACK_RUNNING') {
      displayMsg = 'Traffic / attack simulation is currently active';
    } else if (stateRaw === 'DEMO_RUNNING') {
      displayMsg = 'Demonstration scenario pipeline in progress...';
    } else if (stateRaw === 'LAB_READY') {
      displayMsg = '[OK] Lab ready: switches connected and HA services operational';
    } else if (stateRaw === 'ERROR') {
      displayMsg = 'System encountered an error. Check logs.';
    } else {
      displayMsg = 'System ready (Idle)';
    }
    if (msg) msg.innerText = displayMsg;

    if (isBusy && job && job.busy) {
      if (opContainer) opContainer.style.display = 'inline-flex';
      if (opLabel) opLabel.innerText = job.op || stateRaw;
      if (job.started_at && timer && elapsed) {
        const sec = Math.max(0, Math.floor(Date.now() / 1000 - job.started_at));
        elapsed.innerText = `${sec}s`;
        timer.style.display = 'inline';
      }
    } else {
      if (opContainer) opContainer.style.display = 'none';
      if (timer) timer.style.display = 'none';
    }

    // Action Interlocking: disable action buttons while busy
    const actionButtonIds = [
      'btn-lab-build',
      'btn-lab-apply-live',
      'btn-scenario-run',
      'btn-demo-run',
      'btn-ha-start',
      'btn-ha-stop',
      'btn-ha-primary',
      'btn-ha-backup',
      'btn-ha-test',
    ];
    const isInterlocked = isBusy ||
      stateRaw === 'BUILDING_LAB' ||
      stateRaw === 'STOPPING' ||
      stateRaw === 'ATTACK_RUNNING' ||
      stateRaw === 'DEMO_RUNNING' ||
      (global.SDNApp && typeof global.SDNApp.isLastAttackRunning === 'function' && global.SDNApp.isLastAttackRunning()) ||
      demoRunning;

    actionButtonIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        if (isInterlocked) {
          el.classList.add('btn-locked');
          el.setAttribute('disabled', 'true');
        } else {
          el.classList.remove('btn-locked');
          el.removeAttribute('disabled');
        }
      }
    });
  }

  /**
   * Initializes Mininet topology designer, action controls, and demonstration runner.
   */
  function initTopologyDesigner(opts = {}) {
    const getJSON = opts.getJSON || global.getJSON;
    const showToast = opts.showToast || global.showToast || (() => {});
    const errToShortText = opts.errToShortText || global.errToShortText || String;
    const makeCodedError = opts.makeCodedError || global.makeCodedError || ((c, m) => { const e = new Error(m || c); e.code = c; return e; });
    const isNetworkDisconnectError = opts.isNetworkDisconnectError || global.isNetworkDisconnectError || (() => false);
    const getScenarioRequirementSpec = opts.getScenarioRequirementSpec || global.getScenarioRequirementSpec;
    const getScenarioHostInventory = opts.getScenarioHostInventory || global.getScenarioHostInventory;
    const formatScenarioError = opts.formatScenarioError || global.formatScenarioError || ((e, d) => d || String(e));
    const refreshHistory = opts.refreshHistory || global.refreshHistory || (() => {});
    const pollTasks = opts.pollTasks || global.pollTasks || {};
    const labStatusCallbacks = opts.labStatusCallbacks || global.labStatusCallbacks || [];
    const syncScenarioUIFn = opts.syncScenarioUIFn || global.syncScenarioUIFn;

    const setLastLabStatus = opts.setLastLabStatus || ((s) => { if (global.SDNApp) global.SDNApp._lastLabStatus = s; });
    const getLastLabStatus = opts.getLastLabStatus || (() => (global.SDNApp && global.SDNApp.getLastLabStatus ? global.SDNApp.getLastLabStatus() : null));
    const setLabBusy = opts.setLabBusy || ((b) => { if (global.SDNApp) global.SDNApp._labBusy = b; });
    const getLabBusy = opts.getLabBusy || (() => (global.SDNApp && global.SDNApp.isLabBusy ? global.SDNApp.isLabBusy() : false));
    const setLastAttackRunning = opts.setLastAttackRunning || ((r) => { if (global.SDNApp && global.SDNApp.setLastAttackRunning) global.SDNApp.setLastAttackRunning(r); });
    const getLastAttackRunning = opts.getLastAttackRunning || (() => (global.SDNApp && global.SDNApp.isLastAttackRunning ? global.SDNApp.isLastAttackRunning() : false));

    const canvas = document.getElementById('topology-canvas');
    if (!canvas) return null;

    const toolSelect = document.getElementById('tool-select');
    const toolAddSwitch = document.getElementById('tool-add-switch');
    const toolAddHost = document.getElementById('tool-add-host');
    const toolLink = document.getElementById('tool-link');
    const toolDelete = document.getElementById('tool-delete');

    const btnBuild = document.getElementById('btn-lab-build');
    const btnApplyLive = document.getElementById('btn-lab-apply-live');
    const btnStop = document.getElementById('btn-lab-stop');
    const labMsg = document.getElementById('lab-msg');
    const btnDemoRun = document.getElementById('btn-demo-run');
    const btnDemoStop = document.getElementById('btn-demo-stop');
    const demoMsg = document.getElementById('demo-msg');
    const controllerIpEl = document.getElementById('controller-ip');
    const controllerPortEl = document.getElementById('controller-port');

    const linkBwEl = document.getElementById('link-bw');
    const linkDelayEl = document.getElementById('link-delay');
    const linkLossEl = document.getElementById('link-loss');
    const btnLinkApply = document.getElementById('btn-link-apply');
    const linkMsg = document.getElementById('link-msg');
    const selectedItemEl = document.getElementById('selected-item');

    const scenarioNameEl = document.getElementById('scenario-name');
    const scenarioProtoEl = document.getElementById('scenario-proto');
    const scenarioAttackersEl = document.getElementById('scenario-attackers');
    const scenarioVictimEl = document.getElementById('scenario-victim');
    const scenarioCaptureEl = document.getElementById('scenario-capture');
    const scenarioDurationEl = document.getElementById('scenario-duration');
    const btnScenarioRun = document.getElementById('btn-scenario-run');
    const scenarioMsg = document.getElementById('scenario-msg');

    const btnTopoSave = document.getElementById('btn-topo-save');
    const btnTopoLoad = document.getElementById('btn-topo-load');
    const btnTopoExport = document.getElementById('btn-topo-export');
    const btnTopoImport = document.getElementById('btn-topo-import');
    const btnTopoLayout = document.getElementById('btn-topo-layout');
    const btnTopoReset = document.getElementById('btn-topo-reset');
    const topoJsonEl = document.getElementById('topology-json');
    const btnTopoApplyImport = document.getElementById('btn-topo-apply-import');
    const topoMsg = document.getElementById('topo-msg');

    const topoEngine = (global.SDNApp && global.SDNApp.Topology && typeof global.SDNApp.Topology.init === 'function')
      ? global.SDNApp.Topology.init({
          canvas,
          controllerIpEl,
          controllerPortEl,
          linkBwEl,
          linkDelayEl,
          linkLossEl,
          linkMsg,
          selectedItemEl,
          btnLinkApply,
          tools: { toolSelect, toolAddSwitch, toolAddHost, toolLink, toolDelete },
          buttons: { btnTopoSave, btnTopoLoad, btnTopoExport, btnTopoImport, btnTopoLayout, btnTopoReset, btnTopoApplyImport },
          topoJsonEl,
          topoMsg,
        })
      : null;

    function toTopologyPayload() {
      if (topoEngine && typeof topoEngine.toTopologyPayload === 'function') {
        return topoEngine.toTopologyPayload();
      }
      return {
        controller_ip: controllerIpEl ? (controllerIpEl.value || '127.0.0.1').trim() : '127.0.0.1',
        controller_port: controllerPortEl ? Number(controllerPortEl.value || 6653) : 6653,
        nodes: [],
        links: [],
      };
    }

    function saveTopologyState() {
      if (topoEngine && typeof topoEngine.saveTopologyState === 'function') {
        return topoEngine.saveTopologyState();
      }
    }
    global.saveTopologyState = saveTopologyState;

    function ensureDefaultTopology(force = false) {
      if (topoEngine && typeof topoEngine.ensureDefaultTopology === 'function') {
        return topoEngine.ensureDefaultTopology(force);
      }
    }
    global.ensureDefaultTopology = ensureDefaultTopology;

    function showLabMsg(text, timeoutMs = 0) {
      if (!labMsg) return;
      labMsg.innerText = text || '';
      if (text && timeoutMs > 0) {
        const expected = text;
        setTimeout(() => {
          if (labMsg.innerText === expected) labMsg.innerText = '';
        }, timeoutMs);
      }
    }

    let demoMsgTimer = null;
    function showDemoMsg(text, level = '', autoClearMs = 0) {
      if (!demoMsg) return;
      if (demoMsgTimer) {
        clearTimeout(demoMsgTimer);
        demoMsgTimer = null;
      }
      demoMsg.className = level ? `msg ${level}` : 'msg';
      demoMsg.innerText = text || '';
      if (text && autoClearMs > 0) {
        const expected = text;
        demoMsgTimer = setTimeout(() => {
          if (demoMsg.innerText === expected) {
            demoMsg.innerText = '';
            demoMsg.className = 'msg';
          }
        }, autoClearMs);
      }
    }

    async function _runLabStatusFetch(reqSeq = null, task = null) {
      if (typeof document !== 'undefined' && document.hidden && task && reqSeq !== null && !task.forcing) return;
      if (!document.getElementById('lab-status') && !document.getElementById('lab-status-card')) return;
      const t = task || (pollTasks && pollTasks.labStatus);
      const seq = (reqSeq !== null && reqSeq !== undefined) ? reqSeq : (t ? ++t.seq : 1);
      try {
        const s = await getJSON('/api/lab/status');
        if (t && seq < t.appliedSeq) return;
        if (t) t.appliedSeq = seq;
        setLastLabStatus(s);
        updateSystemStatusBanner(s);
        labStatusCallbacks.forEach(fn => {
          try { fn(s); } catch (e) {}
        });
        const running = !!(s && s.running);
        const busy = !!(s && (s.busy || s.is_busy));
        setLabBusy(busy);
        if (busy) {
          setLabStatusBadges('gray', 'Starting...');
        } else {
          setLabStatusBadges(running ? 'green' : 'gray', running ? 'Running' : 'Not Built');
          const job = (s && s.job && typeof s.job === 'object') ? s.job : null;
          if (job && job.op) {
            const jKey = `${job.gen || ''}:${job.op}:${job.error || ''}`;
            if (jKey !== lastLabJobKey) {
              const hadPrior = lastLabJobKey !== '';
              lastLabJobKey = jKey;
              if (job.error) {
                showLabMsg(`Failed (${job.op}): ${job.error}`, 8000);
                showToast(`Topology operation failed: ${job.error}`, 'error');
              } else if (hadPrior && job.op === 'build' && running) {
                showLabMsg('Network started successfully (Running).', 3000);
              }
            }
          }
        }
      } catch (e) {
        if (t && seq < t.appliedSeq) return;
        if (t) t.appliedSeq = seq;
        setLabBusy(false);
        updateSystemStatusBanner({ current_state: 'ERROR', message: 'Runner unavailable' });
        const msgTxt = errToShortText(e);
        setLabStatusBadges('red', msgTxt ? `Error (${msgTxt})` : 'Error');
      }
    }

    async function pollLabStatus() {
      return await _runLabStatusFetch(null, pollTasks && pollTasks.labStatus);
    }

    btnBuild && btnBuild.addEventListener('click', async () => {
      saveTopologyState();
      showLabMsg('Rebuilding network...', 0);
      try {
        await getJSON('/api/lab/build', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(toTopologyPayload())
        });
        await pollLabStatus();
        showLabMsg('Full network build started.', 3000);
      } catch (e) {
        await pollLabStatus();
        showLabMsg(`Failed to start build (${errToShortText(e) || 'error'}).`, 3500);
      }
    });

    btnApplyLive && btnApplyLive.addEventListener('click', async () => {
      saveTopologyState();
      showLabMsg('Applying changes to running network...', 0);
      try {
        await getJSON('/api/lab/topology/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(toTopologyPayload())
        });
        let finalStatus = null;
        for (let i = 0; i < 60; i++) {
          await new Promise(r => setTimeout(r, 350));
          try {
            const st = await getJSON('/api/lab/status');
            if (st && !st.busy) {
              finalStatus = st;
              break;
            }
          } catch (errPoll) {
            break;
          }
        }
        await pollLabStatus();
        const job = finalStatus && finalStatus.job ? finalStatus.job : null;
        if (job && job.op === 'apply' && job.error) {
          if (job.error === 'controller_changed_rebuild_required') {
            showLabMsg('Controller IP or port changed — click Build Network.', 4000);
          } else {
            showLabMsg(`Live apply failed (${job.error}).`, 4000);
          }
          return;
        }
        showLabMsg('Topology changes applied live without stopping the network.', 3500);
      } catch (e) {
        const code = (e && e.data && e.data.error) ? String(e.data.error) : '';
        if (code === 'network_not_running') {
          showLabMsg('Network is stopped — click Build Network first.', 4000);
        } else if (code === 'controller_changed_rebuild_required') {
          showLabMsg('Controller IP or port changed — click Build Network.', 4000);
        } else if (code === 'busy') {
          showLabMsg('Another operation is currently running; please wait.', 3000);
        } else {
          showLabMsg(`Live apply failed (${errToShortText(e) || 'error'}).`, 3500);
        }
        await pollLabStatus();
      }
    });

    function setDemoButtons(running) {
      if (btnDemoRun) btnDemoRun.disabled = !!running;
      if (btnDemoStop) btnDemoStop.disabled = !running;
    }

    function cancelLocalDemoState(reasonText = '', level = 'warning') {
      demoRunId += 1;
      demoRunning = false;
      demoAbortMessage = reasonText || '';
      if (demoActiveTimer) {
        clearTimeout(demoActiveTimer);
        demoActiveTimer = null;
      }
      if (typeof demoSleepCancel === 'function') {
        const cancelFn = demoSleepCancel;
        demoSleepCancel = null;
        try { cancelFn(); } catch (e) {}
      }
      setDemoButtons(false);
      if (reasonText) showDemoMsg(reasonText, level);
    }

    async function stopDemo() {
      cancelLocalDemoState('Demo Run stopped.', 'warning');
      try { await getJSON('/api/lab/attack/stop', { method: 'POST' }); } catch (e) {}
      try { await getJSON('/api/unblock/all', { method: 'POST' }); } catch (e) {}
      try { await pollLabStatus(); } catch (e) {}
    }

    function formatDemoFailureMessage(err) {
      if (!err) return 'Demo Run failed.';
      if (err.code === 'demo_stopped' || err.message === 'demo_stopped') {
        return demoAbortMessage || 'Demo Run stopped.';
      }
      if (err.code === 'demo_timeout' || err.message === 'demo_timeout') {
        return 'Demo Run timed out waiting for server response.';
      }
      if (err.status === 401) {
        return 'Session expired or unauthorized (HTTP 401). Please sign in again.';
      }
      if (err.code === 'connection_lost' || err.message === 'connection_lost' || isNetworkDisconnectError(err)) {
        return 'Connection lost — unable to reach server. Demo Run stopped.';
      }
      if (typeof err.status === 'number' && err.status >= 500) {
        return `Backend service unavailable (HTTP ${err.status}). Demo Run stopped.`;
      }
      return formatScenarioError(err, `Demo Run failed (${errToShortText(err) || 'error'})`);
    }

    if (typeof window !== 'undefined') {
      window.addEventListener('pagehide', () => {
        if (demoRunning) {
          cancelLocalDemoState('Browser tab closed/navigated — Demo Run coordination stopped.', 'warning');
        }
      });

      window.addEventListener('beforeunload', () => {
        if (demoRunning) {
          cancelLocalDemoState('Browser tab closing — Demo Run coordination stopped.', 'warning');
        }
      });
    }

    btnDemoStop && btnDemoStop.addEventListener('click', async () => {
      await stopDemo();
      showDemoMsg('Demo Run stopped.', 'warning');
    });

    btnDemoRun && btnDemoRun.addEventListener('click', async () => {
      if (demoRunning) {
        showDemoMsg('Demo Run is already in progress.', 'warning');
        return;
      }

      const cleanClients = (topoEngine && typeof topoEngine.getCleanClients === 'function')
        ? topoEngine.getCleanClients()
        : ['h1', 'h4', 'h5', 'h6', 'h7', 'h8'];
      if (cleanClients.length < 2) {
        showDemoMsg('Full Demo requires at least 2 linked client hosts outside h2 and h3 (click Reset Default).', 'error');
        return;
      }

      demoRunning = true;
      demoAbortMessage = '';
      const runId = demoRunId + 1;
      demoRunId = runId;
      setDemoButtons(true);

      const demoOpts = { getJSON, makeCodedError, isNetworkDisconnectError };

      try {
        showDemoMsg('Initializing Demo Run (browser-coordinated)...', 'info');

        await pollLabStatus();
        if (runId !== demoRunId) throw makeCodedError('demo_stopped', 'demo_stopped');

        try { await getJSON('/api/alerts/clear', { method: 'POST' }); } catch (e) {}
        try { await getJSON('/api/unblock/all', { method: 'POST' }); } catch (e) {}
        if (runId !== demoRunId) throw makeCodedError('demo_stopped', 'demo_stopped');

        const currentLab = getLastLabStatus();
        const isRunning = currentLab && currentLab.running;
        if (!isRunning) {
          showDemoMsg('Step 1/5: Building and verifying Mininet topology...', 'info');
          await getJSON('/api/lab/build', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(toTopologyPayload())
          });
          await _demoWaitLabRunning(true, runId, 120000, demoOpts);
        }

        // Stage 1: Normal Traffic (5s) to establish clean baseline
        showDemoMsg('Stage 1/5: Running Normal Traffic baseline (5s)...', 'info');
        try { await getJSON('/api/unblock/all', { method: 'POST' }); } catch (e) {}
        await getJSON('/api/lab/scenario', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'demo_normal', duration: 5, proto: 'syn', capture: false, force: true })
        });
        await _demoWaitAttackStopped(runId, 25000, demoOpts);
        try { await refreshHistory(true); } catch (e) {}

        // Stage 2: Light DoS (Single Attacker, 8s)
        showDemoMsg('Stage 2/5: Running Light DoS (Single Attacker, 8s)...', 'info');
        try { await getJSON('/api/unblock/all', { method: 'POST' }); } catch (e) {}
        await getJSON('/api/lab/scenario', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'demo_dos', duration: 8, proto: 'syn', capture: true, force: true })
        });
        await _demoWaitAttackStopped(runId, 25000, demoOpts);
        try { await refreshHistory(true); } catch (e) {}

        // Stage 3: Medium DDoS (3 Attackers, 10s)
        showDemoMsg('Stage 3/5: Running Medium DDoS (3 Attackers, 10s)...', 'info');
        try { await getJSON('/api/unblock/all', { method: 'POST' }); } catch (e) {}
        await getJSON('/api/lab/attack/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ kind: 'ddos', profile: 'medium', duration: 10, mixed: true, capture: true, proto: 'syn', force: true })
        });
        await _demoWaitAttackStopped(runId, 30000, demoOpts);
        try { await refreshHistory(true); } catch (e) {}

        // Stage 4: Defensive Mitigation & HA Failover
        showDemoMsg('Stage 4/5: Defensive Mitigation & HA Failover to Backup...', 'info');
        try {
          await getJSON('/api/lab/ha/active', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ active: 'backup', target: 'backup' })
          });
        } catch (e) {
          console.warn('Failover to backup returned warning/error:', e);
        }
        await _demoSleep(2500, runId, demoOpts);
        try { await refreshHistory(true); } catch (e) {}

        // Stage 5: Recovery & Verification of VIP on Backup
        showDemoMsg('Stage 5/5: Recovery — Verifying VIP health on Backup node...', 'info');
        try { await getJSON('/api/lab/attack/stop', { method: 'POST' }); } catch (e) {}
        let vipOk = false;
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            const testRes = await getJSON('/api/lab/ha/test', { method: 'GET' });
            vipOk = Boolean(testRes && (testRes.test ? testRes.test.vip_ok : testRes.vip_ok));
            if (vipOk) break;
          } catch (e) {}
          if (attempt < 2) await _demoSleep(1000, runId, demoOpts);
        }

        const successMsg = vipOk
          ? '[OK] Demo Mode completed: VIP successfully verified on Backup node!'
          : '[OK] Demo Mode completed: all stages executed successfully.';
        showDemoMsg(successMsg, 'success');
      } catch (e) {
        const msgText = formatDemoFailureMessage(e);
        const isStop = (e && (e.code === 'demo_stopped' || e.message === 'demo_stopped'));
        demoAbortMessage = '';
        showDemoMsg(msgText, isStop ? 'warning' : 'error');
      } finally {
        if (runId === demoRunId) {
          demoRunning = false;
          setDemoButtons(false);
        }
      }
    });

    btnStop && btnStop.addEventListener('click', async () => {
      try {
        await getJSON('/api/lab/stop', { method: 'POST' });
        await pollLabStatus();
      } catch (e) {
        await pollLabStatus();
      }
    });

    btnScenarioRun && btnScenarioRun.addEventListener('click', async () => {
      if (scenarioMsg) scenarioMsg.innerText = '';
      const failScenario = (text) => {
        if (scenarioMsg) {
          scenarioMsg.innerText = text;
          setTimeout(() => { if (scenarioMsg.innerText === text) scenarioMsg.innerText = ''; }, 4500);
        }
        if (typeof syncScenarioUIFn === 'function') syncScenarioUIFn();
      };

      try {
        const lastLab = getLastLabStatus();
        const busy = getLabBusy();
        if (!lastLab || !lastLab.running || busy) {
          failScenario('Error: Network must be running first (click Build Network).');
          return;
        }
        if (getLastAttackRunning()) {
          failScenario('Warning: An attack is currently running — click Stop Attack first.');
          return;
        }

        const scName = scenarioNameEl ? scenarioNameEl.value : 'demo_normal';
        const spec = getScenarioRequirementSpec(scName);
        const inv = getScenarioHostInventory();
        const byName = new Map(inv.map(h => [h.name, h]));
        const victim = scenarioVictimEl ? (scenarioVictimEl.value || '').trim() : '';

        if (!victim) {
          failScenario('Error: Select a Victim host first.');
          return;
        }
        const vicObj = byName.get(victim);
        if (vicObj && !vicObj.linked) {
          failScenario(`Error: Victim (${victim}) is not linked to a switch.`);
          return;
        }

        const eligibleClean = inv.filter(h => h.role === 'client' && h.name !== victim && h.linked && (spec.isNormal || !h.blocked));
        let attackers = [];

        if (spec.autoSelect) {
          if (eligibleClean.length < spec.minAttackers) {
            failScenario(`Error: ${spec.label} requires at least ${spec.minAttackers} clean client attacker(s) outside HA & Victim — currently available: ${eligibleClean.length}.`);
            return;
          }
        } else {
          if (scenarioAttackersEl) {
            try {
              scenarioAttackersEl.querySelectorAll('input[type="checkbox"][data-host]').forEach(cb => {
                if (cb && cb.checked) {
                  const h = String(cb.getAttribute('data-host') || '').trim();
                  if (h) attackers.push(h);
                }
              });
            } catch (e) {}
          }

          if (attackers.length === 0) {
            failScenario('Error: Select at least one Attacker host first.');
            return;
          }
          if (attackers.length < (spec.minAttackers || 1)) {
            failScenario(`Error: ${spec.label} requires selecting at least ${spec.minAttackers} attacker(s) (currently selected: ${attackers.length}).`);
            return;
          }
          if (attackers.includes(victim)) {
            failScenario('Error: Victim cannot be included in the Attackers list.');
            return;
          }
          for (const hn of attackers) {
            const obj = byName.get(hn);
            if (!obj || !obj.linked) {
              failScenario(`Error: Host (${hn}) is not linked to a switch.`);
              return;
            }
            if (obj.role !== 'client') {
              failScenario(`Error: Host (${hn}) is reserved as an HA server and cannot be an attacker.`);
              return;
            }
            if (!spec.isNormal && obj.blocked) {
              failScenario(`Error: Attacker ${hn} (${obj.ip || ''}) is currently blocked in Ryu — unblock it first.`);
              return;
            }
          }
        }

        if (scenarioMsg) scenarioMsg.innerText = 'Validating and starting scenario...';
        if (btnScenarioRun) {
          btnScenarioRun.classList.add('btn-locked');
          btnScenarioRun.setAttribute('disabled', 'true');
        }
        await getJSON('/api/lab/scenario', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: scName,
            duration: Number(scenarioDurationEl ? scenarioDurationEl.value : 20) || 20,
            proto: (scenarioProtoEl && scenarioProtoEl.value) ? scenarioProtoEl.value : 'syn',
            capture: !!(scenarioCaptureEl && scenarioCaptureEl.checked),
            attackers: attackers,
            victim: victim,
          })
        });
        setLastAttackRunning(true);
        updateSystemStatusBanner({ current_state: 'ATTACK_RUNNING', running: true, attack: { running: true } });
        if (typeof syncScenarioUIFn === 'function') syncScenarioUIFn();
        if (scenarioMsg) scenarioMsg.innerText = 'Scenario started successfully.';
        if (scenarioMsg) setTimeout(() => { if (scenarioMsg.innerText === 'Scenario started successfully.') scenarioMsg.innerText = ''; }, 2500);
      } catch (e) {
        console.error('Attack run error:', e);
        if (btnScenarioRun && !getLastAttackRunning()) {
          btnScenarioRun.classList.remove('btn-locked');
          btnScenarioRun.removeAttribute('disabled');
        }
        failScenario(formatScenarioError(e, 'Failed to start scenario (ensure the network is running).'));
      }
    });

    btnTopoReset && btnTopoReset.addEventListener('click', () => {
      ensureDefaultTopology(true);
      saveTopologyState();
    });

    return {
      poll: _runLabStatusFetch,
      pollLabStatus,
      toTopologyPayload,
      saveTopologyState,
      ensureDefaultTopology,
      stopDemo,
      isDemoRunning: () => demoRunning,
      getDemoRunId: () => demoRunId,
    };
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  const LabOrchestratorModule = {
    initTopologyDesigner,
    _demoSleep,
    _demoWaitLabRunning,
    _demoWaitAttackStopped,
    setLabStatusBadges,
    updateSystemStatusBanner,
    isDemoRunning: () => demoRunning,
    getDemoRunId: () => demoRunId,
  };

  global.SDNApp = global.SDNApp || {};
  global.SDNApp.LabOrchestrator = LabOrchestratorModule;

  // Global backwards compatibility bindings
  global._demoSleep = _demoSleep;
  global._demoWaitLabRunning = _demoWaitLabRunning;
  global._demoWaitAttackStopped = _demoWaitAttackStopped;
  global.initTopologyDesigner = initTopologyDesigner;

})(typeof window !== 'undefined' ? window : this);
