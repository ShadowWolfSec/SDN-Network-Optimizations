/**
 * Command Console & High Availability Module (SDNApp.CmdHA).
 * Handles network diagnostics and HA cluster failover coordination.
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

  function initCmdConsole(opts = {}) {
    const getJSON = resolveGetJSON(opts);
    const selType = document.getElementById('cmd-type');
    const inSrc = document.getElementById('cmd-src');
    const inDst = document.getElementById('cmd-dst');
    const inServer = document.getElementById('cmd-server');
    const inDur = document.getElementById('cmd-duration');
    const inSw = document.getElementById('cmd-switch');
    const btn = document.getElementById('btn-cmd-run');
    const msg = document.getElementById('cmd-msg');
    const out = document.getElementById('cmd-out');

    if (!selType || !btn) return;

    function updateFieldVisibility() {
      const type = (selType.value || '').trim();
      if (type === 'ping') {
        if (inSrc) { inSrc.style.display = ''; inSrc.placeholder = 'Source (e.g., h1 or 10.0.0.1)'; }
        if (inDst) { inDst.style.display = ''; inDst.placeholder = 'Destination (e.g., 10.0.0.2 or h2)'; }
        if (inServer) inServer.style.display = 'none';
        if (inDur) inDur.style.display = 'none';
        if (inSw) inSw.style.display = 'none';
      } else if (type === 'iperf_tcp' || type === 'iperf_udp') {
        if (inSrc) { inSrc.style.display = ''; inSrc.placeholder = 'Client host/IP (e.g., h1 or 10.0.0.1)'; }
        if (inDst) inDst.style.display = 'none';
        if (inServer) { inServer.style.display = ''; inServer.placeholder = 'Server host/IP (e.g., h2 or 10.0.0.2)'; }
        if (inDur) inDur.style.display = '';
        if (inSw) inSw.style.display = 'none';
      } else if (type === 'ovs_dump_flows') {
        if (inSrc) inSrc.style.display = 'none';
        if (inDst) inDst.style.display = 'none';
        if (inServer) inServer.style.display = 'none';
        if (inDur) inDur.style.display = 'none';
        if (inSw) { inSw.style.display = ''; if (!inSw.value) inSw.value = 's1'; }
      }
    }

    selType.addEventListener('change', updateFieldVisibility);
    updateFieldVisibility();

    btn.addEventListener('click', async () => {
      if (msg) { msg.innerText = ''; msg.className = 'msg'; }
      if (out) out.textContent = '';
      const type = (selType.value || '').trim();
      const src = (inSrc && inSrc.value) ? inSrc.value.trim() : '';
      const dst = (inDst && inDst.value) ? inDst.value.trim() : '';
      const server = (inServer && inServer.value) ? inServer.value.trim() : '';
      const sw = (inSw && inSw.value) ? inSw.value.trim() : '';
      const duration = inDur ? Number(inDur.value || 5) : 5;

      const payload = { type };
      if (type === 'ping') {
        if (!dst) {
          if (msg) {
            msg.innerText = 'Please specify a destination IP or host (e.g. 10.0.0.2 or h2).';
            msg.className = 'msg warn';
          }
          if (inDst) inDst.focus();
          return;
        }
        payload.src = src || 'h1';
        payload.dst = dst;
        payload.count = 4;
      } else if (type === 'iperf_tcp' || type === 'iperf_udp') {
        payload.client = src || 'h1';
        payload.server = server || 'h2';
        payload.duration = Number.isFinite(duration) && duration > 0 ? duration : 5;
      } else if (type === 'ovs_dump_flows') {
        payload.switch = sw || 's1';
      }

      btn.disabled = true;
      const origText = btn.innerText;
      btn.innerText = 'Running...';

      try {
        const r = await getJSON('/api/lab/cmd/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (msg) {
          if (r.ok) {
            if (r.returncode !== undefined && r.returncode !== 0) {
              msg.innerText = `Completed with errors (Exit code ${r.returncode})`;
              msg.className = 'msg warn';
            } else {
              msg.innerText = 'Success (OK)';
              msg.className = 'msg success';
            }
          } else {
            msg.innerText = r.error || 'Error';
            msg.className = 'msg error';
          }
        }
        if (out) out.textContent = r.output || r.error || '';
      } catch (e) {
        const errData = e.data || e.bodyJson || {};
        const errCode = String(errData.error || e.message || '').trim();
        let displayMsg = 'Command failed';
        if (errCode === 'network_not_built') {
          displayMsg = 'Lab network is not running. Please start the topology first from Lab tab.';
        } else if (errCode === 'missing_src_or_dst' || errCode === 'src_not_found') {
          displayMsg = 'Source host not found. Please enter a valid host (e.g. h1 or 10.0.0.1).';
        } else if (errCode === 'missing_client_or_server' || errCode === 'client_or_server_not_found') {
          displayMsg = 'Client/Server host not found (e.g. h1 / h2 or 10.0.0.1 / 10.0.0.2).';
        } else if (errCode === 'client_must_differ_from_server') {
          displayMsg = 'Client and Server must be different hosts.';
        } else if (errCode === 'switch_not_found' || errCode === 'missing_switch') {
          displayMsg = 'Switch not found. Please enter a valid switch name (e.g. s1).';
        } else if (errCode === 'service_unavailable' || e.status === 502 || e.status === 503) {
          displayMsg = 'Mininet Runner service is offline. Please check runner status.';
        } else if (errData.message) {
          displayMsg = errData.message;
        } else if (errCode) {
          displayMsg = errCode;
        }
        if (msg) {
          msg.innerText = displayMsg;
          msg.className = 'msg error';
        }
        if (out) out.textContent = errData.output || errData.message || '';
      } finally {
        btn.disabled = false;
        btn.innerText = origText;
      }
    });
  }

  function initHaDemo(opts = {}) {
    const getJSON = resolveGetJSON(opts);
    const isLabBusy = typeof opts.isLabBusy === 'function'
      ? opts.isLabBusy
      : () => (global.SDNApp && global.SDNApp.Monitoring && typeof global.SDNApp.Monitoring.isLabBusy === 'function' ? global.SDNApp.Monitoring.isLabBusy() : false);
    const registerPollTask = typeof opts.registerPollTask === 'function'
      ? opts.registerPollTask
      : (global.SDNApp && global.SDNApp.Monitoring && typeof global.SDNApp.Monitoring.registerPollTask === 'function' ? global.SDNApp.Monitoring.registerPollTask : global.registerPollTask);
    const pollTasks = opts.pollTasks || global.pollTasks || {};

    const elActive = document.getElementById('ha-active');
    const elVip = document.getElementById('ha-vip');
    const elHealth = document.getElementById('ha-health');
    const msg = document.getElementById('ha-msg');
    const btnPrimary = document.getElementById('btn-ha-primary');
    const btnBackup = document.getElementById('btn-ha-backup');
    const btnStart = document.getElementById('btn-ha-start');
    const btnStop = document.getElementById('btn-ha-stop');
    const btnTest = document.getElementById('btn-ha-test');

    if (!elActive && !elVip) return;

    async function poll(reqSeq = null, task = null) {
      if (isLabBusy()) return;
      if (document.hidden && (!task || reqSeq === null || !task.forcing)) return;
      const t = task || pollTasks.ha;
      const seq = (reqSeq !== null && reqSeq !== undefined) ? reqSeq : (t ? ++t.seq : 1);
      try {
        const s = await getJSON('/api/lab/ha/status');
        if (t && seq < t.appliedSeq) return;
        if (t) t.appliedSeq = seq;
        const ha = (s && s.ha) ? s.ha : {};
        const vip = ha.vip_ip || '-';
        const active = ha.active || '-';
        const activeHost = (s && s.active_host) ? String(s.active_host) : '';
        const lastTest = (s && s.last_test) ? s.last_test : null;
        const vipKnown = !!lastTest;
        const vipOk = vipKnown && (lastTest.vip_ok === true);
        if (elVip) elVip.innerText = `VIP: ${vip}`;
        if (elActive) {
          elActive.classList.remove('green', 'red', 'gray');
          elActive.classList.add(active === 'primary' ? 'green' : (active === 'backup' ? 'red' : 'gray'));
          elActive.innerText = activeHost ? `HA: ${active} (${activeHost})` : `HA: ${active}`;
        }
        if (elHealth) {
          elHealth.classList.remove('green', 'red', 'gray');
          elHealth.classList.add(!vipKnown ? 'gray' : (vipOk ? 'green' : 'red'));
          elHealth.innerText = !vipKnown ? 'VIP: -' : (vipOk ? 'VIP: UP' : 'VIP: DOWN');
        }
      } catch (e) {
      }
    }

    async function setActive(active) {
      if (msg) msg.innerText = '';
      try {
        await getJSON('/api/lab/ha/active', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ active })
        });
        if (msg) msg.innerText = `Switched to ${active}`;
        if (msg) setTimeout(() => { if (msg.innerText === `Switched to ${active}`) msg.innerText = ''; }, 2000);
        poll();
      } catch (e) {
        if (msg) msg.innerText = 'Failover failed (check Lab topology: need 2 servers)';
        if (msg) setTimeout(() => { if (msg.innerText === 'Failover failed (check Lab topology: need 2 servers)') msg.innerText = ''; }, 2500);
      }
    }

    if (btnPrimary) btnPrimary.addEventListener('click', () => setActive('primary'));
    if (btnBackup) btnBackup.addEventListener('click', () => setActive('backup'));

    if (btnStart) btnStart.addEventListener('click', async () => {
      if (msg) msg.innerText = '';
      try {
        await getJSON('/api/lab/ha/service/start', { method: 'POST' });
        if (msg) msg.innerText = 'Service started';
        if (msg) setTimeout(() => { if (msg.innerText === 'Service started') msg.innerText = ''; }, 2000);
      } catch (e) {
        if (msg) msg.innerText = 'Service start failed';
        if (msg) setTimeout(() => { if (msg.innerText === 'Service start failed') msg.innerText = ''; }, 2000);
      }
      poll();
    });

    if (btnStop) btnStop.addEventListener('click', async () => {
      if (msg) msg.innerText = '';
      try {
        await getJSON('/api/lab/ha/service/stop', { method: 'POST' });
        if (msg) msg.innerText = 'Service stopped';
        if (msg) setTimeout(() => { if (msg.innerText === 'Service stopped') msg.innerText = ''; }, 2000);
      } catch (e) {
        if (msg) msg.innerText = 'Service stop failed';
        if (msg) setTimeout(() => { if (msg.innerText === 'Service stop failed') msg.innerText = ''; }, 2000);
      }
      poll();
    });

    if (btnTest) btnTest.addEventListener('click', async () => {
      if (msg) msg.innerText = '';
      try {
        const r = await getJSON('/api/lab/ha/test');
        const resp = (r && r.response) ? r.response : '';
        if (msg) msg.innerText = `Test: ${resp}`;
      } catch (e) {
        if (msg) msg.innerText = 'VIP test failed (start service + build lab)';
        if (msg) setTimeout(() => { if (msg.innerText === 'VIP test failed (start service + build lab)') msg.innerText = ''; }, 2500);
      }
    });

    if (opts.registerPoll && typeof registerPollTask === 'function') {
      registerPollTask('ha', {
        intervalMs: 2000,
        tabs: ['lab'],
        bootstrapOnce: true,
        run: (reqSeq, task) => poll(reqSeq, task),
      });
    }

    return { poll, setActive };
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  global.SDNApp = global.SDNApp || {};
  global.SDNApp.CmdHA = {
    initCmdConsole,
    initHaDemo,
  };

  global.initCmdConsole = initCmdConsole;
  global.initHaDemo = initHaDemo;

})(typeof window !== 'undefined' ? window : this);
