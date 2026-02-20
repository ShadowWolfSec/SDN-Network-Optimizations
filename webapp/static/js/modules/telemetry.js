/**
 * Telemetry & Status Badges Module (SDNApp.Telemetry).
 * Handles host metrics, process health badges, and flow counters.
 */

(function (global) {
  'use strict';

  // Resolve utility helpers safely from SDNApp.Utils or global
  function getUtils() {
    return (global.SDNApp && global.SDNApp.Utils) || {};
  }

  function fmtNum(val, dec) {
    if (dec === undefined) dec = 0;
    const utils = getUtils();
    if (typeof utils.fmtNum === 'function') return utils.fmtNum(val, dec);
    if (typeof global.fmtNum === 'function') return global.fmtNum(val, dec);
    const n = Number(val);
    return Number.isFinite(n) ? n.toFixed(dec) : '-';
  }

  function formatGlancesFailureReason(metrics) {
    const utils = getUtils();
    if (typeof utils.formatGlancesFailureReason === 'function') {
      return utils.formatGlancesFailureReason(metrics);
    }
    if (typeof global.formatGlancesFailureReason === 'function') {
      return global.formatGlancesFailureReason(metrics);
    }
    return (metrics && metrics.error) || 'degraded';
  }

  function updateFlowSummary(flows) {
    const elTotal = document.getElementById('flows-total');
    const elDrop = document.getElementById('flows-drop');
    if (!elTotal && !elDrop) return;

    const obj = (flows && typeof flows === 'object') ? flows : {};
    let total = 0;
    let drop = 0;
    for (const k in obj) {
      if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
      const s = obj[k] || {};
      const t = Number(s.total_flows);
      const d = Number(s.drop_flows);
      if (Number.isFinite(t)) total += t;
      if (Number.isFinite(d)) drop += d;
    }
    if (elTotal) elTotal.innerText = total || 0;
    if (elDrop) elDrop.innerText = drop || 0;
  }

  function renderVmValues(src) {
    const elCpu = document.getElementById('vm-cpu');
    const elMem = document.getElementById('vm-mem');
    const elLoad = document.getElementById('vm-load');
    const elDisk = document.getElementById('vm-disk');
    const elNet = document.getElementById('vm-net');
    if (!elCpu && !elMem && !elLoad && !elDisk && !elNet) return;

    if (!src) {
      if (elCpu) elCpu.innerText = '-';
      if (elMem) elMem.innerText = '-';
      if (elLoad) elLoad.innerText = '-';
      if (elDisk) elDisk.innerText = '-';
      if (elNet) elNet.innerText = 'Net: -';
      return;
    }

    if (elCpu) elCpu.innerText = fmtNum(src.cpu_percent, 1);
    if (elMem) elMem.innerText = fmtNum(src.mem_percent, 1);
    if (elLoad) elLoad.innerText = fmtNum(src.load && src.load.min1, 2);
    if (elDisk) {
      const p = (src.disk && src.disk.percent !== null && src.disk.percent !== undefined) ? Number(src.disk.percent) : null;
      elDisk.innerText = (p === null || !Number.isFinite(p)) ? '-' : p.toFixed(1);
    }
    if (elNet) {
      const rx = src.network ? src.network.rx_rate : null;
      const tx = src.network ? src.network.tx_rate : null;
      elNet.innerText = `Net: rx ${fmtNum(rx, 0)}/s tx ${fmtNum(tx, 0)}/s`;
    }
  }

  function updateVmMetrics(vm) {
    const elCpu = document.getElementById('vm-cpu');
    const elMem = document.getElementById('vm-mem');
    const elLoad = document.getElementById('vm-load');
    const elDisk = document.getElementById('vm-disk');
    const elNet = document.getElementById('vm-net');
    const elMsg = document.getElementById('vm-msg');

    if (!elCpu && !elMem && !elLoad && !elDisk && !elNet) return;
    if (vm && vm.ok === true) {
      renderVmValues(vm);
      if (elMsg) {
        const ageVal = (vm.age_sec !== undefined && vm.age_sec !== null && Number.isFinite(Number(vm.age_sec)))
          ? Number(vm.age_sec) : null;
        const stateLabel = vm.service_state === 'half_open' ? 'Recovering' : (vm.cached ? 'Cached' : 'Live');
        const ageTxt = ageVal !== null ? ` (${ageVal.toFixed(1)}s ago)` : '';
        elMsg.className = 'msg';
        elMsg.dataset.source = 'vm';
        elMsg.innerText = `Status: ${stateLabel}${ageTxt}`;
      }
      return;
    }

    if (vm && vm.stale_available && vm.last_good && vm.last_good.ok === true) {
      renderVmValues(vm.last_good);
      if (elMsg) {
        const age = (vm.age_sec !== undefined && vm.age_sec !== null) ? `${Math.round(Number(vm.age_sec))}s ago` : 'cached';
        elMsg.className = 'msg warning';
        elMsg.dataset.source = 'vm-degraded';
        elMsg.innerText = `Stale metrics (${age}) — Glances degraded (${formatGlancesFailureReason(vm)})`;
      }
      return;
    }

    renderVmValues(null);
    if (elMsg) {
      elMsg.className = 'msg error';
      elMsg.dataset.source = 'vm-degraded';
      elMsg.innerText = `VM metrics unavailable (${formatGlancesFailureReason(vm)})`;
    }
  }

  function updateStatusBadge(elementId, status) {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    el.classList.remove('unknown', 'healthy', 'unhealthy');
    
    if (status === true || status === 'healthy' || status === 'running') {
      el.classList.add('healthy');
      el.textContent = 'Healthy';
    } else if (status === false || status === 'unhealthy' || status === 'stopped') {
      el.classList.add('unhealthy');
      el.textContent = 'Unhealthy';
    } else {
      el.classList.add('unknown');
      el.textContent = 'Unknown';
    }
  }

  function renderProcValues(src) {
    const ryuCpu = document.getElementById('proc-ryu-cpu');
    const ryuMem = document.getElementById('proc-ryu-mem');
    const ryuTh = document.getElementById('proc-ryu-th');
    const ovsCpu = document.getElementById('proc-ovs-cpu');
    const ovsMem = document.getElementById('proc-ovs-mem');
    const ovsN = document.getElementById('proc-ovs-n');
    if (!ryuCpu && !ovsCpu) return;

    if (!src) {
      if (ryuCpu) ryuCpu.innerText = '-';
      if (ryuMem) ryuMem.innerText = '-';
      if (ryuTh) ryuTh.innerText = '-';
      if (ovsCpu) ovsCpu.innerText = '-';
      if (ovsMem) ovsMem.innerText = '-';
      if (ovsN) ovsN.innerText = '-';
      return;
    }

    const ryu = src.ryu || {};
    const ovs = src.ovs || {};
    if (ryuCpu) ryuCpu.innerText = fmtNum(ryu.cpu_percent, 2);
    if (ryuMem) ryuMem.innerText = fmtNum(ryu.mem_mb, 1);
    if (ryuTh) ryuTh.innerText = (ryu.threads !== undefined && ryu.threads !== null) ? String(ryu.threads) : '-';
    if (ovsCpu) ovsCpu.innerText = fmtNum(ovs.cpu_percent, 2);
    if (ovsMem) ovsMem.innerText = fmtNum(ovs.mem_mb, 1);
    if (ovsN) ovsN.innerText = (ovs.count !== undefined && ovs.count !== null) ? String(ovs.count) : '-';
  }

  function updateProcMetrics(p) {
    const ryuCpu = document.getElementById('proc-ryu-cpu');
    const ovsCpu = document.getElementById('proc-ovs-cpu');
    const elMsg = document.getElementById('vm-msg');
    if (!ryuCpu && !ovsCpu) return;

    if (p && p.ok === true) {
      renderProcValues(p);
      if (elMsg && elMsg.dataset.source === 'proc') {
        elMsg.className = 'msg';
        elMsg.dataset.source = '';
        elMsg.innerText = '';
      }
      return;
    }

    if (p && p.stale_available && p.last_good && p.last_good.ok === true) {
      renderProcValues(p.last_good);
      if (elMsg && elMsg.dataset.source !== 'vm-degraded') {
        const age = (p.age_sec !== undefined && p.age_sec !== null) ? `${Math.round(Number(p.age_sec))}s ago` : 'cached';
        elMsg.className = 'msg warning';
        elMsg.dataset.source = 'proc';
        elMsg.innerText = `Stale process metrics (${age}) — Glances degraded (${formatGlancesFailureReason(p)})`;
      }
      return;
    }

    renderProcValues(null);
    if (elMsg && elMsg.dataset.source !== 'vm-degraded') {
      elMsg.className = 'msg error';
      elMsg.dataset.source = 'proc';
      elMsg.innerText = `Process metrics unavailable (${formatGlancesFailureReason(p)})`;
    }
  }

  function renderDetails(m, flows) {
    const flowPre = document.getElementById('flow-stats');
    if (flowPre && flows) {
      flowPre.textContent = JSON.stringify(flows, null, 2);
    }
    const blockedPre = document.getElementById('blocked-info');
    if (blockedPre && m && m.blocked_info) {
      blockedPre.textContent = JSON.stringify(m.blocked_info, null, 2);
    }
    const lastPktsPre = document.getElementById('last-packets');
    if (lastPktsPre && m && m.last_packets) {
      lastPktsPre.textContent = JSON.stringify(m.last_packets.slice(-20), null, 2);
    }
    const portsPre = document.getElementById('port-stats');
    if (portsPre && m && m.port_stats) {
      portsPre.textContent = JSON.stringify(m.port_stats, null, 2);
    }
    const macTablePre = document.getElementById('mac-table');
    if (macTablePre && m && m.mac_table) {
      macTablePre.textContent = JSON.stringify(m.mac_table, null, 2);
    }
  }

  function setStatus(ok) {
    const el = document.getElementById('ryu-status');
    if (!el) return;
    updateStatusBadge('ryu-status', ok ? 'healthy' : 'unhealthy');
  }

  // ============================================
  // Export to SDNApp.Telemetry & Window Global
  // ============================================
  const Telemetry = {
    updateFlowSummary,
    renderVmValues,
    updateVmMetrics,
    updateStatusBadge,
    renderProcValues,
    updateProcMetrics,
    renderDetails,
    setStatus,
  };

  global.SDNApp = global.SDNApp || {};
  global.SDNApp.Telemetry = Telemetry;

  // Window global backwards compatibility
  global.updateFlowSummary = updateFlowSummary;
  global.renderVmValues = renderVmValues;
  global.updateVmMetrics = updateVmMetrics;
  global.updateStatusBadge = updateStatusBadge;
  global.renderProcValues = renderProcValues;
  global.updateProcMetrics = updateProcMetrics;
  global.renderDetails = renderDetails;
  global.setStatus = setStatus;

})(typeof window !== 'undefined' ? window : this);
