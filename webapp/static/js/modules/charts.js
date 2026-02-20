/**
 * Charts & Telemetry Visualization Module (SDNApp.Charts).
 * Encapsulates Chart.js instances and live traffic monitors.
 */

(function (global) {
  'use strict';

  // Chart instances
  let chartPps = null;
  let chartSyn = null;
  let chartUdp = null;
  let chartLive = null;
  let lastLiveUpdate = 0;

  // Chart dataset states
  const chartData = {
    labels: [],
    datasets: [{
      label: 'pps',
      data: [],
      borderColor: '#3a6fff',
      backgroundColor: 'rgba(58,111,255,0.25)'
    }]
  };

  const chartDataSyn = {
    labels: [],
    datasets: [{
      label: 'syn pps',
      data: [],
      borderColor: '#ff7a3a',
      backgroundColor: 'rgba(255,122,58,0.25)'
    }]
  };

  const chartDataUdp = {
    labels: [],
    datasets: [{
      label: 'udp pps',
      data: [],
      borderColor: '#3aff7a',
      backgroundColor: 'rgba(58,255,122,0.25)'
    }]
  };

  const chartDataLive = {
    labels: [],
    datasets: [
      {
        label: 'Live Traffic Rate (pps)',
        data: [],
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.12)',
        tension: 0.25,
        fill: true,
        pointRadius: 0
      },
      {
        label: 'Threshold',
        data: [],
        borderColor: '#f59e0b',
        borderDash: [6, 4],
        tension: 0,
        fill: false,
        pointRadius: 0
      }
    ]
  };

  /**
   * Sort and return the top 7 talkers from an IP rate map.
   */
  function topTalkersFromRates(rates) {
    const items = [];
    for (const k in rates) {
      if (!Object.prototype.hasOwnProperty.call(rates, k)) continue;
      if (k.startsWith('ip:')) {
        items.push({ key: k.substring(3), val: rates[k] });
      }
    }
    items.sort((a, b) => b.val - a.val);
    return items.slice(0, 7);
  }

  /**
   * Sort and return top 7 IP talkers from raw IP-to-rate map.
   */
  function topTalkersFromIPRates(rates) {
    const items = [];
    for (const k in rates) {
      if (!Object.prototype.hasOwnProperty.call(rates, k)) continue;
      items.push({ key: k, val: rates[k] });
    }
    items.sort((a, b) => b.val - a.val);
    return items.slice(0, 7);
  }

  /**
   * Aggregate total packet-per-second across all rate entries.
   */
  function aggregatePps(m) {
    const rates = (m && m.rates) ? m.rates : {};
    let sum = 0;
    for (const k in rates) {
      if (!Object.prototype.hasOwnProperty.call(rates, k)) continue;
      const v = Number(rates[k]);
      if (!Number.isFinite(v)) continue;
      sum += v;
    }
    return sum;
  }

  /**
   * Initialize Chart.js instances for PPS, SYN flood, UDP flood, and Live Monitor.
   */
  function setupChart() {
    const ChartCtor = (typeof Chart !== 'undefined' ? Chart : (global && global.Chart));
    if (!ChartCtor) {
      chartPps = null;
      chartSyn = null;
      chartUdp = null;
      chartLive = null;
      syncGlobalInstances();
      return;
    }

    const elPps = document.getElementById('chart-pps');
    if (elPps && elPps.getContext) {
      const ctx = elPps.getContext('2d');
      chartPps = new ChartCtor(ctx, {
        type: 'bar',
        data: chartData,
        options: {
          responsive: true,
          plugins: {
            legend: { display: false },
          },
          scales: {
            x: { ticks: { color: '#9fb3c8' } },
            y: { ticks: { color: '#9fb3c8' }, beginAtZero: true }
          }
        }
      });
    }


    const ctxSyn = document.getElementById('chart-syn');
    if (ctxSyn && ctxSyn.getContext) {
      chartSyn = new ChartCtor(ctxSyn.getContext('2d'), {
        type: 'bar',
        data: chartDataSyn,
        options: {
          responsive: true,
          plugins: {
            legend: { display: false },
            title: {
              display: true,
              text: 'SYN Flood Detection',
              color: '#9fb3c8'
            }
          },
          scales: { x: { ticks: { color: '#9fb3c8' } }, y: { ticks: { color: '#9fb3c8' }, beginAtZero: true } }
        }
      });
    }

    const ctxUdp = document.getElementById('chart-udp');
    if (ctxUdp && ctxUdp.getContext) {
      chartUdp = new ChartCtor(ctxUdp.getContext('2d'), {
        type: 'bar',
        data: chartDataUdp,
        options: {
          responsive: true,
          plugins: {
            legend: { display: false },
            title: {
              display: true,
              text: 'UDP Flood Detection',
              color: '#9fb3c8'
            }
          },
          scales: { x: { ticks: { color: '#9fb3c8' } }, y: { ticks: { color: '#9fb3c8' }, beginAtZero: true } }
        }
      });
    }

    const ctxLive = document.getElementById('chart-live');
    if (ctxLive && ctxLive.getContext) {
      chartLive = new ChartCtor(ctxLive.getContext('2d'), {
        type: 'line',
        data: chartDataLive,
        options: {
          responsive: true,
          plugins: {
            legend: { labels: { color: '#9fb3c8' } },
            title: {
              display: true,
              text: 'Live Traffic Rate',
              color: '#9fb3c8'
            }
          },
          scales: {
            x: { ticks: { color: '#9fb3c8' } },
            y: { ticks: { color: '#9fb3c8' }, beginAtZero: true }
          }
        }
      });
    }

    syncGlobalInstances();
  }

  /**
   * Update PPS, SYN, and UDP bar charts with new telemetry payload.
   */
  function updateChart(m) {
    if (!m) return;
    const top = topTalkersFromRates(m.rates || {});
    chartData.labels = top.map(x => x.key);
    chartData.datasets[0].data = top.map(x => x.val);
    if (chartPps) chartPps.update();

    if (chartSyn && m.syn_rates) {
      const ts = topTalkersFromIPRates(m.syn_rates || {});
      chartDataSyn.labels = ts.map(x => x.key);
      chartDataSyn.datasets[0].data = ts.map(x => x.val);
      chartSyn.update();
    }
    if (chartUdp && m.udp_rates) {
      const tu = topTalkersFromIPRates(m.udp_rates || {});
      chartDataUdp.labels = tu.map(x => x.key);
      chartDataUdp.datasets[0].data = tu.map(x => x.val);
      chartUdp.update();
    }
  }

  /**
   * Update live line chart with sliding window of recent telemetry points.
   */
  function updateLiveMonitor(m) {
    if (!chartLive) return;
    const now = Date.now();
    if (now - lastLiveUpdate < 1800) return;
    lastLiveUpdate = now;

    const label = new Date().toLocaleTimeString();
    const live = aggregatePps(m);
    const thr = Number((m && m.threshold_pps) ? m.threshold_pps : 0);

    chartDataLive.labels.push(label);
    chartDataLive.datasets[0].data.push(live);
    chartDataLive.datasets[1].data.push(thr);

    const maxPts = 60;
    while (chartDataLive.labels.length > maxPts) chartDataLive.labels.shift();
    while (chartDataLive.datasets[0].data.length > maxPts) chartDataLive.datasets[0].data.shift();
    while (chartDataLive.datasets[1].data.length > maxPts) chartDataLive.datasets[1].data.shift();

    chartLive.update();
  }

  /**
   * Update the title of the live monitor chart (e.g. during an attack).
   */
  function setLiveChartTitle(subtitle) {
    if (!chartLive || !chartLive.options || !chartLive.options.plugins) return;
    chartLive.options.plugins.title = {
      display: true,
      text: subtitle ? `Live Traffic Rate (${subtitle})` : 'Live Traffic Rate',
      color: '#9fb3c8'
    };
    chartLive.update();
  }

  function syncGlobalInstances() {
    global.chartPps = chartPps;
    global.chartSyn = chartSyn;
    global.chartUdp = chartUdp;
    global.chartLive = chartLive;
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  const ChartsModule = {
    setup: setupChart,
    setupChart: setupChart,
    initTrafficChart: setupChart,
    update: updateChart,
    updateChart: updateChart,
    updateMetrics: updateChart,
    updateLive: updateLiveMonitor,
    updateLiveMonitor: updateLiveMonitor,
    aggregatePps: aggregatePps,
    topTalkersFromRates: topTalkersFromRates,
    topTalkersFromIPRates: topTalkersFromIPRates,
    setLiveChartTitle: setLiveChartTitle,
    getLiveChart: () => chartLive,
    getPpsChart: () => chartPps,
    getSynChart: () => chartSyn,
    getUdpChart: () => chartUdp,
    getData: () => chartDataLive,
    getDataLive: () => chartDataLive,
    getDataPps: () => chartData,
    getDataSyn: () => chartDataSyn,
    getDataUdp: () => chartDataUdp,
  };

  global.SDNApp = global.SDNApp || {};
  global.SDNApp.Charts = ChartsModule;

  // Global backwards compatibility bindings
  global.setupChart = setupChart;
  global.updateChart = updateChart;
  global.aggregatePps = aggregatePps;
  global.topTalkersFromRates = topTalkersFromRates;
  global.topTalkersFromIPRates = topTalkersFromIPRates;
  global.updateLiveMonitor = updateLiveMonitor;
  global.chartDataLive = chartDataLive;
  global.chartData = chartData;
  global.chartDataSyn = chartDataSyn;
  global.chartDataUdp = chartDataUdp;

  syncGlobalInstances();

})(typeof window !== 'undefined' ? window : this);
