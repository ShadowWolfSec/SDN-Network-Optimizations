/**
 * Interactive Topology Canvas Module (SDNApp.Topology).
 * HTML5 Canvas rendering for SDN switches, links, and hosts.
 */

(function (global) {
  'use strict';

  const STORAGE_KEY = 'sdn_topology_v1';

  /**
   * Factory that creates and binds an interactive topology canvas instance.
   */
  function createTopologyCanvas(opts) {
    opts = opts || {};
    const canvas = opts.canvas || document.getElementById('topology-canvas');
    if (!canvas || !canvas.getContext) return null;
    const ctx = canvas.getContext('2d');

    // Tool Buttons
    const tools = opts.tools || {};
    const toolSelect = tools.toolSelect || document.getElementById('tool-select');
    const toolAddSwitch = tools.toolAddSwitch || document.getElementById('tool-add-switch');
    const toolAddHost = tools.toolAddHost || document.getElementById('tool-add-host');
    const toolLink = tools.toolLink || document.getElementById('tool-link');
    const toolDelete = tools.toolDelete || document.getElementById('tool-delete');

    // Link inspection elements
    const linkBwEl = opts.linkBwEl || document.getElementById('link-bw');
    const linkDelayEl = opts.linkDelayEl || document.getElementById('link-delay');
    const linkLossEl = opts.linkLossEl || document.getElementById('link-loss');
    const linkMsg = opts.linkMsg || document.getElementById('link-msg');
    const selectedItemEl = opts.selectedItemEl || document.getElementById('selected-item');
    const btnLinkApply = opts.btnLinkApply || document.getElementById('btn-link-apply');

    // Controller inputs
    const controllerIpEl = opts.controllerIpEl || document.getElementById('controller-ip');
    const controllerPortEl = opts.controllerPortEl || document.getElementById('controller-port');

    // Topology Import / Export / Control Buttons
    const buttons = opts.buttons || {};
    const btnTopoSave = buttons.btnTopoSave || document.getElementById('btn-topo-save');
    const btnTopoLoad = buttons.btnTopoLoad || document.getElementById('btn-topo-load');
    const btnTopoExport = buttons.btnTopoExport || document.getElementById('btn-topo-export');
    const btnTopoImport = buttons.btnTopoImport || document.getElementById('btn-topo-import');
    const btnTopoLayout = buttons.btnTopoLayout || document.getElementById('btn-topo-layout');
    const btnTopoReset = buttons.btnTopoReset || document.getElementById('btn-topo-reset');
    const btnTopoApplyImport = buttons.btnTopoApplyImport || document.getElementById('btn-topo-apply-import');
    const topoJsonEl = opts.topoJsonEl || document.getElementById('topology-json');
    const topoMsg = opts.topoMsg || document.getElementById('topo-msg');

    // Canvas & Editor State
    let mode = 'select';
    let drag = null;
    let dragMoved = false;
    let nodes = [];
    let links = [];
    let selected = { type: null, id: null };
    let linkPendingFrom = null;
    let seqSwitch = 0;
    let seqHost = 0;

    function setMode(m) {
      mode = m;
      linkPendingFrom = null;
      highlightToolButtons();
    }

    function highlightToolButtons() {
      const active = (
        mode === 'select' ? toolSelect :
        mode === 'add_switch' ? toolAddSwitch :
        mode === 'add_host' ? toolAddHost :
        mode === 'link' ? toolLink :
        mode === 'delete' ? toolDelete : null
      );
      const all = [toolSelect, toolAddSwitch, toolAddHost, toolLink, toolDelete];
      all.forEach(b => {
        if (!b) return;
        b.style.filter = '';
        const isAct = (b === active);
        b.classList.toggle('active', isAct);
        b.setAttribute('aria-pressed', isAct ? 'true' : 'false');
      });
    }

    function newNode(type, x, y) {
      if (type === 'switch') {
        seqSwitch += 1;
        return { id: `s${seqSwitch}`, name: `s${seqSwitch}`, type: 'switch', x, y };
      }
      seqHost += 1;
      return { id: `h${seqHost}`, name: `h${seqHost}`, type: 'host', x, y };
    }

    function nodeRadius(n) {
      return n.type === 'switch' ? 22 : 18;
    }

    function findNodeAt(x, y) {
      for (let i = nodes.length - 1; i >= 0; i--) {
        const n = nodes[i];
        const r = nodeRadius(n);
        const dx = x - n.x;
        const dy = y - n.y;
        if ((dx * dx + dy * dy) <= (r * r)) return n;
      }
      return null;
    }

    function distToSegment(px, py, x1, y1, x2, y2) {
      const vx = x2 - x1;
      const vy = y2 - y1;
      const wx = px - x1;
      const wy = py - y1;
      const c1 = vx * wx + vy * wy;
      if (c1 <= 0) return Math.hypot(px - x1, py - y1);
      const c2 = vx * vx + vy * vy;
      if (c2 <= c1) return Math.hypot(px - x2, py - y2);
      const b = c1 / c2;
      const bx = x1 + b * vx;
      const by = y1 + b * vy;
      return Math.hypot(px - bx, py - by);
    }

    function findLinkAt(x, y) {
      for (let i = links.length - 1; i >= 0; i--) {
        const l = links[i];
        const a = nodes.find(n => n.id === l.a);
        const b = nodes.find(n => n.id === l.b);
        if (!a || !b) continue;
        const d = distToSegment(x, y, a.x, a.y, b.x, b.y);
        if (d <= 6) return l;
      }
      return null;
    }

    function selectNone() {
      selected = { type: null, id: null };
      updateSelectionUI();
      render();
    }

    function selectNode(n) {
      selected = { type: 'node', id: n.id };
      updateSelectionUI();
      render();
    }

    function selectLink(l) {
      selected = { type: 'link', id: l.id };
      updateSelectionUI();
      render();
    }

    function updateSelectionUI() {
      if (linkMsg) linkMsg.innerText = '';
      if (selected.type === 'node') {
        const n = nodes.find(x => x.id === selected.id);
        if (selectedItemEl) selectedItemEl.innerText = n ? `Selected: ${n.name} (${n.type})` : '';
        if (linkBwEl) linkBwEl.value = '';
        if (linkDelayEl) linkDelayEl.value = '';
        if (linkLossEl) linkLossEl.value = '';
        return;
      }
      if (selected.type === 'link') {
        const l = links.find(x => x.id === selected.id);
        if (selectedItemEl) selectedItemEl.innerText = l ? `Selected Link: ${l.a} <-> ${l.b}` : '';
        if (l) {
          if (linkBwEl) linkBwEl.value = l.bw ?? '';
          if (linkDelayEl) linkDelayEl.value = l.delay_ms ?? '';
          if (linkLossEl) linkLossEl.value = l.loss ?? '';
        }
        return;
      }
      if (selectedItemEl) selectedItemEl.innerText = '';
      if (linkBwEl) linkBwEl.value = '';
      if (linkDelayEl) linkDelayEl.value = '';
      if (linkLossEl) linkLossEl.value = '';
    }

    function render() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      links.forEach(l => {
        const a = nodes.find(n => n.id === l.a);
        const b = nodes.find(n => n.id === l.b);
        if (!a || !b) return;
        const isSel = selected.type === 'link' && selected.id === l.id;
        ctx.strokeStyle = isSel ? '#3a6fff' : '#284061';
        ctx.lineWidth = isSel ? 3 : 2;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();

        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2;
        ctx.fillStyle = '#9fb3c8';
        ctx.font = '12px system-ui';
        const labelParts = [];
        if (l.bw !== undefined && l.bw !== null && l.bw !== '') labelParts.push(`${l.bw}Mbps`);
        if (l.delay_ms !== undefined && l.delay_ms !== null && l.delay_ms !== '') labelParts.push(`${l.delay_ms}ms`);
        if (l.loss !== undefined && l.loss !== null && l.loss !== '') labelParts.push(`${l.loss}%`);
        const label = labelParts.join(' / ');
        if (label) ctx.fillText(label, mx + 6, my - 6);
      });

      nodes.forEach(n => {
        const r = nodeRadius(n);
        const isSel = selected.type === 'node' && selected.id === n.id;
        ctx.fillStyle = n.type === 'switch' ? '#1f5eff' : '#0f3';
        ctx.strokeStyle = isSel ? '#ff7a3a' : '#1d2a44';
        ctx.lineWidth = isSel ? 4 : 2;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = n.type === 'switch' ? '#fff' : '#000';
        ctx.font = '13px system-ui';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(n.name, n.x, n.y);
      });

      if (mode === 'link' && linkPendingFrom) {
        const a = nodes.find(n => n.id === linkPendingFrom);
        if (a) {
          ctx.fillStyle = '#9fb3c8';
          ctx.font = '12px system-ui';
          ctx.textAlign = 'left';
          ctx.textBaseline = 'top';
          ctx.fillText(`Select second node to link ${a.name}`, 10, 10);
        }
      }
    }

    function ensureDefaultTopology(force = false) {
      if (!force && nodes.length > 0) return;
      nodes = [
        { id: 's1', name: 's1', type: 'switch', x: 450, y: 250 },
        { id: 'h1', name: 'h1', type: 'host', x: 160, y: 120 },
        { id: 'h2', name: 'h2', type: 'host', x: 760, y: 160 },
        { id: 'h3', name: 'h3', type: 'host', x: 760, y: 340 },
        { id: 'h4', name: 'h4', type: 'host', x: 160, y: 250 },
        { id: 'h5', name: 'h5', type: 'host', x: 160, y: 380 },
        { id: 'h6', name: 'h6', type: 'host', x: 330, y: 90 },
        { id: 'h7', name: 'h7', type: 'host', x: 330, y: 410 },
        { id: 'h8', name: 'h8', type: 'host', x: 580, y: 90 },
      ];
      links = [
        { id: 'l1', a: 'h1', b: 's1' },
        { id: 'l2', a: 'h2', b: 's1' },
        { id: 'l3', a: 'h3', b: 's1' },
        { id: 'l4', a: 'h4', b: 's1' },
        { id: 'l5', a: 'h5', b: 's1' },
        { id: 'l6', a: 'h6', b: 's1' },
        { id: 'l7', a: 'h7', b: 's1' },
        { id: 'l8', a: 'h8', b: 's1' },
      ];
      seqSwitch = 1;
      seqHost = 8;
      selectNone();
      render();
    }

    function toTopologyPayload() {
      const controller_ip = controllerIpEl ? (controllerIpEl.value || '127.0.0.1').trim() : '127.0.0.1';
      const controller_port = controllerPortEl ? Number(controllerPortEl.value || 6653) : 6653;
      return {
        controller_ip,
        controller_port,
        nodes: nodes.map(n => ({ type: n.type, name: n.name })),
        links: links.map(l => ({ a: l.a, b: l.b, bw: l.bw, delay_ms: l.delay_ms, loss: l.loss })),
      };
    }

    function toEditorState() {
      const controller_ip = controllerIpEl ? (controllerIpEl.value || '127.0.0.1').trim() : '127.0.0.1';
      const controller_port = controllerPortEl ? Number(controllerPortEl.value || 6653) : 6653;
      return {
        controller_ip,
        controller_port,
        nodes: nodes.map(n => ({ id: n.id, name: n.name, type: n.type, x: n.x, y: n.y })),
        links: links.map(l => ({ id: l.id, a: l.a, b: l.b, bw: l.bw, delay_ms: l.delay_ms, loss: l.loss })),
      };
    }

    function setEditorState(state) {
      const ns = (state && state.nodes) ? state.nodes : [];
      const ls = (state && state.links) ? state.links : [];
      nodes = ns.map(n => ({
        id: String(n.id || n.name),
        name: String(n.name || n.id),
        type: String(n.type || 'host'),
        x: Number.isFinite(n.x) ? n.x : (50 + Math.random() * (canvas.width - 100)),
        y: Number.isFinite(n.y) ? n.y : (50 + Math.random() * (canvas.height - 100)),
      }));
      links = ls.map((l, idx) => ({
        id: String(l.id || `l${idx + 1}_${Date.now()}`),
        a: String(l.a),
        b: String(l.b),
        bw: l.bw,
        delay_ms: l.delay_ms,
        loss: l.loss,
      })).filter(l => l.a && l.b);

      if (state && state.controller_ip && controllerIpEl) controllerIpEl.value = state.controller_ip;
      if (state && state.controller_port && controllerPortEl) controllerPortEl.value = state.controller_port;

      seqSwitch = 0;
      seqHost = 0;
      nodes.forEach(n => {
        const mS = /^s(\d+)$/i.exec(n.name);
        const mH = /^h(\d+)$/i.exec(n.name);
        if (mS) seqSwitch = Math.max(seqSwitch, Number(mS[1]));
        if (mH) seqHost = Math.max(seqHost, Number(mH[1]));
      });

      selectNone();
      render();
    }

    function exportJsonToTextarea() {
      if (!topoJsonEl) return;
      topoJsonEl.value = JSON.stringify(toEditorState(), null, 2);
    }

    function showTopoMsg(text) {
      if (!topoMsg) return;
      topoMsg.innerText = text || '';
      if (text) setTimeout(() => { if (topoMsg.innerText === text) topoMsg.innerText = ''; }, 2500);
    }

    function tryLoadSavedTopology() {
      try {
        const storage = (global && global.localStorage) || (typeof localStorage !== 'undefined' ? localStorage : null);
        if (!storage) return false;
        const raw = storage.getItem(STORAGE_KEY);
        if (!raw) return false;
        const st = JSON.parse(raw);
        setEditorState(st);
        return true;
      } catch (e) {
        return false;
      }
    }

    function saveTopologyState() {
      try {
        const storage = (global && global.localStorage) || (typeof localStorage !== 'undefined' ? localStorage : null);
        if (storage) storage.setItem(STORAGE_KEY, JSON.stringify(toEditorState()));
      } catch (e) {}
      try {
        exportJsonToTextarea();
      } catch (e) {}
    }

    function autoLayout() {
      const sw = nodes.filter(n => n.type === 'switch');
      const hs = nodes.filter(n => n.type !== 'switch');
      const cx = canvas.width * 0.36;
      const cy = canvas.height * 0.52;
      const r = Math.min(canvas.width, canvas.height) * 0.22;

      if (sw.length === 0 && nodes.length > 0) {
        const step = (2 * Math.PI) / Math.max(1, nodes.length);
        nodes.forEach((n, i) => {
          n.x = cx + Math.cos(i * step) * r;
          n.y = cy + Math.sin(i * step) * r;
        });
        render();
        return;
      }

      const step = (2 * Math.PI) / Math.max(1, sw.length);
      sw.forEach((n, i) => {
        n.x = cx + Math.cos(i * step) * r;
        n.y = cy + Math.sin(i * step) * r;
      });

      const hostBySwitch = new Map();
      hs.forEach(h => {
        let attached = null;
        for (const l of links) {
          if (l.a === h.id) attached = l.b;
          else if (l.b === h.id) attached = l.a;
          if (attached) break;
        }
        const s = sw.find(x => x.id === attached) ? attached : (sw[0] ? sw[0].id : null);
        if (!hostBySwitch.has(s)) hostBySwitch.set(s, []);
        hostBySwitch.get(s).push(h);
      });

      hostBySwitch.forEach((arr, sid) => {
        const s = sw.find(x => x.id === sid) || sw[0];
        if (!s) return;
        const rr = 70;
        const st = (2 * Math.PI) / Math.max(1, arr.length);
        arr.forEach((h, i) => {
          h.x = s.x + Math.cos(i * st) * rr;
          h.y = s.y + Math.sin(i * st) * rr;
        });
      });

      render();
    }

    function canvasToLocal(ev) {
      const rect = canvas.getBoundingClientRect();
      const x = (ev.clientX - rect.left) * (canvas.width / rect.width);
      const y = (ev.clientY - rect.top) * (canvas.height / rect.height);
      return { x, y };
    }

    // Bind Canvas Interactions
    canvas.addEventListener('mousedown', (ev) => {
      const { x, y } = canvasToLocal(ev);

      if (mode === 'add_switch') {
        const n = newNode('switch', x, y);
        nodes.push(n);
        selectNode(n);
        render();
        saveTopologyState();
        return;
      }
      if (mode === 'add_host') {
        const n = newNode('host', x, y);
        nodes.push(n);
        selectNode(n);
        render();
        saveTopologyState();
        return;
      }

      const n = findNodeAt(x, y);
      const l = n ? null : findLinkAt(x, y);

      if (mode === 'delete') {
        if (l) {
          links = links.filter(x => x.id !== l.id);
          selectNone();
          render();
          saveTopologyState();
          return;
        }
        if (n) {
          links = links.filter(x => x.a !== n.id && x.b !== n.id);
          nodes = nodes.filter(x => x.id !== n.id);
          selectNone();
          render();
          saveTopologyState();
          return;
        }
        return;
      }

      if (mode === 'link') {
        if (!n) return;
        if (!linkPendingFrom) {
          linkPendingFrom = n.id;
          selectNode(n);
          render();
          return;
        }
        if (linkPendingFrom === n.id) return;

        const a = linkPendingFrom;
        const b = n.id;
        const exists = links.some(x => (x.a === a && x.b === b) || (x.a === b && x.b === a));
        if (!exists) {
          const lid = `l${links.length + 1}_${Date.now()}`;
          links.push({ id: lid, a, b });
          saveTopologyState();
        }
        linkPendingFrom = null;
        render();
        return;
      }

      if (n) {
        selectNode(n);
        drag = { id: n.id, dx: x - n.x, dy: y - n.y };
        dragMoved = false;
        return;
      }
      if (l) {
        selectLink(l);
        return;
      }
      selectNone();
    });

    canvas.addEventListener('mousemove', (ev) => {
      if (!drag) return;
      if (mode !== 'select') return;
      const { x, y } = canvasToLocal(ev);
      const n = nodes.find(nn => nn.id === drag.id);
      if (!n) return;
      n.x = Math.max(20, Math.min(canvas.width - 20, x - drag.dx));
      n.y = Math.max(20, Math.min(canvas.height - 20, y - drag.dy));
      dragMoved = true;
      render();
    });

    window.addEventListener('mouseup', () => {
      if (drag && dragMoved) {
        saveTopologyState();
      }
      drag = null;
      dragMoved = false;
    });

    // Tool Button Event Listeners
    toolSelect && toolSelect.addEventListener('click', () => setMode('select'));
    toolAddSwitch && toolAddSwitch.addEventListener('click', () => setMode('add_switch'));
    toolAddHost && toolAddHost.addEventListener('click', () => setMode('add_host'));
    toolLink && toolLink.addEventListener('click', () => setMode('link'));
    toolDelete && toolDelete.addEventListener('click', () => setMode('delete'));
    controllerIpEl && controllerIpEl.addEventListener('change', () => saveTopologyState());
    controllerPortEl && controllerPortEl.addEventListener('change', () => saveTopologyState());

    // Link Property Application
    btnLinkApply && btnLinkApply.addEventListener('click', async () => {
      if (linkMsg) linkMsg.innerText = '';
      if (selected.type !== 'link') {
        if (linkMsg) linkMsg.innerText = 'Select a link first.';
        return;
      }
      const l = links.find(x => x.id === selected.id);
      if (!l) return;
      const bw = linkBwEl ? linkBwEl.value.trim() : '';
      const delay_ms = linkDelayEl ? linkDelayEl.value.trim() : '';
      const loss = linkLossEl ? linkLossEl.value.trim() : '';
      l.bw = bw === '' ? undefined : Number(bw);
      l.delay_ms = delay_ms === '' ? undefined : Number(delay_ms);
      l.loss = loss === '' ? undefined : Number(loss);
      render();
      saveTopologyState();

      try {
        const fetcher = (global.SDNApp && global.SDNApp.Utils && global.SDNApp.Utils.getJSON) || global.getJSON;
        if (fetcher) {
          await fetcher('/api/lab/link/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ a: l.a, b: l.b, bw: l.bw, delay_ms: l.delay_ms, loss: l.loss })
          });
        }
        if (linkMsg) {
          linkMsg.innerText = 'Link configuration applied.';
          setTimeout(() => { if (linkMsg.innerText === 'Link configuration applied.') linkMsg.innerText = ''; }, 2000);
        }
      } catch (e) {
        if (linkMsg) {
          linkMsg.innerText = 'Failed to apply link configuration (network may not be running).';
          setTimeout(() => { linkMsg.innerText = ''; }, 2500);
        }
      }
    });

    // Topology Persistence Buttons
    btnTopoSave && btnTopoSave.addEventListener('click', () => {
      saveTopologyState();
      showTopoMsg('Saved');
    });

    btnTopoLoad && btnTopoLoad.addEventListener('click', () => {
      if (tryLoadSavedTopology()) {
        exportJsonToTextarea();
        showTopoMsg('Loaded');
      } else {
        showTopoMsg('No saved topology found');
      }
    });

    btnTopoExport && btnTopoExport.addEventListener('click', () => {
      exportJsonToTextarea();
      showTopoMsg('Exported');
    });

    btnTopoImport && btnTopoImport.addEventListener('click', () => {
      showTopoMsg('Paste JSON in the box below, then click Apply Import');
    });

    btnTopoApplyImport && btnTopoApplyImport.addEventListener('click', () => {
      try {
        const st = JSON.parse((topoJsonEl && topoJsonEl.value) ? topoJsonEl.value : '{}');
        setEditorState(st);
        saveTopologyState();
        showTopoMsg('Imported and saved');
      } catch (e) {
        showTopoMsg('Invalid JSON');
      }
    });

    btnTopoLayout && btnTopoLayout.addEventListener('click', () => {
      autoLayout();
      saveTopologyState();
    });

    btnTopoReset && btnTopoReset.addEventListener('click', () => {
      ensureDefaultTopology(true);
      saveTopologyState();
      showTopoMsg('Default topology restored (s1 + h1..h8)');
    });

    // Helper: get linked host names for demo / attack coordination
    function getLinkedHostNames() {
      const linkedIds = new Set();
      links.forEach(l => { linkedIds.add(l.a); linkedIds.add(l.b); });
      return nodes.filter(n => n.type !== 'switch' && linkedIds.has(n.name)).map(n => n.name);
    }

    function getCleanClients() {
      return getLinkedHostNames().filter(n => n !== 'h2' && n !== 'h3');
    }

    // Initial state bootstrapping
    setMode('select');
    if (!tryLoadSavedTopology()) {
      ensureDefaultTopology();
      saveTopologyState();
    } else {
      exportJsonToTextarea();
    }

    // Engine public interface
    const engine = {
      canvas,
      ctx,
      getNodes: () => nodes,
      getLinks: () => links,
      getSelected: () => selected,
      render,
      autoLayout,
      newNode,
      selectNone,
      selectNode,
      selectLink,
      saveTopologyState,
      tryLoadSavedTopology,
      ensureDefaultTopology,
      toTopologyPayload,
      toEditorState,
      setEditorState,
      exportJsonToTextarea,
      showTopoMsg,
      getLinkedHostNames,
      getCleanClients,
    };

    // Global backwards-compatibility exports
    global.saveTopologyState = saveTopologyState;
    global.ensureDefaultTopology = ensureDefaultTopology;

    return engine;
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  global.SDNApp = global.SDNApp || {};
  global.SDNApp.Topology = {
    init: createTopologyCanvas,
    create: createTopologyCanvas,
  };

})(typeof window !== 'undefined' ? window : this);
