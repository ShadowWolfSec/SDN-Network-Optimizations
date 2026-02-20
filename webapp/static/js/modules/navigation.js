/**
 * Navigation & UI Displays Module (SDNApp.Navigation).
 * Manages tab switching, status badges, and blocked IP cards.
 */

(function (global) {
  'use strict';

  /**
   * Switch the active view to the specified tab.
   */
  function switchTab(tabName) {
    const item = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
    if (item) {
      item.click();
    } else {
      const tabPanes = document.querySelectorAll('.tab-pane');
      const navItems = document.querySelectorAll('.nav-item');
      navItems.forEach(nav => nav.classList.remove('active'));
      tabPanes.forEach(pane => pane.classList.remove('active'));
      const targetPane = document.getElementById(`tab-${tabName}`);
      if (targetPane) targetPane.classList.add('active');
      if (typeof global.onTabActivated === 'function') {
        global.onTabActivated(tabName);
      }
    }
  }

  /**
   * Initializes tab click listeners, pane visibility, and header title updates.
   */
  function initTabNavigation(opts = {}) {
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const pageTitle = document.getElementById('page-title');
    const pageSubtitle = document.getElementById('page-subtitle');

    const tabTitles = {
      'dashboard': { title: 'Live Dashboard', subtitle: 'Real-time network monitoring and threat detection' },
      'lab': { title: 'Lab & Attacks', subtitle: 'Network topology design and attack simulation' },
      'forensics': { title: 'Forensics & Flows', subtitle: 'Detailed flow analysis and attack history' },
      'settings': { title: 'Settings', subtitle: 'Detection thresholds and security controls' }
    };

    navItems.forEach(item => {
      item.onclick = () => {
        const tabName = item.dataset.tab;
        
        // Update nav items
        navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
        
        // Update tab panes
        tabPanes.forEach(pane => pane.classList.remove('active'));
        const targetPane = document.getElementById(`tab-${tabName}`);
        if (targetPane) targetPane.classList.add('active');
        
        // Update page title
        if (pageTitle && pageSubtitle && tabTitles[tabName]) {
          pageTitle.textContent = tabTitles[tabName].title;
          pageSubtitle.textContent = tabTitles[tabName].subtitle;
        }
        
        const callback = (opts && typeof opts.onTabActivated === 'function')
          ? opts.onTabActivated
          : (typeof global.onTabActivated === 'function' ? global.onTabActivated : null);
        if (callback) {
          try {
            callback(tabName);
          } catch (e) {
            console.error('Error in onTabActivated:', e);
          }
        }
      };
    });
  }

  /**
   * Sync mitigation status badge and toggle button state across Dashboard and Settings.
   */
  function syncMitigationDisplay(enabled) {
    if (enabled === null || enabled === undefined) return;
    const on = !!enabled;
    ['mitigation-status', 'mitigation-status-settings'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.remove('green', 'red', 'gray');
      el.classList.add(on ? 'green' : 'red');
      el.innerText = on ? 'Mitigation: ON' : 'Mitigation: OFF';
    });
    const btnMit = document.getElementById('btn-mitigation-toggle');
    if (btnMit) {
      btnMit.classList.remove('btn-secondary', 'btn-success', 'btn-danger');
      btnMit.classList.add(on ? 'btn-success' : 'btn-danger');
      btnMit.innerText = on ? 'ON' : 'OFF';
    }
  }

  /**
   * Sync auto-failover status badge and toggle button state across Dashboard and Settings.
   */
  function syncAutoFailoverDisplay(enabled) {
    if (enabled === null || enabled === undefined) return;
    const on = !!enabled;
    ['auto-failover-status', 'auto-failover-status-settings'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.remove('green', 'red', 'gray');
      el.classList.add(on ? 'green' : 'gray');
      el.innerText = on ? 'Auto Failover: ON' : 'Auto Failover: OFF';
    });
    const btnAF = document.getElementById('btn-auto-failover-toggle');
    if (btnAF) {
      btnAF.classList.remove('btn-secondary', 'btn-success', 'btn-danger');
      btnAF.classList.add(on ? 'btn-success' : 'btn-danger');
      btnAF.innerText = on ? 'ON' : 'OFF';
    }
  }

  /**
   * Render individual blocked IP card badges with clipboard copy and manual unblock buttons.
   */
  function renderBlockedIpCards(container, ips, opts = {}) {
    if (!container) return;
    const list = Array.isArray(ips) ? ips.map(x => String(x || '').trim()).filter(Boolean) : [];
    const nextKey = JSON.stringify(list);
    if (container.dataset.ipsKey === nextKey) return;
    container.dataset.ipsKey = nextKey;
    container.innerHTML = '';

    const copyTextToClipboard = opts.copyTextToClipboard || global.copyTextToClipboard || (global.SDNApp && global.SDNApp.Utils && global.SDNApp.Utils.copyTextToClipboard);
    const showToast = opts.showToast || global.showToast || (global.SDNApp && global.SDNApp.Utils && global.SDNApp.Utils.showToast) || (() => {});
    const getJSON = opts.getJSON || global.getJSON;
    const errToShortText = opts.errToShortText || global.errToShortText || String;
    const refreshMetricsNow = opts.refreshMetricsNow || global.refreshMetricsNow || (() => {});

    list.forEach(ip => {
      const card = document.createElement('span');
      card.className = 'blocked-ip-card';

      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'blocked-ip-copy';
      copyBtn.textContent = ip;
      copyBtn.title = `Click to copy ${ip}`;
      copyBtn.setAttribute('aria-label', `Copy blocked IP ${ip} to clipboard`);
      copyBtn.addEventListener('click', async () => {
        const ok = await copyTextToClipboard(ip);
        showToast(ok ? `Copied ${ip} to clipboard.` : `Could not copy ${ip} to clipboard.`, ok ? 'info' : 'warning');
      });

      card.appendChild(copyBtn);

      const metaRole = document.querySelector('meta[name="user-role"]');
      const userEl = document.querySelector('.user-name');
      const userName = (userEl ? userEl.textContent.trim().toLowerCase() : '');
      const userRole = (metaRole ? metaRole.getAttribute('content') : '') || (document.body ? document.body.dataset.userRole : '') || (userName === 'admin' ? 'admin' : 'user');
      if (userRole === 'admin' || userName === 'admin') {
        const unblockBtn = document.createElement('button');
        unblockBtn.type = 'button';
        unblockBtn.className = 'blocked-ip-unblock';
        unblockBtn.textContent = 'Unblock';
        unblockBtn.title = `Unblock ${ip}`;
        unblockBtn.setAttribute('aria-label', `Unblock IP ${ip}`);
        unblockBtn.addEventListener('click', async () => {
          if (!window.confirm(`Unblock IP ${ip}?`)) return;
          unblockBtn.disabled = true;
          try {
            await getJSON('/api/unblock/ip', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ ip })
            });
            showToast(`Unblocked IP ${ip}.`, 'success');
            ['blocked-list', 'blocked-list-settings'].forEach(cid => {
              const el = document.getElementById(cid);
              if (el) delete el.dataset.ipsKey;
            });
            await refreshMetricsNow();
          } catch (e) {
            unblockBtn.disabled = false;
            showToast(`Failed to unblock ${ip} (${errToShortText(e) || 'error'})`, 'error');
          }
        });
        card.appendChild(unblockBtn);
      }
      container.appendChild(card);
    });
  }

  /**
   * Render blocked IP cards across both dashboard and settings containers.
   */
  function renderBlockedIpLists(ips, opts = {}) {
    ['blocked-list', 'blocked-list-settings'].forEach(id => {
      const el = document.getElementById(id);
      if (el) renderBlockedIpCards(el, ips, opts);
    });
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  const NavigationModule = {
    switchTab,
    initTabNavigation,
    syncMitigationDisplay,
    syncAutoFailoverDisplay,
    renderBlockedIpCards,
    renderBlockedIpLists,
  };

  global.SDNApp = global.SDNApp || {};
  global.SDNApp.Navigation = NavigationModule;

  // Global backwards compatibility bindings
  global.switchTab = switchTab;
  global.initTabNavigation = initTabNavigation;
  global.syncMitigationDisplay = syncMitigationDisplay;
  global.syncAutoFailoverDisplay = syncAutoFailoverDisplay;
  global.renderBlockedIpCards = renderBlockedIpCards;
  global.renderBlockedIpLists = renderBlockedIpLists;

  // Auto-init tab listeners on DOM ready as a fallback safeguard
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        try { initTabNavigation(); } catch (e) {}
      });
    } else {
      try { initTabNavigation(); } catch (e) {}
    }
  }

})(typeof window !== 'undefined' ? window : this);
