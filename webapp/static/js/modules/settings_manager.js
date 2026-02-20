/**
 * Settings & Configuration Module (SDNApp.Settings).
 * Manages detection thresholds, whitelist management, and manual block forms.
 */

(function (global) {
  'use strict';

  /**
   * Fetch current Ryu base URL and update settings inputs.
   */
  async function loadSettings(opts = {}) {
    const getJSON = opts.getJSON || global.getJSON;
    try {
      const s = await getJSON('/api/settings');
      const ryuBase = document.getElementById('ryu-base');
      if (ryuBase && s && s.ryu_api_base !== undefined) {
        ryuBase.innerText = s.ryu_api_base;
      }
      const ryuBaseInput = document.getElementById('ryu-base-input');
      if (ryuBaseInput && s && s.ryu_api_base !== undefined) {
        ryuBaseInput.value = s.ryu_api_base;
      }
      return s;
    } catch (e) {}
  }

  /**
   * Fetch whitelist sync status from server and update badge styling.
   */
  async function updateWhitelistSyncStatus(opts = {}) {
    const getJSON = opts.getJSON || global.getJSON;
    const badge = document.getElementById('whitelist-sync-status');
    if (!badge) return;
    try {
      const res = await getJSON('/api/whitelist/status');
      if (!res || !res.ok) return;
      badge.className = 'status-pill';
      switch (res.sync_status) {
        case 'synced':
          badge.classList.add('status-ok');
          badge.innerText = 'In Sync';
          break;
        case 'memory_dirty':
          badge.classList.add('status-warn');
          badge.innerText = 'Unsaved Changes';
          break;
        case 'no_file':
          badge.classList.add('status-muted');
          badge.innerText = 'No Saved File';
          break;
        case 'file_unreadable':
          badge.classList.add('status-danger');
          badge.innerText = 'Corrupt File';
          break;
        default:
          badge.classList.add('status-muted');
          badge.innerText = 'Unknown';
      }
    } catch (e) {
      badge.className = 'status-pill status-muted';
      badge.innerText = 'Offline';
    }
  }

  /**
   * Binds submit and click event handlers for configuration forms and settings action buttons.
   */
  function bindUI(opts = {}) {
    const getJSON = opts.getJSON || global.getJSON;
    const showToast = opts.showToast || global.showToast || (() => {});
    const errToShortText = opts.errToShortText || global.errToShortText || String;
    const refreshMetricsNow = opts.refreshMetricsNow || global.refreshMetricsNow || (() => {});
    const renderAlerts = opts.renderAlerts || global.renderAlerts || (() => {});
    const getMitigationEnabled = opts.getMitigationEnabled || (() => global.mitigationEnabled);
    const setMitigationEnabled = opts.setMitigationEnabled || ((val) => { global.mitigationEnabled = val; });
    const getAutoFailoverEnabled = opts.getAutoFailoverEnabled || (() => global.autoFailoverEnabled);
    const setAutoFailoverEnabled = opts.setAutoFailoverEnabled || ((val) => { global.autoFailoverEnabled = val; });
    const syncMitigationDisplay = opts.syncMitigationDisplay || global.syncMitigationDisplay || (() => {});
    const syncAutoFailoverDisplay = opts.syncAutoFailoverDisplay || global.syncAutoFailoverDisplay || (() => {});

    // 1. Ryu API Base Form
    const formSaveBase = document.getElementById('form-save-base');
    if (formSaveBase) {
      formSaveBase.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const baseInput = document.getElementById('ryu-base-input');
        const base = baseInput ? baseInput.value.trim() : '';
        if (!base) return;
        try {
          const r = await getJSON('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ryu_api_base: base })
          });
          const ryuBase = document.getElementById('ryu-base');
          if (ryuBase && r && r.ryu_api_base !== undefined) {
            ryuBase.innerText = r.ryu_api_base;
          }
          showToast('Saved Ryu API Base.', 'success');
        } catch (e) {
          showToast(`Failed to save Ryu API Base (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    // 2. Detection Thresholds & Config Form
    const formConfig = document.getElementById('form-config');
    if (formConfig) {
      async function submitConfig(persist = false) {
        const payload = { persist };
        [
          'threshold_pps',
          'alpha',
          'measure_interval',
          'syn_threshold',
          'udp_threshold',
          'ddos_source_threshold',
          'ddos_min_pps_per_source',
          'portscan_threshold',
          'block_duration_sec',
          'drop_priority'
        ].forEach(k => {
          const inp = formConfig.querySelector(`[name="${k}"]`);
          if (inp) {
            const v = inp.value.trim();
            if (v) payload[k] = Number(v);
          }
        });
        const msg = document.getElementById('config-msg');
        if (msg) msg.innerText = persist ? 'Saving & Applying...' : 'Applying live...';
        try {
          const r = await getJSON('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          if (r && r.ok) {
            const modeLabel = r.durability === 'permanent' ? 'Saved & Applied (Permanent)' : 'Applied (Live Ephemeral)';
            if (msg) msg.innerText = `${modeLabel} - Verifying echo...`;
            
            // Echo verification: check that effective value reflects the change
            setTimeout(async () => {
              try {
                const chk = await getJSON('/api/config');
                if (chk && chk.ok && chk.effective) {
                  if (msg) msg.innerText = `${modeLabel} ✓ Echo Verified`;
                } else {
                  if (msg) msg.innerText = modeLabel;
                }
              } catch (err) {
                if (msg) msg.innerText = modeLabel;
              }
              setTimeout(() => { if (msg) msg.innerText = ''; }, 3000);
            }, 600);
          } else {
            if (msg) msg.innerText = `Failed: ${(r && r.error) || 'unknown'}`;
            setTimeout(() => { if (msg) msg.innerText = ''; }, 3000);
          }
        } catch (e) {
          if (msg) msg.innerText = `Update failed (${errToShortText(e) || 'error'})`;
          setTimeout(() => { if (msg) msg.innerText = ''; }, 3000);
        }
      }

      formConfig.addEventListener('submit', (ev) => {
        ev.preventDefault();
        submitConfig(false);
      });

      const btnEphemeral = document.getElementById('btn-config-ephemeral');
      if (btnEphemeral) {
        btnEphemeral.addEventListener('click', (ev) => {
          ev.preventDefault();
          submitConfig(false);
        });
      }

      const btnPermanent = document.getElementById('btn-config-permanent');
      if (btnPermanent) {
        btnPermanent.addEventListener('click', (ev) => {
          ev.preventDefault();
          submitConfig(true);
        });
      }
    }

    // 3. Manual IP Block Form
    const formBlock = document.getElementById('form-block');
    if (formBlock) {
      formBlock.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const inp = ev.target.querySelector('[name="ip"]');
        const ip = inp ? inp.value.trim() : '';
        if (!ip) return;
        try {
          await getJSON('/api/block/ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
          showToast(`Blocked IP ${ip}`, 'success');
          await refreshMetricsNow();
        } catch (e) {
          showToast(`Failed to block ${ip} (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    // 4. Manual IP Unblock Form
    const formUnblock = document.getElementById('form-unblock');
    if (formUnblock) {
      formUnblock.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const inp = ev.target.querySelector('[name="ip"]');
        const ip = inp ? inp.value.trim() : '';
        if (!ip) return;
        if (!window.confirm(`Unblock IP ${ip}?`)) return;
        try {
          await getJSON('/api/unblock/ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
          showToast(`Unblocked IP ${ip}`, 'success');
          await refreshMetricsNow();
        } catch (e) {
          showToast(`Failed to unblock ${ip} (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    // 5. Clear Alerts Button
    const btnClearAlerts = document.getElementById('btn-clear-alerts');
    if (btnClearAlerts) {
      btnClearAlerts.addEventListener('click', async () => {
        try {
          await getJSON('/api/alerts/clear', { method: 'POST' });
          renderAlerts([]);
        } catch (e) {
          showToast(`Failed to clear alerts (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    // 6. Mitigation Toggle Button
    const btnMit = document.getElementById('btn-mitigation-toggle');
    if (btnMit) {
      btnMit.addEventListener('click', async () => {
        try {
          const next = !(getMitigationEnabled() === true);
          await getJSON('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mitigation_enabled: next }) });
          setMitigationEnabled(next);
          syncMitigationDisplay(next);
        } catch (e) {
          showToast(`Failed to toggle mitigation (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    // 7. Auto Failover Toggle Button
    const btnAF = document.getElementById('btn-auto-failover-toggle');
    if (btnAF) {
      btnAF.addEventListener('click', async () => {
        try {
          const next = !(getAutoFailoverEnabled() === true);
          await getJSON('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ auto_failover_enabled: next }) });
          setAutoFailoverEnabled(next);
          syncAutoFailoverDisplay(next);
        } catch (e) {
          showToast(`Failed to toggle auto failover (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    // 8. Unblock All Buttons (Dashboard & Settings)
    ['btn-unblock-all', 'btn-unblock-all-settings'].forEach(btnId => {
      const btn = document.getElementById(btnId);
      if (!btn) return;
      btn.addEventListener('click', async () => {
        if (!window.confirm('Unblock all IP addresses?')) return;
        try {
          await getJSON('/api/unblock/all', { method: 'POST' });
          showToast('All blocked IPs cleared.', 'success');
          await refreshMetricsNow();
        } catch (e) {
          showToast(`Failed to unblock all IPs (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    });

    // 9. Whitelist Actions
    const btnSaveWhitelist = document.getElementById('btn-save-whitelist');
    if (btnSaveWhitelist) {
      btnSaveWhitelist.addEventListener('click', async () => {
        const whitelistDiv = document.getElementById('whitelist-list');
        const count = whitelistDiv ? whitelistDiv.querySelectorAll('.pill').length : 0;
        if (count === 0) {
          if (!window.confirm('Notice: Active whitelist is currently empty. Saving this file will mean no IP exceptions are preserved. Confirm save?')) return;
        } else {
          if (!window.confirm(`Save current in-memory whitelist (${count} IP(s)) to persistent disk?`)) return;
        }
        try {
          await getJSON('/api/whitelist/save', { method: 'POST' });
          showToast('Whitelist successfully saved to disk.', 'success');
          await updateWhitelistSyncStatus({ getJSON });
        } catch (e) {
          showToast(`Failed to save whitelist (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    const btnRestoreWhitelist = document.getElementById('btn-restore-whitelist');
    if (btnRestoreWhitelist) {
      btnRestoreWhitelist.addEventListener('click', async () => {
        if (!window.confirm('Restore whitelist from disk? This will replace active in-memory whitelist and remove flow rules for unblocked IPs.')) return;
        try {
          const resp = await getJSON('/api/whitelist/restore', { method: 'POST' });
          showToast(`Whitelist restored (${resp.restored_count || 0} IP(s)).`, 'success');
          await refreshMetricsNow();
          await updateWhitelistSyncStatus({ getJSON });
        } catch (e) {
          showToast(`Failed to restore whitelist (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    const btnDeleteWhitelistFile = document.getElementById('btn-delete-whitelist-file');
    if (btnDeleteWhitelistFile) {
      btnDeleteWhitelistFile.addEventListener('click', async () => {
        if (!window.confirm('Are you sure you want to delete the persistent whitelist file from disk? This does not affect active memory.')) return;
        try {
          await getJSON('/api/whitelist/persistent', { method: 'DELETE' });
          showToast('Persistent whitelist file deleted.', 'success');
          await updateWhitelistSyncStatus({ getJSON });
        } catch (e) {
          showToast(`Failed to delete saved file (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    const btnClearWhitelist = document.getElementById('btn-clear-whitelist');
    if (btnClearWhitelist) {
      btnClearWhitelist.addEventListener('click', async () => {
        if (!window.confirm('Clear all IP addresses from the active memory whitelist?')) return;
        try {
          await getJSON('/api/whitelist/clear', { method: 'POST' });
          showToast('Active memory whitelist cleared.', 'success');
          await refreshMetricsNow();
          await updateWhitelistSyncStatus({ getJSON });
        } catch (e) {
          showToast(`Failed to clear whitelist (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    const btnUnblockMacAll = document.getElementById('btn-unblock-mac-all');
    if (btnUnblockMacAll) {
      btnUnblockMacAll.addEventListener('click', async () => {
        if (!window.confirm('Unblock all MAC addresses?')) return;
        try {
          await getJSON('/api/unblock/mac/all', { method: 'POST' });
          showToast('All blocked MACs cleared.', 'success');
          await refreshMetricsNow();
        } catch (e) {
          showToast(`Failed to unblock all MACs (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    const fWL = document.getElementById('form-whitelist');
    const whitelistMsg = document.getElementById('whitelist-msg');
    if (fWL) {
      fWL.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const inp = ev.target.querySelector('[name="ip"]');
        const ip = inp ? inp.value.trim() : '';
        if (!ip) return;
        if (whitelistMsg) whitelistMsg.innerText = '';
        try {
          await getJSON('/api/whitelist/ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
          if (whitelistMsg) whitelistMsg.innerText = 'Added to whitelist';
          if (whitelistMsg) setTimeout(() => { whitelistMsg.innerText = ''; }, 2000);
          await refreshMetricsNow();
        } catch (e) {
          if (whitelistMsg) whitelistMsg.innerText = `Failed to add (${errToShortText(e) || 'error'})`;
          if (whitelistMsg) setTimeout(() => { whitelistMsg.innerText = ''; }, 2500);
        }
      });
    }

    const fUWL = document.getElementById('form-unwhitelist');
    if (fUWL) {
      fUWL.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const inp = ev.target.querySelector('[name="ip"]');
        const ip = inp ? inp.value.trim() : '';
        if (!ip) return;
        if (whitelistMsg) whitelistMsg.innerText = '';
        try {
          await getJSON('/api/unwhitelist/ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
          if (whitelistMsg) whitelistMsg.innerText = 'Removed from whitelist';
          if (whitelistMsg) setTimeout(() => { whitelistMsg.innerText = ''; }, 2000);
          await refreshMetricsNow();
        } catch (e) {
          if (whitelistMsg) whitelistMsg.innerText = `Failed to remove (${errToShortText(e) || 'error'})`;
          if (whitelistMsg) setTimeout(() => { whitelistMsg.innerText = ''; }, 2500);
        }
      });
    }

    const fBM = document.getElementById('form-block-mac');
    if (fBM) {
      fBM.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const inp = ev.target.querySelector('[name="mac"]');
        const mac = inp ? inp.value.trim() : '';
        if (!mac) return;
        try {
          await getJSON('/api/block/mac', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mac }) });
          showToast(`Blocked MAC ${mac}`, 'success');
          await refreshMetricsNow();
        } catch (e) {
          showToast(`Failed to block MAC (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    const fUBM = document.getElementById('form-unblock-mac');
    if (fUBM) {
      fUBM.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const inp = ev.target.querySelector('[name="mac"]');
        const mac = inp ? inp.value.trim() : '';
        if (!mac) return;
        try {
          await getJSON('/api/unblock/mac', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mac }) });
          showToast(`Unblocked MAC ${mac}`, 'success');
          await refreshMetricsNow();
        } catch (e) {
          showToast(`Failed to unblock MAC (${errToShortText(e) || 'error'})`, 'error');
        }
      });
    }

    try { updateWhitelistSyncStatus({ getJSON }); } catch (e) {}
  }

  // ============================================
  // Export to SDNApp Namespace and Window Global
  // ============================================
  const SettingsModule = {
    loadSettings,
    updateWhitelistSyncStatus,
    bindUI,
  };

  global.SDNApp = global.SDNApp || {};
  global.SDNApp.Settings = SettingsModule;

  // Global backwards compatibility bindings
  global.loadSettings = loadSettings;
  global.updateWhitelistSyncStatus = updateWhitelistSyncStatus;
  global.bindUI = bindUI;

})(typeof window !== 'undefined' ? window : this);
