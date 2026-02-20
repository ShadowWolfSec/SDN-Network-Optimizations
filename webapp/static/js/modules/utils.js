// Core Utilities Module (SDNApp.Utils)

(function (window) {
  'use strict';

  const SDNApp = window.SDNApp || {};
  window.SDNApp = SDNApp;

  /**
   * Escape HTML characters to prevent XSS.
   */
  function escHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  /**
   * Format a number with fixed decimal places or '-' if invalid.
   */
  function fmtNum(v, digits = 1) {
    if (v === null || v === undefined) return '-';
    const n = Number(v);
    if (!Number.isFinite(n)) return '-';
    return n.toFixed(digits);
  }

  /**
   * Toast Notification with auto-dismiss.
   */
  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const span = document.createElement('span');
    span.textContent = String(message || '');
    toast.appendChild(span);

    container.appendChild(toast);

    // Auto-remove after 4 seconds
    setTimeout(() => {
      toast.style.animation = 'slideIn 0.25s ease reverse';
      setTimeout(() => toast.remove(), 250);
    }, 4000);
  }

  /**
   * Copy text to clipboard with modern API fallback to execCommand.
   */
  async function copyTextToClipboard(text) {
    const val = String(text || '');
    if (!val) return false;
    try {
      if (navigator && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(val);
        return true;
      }
    } catch (e) {
    }
    try {
      const ta = document.createElement('textarea');
      ta.value = val;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      const ok = !!(document.execCommand && document.execCommand('copy'));
      document.body.removeChild(ta);
      return ok;
    } catch (e) {
      return false;
    }
  }

  /**
   * Format Glances telemetry circuit / recovery error reason.
   */
  function formatGlancesFailureReason(payload) {
    if (!payload) return 'unavailable';
    if (payload.circuit_open) {
      const rem = Number(payload.cooldown_remaining_sec || 0);
      return rem > 0 ? `circuit open, retry in ${Math.ceil(rem)}s` : 'circuit open';
    }
    if (payload.service_state === 'half_open') {
      return `recovery probe failed (${payload.error || 'error'})`;
    }
    return payload.error || 'unavailable';
  }

  /**
   * Universal JSON fetcher with CSRF protection, 401 redirect, and error wrapping.
   */
  async function getJSON(url, opts = {}) {
    const method = String((opts && opts.method) || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      const meta = document.querySelector('meta[name="csrf-token"]');
      const csrfToken = meta ? meta.getAttribute('content') : '';
      if (csrfToken) {
        opts = { ...opts, headers: { ...(opts.headers || {}), 'X-CSRF-Token': csrfToken } };
      }
    }
    const r = await fetch(url, opts);
    if (r.ok) return await r.json();

    if (r.status === 401) {
      try {
        const ct = (r.headers.get('content-type') || '').toLowerCase();
        if (ct.includes('application/json')) {
          const j = await r.clone().json();
          if (j && typeof j === 'object' && (j.error === 'unauthorized' || j.error === 'session_expired' || j.error === 'session_invalidated')) {
            window.location.href = '/login';
          }
        }
      } catch (e) {
      }
    }

    let text = '';
    let data = null;
    try { text = (await r.text()) || ''; } catch (e) { text = ''; }
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
    const err = new Error(`HTTP ${r.status}`);
    err.status = r.status;
    err.url = url;
    err.bodyText = text;
    err.bodyJson = data;
    err.data = data;
    throw err;
  }

  /**
   * Extract human-readable short error message from fetch error.
   */
  function errToShortText(e) {
    if (!e) return '';
    const status = e.status ? `HTTP ${e.status}` : '';
    const j = e.bodyJson;
    if (j && typeof j === 'object') {
      if (j.error) return `${status} ${j.error}`.trim();
      if (j.message) return `${status} ${j.message}`.trim();
      return `${status} ${JSON.stringify(j).slice(0, 120)}`.trim();
    }
    const t = (e.bodyText || e.message || '').trim();
    return `${status} ${t.slice(0, 120)}`.trim();
  }

  /**
   * Create an Error object with an explicit error code and HTTP status.
   */
  function makeCodedError(code, message, status = null) {
    const err = new Error(message || code || 'error');
    err.code = code;
    if (status !== null && status !== undefined) err.status = status;
    return err;
  }

  /**
   * Check if an error was caused by a network disconnect or abort.
   */
  function isNetworkDisconnectError(err) {
    if (!err) return true;
    if (err.code === 'demo_stopped' || err.message === 'demo_stopped') return false;
    if (err.code === 'demo_timeout' || err.message === 'demo_timeout') return false;
    return !(typeof err.status === 'number' && err.status > 0);
  }

  // Export to SDNApp.Utils namespace
  SDNApp.Utils = {
    escHtml,
    fmtNum,
    showToast,
    copyTextToClipboard,
    formatGlancesFailureReason,
    getJSON,
    errToShortText,
    makeCodedError,
    isNetworkDisconnectError,
  };

  // Backwards compatibility globals
  window.escHtml = escHtml;
  window.fmtNum = fmtNum;
  window.showToast = showToast;
  window.copyTextToClipboard = copyTextToClipboard;
  window.formatGlancesFailureReason = formatGlancesFailureReason;
  window.getJSON = getJSON;
  window.errToShortText = errToShortText;
  window.makeCodedError = makeCodedError;
  window.isNetworkDisconnectError = isNetworkDisconnectError;

})(window);
