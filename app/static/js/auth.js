/**
 * auth.js — API key prompt overlay for Tidewall dashboard.
 *
 * When auth is enabled and no key is stored in localStorage,
 * shows a fullscreen overlay prompting for the API key.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'tidewall_api_key';
  var _readyCallbacks = [];
  var _isReady = false;
  var _credentialCallbacks = [];

  // Anything holding data fetched under one credential needs to know when the
  // credential changes, because a value read as one principal must not be shown
  // as another. There was no way to observe that: setStoredKey and
  // clearStoredKey are private and notified nobody, a storage event does not
  // fire for same-tab writes, and re-entering the same key emits nothing at
  // all. So every mutation routes through here.
  function _notifyCredentialChange() {
    _credentialCallbacks.forEach(function (cb) {
      try { cb(); } catch (e) { /* one listener must not stop the others */ }
    });
  }

  function getStoredKey() {
    return localStorage.getItem(STORAGE_KEY);
  }

  function setStoredKey(key) {
    localStorage.setItem(STORAGE_KEY, key);
    // On any accepted entry, including re-entering the same key. Detecting
    // equality would be a cheaper-looking rule that is wrong the moment two
    // keys share a value.
    _notifyCredentialChange();
  }

  function clearStoredKey() {
    localStorage.removeItem(STORAGE_KEY);
    _notifyCredentialChange();
  }

  // Another tab replacing or clearing the key.
  window.addEventListener('storage', function (e) {
    if (e.key === STORAGE_KEY) _notifyCredentialChange();
  });

  function _notifyReady() {
    _isReady = true;
    _readyCallbacks.forEach(function (cb) { cb(); });
    _readyCallbacks = [];
  }

  function showKeyPrompt() {
    // Remove any existing overlay first
    var existing = document.getElementById('auth-overlay');
    if (existing) existing.remove();

    var overlay = document.createElement('div');
    overlay.id = 'auth-overlay';
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;' +
      'background:rgba(13,17,23,0.95);display:flex;align-items:center;justify-content:center;z-index:9999;';

    overlay.innerHTML = '<div style="background:#161b22;border:1px solid #30363d;border-radius:12px;' +
      'padding:40px;max-width:420px;width:90%;text-align:center;">' +
      '<h2 style="color:#f0f6fc;margin:0 0 8px;">Tidewall</h2>' +
      '<p style="color:#8b949e;margin:0 0 24px;">Enter your API key to continue</p>' +
      '<input id="auth-key-input" type="password" placeholder="ak_..." ' +
      'style="width:100%;padding:10px 14px;background:#0d1117;border:1px solid #30363d;' +
      'border-radius:6px;color:#c9d1d9;font-family:monospace;font-size:14px;box-sizing:border-box;" />' +
      '<button id="auth-key-submit" style="margin-top:16px;padding:10px 24px;background:#238636;' +
      'color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px;width:100%;">Authenticate</button>' +
      '<p id="auth-error" style="color:#f85149;margin:12px 0 0;display:none;font-size:13px;"></p>' +
      '</div>';

    document.body.appendChild(overlay);

    var input = document.getElementById('auth-key-input');
    var btn = document.getElementById('auth-key-submit');
    var errEl = document.getElementById('auth-error');

    function tryAuth() {
      var key = input.value.trim();
      if (!key) return;

      // Test the key against /v1/logs/stats (needs viewer+)
      fetch('/v1/logs/stats', {
        headers: { 'Authorization': 'Bearer ' + key }
      }).then(function (resp) {
        if (resp.ok) {
          setStoredKey(key);
          overlay.remove();
          _notifyReady();
        } else if (resp.status === 403) {
          errEl.textContent = 'This key has insufficient permissions for the dashboard. Use an admin or viewer key.';
          errEl.style.display = 'block';
        } else {
          errEl.textContent = 'Invalid API key';
          errEl.style.display = 'block';
        }
      }).catch(function () {
        errEl.textContent = 'Connection error';
        errEl.style.display = 'block';
      });
    }

    btn.addEventListener('click', tryAuth);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') tryAuth();
    });
    input.focus();
  }

  // Check if auth is needed by testing a protected endpoint
  function checkAuth() {
    var key = getStoredKey();
    var headers = key ? { 'Authorization': 'Bearer ' + key } : {};

    fetch('/v1/logs/stats', { headers: headers }).then(function (resp) {
      if (resp.status === 401) {
        clearStoredKey();
        showKeyPrompt();
        // Don't notify ready — wait for user to enter key
      } else {
        // 200 or 403 means auth is fine (or disabled)
        _notifyReady();
      }
    }).catch(function () {
      // Server down — notify ready anyway (pages will show errors)
      _notifyReady();
    });
  }

  // Export for api.js and page scripts
  window.TidewallAuth = {
    getKey: getStoredKey,
    clearKey: clearStoredKey,
    checkAuth: checkAuth,
    /** Register a callback for when auth is confirmed. Fires immediately if already ready. */
    onReady: function (cb) {
      if (_isReady) { cb(); }
      else { _readyCallbacks.push(cb); }
    },
    /**
     * Register a callback for when the stored credential changes.
     *
     * Fires on a key being written, cleared, or re-entered, on a storage event
     * from another tab, and on any 401 -- which is the only way an expired or
     * revoked key becomes observable, so there is an unavoidable delay between
     * revocation and the next response.
     */
    onCredentialChange: function (cb) { _credentialCallbacks.push(cb); },
    /** Called by api.js on any 401. */
    notifyCredentialChange: _notifyCredentialChange,
  };

  // Auto-check on page load
  checkAuth();
})();
