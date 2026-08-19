/**
 * api.js — HTTP client for Tidewall API.
 */
var API = (function () {
  'use strict';

  async function request(method, url, body) {
    var headers = { 'Content-Type': 'application/json' };

    // Add Bearer token if stored
    var key = window.TidewallAuth && window.TidewallAuth.getKey ? window.TidewallAuth.getKey() : null;
    if (key) {
      headers['Authorization'] = 'Bearer ' + key;
    }

    var opts = { method: method, headers: headers };
    if (body) opts.body = JSON.stringify(body);

    var resp = await fetch(url, opts);
    if (resp.status === 401) {
      // Key expired or invalid — clear and prompt
      if (window.TidewallAuth) window.TidewallAuth.clearKey();
      if (window.TidewallAuth) window.TidewallAuth.checkAuth();
      throw new Error('Authentication required');
    }
    if (!resp.ok) {
      throw new Error('HTTP ' + resp.status + ': ' + resp.statusText);
    }
    if (resp.status === 204) return null;
    return resp.json();
  }

  /**
   * A request whose status the caller can act on.
   *
   * request() throws an Error carrying the status inside its message, so a
   * caller wanting to distinguish 403 from 404 from 503 would have to match on
   * that string. Content retrieval has a distinct panel state per status, and a
   * string-matching contract for that would be one refactor away from silently
   * showing the wrong one.
   */
  async function statusRequest(method, url, options) {
    var headers = { 'Content-Type': 'application/json' };
    var key = window.TidewallAuth && window.TidewallAuth.getKey ? window.TidewallAuth.getKey() : null;
    if (key) headers['Authorization'] = 'Bearer ' + key;

    var opts = { method: method, headers: headers };
    if (options && options.signal) opts.signal = options.signal;

    var resp;
    try {
      resp = await fetch(url, opts);
    } catch (e) {
      // An abort is a deliberate lifecycle action, not a failure to report.
      return { ok: false, status: 0, body: null, aborted: e && e.name === 'AbortError' };
    }

    if (resp.status === 401) {
      // Same handling as request(): clear and re-prompt. clearKey() notifies
      // credential-change listeners, which is how a disclosure fetched under
      // the old key gets discarded.
      if (window.TidewallAuth) window.TidewallAuth.clearKey();
      if (window.TidewallAuth) window.TidewallAuth.checkAuth();
      return { ok: false, status: 401, body: null };
    }

    var body = null;
    try {
      body = resp.status === 204 ? null : await resp.json();
    } catch (e) {
      // A body that is not JSON is a malformed response, not a status.
      return { ok: false, status: resp.status, body: null, malformed: true };
    }
    return { ok: resp.ok, status: resp.status, body: body };
  }

  return {
    /** The caller's own effective content capabilities. Advisory: the content
     *  endpoint stays authoritative. */
    getCapabilities: function () {
      return statusRequest('GET', '/v1/me/capabilities');
    },
    /** Retained content for ONE interaction, in ONE projection. */
    getLogContent: function (interactionId, view, options) {
      return statusRequest(
        'GET',
        '/v1/logs/' + encodeURIComponent(interactionId) + '/content?view=' + encodeURIComponent(view),
        options
      );
    },
    guardChatCompletions: function (messages, eventType, meta) {
      // Normalize: accept a string, array of strings, or array of {role, content}
      var msgs = window.__tidewall_lib && window.__tidewall_lib.normalizeMessages
        ? window.__tidewall_lib.normalizeMessages(messages)
        : messages;
      return request('POST', '/v1/guard_chat_completions', Object.assign({
        guard_input: { messages: msgs },
        event_type: eventType || 'input'
      }, meta || {}));
    },
    getLogs: function (params) {
      var qs = new URLSearchParams(params || {}).toString();
      return request('GET', '/v1/logs' + (qs ? '?' + qs : ''));
    },
    getStats: function () { return request('GET', '/v1/logs/stats'); },
    getFlows: function () { return request('GET', '/v1/logs/flows'); },
    getPolicy: function () { return request('GET', '/v1/policy'); },
    getPolicies: function () { return request('GET', '/v1/policies'); },
    updateDetector: function (name, data) {
      return request('PATCH', '/v1/policy/detectors/' + name, data);
    },
    updateRuleSet: function (policyId, eventType, data) {
      return request('PATCH', '/v1/policies/' + policyId + '/rule-sets/' + eventType, data);
    },
    deleteLogs: function () { return request('DELETE', '/v1/logs'); },
    getHealth: function () { return request('GET', '/health'); },
  };
})();
