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

  return {
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
