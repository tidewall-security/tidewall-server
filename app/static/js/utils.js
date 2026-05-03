/**
 * utils.js — Shared utility functions for Tidewall UI.
 */
var Utils = (function () {
  'use strict';

  var DETECTOR_DISPLAY_NAMES = {
    malicious_prompt: 'Malicious Prompt',
    confidential_and_pii_entity: 'Confidential & PII',
    secret_and_key_entity: 'Secrets & Keys',
    topic: 'Topic Detection',
    language: 'Language',
    code: 'Code Detection',
    competitors: 'Competitors',
    custom_entity: 'Custom Entity',
    malicious_entity: 'Malicious Entity',
    emoji: 'Emoji'
  };

  function escHtml(s) {
    if (s == null) return '';
    var div = document.createElement('div');
    div.textContent = String(s);
    return div.innerHTML;
  }

  function escAttr(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function truncate(s, n) {
    if (!s) return '';
    return s.length > n ? s.slice(0, n) + '...' : s;
  }

  function formatTime(ts) {
    if (!ts) return '--';
    try {
      var d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (e) {
      return ts;
    }
  }

  function formatDate(ts) {
    if (!ts) return '--';
    try {
      var d = new Date(ts);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return ts;
    }
  }

  function detectorDisplayName(key) {
    return DETECTOR_DISPLAY_NAMES[key] || key.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  // Status badge HTML
  function statusBadge(status) {
    var map = {
      'blocked': 'badge-blocked',
      'transformed': 'badge-transformed',
      'allowed': 'badge-allowed',
      'alerted': 'badge-alerted',
      'reported': 'badge-reported',
    };
    var cls = map[(status || '').toLowerCase()] || 'badge-allowed';
    var label = status ? status.toUpperCase() : 'ALLOWED';
    return '<span class="badge ' + cls + '">' + escHtml(label) + '</span>';
  }

  // Detector chip HTML
  function detectorChip(detectorName) {
    var display = detectorDisplayName(detectorName);
    return '<span class="detector-chip">' + escHtml(display) + '</span>';
  }

  // Stat card HTML
  function statCard(label, value, colorVar, accentClass) {
    return '<div class="stat-card ' + (accentClass || '') + '">' +
      '<div class="stat-label">' + escHtml(label) + '</div>' +
      '<div class="stat-number" style="color:var(' + escAttr(colorVar) + ')">' + escHtml(value) + '</div>' +
    '</div>';
  }

  return {
    escHtml: escHtml,
    escAttr: escAttr,
    truncate: truncate,
    formatTime: formatTime,
    formatDate: formatDate,
    detectorDisplayName: detectorDisplayName,
    DETECTOR_DISPLAY_NAMES: DETECTOR_DISPLAY_NAMES,
    statusBadge: statusBadge,
    detectorChip: detectorChip,
    statCard: statCard
  };
})();
