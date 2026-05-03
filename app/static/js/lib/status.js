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
  emoji: 'Emoji',
};

function deriveStatus(blocked, transformed) {
  if (blocked) return 'blocked';
  if (transformed) return 'transformed';
  return 'allowed';
}

function detectorDisplayName(key) {
  if (DETECTOR_DISPLAY_NAMES[key]) return DETECTOR_DISPLAY_NAMES[key];
  // Title-case fallback: replace underscores with spaces, capitalize each word
  return key.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
}

function _escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function statusBadge(status) {
  var safe = _escHtml(status);
  return '<span class="badge badge-' + safe + '">' + safe + '</span>';
}

function detectorChip(detectorName) {
  var safe = _escHtml(detectorName);
  return '<span class="detector-chip">' + safe + '</span>';
}

if (typeof window !== 'undefined') {
  window.__tidewall_lib = window.__tidewall_lib || {};
  window.__tidewall_lib.DETECTOR_DISPLAY_NAMES = DETECTOR_DISPLAY_NAMES;
  window.__tidewall_lib.deriveStatus = deriveStatus;
  window.__tidewall_lib.detectorDisplayName = detectorDisplayName;
  window.__tidewall_lib.statusBadge = statusBadge;
  window.__tidewall_lib.detectorChip = detectorChip;
}
