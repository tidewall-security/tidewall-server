/**
 * policies.js — Policy configuration page with header card, rule set tabs,
 * and single-column detector cards.
 */
(function () {
  'use strict';

  // ---- State ----
  var currentPolicy = null;
  var activeEventType = 'input';

  // ---- DOM refs ----
  var policyHeaderEl = document.getElementById('policyHeader');
  var ruleSetTabsEl = document.getElementById('ruleSetTabs');
  var detectorListEl = document.getElementById('detectorList');

  // ---- Init ----
  function init() {
    loadPolicies();
  }

  // ---- Load policies ----
  function loadPolicies() {
    policyHeaderEl.innerHTML = '<span class="text-muted">Loading...</span>';
    detectorListEl.innerHTML = '';

    API.getPolicies().then(function (policies) {
      if (!policies || policies.length === 0) {
        policyHeaderEl.innerHTML = '<span class="text-muted">No policies configured.</span>';
        return;
      }

      // Use first (default) policy
      currentPolicy = policies[0];
      renderPolicyHeader(currentPolicy);
      renderRuleSetTabs();
      renderDetectors();
    }).catch(function (err) {
      policyHeaderEl.innerHTML = '<span class="text-muted">Failed to load policies.</span>';
      console.error('Failed to load policies:', err);
    });
  }

  // ---- Policy header card ----
  function renderPolicyHeader(policy) {
    var detectorCount = countDetectors(policy);
    var ruleSetCount = (policy.rule_sets || []).length;

    var typeBadgeHtml = '<span class="badge" style="background:var(--brand-muted);color:var(--brand);border:1px solid rgba(56,189,248,0.2);">' +
      Utils.escHtml((policy.type || 'application').toLowerCase()) + '</span>';

    var statusBadgeHtml = policy.report_only
      ? '<span class="badge badge-transformed">REPORT ONLY</span>'
      : '<span class="badge badge-allowed">ENFORCING</span>';

    var exportUrl = '/v1/policies/' + Utils.escAttr(policy.id) + '/export';

    policyHeaderEl.innerHTML =
      '<div style="flex:1;min-width:0;">' +
        '<div class="policy-name-row">' +
          '<span class="policy-name">' + Utils.escHtml(policy.name || 'Unnamed Policy') + '</span>' +
          typeBadgeHtml +
          statusBadgeHtml +
        '</div>' +
        '<div class="policy-meta">' +
          Utils.escHtml(detectorCount + ' detector' + (detectorCount !== 1 ? 's' : '')) + ' &middot; ' +
          Utils.escHtml(ruleSetCount + ' rule set' + (ruleSetCount !== 1 ? 's' : '')) +
        '</div>' +
      '</div>' +
      '<div style="display:flex;align-items:center;gap:var(--space-sm);flex-shrink:0;">' +
        '<button class="btn btn-ghost" id="exportYamlBtn" data-url="' + exportUrl + '">Export YAML</button>' +
        '<button class="btn btn-primary" disabled title="Coming soon" style="opacity:0.45;cursor:not-allowed;">+ New Policy</button>' +
      '</div>';

    // Bind export button — fetches with auth header and triggers download
    var exportBtn = document.getElementById('exportYamlBtn');
    if (exportBtn) {
      exportBtn.addEventListener('click', function () {
        var url = exportBtn.dataset.url;
        var key = window.TidewallAuth && window.TidewallAuth.getKey ? window.TidewallAuth.getKey() : null;
        var headers = key ? { 'Authorization': 'Bearer ' + key } : {};
        fetch(url, { headers: headers })
          .then(function (resp) {
            if (!resp.ok) throw new Error('Export failed: ' + resp.status);
            return resp.text();
          })
          .then(function (text) {
            var blob = new Blob([text], { type: 'application/x-yaml' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = (policy.name || 'policy') + '.yaml';
            a.click();
            URL.revokeObjectURL(a.href);
          })
          .catch(function (err) {
            alert('Export failed: ' + err.message);
          });
      });
    }
  }

  function countDetectors(policy) {
    var seen = {};
    (policy.rule_sets || []).forEach(function (rs) {
      Object.keys(rs.detectors || {}).forEach(function (k) { seen[k] = true; });
    });
    return Object.keys(seen).length;
  }

  // ---- Rule set tabs ----
  function renderRuleSetTabs() {
    var tabs = [
      { eventType: 'input',  label: 'Input Rules' },
      { eventType: 'output', label: 'Output Rules' },
    ];

    var html = tabs.map(function (tab) {
      var cls = 'rule-set-tab' + (tab.eventType === activeEventType ? ' active' : '');
      return '<button class="' + cls + '" data-event-type="' + Utils.escAttr(tab.eventType) + '">' +
        Utils.escHtml(tab.label) + '</button>';
    }).join('');

    ruleSetTabsEl.innerHTML = html;

    ruleSetTabsEl.querySelectorAll('.rule-set-tab').forEach(function (btn) {
      btn.addEventListener('click', function () {
        activeEventType = btn.dataset.eventType;
        // Update active class
        ruleSetTabsEl.querySelectorAll('.rule-set-tab').forEach(function (b) {
          b.classList.toggle('active', b.dataset.eventType === activeEventType);
        });
        renderDetectors();
      });
    });
  }

  // ---- Detector list ----
  function renderDetectors() {
    if (!currentPolicy) return;

    detectorListEl.innerHTML = '<span class="text-muted" style="padding:var(--space-md) 0;display:block;">Loading detectors...</span>';

    // Find rule set for active event type
    var ruleSet = null;
    (currentPolicy.rule_sets || []).forEach(function (rs) {
      if (rs.event_type === activeEventType) ruleSet = rs;
    });

    if (!ruleSet) {
      detectorListEl.innerHTML = '<div class="empty-state">No ' + Utils.escHtml(activeEventType) + ' rule set configured.</div>';
      return;
    }

    var detectors = ruleSet.detectors || {};
    var names = Object.keys(detectors);

    if (names.length === 0) {
      detectorListEl.innerHTML = '<div class="empty-state">No detectors configured for this rule set.</div>';
      return;
    }

    var html = names.map(function (name) {
      var det = detectors[name];
      var enabled = det.enabled !== false;
      var action = enabled ? (det.action || 'report') : 'disabled';
      var actionClass = actionToClass(action);

      return '<div class="detector-card ' + actionClass + '" id="card-' + Utils.escAttr(name) + '">' +
        '<div style="flex:1;min-width:0;">' +
          '<div class="detector-name">' + Utils.escHtml(Utils.detectorDisplayName(name)) + '</div>' +
          '<div class="detector-key">' + Utils.escHtml(name) + '</div>' +
        '</div>' +
        '<div class="detector-card-body">' +
          '<label class="toggle-switch">' +
            '<input type="checkbox" class="detector-toggle"' + (enabled ? ' checked' : '') +
              ' data-detector="' + Utils.escAttr(name) + '">' +
            '<span class="toggle-slider"></span>' +
          '</label>' +
          '<select class="action-select" data-detector="' + Utils.escAttr(name) + '">' +
            actionOption('block',    action) +
            actionOption('report',   action) +
            actionOption('redact',   action) +
            actionOption('disabled', action) +
          '</select>' +
        '</div>' +
      '</div>';
    }).join('');

    detectorListEl.innerHTML = html;
    bindDetectorEvents(detectors);
  }

  function actionToClass(action) {
    var map = { block: 'action-block', redact: 'action-redact', report: 'action-report', disabled: 'action-disabled' };
    return map[action] || 'action-report';
  }

  function actionOption(value, current) {
    var labels = { block: 'Block', report: 'Report', redact: 'Redact', disabled: 'Disabled' };
    return '<option value="' + value + '"' + (value === current ? ' selected' : '') + '>' +
      (labels[value] || value) + '</option>';
  }

  // ---- Bind events ----
  function bindDetectorEvents(detectors) {
    // Toggle switches
    detectorListEl.querySelectorAll('.detector-toggle').forEach(function (toggle) {
      toggle.addEventListener('change', function () {
        var name = toggle.dataset.detector;
        var card = document.getElementById('card-' + name);
        var select = card.querySelector('.action-select');
        var enabled = toggle.checked;

        if (!enabled) {
          select.value = 'disabled';
        } else if (select.value === 'disabled') {
          select.value = 'report';
        }

        var newDetectors = buildUpdatedDetectors(detectors, name, {
          enabled: enabled,
          action: enabled ? select.value : (detectors[name] && detectors[name].action ? detectors[name].action : 'report'),
        });
        persistRuleSet(name, newDetectors, select.value);
      });
    });

    // Action dropdowns
    detectorListEl.querySelectorAll('.action-select').forEach(function (select) {
      select.addEventListener('change', function () {
        var name = select.dataset.detector;
        var card = document.getElementById('card-' + name);
        var toggle = card.querySelector('.detector-toggle');
        var action = select.value;
        var enabled = action !== 'disabled';

        toggle.checked = enabled;

        var newDetectors = buildUpdatedDetectors(detectors, name, {
          enabled: enabled,
          action: enabled ? action : (detectors[name] && detectors[name].action ? detectors[name].action : 'report'),
        });
        persistRuleSet(name, newDetectors, action);
      });
    });
  }

  // Build a full updated detectors dict with a single change applied
  function buildUpdatedDetectors(current, changedName, changes) {
    var updated = {};
    Object.keys(current).forEach(function (k) {
      updated[k] = Object.assign({}, current[k]);
    });
    updated[changedName] = Object.assign({}, current[changedName] || {}, changes);
    return updated;
  }

  // Persist via PATCH and flash card
  function persistRuleSet(changedName, newDetectors, action) {
    var card = document.getElementById('card-' + changedName);

    API.updateRuleSet(currentPolicy.id, activeEventType, { detectors: newDetectors }).then(function (result) {
      // Update in-memory detectors for the current rule set
      var ruleSet = null;
      (currentPolicy.rule_sets || []).forEach(function (rs) {
        if (rs.event_type === activeEventType) ruleSet = rs;
      });
      if (ruleSet && result && result.detectors) {
        ruleSet.detectors = result.detectors;
      }

      // Update card border class
      if (card) {
        card.className = card.className.replace(/action-\w+/g, '').trim();
        card.classList.add(actionToClass(action));
        // Flash success
        card.classList.add('flash-success');
        setTimeout(function () { card.classList.remove('flash-success'); }, 800);
      }
    }).catch(function (err) {
      if (card) {
        card.classList.add('flash-error');
        setTimeout(function () { card.classList.remove('flash-error'); }, 800);
      }
      console.error('Failed to update rule set:', err);
    });
  }

  // ---- Start (wait for auth) ----
  if (window.TidewallAuth && window.TidewallAuth.onReady) {
    window.TidewallAuth.onReady(init);
  } else {
    init();
  }
})();
