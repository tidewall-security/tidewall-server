/**
 * findings.js — Findings page: event log table with expandable detail rows,
 * status filter pills, stats row, pagination, and auto-refresh.
 */
(function () {
  'use strict';

  // ---- State ----
  var allEvents = [];
  var filteredEvents = [];
  var currentFilter = 'all';
  var searchTerm = '';
  var currentPage = 1;
  var PAGE_SIZE = 20;
  var refreshTimer = null;
  var expandedRowEl = null;
  var expandedIdx = null;
  var expandedRequestId = null;  // track by request_id (stable across refresh)

  // ---- DOM refs ----
  var tbody = document.getElementById('eventsBody');
  var paginationEl = document.getElementById('pagination');
  var searchInputEl = document.getElementById('searchInput');
  var statsRowEl = document.getElementById('statsRow');
  var statusFilterEl = document.getElementById('statusFilter');

  // ---- Init ----
  function init() {
    renderFilterPills();
    bindSearch();
    bindAutoRefresh();
    bindClearLogs();
    refresh();
    startAutoRefresh();
  }

  function bindClearLogs() {
    var btn = document.getElementById('clearLogs');
    if (!btn) return;
    btn.addEventListener('click', function () {
      if (!confirm('Delete all findings? This cannot be undone.')) return;
      API.deleteLogs().then(function () {
        allEvents = [];
        filteredEvents = [];
        expandedIdx = null;
        expandedRowEl = null;
        expandedRequestId = null;
        renderStats({ total: 0, blocked: 0, transformed: 0, clean: 0 });
        applyFilters();
        var checkbox = document.getElementById('autoRefresh');
        if (checkbox && checkbox.checked) startAutoRefresh();
      }).catch(function (err) {
        alert('Failed to clear logs: ' + err.message);
      });
    });
  }

  // ---- Data fetching ----
  function refresh() {
    Promise.all([
      API.getStats(),
      API.getLogs({ limit: 100 })
    ]).then(function (results) {
      renderStats(results[0]);
      allEvents = results[1] || [];
      applyFilters();
    }).catch(function (err) {
      console.error('Findings refresh error:', err);
    });
  }

  // ---- Stats row ----
  function renderStats(s) {
    if (!s || !statsRowEl) return;
    statsRowEl.innerHTML =
      Utils.statCard('Total', s.total || 0, '--brand', '') +
      Utils.statCard('Blocked', s.blocked || 0, '--status-blocked', '') +
      Utils.statCard('Transformed', s.transformed || 0, '--status-transformed', '') +
      Utils.statCard('Clean', s.clean || 0, '--status-allowed', '');
  }

  // ---- Status filter pills ----
  var PILLS = [
    { key: 'all',         label: 'All',         cls: '' },
    { key: 'blocked',     label: 'Blocked',     cls: 'pill-blocked' },
    { key: 'transformed', label: 'Transformed', cls: 'pill-transformed' },
    { key: 'clean',       label: 'Clean',       cls: 'pill-clean' },
  ];

  function renderFilterPills() {
    if (!statusFilterEl) return;
    statusFilterEl.innerHTML = PILLS.map(function (p) {
      var active = p.key === currentFilter ? ' active' : '';
      return '<button class="filter-pill ' + p.cls + active + '" data-filter="' + p.key + '">' + p.label + '</button>';
    }).join('');

    statusFilterEl.querySelectorAll('.filter-pill').forEach(function (btn) {
      btn.addEventListener('click', function () {
        statusFilterEl.querySelectorAll('.filter-pill').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        currentPage = 1;
        applyFilters();
      });
    });
  }

  // ---- Search ----
  function bindSearch() {
    if (!searchInputEl) return;
    searchInputEl.addEventListener('input', function () {
      searchTerm = searchInputEl.value.trim().toLowerCase();
      currentPage = 1;
      applyFilters();
    });
  }

  // ---- Filtering ----
  function getStatus(ev) {
    return ev.status || (ev.blocked ? 'blocked' : ev.transformed ? 'transformed' : 'allowed');
  }

  function applyFilters() {
    filteredEvents = allEvents.filter(function (ev) {
      var status = getStatus(ev);

      if (currentFilter === 'blocked' && status !== 'blocked') return false;
      if (currentFilter === 'transformed' && status !== 'transformed') return false;
      if (currentFilter === 'clean' && status !== 'allowed') return false;

      if (searchTerm) {
        var inputText = '';
        if (ev.input_messages && Array.isArray(ev.input_messages)) {
          inputText = ev.input_messages.map(function (m) { return m.content || ''; }).join(' ');
        }
        var haystack = [
          ev.summary || '',
          ev.user_id || '',
          ev.app_id || '',
          ev.model || '',
          ev.request_id || '',
          inputText
        ].join(' ').toLowerCase();
        if (haystack.indexOf(searchTerm) === -1) return false;
      }

      return true;
    });

    renderTable();
    renderPagination();
  }

  // ---- Auto-refresh ----
  function bindAutoRefresh() {
    var checkbox = document.getElementById('autoRefresh');
    if (!checkbox) return;
    checkbox.addEventListener('change', function () {
      if (this.checked) startAutoRefresh();
      else stopAutoRefresh();
    });
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    refreshTimer = setInterval(refresh, 5000);
  }

  function stopAutoRefresh() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  }

  // ---- Table rendering ----
  function renderTable() {
    if (!tbody) return;
    var start = (currentPage - 1) * PAGE_SIZE;
    var page = filteredEvents.slice(start, start + PAGE_SIZE);

    if (page.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No findings match your filters</td></tr>';
      return;
    }

    var html = '';
    page.forEach(function (ev, idx) {
      var globalIdx = start + idx;
      var status = getStatus(ev);

      // Findings: detector chips for detected detectors
      var chips = '';
      if (ev.detectors_json && typeof ev.detectors_json === 'object') {
        Object.keys(ev.detectors_json).forEach(function (dn) {
          if (dn.charAt(0) === '_') return;  // reserved scan metadata, not a detector
          var di = ev.detectors_json[dn];
          if (di && di.detected) {
            chips += Utils.detectorChip(dn);
          }
        });
      }
      if (!chips) chips = '<span class="text-muted">None</span>';

      // Input text from messages
      var inputText = '';
      if (ev.input_messages && Array.isArray(ev.input_messages)) {
        inputText = ev.input_messages.map(function (m) { return m.content || ''; }).join(' ');
      }

      var timeStr = Utils.formatTime(ev.timestamp);

      html += '<tr class="findings-row" data-idx="' + globalIdx + '">';
      html += '<td class="expand-icon" style="cursor:pointer;user-select:none;">&#9654;</td>';
      html += '<td style="color:var(--text-secondary);">' + Utils.escHtml(timeStr) + '</td>';
      html += '<td>' + Utils.statusBadge(status) + '</td>';
      html += '<td><div class="det-tags">' + chips + '</div></td>';
      html += '<td>' + Utils.escHtml(Utils.truncate(ev.user_id || '--', 24)) + '</td>';
      html += '<td>' + Utils.escHtml(Utils.truncate(ev.app_id || '--', 24)) + '</td>';
      html += '<td>' + Utils.escHtml(Utils.truncate(ev.model || '--', 24)) + '</td>';
      html += '<td class="text-mono" style="color:var(--text-secondary);" title="' + Utils.escAttr(inputText) + '">' + Utils.escHtml(Utils.truncate(inputText, 80)) + '</td>';
      html += '</tr>';

      // Expandable detail row (hidden by default)
      html += '<tr class="expandable-row" id="detail-' + globalIdx + '" style="display:none;">';
      html += '<td colspan="8">' + buildDetailPanel(ev) + '</td>';
      html += '</tr>';
    });

    tbody.innerHTML = html;
    bindRowClicks();

    // Restore previously expanded row after re-render (auto-refresh).
    // We match by request_id (stable) rather than index (shifts when new events arrive).
    expandedRowEl = null;
    expandedIdx = null;
    if (expandedRequestId) {
      var restoredIdx = null;
      for (var ri = 0; ri < page.length; ri++) {
        if (page[ri].request_id === expandedRequestId) {
          restoredIdx = start + ri;
          break;
        }
      }
      if (restoredIdx !== null) {
        var detailRow = document.getElementById('detail-' + restoredIdx);
        if (detailRow) {
          detailRow.style.display = 'table-row';
          var summaryRow = tbody.querySelector('tr[data-idx="' + restoredIdx + '"]');
          if (summaryRow) {
            var icon = summaryRow.querySelector('.expand-icon');
            if (icon) icon.innerHTML = '&#9660;';
          }
          expandedRowEl = detailRow;
          expandedIdx = restoredIdx;
        }
      } else {
        expandedRequestId = null;
      }
    }
  }

  // ---- Detail panel ----
  function buildDetailPanel(ev) {
    var html = '<div class="detail-panel" style="padding:16px 20px;">';

    // Two-column flex layout
    html += '<div style="display:flex;gap:24px;margin-bottom:16px;">';

    // Left column: metadata pairs
    html += '<div style="flex:1;min-width:0;">';
    html += '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-secondary);margin-bottom:10px;">Event Details</div>';
    var metaFields = [
      ['Actor',       ev.user_id],
      ['Application', ev.app_id],
      ['Model',       ev.model],
      ['Provider',    ev.llm_provider],
      ['Event Type',  ev.event_type],
      ['Policy',      ev.policy],
      ['Latency',     ev.latency_ms != null ? ev.latency_ms.toFixed(1) + ' ms' : null],
      ['Request ID',  ev.request_id],
    ];
    metaFields.forEach(function (pair) {
      var val = pair[1] != null && pair[1] !== '' ? pair[1] : '--';
      html += '<div style="display:flex;gap:8px;margin-bottom:6px;font-size:13px;">';
      html += '<span style="color:var(--brand);font-weight:500;min-width:100px;flex-shrink:0;">' + Utils.escHtml(pair[0]) + '</span>';
      html += '<span style="color:var(--text-primary);">' + Utils.escHtml(String(val)) + '</span>';
      html += '</div>';
    });
    html += '</div>';

    // Right column: input messages
    html += '<div style="flex:1;min-width:0;">';
    html += '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-secondary);margin-bottom:10px;">Input Messages</div>';
    if (ev.input_messages && Array.isArray(ev.input_messages) && ev.input_messages.length > 0) {
      ev.input_messages.forEach(function (msg) {
        var role = msg.role || 'user';
        var roleCls = role === 'user' ? 'badge-blocked' : role === 'assistant' ? 'badge-allowed' : 'badge-reported';
        html += '<div style="margin-bottom:10px;">';
        html += '<span class="badge ' + roleCls + '" style="margin-bottom:4px;display:inline-block;">' + Utils.escHtml(role) + '</span>';
        html += '<div style="font-size:13px;color:var(--text-primary);background:var(--bg-primary);border-radius:var(--radius-sm);padding:8px;white-space:pre-wrap;">' + Utils.escHtml(msg.content || '') + '</div>';
        html += '</div>';
      });
    } else {
      html += '<div class="text-muted">No input messages</div>';
    }
    html += '</div>';

    html += '</div>'; // end two-column flex

    // Detector results
    if (ev.detectors_json && typeof ev.detectors_json === 'object') {
      // Reserved metadata keys (e.g. _degraded) are not detectors; rendering
      // them as detector cards showed a nonexistent detector with a "Clear"
      // badge, which is exactly backwards for a degraded scan.
      var detNames = Object.keys(ev.detectors_json).filter(function (n) {
        return n.charAt(0) !== '_';
      });
      if (detNames.length > 0) {
        html += '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-secondary);margin-bottom:10px;">Detector Results</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;">';
        detNames.forEach(function (dn) {
          var di = ev.detectors_json[dn];
          var detected = di && di.detected;
          var borderColor = detected ? 'var(--status-blocked)' : 'var(--border)';
          html += '<div style="background:var(--bg-primary);border:1px solid ' + borderColor + ';border-radius:var(--radius-md);padding:10px 14px;min-width:160px;flex:0 0 auto;">';
          html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">';
          html += '<span style="font-size:13px;font-weight:600;color:var(--text-primary);">' + Utils.escHtml(Utils.detectorDisplayName(dn)) + '</span>';
          html += detected
            ? '<span class="badge badge-blocked" style="margin-left:auto;">Detected</span>'
            : '<span class="badge badge-allowed" style="margin-left:auto;">Clear</span>';
          html += '</div>';
          if (di && di.data) {
            var summary = JSON.stringify(di.data);
            if (summary.length > 120) summary = summary.slice(0, 120) + '...';
            html += '<div style="font-size:11px;color:var(--text-secondary);font-family:var(--font-mono);">' + Utils.escHtml(summary) + '</div>';
          }
          html += '</div>';
        });
        html += '</div>';
      }
    }

    // "Show Raw JSON" button + pre block
    var uid = 'raw-' + Math.random().toString(36).slice(2);
    var rawJson = syntaxHighlightJson(ev);
    html += '<div>';
    html += '<button class="btn btn-ghost" style="font-size:12px;padding:4px 12px;" onclick="(function(){var el=document.getElementById(\'' + uid + '\');el.style.display=el.style.display===\'none\'?\'block\':\'none\';})()">Show Raw JSON</button>';
    html += '<pre class="json-tree" id="' + uid + '" style="display:none;margin-top:8px;">' + rawJson + '</pre>';
    html += '</div>';

    html += '</div>'; // end detail-panel
    return html;
  }

  // ---- JSON syntax highlighting ----
  function syntaxHighlightJson(obj) {
    var json = JSON.stringify(obj, null, 2);
    // Escape HTML first
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    // Apply span classes for syntax highlighting
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
      var cls = 'json-number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'json-key';
        } else {
          cls = 'json-string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'json-bool';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return '<span class="' + cls + '">' + match + '</span>';
    });
  }

  // ---- Row click expand/collapse ----
  function bindRowClicks() {
    tbody.querySelectorAll('.findings-row').forEach(function (row) {
      row.addEventListener('click', function () {
        var idx = row.dataset.idx;
        var detailRow = document.getElementById('detail-' + idx);
        if (!detailRow) return;

        // Collapse previously expanded row (switching to a different row)
        if (expandedRowEl && expandedRowEl !== detailRow) {
          expandedRowEl.style.display = 'none';
          var prevMainRow = expandedRowEl.previousElementSibling;
          if (prevMainRow) {
            var prevIcon = prevMainRow.querySelector('.expand-icon');
            if (prevIcon) prevIcon.innerHTML = '&#9654;';
          }
          expandedRequestId = null;
        }

        var globalIdx = parseInt(idx, 10);
        var ev = filteredEvents[globalIdx];
        var icon = row.querySelector('.expand-icon');
        if (detailRow.style.display === 'none') {
          detailRow.style.display = 'table-row';
          if (icon) icon.innerHTML = '&#9660;';
          expandedRowEl = detailRow;
          expandedIdx = globalIdx;
          expandedRequestId = ev ? ev.request_id : null;
          // Pause auto-refresh while a row is expanded so toggle
          // states (e.g. "Show Raw JSON") are not lost on re-render.
          stopAutoRefresh();
        } else {
          detailRow.style.display = 'none';
          if (icon) icon.innerHTML = '&#9654;';
          expandedRowEl = null;
          expandedIdx = null;
          expandedRequestId = null;
          // Resume auto-refresh when row is collapsed
          var checkbox = document.getElementById('autoRefresh');
          if (checkbox && checkbox.checked) startAutoRefresh();
        }
      });
    });
  }

  // ---- Pagination ----
  function renderPagination() {
    if (!paginationEl) return;
    var totalPages = Math.ceil(filteredEvents.length / PAGE_SIZE) || 1;

    if (totalPages <= 1) {
      paginationEl.innerHTML = '';
      return;
    }

    var prevDisabled = currentPage <= 1 ? ' disabled' : '';
    var nextDisabled = currentPage >= totalPages ? ' disabled' : '';
    paginationEl.innerHTML =
      '<button class="btn btn-ghost"' + prevDisabled + ' data-page="' + (currentPage - 1) + '">&#8592; Prev</button>' +
      '<span style="color:var(--text-secondary);font-size:13px;">Page ' + currentPage + ' of ' + totalPages + '</span>' +
      '<button class="btn btn-ghost"' + nextDisabled + ' data-page="' + (currentPage + 1) + '">Next &#8594;</button>';

    paginationEl.querySelectorAll('button').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var p = parseInt(btn.dataset.page, 10);
        if (p >= 1 && p <= totalPages) {
          currentPage = p;
          renderTable();
          renderPagination();
        }
      });
    });
  }

  // ---- Start (wait for auth) ----
  if (window.TidewallAuth && window.TidewallAuth.onReady) {
    window.TidewallAuth.onReady(init);
  } else {
    init();
  }
})();
