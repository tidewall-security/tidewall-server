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

  // ---- Retained content disclosure ----
  //
  // Retrieval is deliberate: nothing about loading, refreshing or expanding may
  // fetch content. A person decides, clicks, and that click produces an audit
  // record with their key on it.
  //
  // `disclosure` holds at most one retrieved value. It is NOT in allEvents or
  // filteredEvents, which survive re-render and are searched by applyFilters --
  // which is exactly how the removed `summary` field became searchable.
  var disclosure = null;           // {interactionId, requestId, view, value, generation, authEpoch}
  var disclosureGeneration = 0;    // bumped to invalidate an in-flight request
  var disclosureAbort = null;
  var authEpoch = 0;               // bumped whenever the stored credential changes
  var listGeneration = 0;          // bumped on every successful /v1/logs fetch
  var capabilities = null;         // null = unknown, {matches, full} once loaded
  var capabilitiesFailed = false;

  /**
   * Drop any retained value and abort any request in flight.
   *
   * Idempotent, and the only way a disclosure ends. Bumping the generation is
   * part of it: clearing the container alone would leave the module object and
   * a pending callback's closure holding the value.
   */
  function clearDisclosure() {
    disclosureGeneration += 1;
    if (disclosureAbort) {
      try { disclosureAbort.abort(); } catch (e) { /* already settled */ }
      disclosureAbort = null;
    }
    disclosure = null;
    var host = document.querySelector('[data-content-value]');
    if (host && host.isConnected) host.textContent = '';
  }

  /**
   * Whether a retained value may be reattached to a rebuilt panel.
   *
   * Five conditions. Which of them actually carry weight is worth stating,
   * because mutation testing showed only some do:
   *
   * 0. LOAD-BEARING. It was fetched against the CURRENT list response.
   *    Interaction ids are reused after DELETE /v1/logs and request_id is
   *    unique only among rows currently present, so no database value can be
   *    proved non-recurring -- but a deleted-and-recreated interaction can only
   *    arrive through a logs fetch. Removing this AND the clear in refresh()
   *    lets a disclosure cross a list response, and the test catches it.
   *
   * 1-4. DEFENCE IN DEPTH, and unreachable while 0 holds: the list-generation
   *    bound already clears before any of them could differ. They are kept
   *    because each was a real defect in an earlier design -- a purge being
   *    undone, a value reappearing under a different credential -- and if the
   *    bound in 0 is ever loosened they become load-bearing again. No test
   *    isolates them, and this comment says so rather than implying otherwise.
   *
   * 1. the same row is still expanded.
   * 2. the view is still permitted. "Unknown" fails this as surely as "no".
   * 3. the server still says content exists.
   * 4. the same credential. Two keys can have identical capabilities and
   *    different audit identities.
   */
  function mayReattach(ev) {
    if (!disclosure || !ev) return false;
    if (disclosure.listGeneration !== listGeneration) return false;
    if (disclosure.interactionId !== ev.id || disclosure.requestId !== ev.request_id) return false;
    if (!capabilities || capabilitiesFailed) return false;
    if (!capabilities[disclosure.view]) return false;
    if (!ev.content_available) return false;
    if (disclosure.authEpoch !== authEpoch) return false;
    return true;
  }

  // ---- DOM refs ----
  var tbody = document.getElementById('eventsBody');
  var paginationEl = document.getElementById('pagination');
  var searchInputEl = document.getElementById('searchInput');
  var statsRowEl = document.getElementById('statsRow');
  var statusFilterEl = document.getElementById('statusFilter');

  // ---- Init ----
  function init() {
    if (window.TidewallAuth && window.TidewallAuth.onCredentialChange) {
      window.TidewallAuth.onCredentialChange(function () {
        // A value read as one principal must not be shown as another.
        authEpoch += 1;
        capabilities = null;
        capabilitiesFailed = false;
        clearDisclosure();
        // And the buttons must go with it. Nulling the state without
        // re-rendering left the previous principal's controls on screen and
        // clickable -- offering an operation the current credential may not
        // have, and inviting a denied read that gets audited against them.
        renderTable();
        loadCapabilities();
      });
    }
    loadCapabilities();
    bindContentClicks();
    bindPageLifecycle();
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
      clearDisclosure();
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
      // A new list response is the only way a deleted-and-recreated
      // interaction can appear, so a retained value never crosses one.
      listGeneration += 1;
      clearDisclosure();
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
        // Metadata and evidence only. Prompt search went with the prompt.
        var evidenceText = '';
        if (ev.evidence && typeof ev.evidence === 'object') {
          evidenceText = Object.keys(ev.evidence).map(function (dn) {
            var ents = (ev.evidence[dn] && ev.evidence[dn].entities) || [];
            return dn + ' ' + ents.map(function (e) { return e.type || ''; }).join(' ');
          }).join(' ');
        }
        var haystack = [
          ev.user_id || '',
          ev.app_id || '',
          ev.model || '',
          ev.request_id || '',
          ev.policy || '',
          evidenceText
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
      if (ev.evidence && typeof ev.evidence === 'object') {
        Object.keys(ev.evidence).forEach(function (dn) {
          if (dn.charAt(0) === '_') return;  // reserved scan metadata, not a detector
          var di = ev.evidence[dn];
          if (di && di.detected) {
            chips += Utils.detectorChip(dn);
          }
        });
      }
      if (!chips) chips = '<span class="text-muted">None</span>';

      // The prompt is not retained, so there is nothing to render here. Say so
      // explicitly rather than leaving a blank cell, which reads as a failure
      // to load rather than a deliberate absence.
      var inputText = '';

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

    // Before the subtree is replaced: if the retained value may not survive
    // this render, drop it now. Clearing the container afterwards would be too
    // late -- the old node is already detached and the module object would
    // still hold the value.
    if (disclosure) {
      var stillHere = null;
      for (var di = 0; di < page.length; di++) {
        if (String(page[di].id) === String(disclosure.interactionId)) { stillHere = page[di]; break; }
      }
      if (!mayReattach(stillHere)) clearDisclosure();
    }

    tbody.innerHTML = html;
    bindRowClicks();
    reattachDisclosure();

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

    // Right column: content state.
    // The prompt is not retained. Say so explicitly — a blank panel reads as a
    // failure to load rather than as a deliberate absence, and an operator who
    // thinks the UI is broken will go looking for the content elsewhere.
    html += '<div style="flex:1;min-width:0;">';
    html += '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-secondary);margin-bottom:10px;">Content</div>';
    if (ev.content_available) {
      html += '<div class="text-muted" style="font-size:13px;">Retained for this policy. You do not have the grant required to view it.</div>';
    } else {
      html += '<div class="text-muted" style="font-size:13px;">Not retained. Tidewall stores what was detected, not the prompt itself.</div>';
    }
    html += '</div>';

    html += '</div>'; // end two-column flex

    // Detector results
    if (ev.evidence && typeof ev.evidence === 'object') {
      // Reserved metadata keys (e.g. _degraded) are not detectors; rendering
      // them as detector cards showed a nonexistent detector with a "Clear"
      // badge, which is exactly backwards for a degraded scan.
      var detNames = Object.keys(ev.evidence).filter(function (n) {
        return n.charAt(0) !== '_';
      });
      if (detNames.length > 0) {
        html += '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-secondary);margin-bottom:10px;">Detector Results</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;">';
        detNames.forEach(function (dn) {
          var di = ev.evidence[dn];
          var detected = di && di.detected;
          var borderColor = detected ? 'var(--status-blocked)' : 'var(--border)';
          html += '<div style="background:var(--bg-primary);border:1px solid ' + borderColor + ';border-radius:var(--radius-md);padding:10px 14px;min-width:160px;flex:0 0 auto;">';
          html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">';
          html += '<span style="font-size:13px;font-weight:600;color:var(--text-primary);">' + Utils.escHtml(Utils.detectorDisplayName(dn)) + '</span>';
          html += detected
            ? '<span class="badge badge-blocked" style="margin-left:auto;">Detected</span>'
            : '<span class="badge badge-allowed" style="margin-left:auto;">Clear</span>';
          html += '</div>';
          // Types and counts, which is what the record holds now.
          if (di && Array.isArray(di.entities) && di.entities.length > 0) {
            var parts = di.entities.map(function (e) { return (e.type || '?') + ' x' + (e.count || 1); });
            html += '<div style="font-size:11px;color:var(--text-secondary);font-family:var(--font-mono);">' + Utils.escHtml(parts.join(', ')) + '</div>';
          }
          if (di && di.failure_code) {
            html += '<div style="font-size:11px;color:var(--status-blocked);">' + Utils.escHtml(di.failure_code) + '</div>';
          }
          html += '</div>';
        });
        html += '</div>';
      }
    }

    // The stored record, in full.
    //
    // The plan said remove this because it dumped the whole event including
    // the prompt. The DTO it renders is now allowlisted and built field by
    // field, so it cannot carry content — and showing an operator exactly what
    // is retained is the honest answer to "what do you keep about me". Renamed
    // so it does not read as a debug escape hatch.
    var uid = 'raw-' + Math.random().toString(36).slice(2);
    var rawJson = syntaxHighlightJson(ev);
    html += '<div>';
    html += '<button class="btn btn-ghost" style="font-size:12px;padding:4px 12px;" onclick="(function(){var el=document.getElementById(\'' + uid + '\');el.style.display=el.style.display===\'none\'?\'block\':\'none\';})()">Show stored record</button>';
    html += '<pre class="json-tree" id="' + uid + '" style="display:none;margin-top:8px;">' + rawJson + '</pre>';
    html += '</div>';

    html += buildContentSection(ev);

    html += '</div>'; // end detail-panel
    return html;
  }

  /**
   * Put a still-valid retained value back into its rebuilt panel.
   *
   * No request is made here, ever. This exists so that typing in the search box
   * -- which re-renders on every keystroke -- does not erase a value the
   * operator deliberately retrieved, which would train them to disable
   * auto-refresh or click repeatedly, producing duplicate audit records nobody
   * asked for.
   */
  function reattachDisclosure() {
    if (!disclosure || !tbody) return;
    var section = findSectionFor(disclosure.interactionId);
    if (!section) return;
    renderContentSection(section, disclosure.value);
  }

  function findSectionFor(interactionId) {
    if (!tbody) return null;
    var sections = tbody.querySelectorAll('.content-section');
    for (var i = 0; i < sections.length; i++) {
      var btn = sections[i].querySelector('.content-btn');
      if (btn && String(btn.getAttribute('data-content-id')) === String(interactionId)) return sections[i];
    }
    return null;
  }

  // ---- The one place a content request is made ----
  //
  // Delegated and bound once, so nothing needs rebinding after
  // tbody.innerHTML replaces the subtree -- and so there is exactly one
  // listener that can ever call getLogContent.
  function bindContentClicks() {
    if (!tbody) return;
    tbody.addEventListener('click', function (e) {
      var hide = e.target.closest ? e.target.closest('.content-hide') : null;
      if (hide) {
        // The buttons sit in the detail row rather than the summary row, so
        // today nothing would collapse. Kept because that is a layout fact, not
        // an invariant, and a click that both discloses and collapses would be
        // a bad surprise.
        e.stopPropagation();
        var section = hide.closest('.content-section');
        clearDisclosure();
        if (section) renderContentSection(section, null);
        var trigger = section ? section.querySelector('.content-btn') : null;
        if (trigger && trigger.isConnected) trigger.focus();
        return;
      }

      var btn = e.target.closest ? e.target.closest('.content-btn') : null;
      if (!btn) return;
      e.stopPropagation();
      requestContent(btn);
    });
  }

  function requestContent(btn) {
    var section = btn.closest('.content-section');
    if (!section) return;
    var interactionId = btn.getAttribute('data-content-id');
    var view = btn.getAttribute('data-content-view');
    var ev = findEventById(interactionId);
    if (!ev) return;

    // Requesting the other projection replaces the first.
    clearDisclosure();

    var generation = disclosureGeneration;
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    disclosureAbort = controller;

    setButtonsBusy(section, true);
    setStatus(section, '');

    API.getLogContent(interactionId, view, controller ? { signal: controller.signal } : undefined)
      .then(function (res) {
        // A stale response must not be written into a rebuilt panel, and an
        // aborted one is a lifecycle action rather than something to report.
        if (generation !== disclosureGeneration) return;
        if (!section.isConnected) return;
        setButtonsBusy(section, false);
        if (res.aborted) return;

        if (res.ok && res.status === 200) {
          var value = validateBody(res.body, interactionId, view);
          if (value === null) {
            setStatus(section, 'The response could not be read.');
            return;
          }
          disclosure = {
            interactionId: ev.id,
            requestId: ev.request_id,
            view: view,
            value: value,
            generation: generation,
            authEpoch: authEpoch,
            listGeneration: listGeneration
          };
          renderContentSection(section, value);
        } else {
          if (res.status === 403) {
            // The endpoint is authoritative; the advisory snapshot was stale.
            // Re-render so the control actually goes away: updating only the
            // hidden state left a denied button sitting there, immediately
            // retryable, while the comment claimed the UI had updated.
            capabilities = Object.assign({}, capabilities);
            capabilities[view] = false;
            var message = statusMessage(res);
            renderTable();
            var rebuilt = findSectionFor(interactionId);
            if (rebuilt) setStatus(rebuilt, message);
            return;
          }
          setStatus(section, statusMessage(res));
        }
      });
  }

  function statusMessage(res) {
    if (res.malformed) return 'The response could not be read.';
    switch (res.status) {
      case 400: return 'The request was not valid.';
      case 401: return 'Your session is no longer authenticated.';
      case 403: return 'You do not have the grant for this view.';
      case 404: return 'This content is no longer available.';
      case 500: return 'The stored content could not be read.';
      // The truthful wording: nothing appeared because the access could not be
      // recorded, not because the content is missing.
      case 503: return 'Content access could not be recorded, so it was not shown.';
      default: return 'The request failed.';
    }
  }

  /**
   * Validate a 200 body before anything is rendered.
   *
   * Allowlisting which fields are displayed is not validation. A response must
   * also be ABOUT the request: one describing a different interaction or view
   * is malformed, not something to render.
   */
  function validateBody(body, interactionId, view) {
    if (!body || typeof body !== 'object') return null;
    if (String(body.interaction_id) !== String(interactionId)) return null;
    if (body.view !== view) return null;
    if (typeof body.captured_at !== 'string') return null;
    if (body.expires_at !== null && typeof body.expires_at !== 'string') return null;
    if (!validMatches(body.matches)) return null;

    var out = { captured_at: body.captured_at, expires_at: body.expires_at, matches: body.matches };
    if (view === 'full') {
      if (!nullOrArray(body.messages) || !nullOrArray(body.tools) || !nullOrArray(body.output)) return null;
      out.messages = body.messages;
      out.tools = body.tools;
      out.output = body.output;
    }
    // Anything else in the body is ignored. A future server field must be added
    // here deliberately rather than appearing because a dump found it.
    return out;
  }

  function nullOrArray(v) { return v === null || Array.isArray(v); }

  function validMatches(m) {
    if (m === null) return true;
    if (typeof m !== 'object' || Array.isArray(m)) return false;
    return typeof m.schema_version === 'number' && Array.isArray(m.matches);
  }

  function findEventById(interactionId) {
    for (var i = 0; i < filteredEvents.length; i++) {
      if (String(filteredEvents[i].id) === String(interactionId)) return filteredEvents[i];
    }
    return null;
  }

  function setButtonsBusy(section, busy) {
    section.querySelectorAll('.content-btn').forEach(function (b) {
      b.disabled = busy;
      if (busy) b.setAttribute('aria-busy', 'true');
      else b.removeAttribute('aria-busy');
    });
  }

  function setStatus(section, text) {
    var el = section.querySelector('.content-status');
    if (el) el.textContent = text;  // never innerHTML
  }

  /**
   * Show or clear a retrieved value.
   *
   * textContent only, so there is no escaping question for the value. Objects
   * go through JSON.stringify into a <pre>, which makes every untrusted key and
   * scalar a text node by construction -- syntaxHighlightJson() returns HTML
   * from hand-rolled regexes and is deliberately not used here.
   */
  function renderContentSection(section, value) {
    var host = section.querySelector('[data-content-value]');
    var hide = section.querySelector('.content-hide');
    if (!host) return;
    if (value === null) {
      host.textContent = '';
      host.style.display = 'none';
      if (hide) hide.style.display = 'none';
      return;
    }
    var text;
    try {
      text = JSON.stringify(value, null, 2);
    } catch (e) {
      setStatus(section, 'The response could not be read.');
      return;
    }
    host.textContent = text;
    host.style.display = 'block';
    if (hide) hide.style.display = 'inline-block';
    setStatus(section, '');
  }

  // ---- Retained content section ----
  //
  // Emits inert buttons only. This function runs for EVERY row on the page
  // inside renderTable(), so anything that fetched here would fire for every
  // row on every render -- which is the opposite of deliberate.
  function buildContentSection(ev) {
    var html = '<div class="content-section" style="margin-top:16px;">';
    html += '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-secondary);margin-bottom:8px;">Retained content</div>';

    if (capabilitiesFailed) {
      html += '<div class="text-muted" style="font-size:12px;">Permissions could not be checked.</div>';
    } else if (!capabilities) {
      html += '<div class="text-muted" style="font-size:12px;">Checking permissions&hellip;</div>';
    } else if (!capabilities.matches && !capabilities.full) {
      html += '<div class="text-muted" style="font-size:12px;">Retained content requires an additional grant.</div>';
    } else if (!ev.content_available) {
      // A hint, not authority: it is current physical availability, the purge
      // sets it false, and an expired-but-unpurged row still reads true. The
      // button is offered on it; the endpoint decides.
      html += '<div class="text-muted" style="font-size:12px;">No content was retained for this event.</div>';
    } else {
      var id = Utils.escAttr(String(ev.id));
      if (capabilities.matches) {
        html += '<button type="button" class="btn btn-ghost content-btn" data-content-id="' + id + '" data-content-view="matches" style="font-size:12px;padding:4px 12px;margin-right:8px;">Show matches</button>';
      }
      if (capabilities.full) {
        html += '<button type="button" class="btn btn-ghost content-btn" data-content-id="' + id + '" data-content-view="full" style="font-size:12px;padding:4px 12px;margin-right:8px;">Show full content</button>';
      }
      html += '<button type="button" class="btn btn-ghost content-hide" style="font-size:12px;padding:4px 12px;display:none;">Hide</button>';
      html += '<div class="content-status" style="font-size:12px;margin-top:8px;"></div>';
      // The value lives here and nowhere else. textContent only.
      html += '<pre class="json-tree" data-content-value style="display:none;margin-top:8px;white-space:pre-wrap;"></pre>';
    }

    html += '</div>';
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
          // Switching directly from one expanded row to another is a collapse
          // in effect, and must clear before expandedRowEl changes.
          clearDisclosure();
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
          clearDisclosure();
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

  // ---- Capabilities ----
  //
  // Advisory. The content endpoint stays authoritative: a grant revoked after
  // this call still yields 403 there, and the panel updates from that answer.
  function loadCapabilities() {
    if (!window.API || !API.getCapabilities) return;
    API.getCapabilities().then(function (res) {
      if (res && res.ok && res.body && res.body.content) {
        capabilities = {
          matches: res.body.content.matches === true,
          full: res.body.content.full === true
        };
        capabilitiesFailed = false;
      } else {
        // Deliberately distinct from a confirmed absence of grant. Telling an
        // operator they lack a grant when the check merely failed is a lie.
        capabilities = null;
        capabilitiesFailed = true;
      }
      clearDisclosure();
      renderTable();
    });
  }

  // ---- Page lifecycle ----
  function bindPageLifecycle() {
    // visibilitychange fires on every ordinary tab switch and window minimise,
    // not only on walking away, so cross-referencing another tab costs a click
    // and another audit record. That is the accepted plan's "page hiding" and
    // the cost is real.
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') clearDisclosure();
    });
    // Navigation and bfcache. Returning via bfcache must not restore content.
    window.addEventListener('pagehide', function () { clearDisclosure(); });
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
