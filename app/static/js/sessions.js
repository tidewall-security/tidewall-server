/* Authenticated, policy-scoped collector metadata. */
(function () {
  'use strict';
  const auth = window.TidewallAuth;
  const sections = ['sessions', 'unassigned', 'health', 'observations'];
  const requests = new Map();
  let epoch = 0;
  let selected = null;
  const panel = section => document.getElementById(section);

  function element(tag, text, cls) {
    const node = document.createElement(tag);
    node.textContent = text;
    if (cls) node.className = cls;
    return node;
  }
  function message(section, text) {
    panel(section).replaceChildren(element('p', text));
  }
  function button(text, onClick, cls) {
    const node = element('button', text, cls);
    node.type = 'button';
    node.addEventListener('click', onClick);
    return node;
  }
  function sessionCard(row) {
    const card = document.createElement('article');
    const link = button(row.session_id, () => {
      selected = row.session_id;
      panel('sessions').querySelectorAll('.session-link').forEach(b => b.setAttribute('aria-pressed', String(b === link)));
      load('observations');
    }, 'session-link');
    link.setAttribute('aria-pressed', String(row.session_id === selected));
    card.append(element('h3', row.agent), link,
      element('p', row.observation_count + ' observations · First received ' + row.received_at),
      element('p', 'Policy ' + row.policy_id + ' · Device ' + row.device_id));
    return card;
  }
  function observationCard(row) {
    const card = document.createElement('article');
    const source = row.provenance || {};
    card.append(element('h3', row.kind + ' · ' + row.channel),
      element('span', 'Not assessed', 'assessment'),
      element('p', 'Source availability · ' + row.availability),
      element('p', 'Gaps · ' + (row.gaps.length ? row.gaps.join(', ') : 'None reported')),
      element('p', 'Server received ' + row.received_at + ' · Source time ' + (row.source_at || 'unknown')),
      element('p', (row.agent || 'Agent') + ' version ' + row.agent_version + ' · Adapter ' + row.adapter_version +
        ' · Profile ' + row.fixture_profile));
    if (source.native_event) card.append(element('p', 'Native hook · ' + source.native_event));
    if (source.record_origin) card.append(element('p', 'Record origin · ' + source.record_origin +
      ' · Byte ' + source.byte_position + ' · Part ' + source.part + ' · Evidence version ' + source.parser_evidence_version));
    if (row.tool_name) card.append(element('p', 'Reported tool · ' + row.tool_name));
    card.append(element('p', 'Event ' + row.event_id + ' · Device ' + row.device_id));
    return card;
  }
  function healthCard(row) {
    const card = document.createElement('article');
    const h = row.heartbeat;
    card.append(element('h3', h ? h.state : 'Heartbeat detail unavailable'),
      element('p', 'Policy ' + row.policy_id + ' · Device ' + row.device_id));
    if (h) card.append(element('p', 'Server received ' + row.received_at + ' · Revision ' + row.heartbeat_revision),
      element('p', h.pending + ' pending · ' + h.queue_bytes + ' queue bytes · Adapter ' + h.adapter_version +
        ' · Agent version ' + row.agent_version));
    const totals = Object.entries(row.totals);
    const losses = totals.filter(entry => entry[1] > 0).map(entry => entry.join(' '));
    card.append(element('p', 'Reported losses · ' + (losses.join(', ') || (totals.length ? '0' : 'unknown'))));
    return card;
  }
  const render = { sessions: sessionCard, unassigned: observationCard, observations: observationCard, health: healthCard };
  const empty = { sessions: 'No retained sessions.', observations: 'No retained observations.',
    unassigned: 'No unassigned observations.', health: 'No collector health reports.' };

  async function load(section, cursor) {
    const old = requests.get(section);
    if (old) old.abort();
    const controller = new AbortController();
    requests.set(section, controller);
    const started = epoch;
    const key = auth.getKey();
    const node = panel(section);
    const current = () => started === epoch && auth.getKey() === key && !controller.signal.aborted;
    if (cursor) {
      node.querySelector('.more')?.remove();
      node.querySelector('.progress-message')?.remove();
      node.append(element('p', 'Loading more…', 'progress-message'));
    } else {
      message(section, 'Loading…');
    }
    try {
      const result = await API.getSessionPage(section, selected, cursor, controller.signal);
      if (!current()) return;
      if (!result.ok || !Array.isArray(result.body?.items)) throw new Error();
      if (!cursor) node.replaceChildren();
      node.querySelector('.progress-message')?.remove();
      const body = result.body;
      body.items.forEach(row => node.append(render[section](row)));
      if (!node.childElementCount) message(section, empty[section]);
      if (body.next_cursor) node.append(button('Load more', () => load(section, body.next_cursor), 'more'));
    } catch {
      if (!current()) return;
      if (cursor) node.querySelector('.progress-message')?.remove();
      else node.replaceChildren();
      node.append(element('p', 'Metadata unavailable.', 'progress-message'),
        button('Retry', () => load(section, cursor), 'more'));
    }
  }
  function reset() {
    epoch++;
    requests.forEach(controller => controller.abort());
    requests.clear();
    selected = null;
    sections.forEach(section => message(section, 'Waiting for authentication…'));
    message('observations', 'Choose a session to view its observations.');
    if (auth.getKey()) ['sessions', 'unassigned', 'health'].forEach(section => load(section));
  }
  auth.onCredentialChange(reset);
  auth.onReady(reset);
})();
