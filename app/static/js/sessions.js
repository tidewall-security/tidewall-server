/* Authenticated, policy-scoped collector metadata. */
(function () {
  'use strict';
  const auth = window.TidewallAuth;
  const sections = ['sessions', 'unassigned', 'health', 'observations', 'native-prompts'];
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
      load('native-prompts');
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
  const reportStages = [
    ['Stdout', ['stdout_flushed', 'allow_no_output', 'stdout_failed']],
    ['Native acknowledgement', ['native_ack_blocked']],
    ['Controlled effect', ['effect_allow_marker_verified', 'effect_deny_no_effect_verified']],
    ['Unspecified stage', ['unknown']],
  ];
  function appendReports(card, reports) {
    card.append(element('h4', 'Reporter assertions'));
    for (const [label, stages] of reportStages) {
      const matches = reports.filter(report => stages.includes(report.stage));
      if (!matches.length && !stages.includes('unknown')) card.append(element('p', label + ' · unknown'));
      for (const report of matches) {
        const notes = [report.stage, report.evidence_source, report.report_count + (report.report_count === 1 ? ' report' : ' reports'),
          'latest ' + report.received_at];
        if (report.tool_count != null) notes.push('tools ' + report.tool_count);
        if (report.token_count != null) notes.push('tokens ' + report.token_count);
        if (report.marker_present != null) notes.push('marker ' + report.marker_present);
        card.append(element('p', label + ' · ' + notes.join(' · ')));
      }
    }
  }
  function nativeCard(row) {
    const card = document.createElement('article');
    const decision = row.decision;
    const assessment = decision?.assessment;
    card.append(element('h3', row.agent + ' · UserPromptSubmit'),
      element('p', 'Reported version ' + row.agent_version + ' · Native profile ' + row.native_profile),
      element('p', 'Server received ' + row.received_at + ' · Event ' + row.event_id),
      element('span', assessment ? assessment.status : 'Not assessed', 'assessment'));
    if (decision) {
      card.append(element('p', 'Decision ' + decision.status + ' · Reason ' + (decision.reason ?? 'unknown')),
        element('p', 'Policy revision ' + decision.policy_revision + ' · Mode ' + decision.mode),
        element('p', 'Input state · ' + decision.input_state));
    }
    if (assessment) card.append(element('p', 'Assessment profile ' + assessment.profile + ' · Reason ' + assessment.reason));
    if (assessment?.status === 'assessed') {
      const model = assessment.model_identity;
      card.append(element('p', 'Raw unsafe score · ' + assessment.unsafe_score + ' · ' + assessment.score_kind +
        ' · Input tokens ' + assessment.input_tokens),
        element('p', 'Base model · ' + model.base + ' · Revision ' + model.base_revision),
        element('p', 'Adapter · ' + model.adapter + ' · Revision ' + model.adapter_revision),
        element('p', 'Scorer · ' + model.scoring_implementation));
    }
    const prepared = decision?.response_prepared;
    const preparedLabel = prepared == null ? 'unknown' : (prepared ? 'yes' : 'no');
    card.append(element('p', 'Evaluated action · ' + (decision?.evaluated_action ?? 'unknown') +
      ' · Response prepared · ' + preparedLabel +
      ' · Prepared action · ' + (decision?.prepared_action ?? 'unknown')));
    appendReports(card, decision?.delivery_reports ?? []);
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
  const render = { sessions: sessionCard, unassigned: observationCard, observations: observationCard,
    'native-prompts': nativeCard, health: healthCard };
  const empty = { sessions: 'No retained sessions.', observations: 'No retained observations.',
    'native-prompts': 'No retained native prompts.',
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
    message('native-prompts', 'Choose a session to view its native prompts.');
    if (auth.getKey()) ['sessions', 'unassigned', 'health'].forEach(section => load(section));
  }
  auth.onCredentialChange(reset);
  auth.onReady(reset);
})();
