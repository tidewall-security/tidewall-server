/**
 * Step 7: deliberate content retrieval.
 *
 * The guarantee is that nothing except a person's click fetches retained
 * content. These tests spy on the CONTENT OPERATION rather than on fetch:
 * loading the page legitimately calls logs, stats and capabilities, so a
 * transport-level spy would either fail on valid traffic or be weakened until a
 * content call could hide inside it.
 */
// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CANARY = 'swordfish-42';

function loadFindings() {
  const src = readFileSync(join(__dirname, '../../app/static/js/findings.js'), 'utf8');
  new Function(src)();
}

function makeEvent(overrides) {
  return Object.assign({
    id: 1,
    request_id: 'tw_0000000000000001',
    timestamp: '2026-08-19T00:00:00Z',
    event_type: 'input',
    policy: 'p',
    blocked: false,
    transformed: false,
    latency_ms: 1,
    evidence: {},
    content_available: true
  }, overrides || {});
}

function setupDom() {
  document.body.innerHTML =
    '<div id="statsRow"></div><div id="statusFilter"></div>' +
    '<input id="searchInput"><table><tbody id="eventsBody"></tbody></table>' +
    '<div id="pagination"></div><input type="checkbox" id="autoRefresh">';
}

let contentCalls;
let capabilityResponse;
let contentResponse;

beforeEach(() => {
  vi.resetModules();
  setupDom();
  contentCalls = [];
  capabilityResponse = { ok: true, status: 200, body: { content: { matches: true, full: true } } };
  contentResponse = {
    ok: true,
    status: 200,
    body: {
      interaction_id: 1,
      view: 'full',
      captured_at: '2026-08-19T00:00:00Z',
      expires_at: null,
      messages: [{ role: 'user', content: CANARY }],
      tools: null,
      output: null,
      matches: null
    }
  };

  globalThis.Utils = {
    escHtml: (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    escAttr: (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    formatTime: () => '00:00',
    truncate: (s, n) => String(s == null ? '' : s).slice(0, n),
    statusBadge: () => '<span></span>',
    detectorChip: () => '<span></span>',
    statCard: () => '<div></div>'
  };

  globalThis.API = {
    getStats: () => Promise.resolve({}),
    getLogs: () => Promise.resolve([makeEvent()]),
    deleteLogs: () => Promise.resolve(),
    getCapabilities: () => Promise.resolve(capabilityResponse),
    getLogContent: (id, view, opts) => {
      contentCalls.push({ id, view, opts });
      return Promise.resolve(contentResponse);
    }
  };

  globalThis.TidewallAuth = {
    _cbs: [],
    onReady: (cb) => cb(),
    onCredentialChange(cb) { this._cbs.push(cb); },
    fireCredentialChange() { this._cbs.forEach((cb) => cb()); }
  };
});

const flush = () => new Promise((r) => setTimeout(r, 0));

describe('no content request without a click', () => {
  it('does not fetch content on load', async () => {
    loadFindings();
    await flush();
    expect(contentCalls).toEqual([]);
  });

  it('does not fetch content when a row is expanded', async () => {
    loadFindings();
    await flush();
    document.querySelector('.findings-row').click();
    await flush();
    expect(contentCalls).toEqual([]);
  });

  it('does not fetch content on a search render', async () => {
    loadFindings();
    await flush();
    const input = document.getElementById('searchInput');
    input.value = 'a';
    input.dispatchEvent(new window.Event('input'));
    await flush();
    expect(contentCalls).toEqual([]);
  });

  it('renders a button rather than fetching, for every row on the page', async () => {
    globalThis.API.getLogs = () => Promise.resolve(
      Array.from({ length: 15 }, (_, i) => makeEvent({ id: i + 1, request_id: 'tw_' + String(i).padStart(16, '0') }))
    );
    loadFindings();
    await flush();
    expect(document.querySelectorAll('.content-btn').length).toBeGreaterThan(15);
    expect(contentCalls).toEqual([]);
  });
});

describe('a click, and exactly one', () => {
  it('fetches the requested view once', async () => {
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    expect(contentCalls.length).toBe(1);
    expect(contentCalls[0].view).toBe('full');
  });

  it('does not fetch twice on a rapid double click', async () => {
    loadFindings();
    await flush();
    const btn = document.querySelector('[data-content-view="full"]');
    btn.click();
    btn.click();
    await flush();
    expect(contentCalls.length).toBe(1);
  });

  it('does not collapse the row when the button is clicked', async () => {
    loadFindings();
    await flush();
    document.querySelector('.findings-row').click();
    await flush();
    const detail = document.querySelector('.expandable-row');
    expect(detail.style.display).toBe('table-row');
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    expect(detail.style.display).toBe('table-row');
  });

  it('shows the content', async () => {
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    expect(document.querySelector('[data-content-value]').textContent).toContain(CANARY);
  });
});

describe('the value goes nowhere else', () => {
  async function disclose() {
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
  }

  it('is not in any element attribute', async () => {
    await disclose();
    document.querySelectorAll('*').forEach((el) => {
      for (const attr of el.attributes) {
        expect(attr.value).not.toContain(CANARY);
      }
    });
  });

  it('is not in storage, the URL, or the title', async () => {
    await disclose();
    expect(JSON.stringify(window.localStorage)).not.toContain(CANARY);
    expect(JSON.stringify(window.sessionStorage)).not.toContain(CANARY);
    expect(window.location.href).not.toContain(CANARY);
    expect(document.title).not.toContain(CANARY);
  });

  it('cannot be matched by the search filter', async () => {
    // This is exactly how the removed `summary` field became searchable.
    await disclose();
    const input = document.getElementById('searchInput');
    input.value = CANARY;
    input.dispatchEvent(new window.Event('input'));
    await flush();
    expect(document.getElementById('eventsBody').textContent).toContain('No findings match');
  });
});

describe('hostile content is text, not markup', () => {
  it('creates no element and executes nothing', async () => {
    contentResponse.body.messages = [
      { role: 'user', content: '<img src=x onerror="globalThis.__pwned=1">' },
      { role: 'user', content: '</script><script>globalThis.__pwned=2</script>' }
    ];
    contentResponse.body.tools = [{ name: '<svg onload="globalThis.__pwned=3">', __proto__: 'x' }];
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();

    expect(globalThis.__pwned).toBeUndefined();
    expect(document.querySelectorAll('img').length).toBe(0);
    expect(document.querySelectorAll('svg').length).toBe(0);
    // Present as text, which is the point: an analyst must be able to read it.
    expect(document.querySelector('[data-content-value]').textContent).toContain('onerror');
  });
});

describe('the disclosure lifecycle', () => {
  async function disclose() {
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    expect(document.querySelector('[data-content-value]').textContent).toContain(CANARY);
  }

  const shown = () => document.body.textContent.includes(CANARY);

  it('clears on Hide', async () => {
    await disclose();
    document.querySelector('.content-hide').click();
    await flush();
    expect(shown()).toBe(false);
  });

  it('clears when the row is collapsed', async () => {
    await disclose();
    document.querySelector('.findings-row').click();  // expand
    document.querySelector('.findings-row').click();  // collapse
    await flush();
    expect(shown()).toBe(false);
  });

  it('clears when the page is hidden', async () => {
    await disclose();
    Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
    document.dispatchEvent(new window.Event('visibilitychange'));
    await flush();
    expect(shown()).toBe(false);
  });

  it('clears on pagehide, so bfcache cannot restore it', async () => {
    await disclose();
    window.dispatchEvent(new window.Event('pagehide'));
    await flush();
    expect(shown()).toBe(false);
  });

  it('clears when the credential changes', async () => {
    // Two keys can have identical capabilities and different audit identities.
    await disclose();
    globalThis.TidewallAuth.fireCredentialChange();
    await flush();
    expect(shown()).toBe(false);
  });

  it('clears on clear-logs', async () => {
    await disclose();
    document.body.insertAdjacentHTML('beforeend', '<button id="clearLogs"></button>');
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    window.confirm = () => true;
    document.getElementById('clearLogs').click();
    await flush();
    expect(shown()).toBe(false);
  });
});

describe('continuity, and its five conditions', () => {
  async function disclose() {
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
  }

  const shown = () => document.body.textContent.includes(CANARY);

  it('survives a search render, which does not re-fetch', async () => {
    // The case that motivates continuity: the table re-renders on every
    // keystroke, and erasing the value each time would train an operator to
    // click repeatedly, producing duplicate audit records nobody asked for.
    await disclose();
    const input = document.getElementById('searchInput');
    input.value = 't';   // matches request_id tw_...
    input.dispatchEvent(new window.Event('input'));
    await flush();
    expect(shown()).toBe(true);
    expect(contentCalls.length).toBe(1);  // reattached, never refetched
  });

  async function discloseWithFakeTimers() {
    // Fake timers installed BEFORE load, or the interval created during init()
    // belongs to the real clock and advancing fake timers never fires it.
    //
    // And deliberately WITHOUT expanding the row: expanding pauses the
    // refresh timer, and collapsing to resume it would itself clear the
    // disclosure -- so the test would pass whether or not the refresh cleared
    // anything. The content section is rendered for every row regardless of
    // expansion, so the button can be clicked directly.
    vi.useFakeTimers();
    loadFindings();
    await vi.advanceTimersByTimeAsync(1);
    document.querySelector('[data-content-view="full"]').click();
    await vi.advanceTimersByTimeAsync(1);
  }

  async function driveOneRefresh() {
    await vi.advanceTimersByTimeAsync(5100);
  }

  it('does NOT survive a successful logs fetch', async () => {
    // Condition 0, and the decisive test. A deleted-and-recreated interaction
    // can only arrive through a logs fetch, so bounding the disclosure to the
    // list response it was fetched against removes the whole identity-reuse
    // class -- no database value has to be proved non-recurring.
    await discloseWithFakeTimers();
    expect(shown()).toBe(true);

    await driveOneRefresh();
    vi.useRealTimers();

    expect(shown()).toBe(false);
    expect(contentCalls.length).toBe(1);  // and it did not refetch either
  });

  it('does NOT survive content_available flipping to false', async () => {
    // The purge case. Without it the rebuild renders "no content retained" and
    // reconciliation would paste the deleted value back over that answer.
    await discloseWithFakeTimers();
    expect(shown()).toBe(true);

    globalThis.API.getLogs = () => Promise.resolve([makeEvent({ content_available: false })]);
    await driveOneRefresh();
    vi.useRealTimers();

    expect(shown()).toBe(false);
    expect(document.body.textContent).toContain('No content was retained');
    expect(contentCalls.length).toBe(1);
  });
});

describe('a stale response is discarded', () => {
  // Each of these was a guard no test killed until now.
  function deferredContent() {
    let resolve;
    const pending = new Promise((r) => { resolve = r; });
    globalThis.API.getLogContent = (id, view, opts) => {
      contentCalls.push({ id, view, opts });
      return pending;
    };
    return () => resolve(contentResponse);
  }

  async function clickThen(action) {
    loadFindings();
    await flush();
    const settle = deferredContent();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    await action();
    settle();
    await flush();
    return document.body.textContent.includes(CANARY);
  }

  it('does not write after Hide', async () => {
    expect(await clickThen(async () => {
      const hide = document.querySelector('.content-hide');
      if (hide) hide.click();
    })).toBe(false);
  });

  it('does not write after the page is hidden', async () => {
    expect(await clickThen(async () => {
      Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
      document.dispatchEvent(new window.Event('visibilitychange'));
    })).toBe(false);
  });

  it('does not write after pagehide', async () => {
    expect(await clickThen(async () => {
      window.dispatchEvent(new window.Event('pagehide'));
    })).toBe(false);
  });

  it('does not write after the credential changes', async () => {
    expect(await clickThen(async () => {
      globalThis.TidewallAuth.fireCredentialChange();
      await flush();
    })).toBe(false);
  });

  it('does not write into a rebuilt panel after a filter render', async () => {
    // The detached-container guard: without it a late response writes into a
    // node that is no longer in the document, or into the wrong one.
    expect(await clickThen(async () => {
      const input = document.getElementById('searchInput');
      input.value = 'zzz-matches-nothing';
      input.dispatchEvent(new window.Event('input'));
      await flush();
    })).toBe(false);
  });
});

describe('a 200 must be about the request', () => {
  async function attempt(body) {
    contentResponse = { ok: true, status: 200, body: body };
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    return document.body.textContent;
  }

  const good = () => ({
    interaction_id: 1, view: 'full', captured_at: 'x', expires_at: null,
    messages: [{ content: CANARY }], tools: null, output: null, matches: null
  });

  it('rejects a body describing a different interaction', async () => {
    const text = await attempt(Object.assign(good(), { interaction_id: 99 }));
    expect(text).not.toContain(CANARY);
    expect(text).toContain('could not be read');
  });

  it('rejects a body describing a different view', async () => {
    const text = await attempt(Object.assign(good(), { view: 'matches' }));
    expect(text).not.toContain(CANARY);
  });

  it('rejects a non-string captured_at', async () => {
    expect(await attempt(Object.assign(good(), { captured_at: 12345 }))).not.toContain(CANARY);
  });

  it('rejects a non-array messages', async () => {
    expect(await attempt(Object.assign(good(), { messages: 'a string' }))).not.toContain(CANARY);
  });

  it('rejects a malformed matches block', async () => {
    expect(await attempt(Object.assign(good(), { matches: { schema_version: 'one', matches: [] } })))
      .not.toContain(CANARY);
  });

  it('ignores an unexpected extra field', async () => {
    // A future server field must be added deliberately, not appear because a
    // dump found it.
    const text = await attempt(Object.assign(good(), { surprise: 'extra-' + CANARY }));
    expect(text).toContain(CANARY);      // the messages are rendered
    expect(text).not.toContain('extra-' + CANARY);
  });
});

describe('each status has its own answer', () => {
  async function statusText(res) {
    contentResponse = res;
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    return document.querySelector('.content-status').textContent;
  }

  it('403 says the grant is missing, and removes the control', async () => {
    const text = await statusText({ ok: false, status: 403, body: null });
    expect(text).toContain('grant');
    // The endpoint is authoritative: the advisory button must actually go.
    expect(document.querySelector('[data-content-view="full"]')).toBeNull();
  });

  it('404 says it is no longer available', async () => {
    expect(await statusText({ ok: false, status: 404, body: null })).toContain('no longer available');
  });

  it('500 says the stored content could not be read', async () => {
    expect(await statusText({ ok: false, status: 500, body: null })).toContain('could not be read');
  });

  it('503 says the access could not be recorded, not that content is missing', async () => {
    const text = await statusText({ ok: false, status: 503, body: null });
    expect(text).toContain('recorded');
    expect(text).not.toContain('no longer available');
  });

  it('400 says the request was not valid', async () => {
    expect(await statusText({ ok: false, status: 400, body: null })).toContain('not valid');
  });

  it('a network failure says the request failed', async () => {
    expect(await statusText({ ok: false, status: 0, body: null })).toContain('request failed');
  });

  it('leaves the button retryable after a failure', async () => {
    await statusText({ ok: false, status: 500, body: null });
    const btn = document.querySelector('[data-content-view="full"]');
    expect(btn).not.toBeNull();
    expect(btn.disabled).toBe(false);
  });
});

describe('a credential change replaces the previous principal\'s controls', () => {
  it('reloads capabilities and re-renders', async () => {
    loadFindings();
    await flush();
    expect(document.querySelectorAll('.content-btn').length).toBeGreaterThan(0);

    // The new principal may read nothing.
    capabilityResponse = { ok: true, status: 200, body: { content: { matches: false, full: false } } };
    globalThis.TidewallAuth.fireCredentialChange();
    await flush();

    expect(document.querySelectorAll('.content-btn').length).toBe(0);
    expect(document.body.textContent).toContain('requires an additional grant');
  });
});

describe('capability states are distinguishable', () => {
  it('says permissions could not be checked, rather than claiming no grant', async () => {
    capabilityResponse = { ok: false, status: 500, body: null };
    loadFindings();
    await flush();
    expect(document.body.textContent).toContain('could not be checked');
    expect(document.body.textContent).not.toContain('requires an additional grant');
    expect(document.querySelectorAll('.content-btn').length).toBe(0);
  });

  it('offers only the views the caller has', async () => {
    capabilityResponse = { ok: true, status: 200, body: { content: { matches: true, full: false } } };
    loadFindings();
    await flush();
    expect(document.querySelector('[data-content-view="matches"]')).not.toBeNull();
    expect(document.querySelector('[data-content-view="full"]')).toBeNull();
  });
});

describe('a response for a detached panel is discarded', () => {
  it('does not become visible on a later render', async () => {
    // The generation is still current here -- a search render does not clear a
    // disclosure that has not been set yet -- so only the isConnected check
    // stops the value being stored against a node that left the document.
    // Without it the value is retained and the NEXT render reattaches it,
    // which is how a discarded response becomes visible.
    let resolve;
    const pending = new Promise((r) => { resolve = r; });
    loadFindings();
    await flush();
    globalThis.API.getLogContent = (id, view, opts) => {
      contentCalls.push({ id, view, opts });
      return pending;
    };
    document.querySelector('[data-content-view="full"]').click();
    await flush();

    // Re-render so the panel the request started for is detached.
    const input = document.getElementById('searchInput');
    input.value = 'tw_';           // still matches, so the row stays
    input.dispatchEvent(new window.Event('input'));
    await flush();

    resolve(contentResponse);
    await flush();

    // And render once more: a retained value would be reattached here.
    input.value = 'tw';
    input.dispatchEvent(new window.Event('input'));
    await flush();

    expect(document.body.textContent).not.toContain(CANARY);
  });
});

describe('capability responses are scoped to the credential that asked', () => {
  it('a late response for the previous principal does not restore its buttons', async () => {
    // Responses do not have to arrive in order. Without an epoch check, a
    // request started as principal A resolves after the credential changed and
    // overwrites B's state -- restoring buttons for a principal who may not
    // have them.
    let resolveA;
    const first = new Promise((r) => { resolveA = r; });
    let call = 0;
    globalThis.API.getCapabilities = () => {
      call += 1;
      if (call === 1) return first;
      return Promise.resolve({ ok: true, status: 200, body: { content: { matches: false, full: false } } });
    };

    loadFindings();
    await flush();                                   // request A outstanding

    globalThis.TidewallAuth.fireCredentialChange();   // principal B
    await flush();                                   // request B resolves: no capability
    expect(document.querySelectorAll('.content-btn').length).toBe(0);

    resolveA({ ok: true, status: 200, body: { content: { matches: true, full: true } } });
    await flush();

    expect(document.querySelectorAll('.content-btn').length).toBe(0);
  });
});

describe('full-view body validation', () => {
  async function attempt(body) {
    contentResponse = { ok: true, status: 200, body: body };
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="full"]').click();
    await flush();
    return document.body.textContent;
  }

  const good = () => ({
    interaction_id: 1, view: 'full', captured_at: 'x', expires_at: null,
    messages: [], tools: null, output: null, matches: null
  });

  // A canary INSIDE the malformed value, so the assertion fails if the
  // malformed value is rendered -- the first version put the canary elsewhere
  // and passed while the bad value was displayed.
  it.each(['messages', 'tools', 'output'])('rejects a non-array %s', async (field) => {
    const body = good();
    body[field] = 'not-an-array-' + CANARY;
    const text = await attempt(body);
    expect(text).not.toContain(CANARY);
    expect(text).toContain('could not be read');
  });

  it('rejects a non-string, non-null expires_at', async () => {
    const body = good();
    body.expires_at = { nested: CANARY };
    const text = await attempt(body);
    expect(text).not.toContain(CANARY);
  });

  it('accepts a null expires_at, which means no time expiry', async () => {
    const body = good();
    body.messages = [{ content: CANARY }];
    expect(await attempt(body)).toContain(CANARY);
  });
});

describe('the offered views match the capabilities exactly', () => {
  it.each([
    [{ matches: true, full: true }, ['matches', 'full']],
    [{ matches: true, full: false }, ['matches']],
    [{ matches: false, full: true }, ['full']],
    [{ matches: false, full: false }, []]
  ])('%o offers %o', async (content, expected) => {
    capabilityResponse = { ok: true, status: 200, body: { content: content } };
    loadFindings();
    await flush();
    const offered = Array.from(document.querySelectorAll('.content-btn'))
      .map((b) => b.getAttribute('data-content-view'));
    // One row in the fixture, so one button per allowed view.
    expect(offered).toEqual(expected);
  });
});

describe('the matches block is projected, not passed through', () => {
  const group = (over) => Object.assign({
    detector: 'custom_entity',
    match_type: 'CUSTOM',
    rule_id: null,
    source: { kind: 'message', index: 0, field: 'content', role: 'user' },
    value: 'matched-value',
    occurrences: 1
  }, over || {});

  async function attempt(matches) {
    contentResponse = {
      ok: true,
      status: 200,
      body: { interaction_id: 1, view: 'matches', captured_at: 'x', expires_at: null, matches: matches }
    };
    capabilityResponse = { ok: true, status: 200, body: { content: { matches: true, full: false } } };
    loadFindings();
    await flush();
    document.querySelector('[data-content-view="matches"]').click();
    await flush();
    return document.body.textContent;
  }

  it('rejects an unknown schema version', async () => {
    // The server serves exactly version 1; rendering a version this code does
    // not understand would be guessing at the meaning of forensic evidence.
    const text = await attempt({ schema_version: 2, matches: [group({ value: CANARY })] });
    expect(text).not.toContain(CANARY);
    expect(text).toContain('could not be read');
  });

  it('rejects a malformed group', async () => {
    const text = await attempt({ schema_version: 1, matches: [{ detector: CANARY }] });
    expect(text).not.toContain(CANARY);
  });

  it.each(['detector', 'match_type', 'value'])('rejects a non-string %s', async (field) => {
    // Everything else well-formed, so the earlier source and shape checks
    // cannot be what rejects it -- an earlier version of this test used a group
    // missing its source entirely, and the field-type guard survived removal.
    const over = {};
    over[field] = { nested: CANARY };
    const text = await attempt({ schema_version: 1, matches: [group(over)] });
    expect(text).not.toContain(CANARY);
    expect(text).toContain('could not be read');
  });

  it('rejects a non-number occurrences', async () => {
    const text = await attempt({ schema_version: 1, matches: [group({ occurrences: 'one', value: CANARY })] });
    expect(text).not.toContain(CANARY);
  });

  it('rejects a group with a malformed source', async () => {
    const text = await attempt({
      schema_version: 1,
      matches: [group({ source: { kind: 'message', index: 'zero', field: 'content', role: null }, value: CANARY })]
    });
    expect(text).not.toContain(CANARY);
  });

  it('does not carry an extra key on a group or its source', async () => {
    const text = await attempt({
      schema_version: 1,
      matches: [group({ surprise: 'extra-' + CANARY, source: {
        kind: 'message', index: 0, field: 'content', role: null, alsoSurprise: 'src-' + CANARY
      } })]
    });
    expect(text).toContain('matched-value');   // the known fields are shown
    expect(text).not.toContain('extra-' + CANARY);
    expect(text).not.toContain('src-' + CANARY);
  });

  it('renders a well-formed block', async () => {
    const text = await attempt({ schema_version: 1, matches: [group({ value: CANARY })] });
    expect(text).toContain(CANARY);
  });

  it('accepts a null matches block', async () => {
    const text = await attempt(null);
    expect(text).toContain('"matches": null');
  });
});
