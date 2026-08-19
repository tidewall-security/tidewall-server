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
