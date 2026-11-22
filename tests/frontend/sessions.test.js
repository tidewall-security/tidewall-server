// @vitest-environment jsdom
import { it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';

const load = path => readFileSync(new URL('../../app/static/' + path, import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
const page = (items, next_cursor = null) => ({ ok: true, status: 200, json: async () => ({ items, next_cursor }) });

function start() {
  document.body.innerHTML = new DOMParser().parseFromString(load('pages/sessions.html'), 'text/html').body.innerHTML;
  let change;
  let key = 'first';
  window.TidewallAuth = {
    getKey: () => key, onReady: fn => fn(), onCredentialChange: fn => { change = fn; },
    clearKey: vi.fn(), checkAuth: vi.fn(),
  };
  const calls = [];
  globalThis.fetch = (url, options) => new Promise(resolve => calls.push({url, options, resolve}));
  new Function(load('js/api.js') + '\n' + load('js/sessions.js'))();
  return {calls, switchKey: () => { key = 'second'; change(); }};
}
const session = id => ({ session_id: id, agent: 'claude-code', device_id: 'fixture', received_at: '2026-01-01T00:00:00Z', observation_count: 2 });
const obs = kind => ({ kind, assessment_status: 'not_assessed', availability: 'truncated', gaps: ['content_truncated'], channel:'hook', agent_version:'unknown' });

it('renders session details, source gaps and untrusted metadata as text, and fences a previous selection', async () => {
  const {calls} = start();
  calls.find(c => c.url === '/v1/agent-sessions').resolve(page([session('one'),session('two')]));
  calls.find(c => c.url.includes('unassigned')).resolve(page([]));
  calls.find(c => c.url.includes('health')).resolve(page([]));
  await tick();
  const buttons = [...document.querySelectorAll('#sessions button')];
  buttons[0].click(); buttons[1].click();
  expect(calls.at(-2).options.signal.aborted).toBe(true);
  calls.at(-1).resolve(page([obs('<img src=x>')]));
  calls.at(-2).resolve(page([obs('old-session')]));
  await tick();
  const detail = document.querySelector('#observations');
  for (const word of ['Not assessed','truncated','content_truncated','<img src=x>','unknown']) {
    expect(detail.textContent).toContain(word);
  }
  expect(detail.querySelector('img')).toBeNull();
  expect(detail.textContent).not.toContain('old-session');
});

it('clears data synchronously and ignores old successes and unauthorized responses after a credential change', async () => {
  const {calls, switchKey} = start();
  const [a,b,c] = calls;
  a.resolve(page([session('old-principal')]));
  await tick();
  expect(document.body.textContent).toContain('old-principal');
  switchKey();
  expect(document.body.textContent).not.toContain('old-principal');
  expect(b.options.signal.aborted).toBe(true);
  calls.slice(3).forEach(call => call.resolve(page(call.url === '/v1/agent-sessions' ? [session('new-principal')] : [])));
  await tick();
  b.resolve(page([obs('stale-success')]));
  c.resolve({ok:false, status:401});
  await tick();
  expect(window.TidewallAuth.clearKey).not.toHaveBeenCalled();
  expect(document.body.textContent).toContain('new-principal');
  expect(document.body.textContent).not.toContain('stale-success');
});

it('preserves the first page through a failed next page and clears retry feedback after success', async () => {
  const {calls} = start();
  calls[0].resolve(page([session('page-one')], 'opaque-cursor'));
  await tick();
  const list = document.querySelector('#sessions');
  list.querySelector('.more').click();
  expect(calls.at(-1).url).toBe('/v1/agent-sessions?cursor=opaque-cursor');
  calls.at(-1).resolve({ok:false, status:503, json:async () => ({})});
  await tick();
  expect(list.textContent).toContain('page-one');
  expect(list.textContent).toContain('Metadata unavailable');
  list.querySelector('.more').click();
  calls.at(-1).resolve(page([session('page-two')]));
  await tick();
  expect(list.textContent).toContain('page-two');
  expect(list.querySelector('.progress-message')).toBeNull();
});

it('keeps the new credential when a startup auth failure arrives late and clears a cross-tab storage reset', async () => {
  document.body.innerHTML = new DOMParser().parseFromString(load('pages/sessions.html'), 'text/html').body.innerHTML;
  localStorage.setItem('tidewall_api_key', 'old');
  const calls = [];
  globalThis.fetch = (url, options) => new Promise(resolve => calls.push({url, options, resolve}));
  new Function(load('js/auth.js') + '\n' + load('js/api.js') + '\n' + load('js/sessions.js'))();
  localStorage.setItem('tidewall_api_key', 'new');
  window.dispatchEvent(new StorageEvent('storage', {key:'tidewall_api_key'}));
  calls.find(c => c.url === '/v1/agent-sessions').resolve(page([session('valid-session')]));
  await tick();
  calls[0].resolve({ok:false, status:401});
  await tick();
  expect(localStorage.getItem('tidewall_api_key')).toBe('new');
  expect(document.body.textContent).toContain('valid-session');
  localStorage.clear();
  window.dispatchEvent(new StorageEvent('storage', {key:null}));
  expect(document.body.textContent).not.toContain('valid-session');
});
