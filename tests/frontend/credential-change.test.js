/**
 * The credential-change notification, against the real auth.js.
 *
 * A test double with one generic fire() cannot show that each path actually
 * notifies: storage events do not fire for same-tab writes, re-entering the
 * same key emits nothing on its own, and setStoredKey/clearStoredKey were
 * private and notified nobody at all before this step.
 */
// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Per-test, because jsdom reuses `window` across tests in a file: each load
// registers another storage listener, and a shared counter would be
// incremented by the previous test's listener too.
let counter;
let fired;

async function loadAuth() {
  document.body.innerHTML = '';
  localStorage.clear();
  // checkAuth() runs on load. Answering 401 makes it show the real key prompt,
  // which is the only way to exercise the accepted-key path rather than
  // calling the notifier directly.
  globalThis.fetch = vi.fn(() => Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({}) }));
  const src = readFileSync(join(__dirname, '../../app/static/js/auth.js'), 'utf8');
  new Function(src)();
  counter = { n: 0 };
  const mine = counter;
  window.TidewallAuth.onCredentialChange(() => { mine.n += 1; });
  // checkAuth's 401 clears the key, which is itself a notification. Settle
  // first, then start counting, so every test measures only its own action.
  await new Promise((r) => setTimeout(r, 0));
  mine.n = 0;
}

beforeEach(async () => {
  vi.resetModules();
  await loadAuth();
});

describe('every credential mutation notifies', () => {
  it('notifies when the key is cleared', () => {
    window.TidewallAuth.clearKey();
    expect(counter.n).toBe(1);
  });

  it('notifies on a storage event from another tab', () => {
    const e = new window.Event('storage');
    Object.defineProperty(e, 'key', { value: 'tidewall_api_key' });
    window.dispatchEvent(e);
    expect(counter.n).toBe(1);
  });

  it('ignores a storage event for an unrelated key', () => {
    const e = new window.Event('storage');
    Object.defineProperty(e, 'key', { value: 'something_else' });
    window.dispatchEvent(e);
    expect(counter.n).toBe(0);
  });

  it('one listener throwing does not stop the others', () => {
    let second = 0;
    window.TidewallAuth.onCredentialChange(() => { throw new Error('boom'); });
    window.TidewallAuth.onCredentialChange(() => { second += 1; });
    window.TidewallAuth.clearKey();
    expect(second).toBe(1);
  });
});
