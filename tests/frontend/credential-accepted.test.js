/**
 * The accepted-key path notifies.
 *
 * Its own file: auth.js registers a storage listener and runs checkAuth on
 * load, and jsdom reuses one window across a file, so several instances
 * accumulate and the prompt overlay one of them creates is not reliably the one
 * a later test finds. A clean realm is the honest way to exercise this.
 */
// @vitest-environment jsdom
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('a key accepted through the prompt', () => {
  it('notifies on each accepted entry', async () => {
    // Through the prompt's real submit path. An earlier version called
    // notifyCredentialChange() directly, which proved only that a function
    // invokes its callbacks -- and the test name claimed more than that.
    //
    // What this does NOT prove, deliberately: that writing an ALREADY-STORED
    // value notifies. The prompt only appears after a 401, which clears the key
    // first, so that case cannot be reached through this path and an equality
    // check in setStoredKey would survive this test. setStoredKey is
    // unconditional anyway, for the reason given there. Claiming the stronger
    // property here would be claiming more than the test shows.
    document.body.innerHTML = '';
    localStorage.clear();
    globalThis.fetch = vi.fn(() => Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({}) }));

    const src = readFileSync(join(__dirname, '../../app/static/js/auth.js'), 'utf8');
    new Function(src)();
    await new Promise((r) => setTimeout(r, 0));

    const counter = { n: 0 };
    window.TidewallAuth.onCredentialChange(() => { counter.n += 1; });

    globalThis.fetch = vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) }));

    async function acceptTheSameKey() {
      const input = document.getElementById('auth-key-input');
      expect(input).not.toBeNull();
      input.value = 'ak_the_same_key_every_time';
      document.getElementById('auth-key-submit').click();
      await new Promise((r) => setTimeout(r, 0));
    }

    async function reopenThePrompt() {
      globalThis.fetch = vi.fn(() => Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({}) }));
      window.TidewallAuth.checkAuth();
      await new Promise((r) => setTimeout(r, 0));
      globalThis.fetch = vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) }));
    }

    await acceptTheSameKey();
    const afterFirst = counter.n;
    expect(afterFirst).toBeGreaterThanOrEqual(1);
    expect(localStorage.getItem('tidewall_api_key')).toBe('ak_the_same_key_every_time');

    await reopenThePrompt();      // the 401 clears the key, itself a notification
    const beforeSecond = counter.n;

    await acceptTheSameKey();     // a second accepted entry notifies again
    expect(counter.n).toBeGreaterThan(beforeSecond);
    expect(localStorage.getItem('tidewall_api_key')).toBe('ak_the_same_key_every_time');
  });
});
