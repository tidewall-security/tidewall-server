import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let normalizeMessages;

beforeAll(() => {
  // Simulate browser environment
  globalThis.window = globalThis;
  globalThis.__tidewall_lib = {};

  // Evaluate the script in global context (like a <script> tag)
  const src = readFileSync(
    join(__dirname, '../../app/static/js/lib/messages.js'),
    'utf8'
  );
  const fn = new Function(src);
  fn();

  normalizeMessages = globalThis.__tidewall_lib.normalizeMessages;
});

describe('normalizeMessages', () => {
  it('converts a string to a single-element array', () => {
    expect(normalizeMessages('hello')).toEqual([
      { role: 'user', content: 'hello' },
    ]);
  });

  it('converts an array of strings to array of objects', () => {
    expect(normalizeMessages(['hi', 'there'])).toEqual([
      { role: 'user', content: 'hi' },
      { role: 'user', content: 'there' },
    ]);
  });

  it('passes through an array of objects unchanged', () => {
    const input = [{ role: 'assistant', content: 'ok' }];
    expect(normalizeMessages(input)).toBe(input);
  });

  it('converts an empty string to a single-element array', () => {
    expect(normalizeMessages('')).toEqual([
      { role: 'user', content: '' },
    ]);
  });

  it('returns null for null input', () => {
    expect(normalizeMessages(null)).toBeNull();
  });

  it('returns undefined for undefined input', () => {
    expect(normalizeMessages(undefined)).toBeUndefined();
  });

  it('returns an empty array unchanged', () => {
    expect(normalizeMessages([])).toEqual([]);
  });
});
