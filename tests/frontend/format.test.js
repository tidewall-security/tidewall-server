import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let escHtml, escAttr, truncate, formatTime, formatDate;

beforeAll(() => {
  globalThis.window = globalThis;
  globalThis.__tidewall_lib = globalThis.__tidewall_lib || {};

  const src = readFileSync(
    join(__dirname, '../../app/static/js/lib/format.js'),
    'utf8'
  );
  const fn = new Function(src);
  fn();

  escHtml = globalThis.__tidewall_lib.escHtml;
  escAttr = globalThis.__tidewall_lib.escAttr;
  truncate = globalThis.__tidewall_lib.truncate;
  formatTime = globalThis.__tidewall_lib.formatTime;
  formatDate = globalThis.__tidewall_lib.formatDate;
});

describe('escHtml', () => {
  it('escapes HTML special characters', () => {
    expect(escHtml('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    );
  });

  it('escapes ampersands and single quotes', () => {
    expect(escHtml("Tom & Jerry's")).toBe('Tom &amp; Jerry&#039;s');
  });

  it('returns empty string for null', () => {
    expect(escHtml(null)).toBe('');
  });

  it('returns empty string for undefined', () => {
    expect(escHtml(undefined)).toBe('');
  });

  it('converts numbers to string', () => {
    expect(escHtml(42)).toBe('42');
  });

  it('handles empty string', () => {
    expect(escHtml('')).toBe('');
  });
});

describe('escAttr', () => {
  it('escapes attribute-relevant characters', () => {
    expect(escAttr('a&b"c<d>e')).toBe('a&amp;b&quot;c&lt;d&gt;e');
  });

  it('returns empty string for null', () => {
    expect(escAttr(null)).toBe('');
  });
});

describe('truncate', () => {
  it('truncates long strings with ellipsis', () => {
    expect(truncate('hello world', 5)).toBe('hello...');
  });

  it('does not truncate short strings', () => {
    expect(truncate('hi', 5)).toBe('hi');
  });

  it('returns empty string for null', () => {
    expect(truncate(null, 5)).toBe('');
  });

  it('handles exact length', () => {
    expect(truncate('hello', 5)).toBe('hello');
  });
});

describe('formatTime', () => {
  it('formats a timestamp to time string', () => {
    var result = formatTime('2024-01-15T10:30:00Z');
    expect(result).not.toBe('--');
    expect(typeof result).toBe('string');
  });

  it('returns -- for falsy values', () => {
    expect(formatTime(null)).toBe('--');
    expect(formatTime(undefined)).toBe('--');
    expect(formatTime('')).toBe('--');
    expect(formatTime(0)).toBe('--');
  });
});

describe('formatDate', () => {
  it('formats a timestamp to date+time string', () => {
    var result = formatDate('2024-01-15T10:30:00Z');
    expect(result).not.toBe('--');
    expect(result).toContain(' ');
  });

  it('returns -- for falsy values', () => {
    expect(formatDate(null)).toBe('--');
    expect(formatDate(undefined)).toBe('--');
    expect(formatDate('')).toBe('--');
  });
});
