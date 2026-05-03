import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let syntaxHighlightJson;

beforeAll(() => {
  globalThis.window = globalThis;
  globalThis.__tidewall_lib = globalThis.__tidewall_lib || {};

  const src = readFileSync(
    join(__dirname, '../../app/static/js/lib/json-highlight.js'),
    'utf8'
  );
  const fn = new Function(src);
  fn();

  syntaxHighlightJson = globalThis.__tidewall_lib.syntaxHighlightJson;
});

describe('syntaxHighlightJson', () => {
  it('wraps string values with json-string class', () => {
    var result = syntaxHighlightJson({ name: 'test' });
    expect(result).toContain('class="json-string"');
    expect(result).toContain('"test"');
  });

  it('wraps keys with json-key class', () => {
    var result = syntaxHighlightJson({ name: 'test' });
    expect(result).toContain('class="json-key"');
    expect(result).toContain('"name"');
  });

  it('wraps numbers with json-number class', () => {
    var result = syntaxHighlightJson({ count: 42 });
    expect(result).toContain('class="json-number"');
    expect(result).toContain('42');
  });

  it('wraps booleans with json-bool class', () => {
    var result = syntaxHighlightJson({ active: true });
    expect(result).toContain('class="json-bool"');
    expect(result).toContain('true');
  });

  it('wraps null with json-null class', () => {
    var result = syntaxHighlightJson({ value: null });
    expect(result).toContain('class="json-null"');
    expect(result).toContain('null');
  });

  it('HTML-escapes content', () => {
    var result = syntaxHighlightJson({ html: '<b>bold</b>' });
    expect(result).toContain('&lt;b&gt;');
    expect(result).not.toContain('<b>');
  });

  it('returns empty string for undefined input', () => {
    expect(syntaxHighlightJson(undefined)).toBe('');
  });
});
