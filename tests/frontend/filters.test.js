import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let filterEvents, paginateEvents;

beforeAll(() => {
  globalThis.window = globalThis;
  globalThis.__tidewall_lib = globalThis.__tidewall_lib || {};

  const src = readFileSync(
    join(__dirname, '../../app/static/js/lib/filters.js'),
    'utf8'
  );
  const fn = new Function(src);
  fn();

  filterEvents = globalThis.__tidewall_lib.filterEvents;
  paginateEvents = globalThis.__tidewall_lib.paginateEvents;
});

var testEvents = [
  // No summary and no input_messages: the event DTO no longer carries either.
  { user_id: 'alice', app_id: 'app1', model: 'gpt-4', request_id: 'r1', blocked: true, transformed: false, evidence: { confidential_and_pii_entity: { detected: true, entities: [{ type: 'US_SSN', count: 1 }] } } },
  { user_id: 'bob', app_id: 'app2', model: 'gpt-4', request_id: 'r2', blocked: true, transformed: false, evidence: { malicious_prompt: { detected: true } } },
  { user_id: 'carol', app_id: 'app1', model: 'claude', request_id: 'r3', blocked: false, transformed: true, evidence: { topic: { detected: true } } },
  { user_id: 'dave', app_id: 'app3', model: 'claude', request_id: 'r4', blocked: false, transformed: false, evidence: {} },
];

describe('filterEvents', () => {
  it('returns all events with no filter', () => {
    expect(filterEvents(testEvents, 'all', '')).toHaveLength(4);
  });

  it('filters blocked events', () => {
    var result = filterEvents(testEvents, 'blocked', '');
    expect(result).toHaveLength(2);
    expect(result.every(function (e) { return e.blocked; })).toBe(true);
  });

  it('filters transformed events', () => {
    var result = filterEvents(testEvents, 'transformed', '');
    expect(result).toHaveLength(1);
    expect(result[0].user_id).toBe('carol');
  });

  it('filters clean events', () => {
    var result = filterEvents(testEvents, 'clean', '');
    expect(result).toHaveLength(1);
    expect(result[0].user_id).toBe('dave');
  });

  it('searches by user_id', () => {
    var result = filterEvents(testEvents, 'all', 'alice');
    expect(result).toHaveLength(1);
    expect(result[0].user_id).toBe('alice');
  });

  it('searches by app_id', () => {
    var result = filterEvents(testEvents, 'all', 'app1');
    expect(result).toHaveLength(2);
  });

  it('searches case insensitively', () => {
    var result = filterEvents(testEvents, 'all', 'ALICE');
    expect(result).toHaveLength(1);
    expect(result[0].user_id).toBe('alice');
  });

  it('combines filter and search', () => {
    var result = filterEvents(testEvents, 'blocked', 'alice');
    expect(result).toHaveLength(1);
    expect(result[0].user_id).toBe('alice');
    expect(result[0].blocked).toBe(true);
  });

  it('searches evidence detector names and entity types, not content', () => {
    // Content search went with the content. Searching a redacted copy would
    // have been worse: a hit tells you the term was in a prompt you cannot read.
    var result = filterEvents(testEvents, 'all', 'US_SSN');
    expect(result).toHaveLength(1);
    expect(result[0].user_id).toBe('alice');

    var byDetector = filterEvents(testEvents, 'all', 'malicious_prompt');
    expect(byDetector).toHaveLength(1);
    expect(byDetector[0].user_id).toBe('bob');
  });

  it('does not search prompt content even if an event still carries it', () => {
    var withContent = [{ user_id: 'eve', request_id: 'r9', input_messages: [{ role: 'user', content: 'my SSN is 123' }] }];
    expect(filterEvents(withContent, 'all', '123')).toHaveLength(0);
  });
});

describe('paginateEvents', () => {
  var items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

  it('returns first page', () => {
    expect(paginateEvents(items, 1, 3)).toEqual([1, 2, 3]);
  });

  it('returns second page', () => {
    expect(paginateEvents(items, 2, 3)).toEqual([4, 5, 6]);
  });

  it('returns last partial page', () => {
    expect(paginateEvents(items, 4, 3)).toEqual([10]);
  });

  it('returns empty array for out-of-range page', () => {
    expect(paginateEvents(items, 5, 3)).toEqual([]);
  });
});
