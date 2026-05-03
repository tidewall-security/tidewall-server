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
  { summary: 'Blocked PII', user_id: 'alice', app_id: 'app1', model: 'gpt-4', request_id: 'r1', blocked: true, transformed: false, input_messages: [{ role: 'user', content: 'My SSN is 123' }] },
  { summary: 'Blocked malicious', user_id: 'bob', app_id: 'app2', model: 'gpt-4', request_id: 'r2', blocked: true, transformed: false, input_messages: [{ role: 'user', content: 'Drop tables' }] },
  { summary: 'Transformed topic', user_id: 'carol', app_id: 'app1', model: 'claude', request_id: 'r3', blocked: false, transformed: true, input_messages: [{ role: 'user', content: 'Off topic question' }] },
  { summary: 'Clean request', user_id: 'dave', app_id: 'app3', model: 'claude', request_id: 'r4', blocked: false, transformed: false, input_messages: [{ role: 'user', content: 'Normal question' }] },
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
    expect(result[0].summary).toBe('Transformed topic');
  });

  it('filters clean events', () => {
    var result = filterEvents(testEvents, 'clean', '');
    expect(result).toHaveLength(1);
    expect(result[0].summary).toBe('Clean request');
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

  it('searches within input_messages content', () => {
    var result = filterEvents(testEvents, 'all', 'SSN');
    expect(result).toHaveLength(1);
    expect(result[0].user_id).toBe('alice');
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
