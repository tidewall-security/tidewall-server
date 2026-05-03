import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let linkColor, buildSankeyNodes, buildSankeyLinks;

beforeAll(() => {
  globalThis.window = globalThis;
  globalThis.__tidewall_lib = globalThis.__tidewall_lib || {};

  const src = readFileSync(
    join(__dirname, '../../app/static/js/lib/sankey.js'),
    'utf8'
  );
  const fn = new Function(src);
  fn();

  linkColor = globalThis.__tidewall_lib.linkColor;
  buildSankeyNodes = globalThis.__tidewall_lib.buildSankeyNodes;
  buildSankeyLinks = globalThis.__tidewall_lib.buildSankeyLinks;
});

describe('linkColor', () => {
  it('returns red for majority blocked', () => {
    expect(linkColor({ blocked: 6, transformed: 2, clean: 2 })).toBe('rgba(248, 113, 113, 0.4)');
  });

  it('returns yellow for >30% transformed (not majority blocked)', () => {
    expect(linkColor({ blocked: 1, transformed: 4, clean: 5 })).toBe('rgba(251, 191, 36, 0.4)');
  });

  it('returns green for mostly clean', () => {
    expect(linkColor({ blocked: 0, transformed: 0, clean: 10 })).toBe('rgba(52, 211, 153, 0.4)');
  });

  it('returns green for zero total', () => {
    expect(linkColor({ blocked: 0, transformed: 0, clean: 0 })).toBe('rgba(52, 211, 153, 0.4)');
  });

  it('returns green when no counts provided', () => {
    expect(linkColor({})).toBe('rgba(52, 211, 153, 0.4)');
  });
});

describe('buildSankeyNodes', () => {
  it('maps nodes with correct colors', () => {
    var flows = {
      nodes: [
        { id: 'user1', name: 'User 1', category: 'actor' },
        { id: 'app1', name: 'App 1', category: 'application' },
        { id: 'model1', name: 'Model 1', category: 'model' },
      ],
    };
    var result = buildSankeyNodes(flows);
    expect(result).toHaveLength(3);
    expect(result[0]).toEqual({ name: 'user1', label: 'User 1', itemStyle: { color: '#38BDF8' } });
    expect(result[1]).toEqual({ name: 'app1', label: 'App 1', itemStyle: { color: '#A78BFA' } });
    expect(result[2]).toEqual({ name: 'model1', label: 'Model 1', itemStyle: { color: '#34D399' } });
  });

  it('uses fallback color for unknown type', () => {
    var flows = { nodes: [{ id: 'x', name: 'X', category: 'unknown' }] };
    var result = buildSankeyNodes(flows);
    expect(result[0].itemStyle.color).toBe('#38BDF8');
  });
});

describe('buildSankeyLinks', () => {
  it('maps links with lineStyle color', () => {
    var flows = {
      links: [
        { source: 'a', target: 'b', value: 10, blocked: 0, transformed: 0, clean: 10 },
      ],
    };
    var result = buildSankeyLinks(flows);
    expect(result).toHaveLength(1);
    expect(result[0].source).toBe('a');
    expect(result[0].target).toBe('b');
    expect(result[0].value).toBe(10);
    expect(result[0].lineStyle.color).toBe('rgba(52, 211, 153, 0.4)');
  });
});
