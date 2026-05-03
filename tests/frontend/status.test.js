import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let DETECTOR_DISPLAY_NAMES, deriveStatus, detectorDisplayName, statusBadge, detectorChip;

beforeAll(() => {
  globalThis.window = globalThis;
  globalThis.__tidewall_lib = globalThis.__tidewall_lib || {};

  // Load format.js first (status.js may depend on escHtml)
  const formatSrc = readFileSync(
    join(__dirname, '../../app/static/js/lib/format.js'),
    'utf8'
  );
  new Function(formatSrc)();

  const statusSrc = readFileSync(
    join(__dirname, '../../app/static/js/lib/status.js'),
    'utf8'
  );
  new Function(statusSrc)();

  DETECTOR_DISPLAY_NAMES = globalThis.__tidewall_lib.DETECTOR_DISPLAY_NAMES;
  deriveStatus = globalThis.__tidewall_lib.deriveStatus;
  detectorDisplayName = globalThis.__tidewall_lib.detectorDisplayName;
  statusBadge = globalThis.__tidewall_lib.statusBadge;
  detectorChip = globalThis.__tidewall_lib.detectorChip;
});

describe('deriveStatus', () => {
  it('returns blocked when blocked is true', () => {
    expect(deriveStatus(true, false)).toBe('blocked');
  });

  it('returns blocked when both blocked and transformed are true', () => {
    expect(deriveStatus(true, true)).toBe('blocked');
  });

  it('returns transformed when only transformed is true', () => {
    expect(deriveStatus(false, true)).toBe('transformed');
  });

  it('returns allowed when neither blocked nor transformed', () => {
    expect(deriveStatus(false, false)).toBe('allowed');
  });
});

describe('detectorDisplayName', () => {
  it('returns known display name for malicious_prompt', () => {
    expect(detectorDisplayName('malicious_prompt')).toBe('Malicious Prompt');
  });

  it('returns known display name for confidential_and_pii_entity', () => {
    expect(detectorDisplayName('confidential_and_pii_entity')).toBe('Confidential & PII');
  });

  it('title-cases unknown keys', () => {
    expect(detectorDisplayName('some_new_detector')).toBe('Some New Detector');
  });
});

describe('DETECTOR_DISPLAY_NAMES', () => {
  it('has all 10 expected entries', () => {
    var keys = Object.keys(DETECTOR_DISPLAY_NAMES);
    expect(keys).toHaveLength(10);
    expect(keys).toContain('malicious_prompt');
    expect(keys).toContain('confidential_and_pii_entity');
    expect(keys).toContain('secret_and_key_entity');
    expect(keys).toContain('topic');
    expect(keys).toContain('language');
    expect(keys).toContain('code');
    expect(keys).toContain('competitors');
    expect(keys).toContain('custom_entity');
    expect(keys).toContain('malicious_entity');
    expect(keys).toContain('emoji');
  });
});

describe('statusBadge', () => {
  it('returns a span with badge class', () => {
    expect(statusBadge('blocked')).toBe('<span class="badge badge-blocked">blocked</span>');
  });

  it('escapes HTML in status', () => {
    var result = statusBadge('<script>');
    expect(result).not.toContain('<script>');
    expect(result).toContain('&lt;script&gt;');
  });
});

describe('detectorChip', () => {
  it('returns a span with detector-chip class', () => {
    expect(detectorChip('PII')).toBe('<span class="detector-chip">PII</span>');
  });
});
