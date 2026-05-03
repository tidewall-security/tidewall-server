function normalizeMessages(input) {
  if (input == null) return input;
  if (typeof input === 'string') {
    return [{ role: 'user', content: input }];
  }
  if (Array.isArray(input) && input.length > 0 && typeof input[0] === 'string') {
    return input.map(function (m) { return { role: 'user', content: m }; });
  }
  return input;
}

if (typeof window !== 'undefined') {
  window.__tidewall_lib = window.__tidewall_lib || {};
  window.__tidewall_lib.normalizeMessages = normalizeMessages;
}

