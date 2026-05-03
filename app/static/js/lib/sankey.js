var NODE_COLORS = {
  actor: '#38BDF8',
  application: '#A78BFA',
  model: '#34D399',
};

function linkColor(link) {
  var total = (link.blocked || 0) + (link.transformed || 0) + (link.clean || 0);
  if (total === 0) return 'rgba(52, 211, 153, 0.4)';
  var blockedRatio = (link.blocked || 0) / total;
  var transformedRatio = (link.transformed || 0) / total;
  if (blockedRatio > 0.5) return 'rgba(248, 113, 113, 0.4)';
  if (transformedRatio > 0.3) return 'rgba(251, 191, 36, 0.4)';
  return 'rgba(52, 211, 153, 0.4)';
}

function buildSankeyNodes(flows) {
  return flows.nodes.map(function (n) {
    return {
      name: n.id,
      label: n.name,
      itemStyle: { color: NODE_COLORS[n.category] || '#38BDF8' },
    };
  });
}

function buildSankeyLinks(flows) {
  return flows.links.map(function (l) {
    return {
      source: l.source,
      target: l.target,
      value: l.value,
      lineStyle: { color: linkColor(l) },
    };
  });
}

if (typeof window !== 'undefined') {
  window.__tidewall_lib = window.__tidewall_lib || {};
  window.__tidewall_lib.linkColor = linkColor;
  window.__tidewall_lib.buildSankeyNodes = buildSankeyNodes;
  window.__tidewall_lib.buildSankeyLinks = buildSankeyLinks;
}
