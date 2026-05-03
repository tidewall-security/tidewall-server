/**
 * visibility.js — Sankey diagram page showing AI usage flow patterns.
 */
(function () {
  'use strict';

  var chart = null;

  // ---- Node colors by category ----
  var NODE_COLORS = {
    actor: '#38BDF8',
    application: '#A78BFA',
    model: '#34D399'
  };

  var DET_COLORS = {
    malicious_prompt: '#F87171',
    confidential_and_pii_entity: '#FBBF24',
    secret_and_key_entity: '#FBBF24',
    custom_entity: '#FBBF24',
    malicious_entity: '#F87171',
    topic: '#38BDF8',
    language: '#38BDF8',
    code: '#38BDF8',
    competitors: '#A78BFA',
    emoji: '#A78BFA'
  };

  // ---- Init ----
  async function init() {
    chart = echarts.init(document.getElementById('sankeyChart'));
    window.addEventListener('resize', function () { chart && chart.resize(); });
    document.getElementById('refreshBtn').addEventListener('click', refresh);
    await refresh();
  }

  // ---- Data fetching and rendering ----
  async function refresh() {
    var results = await Promise.all([
      API.getFlows(),
      API.getStats()
    ]);
    var flows = results[0];
    var stats = results[1];

    renderStats(stats);
    renderDetectorBreakdown(stats);
    renderTopActors(flows);
    renderSankey(flows, stats);
  }

  // ---- Stats row ----
  function renderStats(s) {
    if (!s) return;
    var html = '';
    html += Utils.statCard('Total Events', s.total || 0, '--text-primary', 'accent-default');
    html += Utils.statCard('Blocked', s.blocked || 0, '--status-blocked', 'accent-blocked');
    html += Utils.statCard('Transformed', s.transformed || 0, '--status-transformed', 'accent-transformed');
    html += Utils.statCard('Clean', s.clean || 0, '--status-allowed', 'accent-clean');
    document.getElementById('statsRow').innerHTML = html;
  }

  // ---- Detector breakdown ----
  function renderDetectorBreakdown(s) {
    var container = document.getElementById('detectorBars');
    var counts = s && s.detector_counts ? s.detector_counts : {};
    var names = Object.keys(counts);

    var html = '<h3 style="margin:0 0 var(--space-md) 0; font-size:13px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-secondary);">Detector Breakdown</h3>';

    if (names.length === 0) {
      html += '<div class="text-muted" style="font-size:13px;">No detections yet</div>';
      container.innerHTML = html;
      return;
    }

    var max = Math.max.apply(null, names.map(function (n) { return counts[n]; })) || 1;
    names.sort(function (a, b) { return counts[b] - counts[a]; });

    names.forEach(function (name) {
      var pct = Math.max((counts[name] / max) * 100, 4);
      var color = DET_COLORS[name] || '#38BDF8';
      html += '<div class="det-row" style="display:flex; align-items:center; gap:var(--space-sm); margin-bottom:var(--space-sm);">';
      html += '<span class="det-name" style="font-size:12px; color:var(--text-secondary); min-width:0; flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">' + Utils.escHtml(Utils.detectorDisplayName(name)) + '</span>';
      html += '<div class="det-bar-wrap" style="flex:1; background:var(--bg-elevated); border-radius:var(--radius-sm); height:6px; min-width:40px;">';
      html += '<div class="det-bar" style="width:' + pct + '%; background:' + color + '; height:100%; border-radius:var(--radius-sm); transition:width 300ms;"></div>';
      html += '</div>';
      html += '<span class="det-count" style="font-size:12px; font-weight:600; color:' + color + '; min-width:24px; text-align:right;">' + counts[name] + '</span>';
      html += '</div>';
    });

    container.innerHTML = html;
  }

  // ---- Top Actors ----
  function renderTopActors(flows) {
    var container = document.getElementById('topActors');
    if (!flows || !flows.nodes || !flows.links) {
      container.innerHTML = '';
      return;
    }

    // Find actor nodes
    var actorNodes = flows.nodes.filter(function (n) { return n.category === 'actor'; });
    if (actorNodes.length === 0) {
      container.innerHTML = '';
      return;
    }

    // Sum link values per actor id
    var actorCounts = {};
    actorNodes.forEach(function (n) { actorCounts[n.id] = 0; });
    flows.links.forEach(function (l) {
      if (actorCounts.hasOwnProperty(l.source)) {
        actorCounts[l.source] += (l.value || 0);
      }
    });

    // Sort by count descending, take top 5
    var sorted = actorNodes.slice().sort(function (a, b) {
      return (actorCounts[b.id] || 0) - (actorCounts[a.id] || 0);
    }).slice(0, 5);

    var html = '<h3 style="margin:0 0 var(--space-md) 0; font-size:13px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-secondary);">Top Actors</h3>';

    sorted.forEach(function (actor) {
      var name = actor.name || actor.id;
      var count = actorCounts[actor.id] || 0;
      var letter = name.charAt(0).toUpperCase();
      html += '<div style="display:flex; align-items:center; gap:var(--space-sm); margin-bottom:var(--space-sm);">';
      html += '<div style="width:28px; height:28px; border-radius:50%; background:#38BDF8; color:#0C1018; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:700; flex-shrink:0;">' + Utils.escHtml(letter) + '</div>';
      html += '<span style="font-size:12px; color:var(--text-primary); flex:1; min-width:0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="' + Utils.escAttr(name) + '">' + Utils.escHtml(name) + '</span>';
      html += '<span style="font-size:12px; font-weight:600; color:var(--text-secondary);">' + count + '</span>';
      html += '</div>';
    });

    container.innerHTML = html;
  }

  // ---- Sankey chart ----
  function renderSankey(flows) {
    var chartEl = document.getElementById('sankeyChart');
    var emptyEl = document.getElementById('chartEmpty');

    if (!flows || !flows.nodes || flows.nodes.length === 0) {
      chartEl.style.display = 'none';
      emptyEl.style.display = 'block';
      return;
    }

    chartEl.style.display = 'block';
    emptyEl.style.display = 'none';

    // Build id→name lookup
    var idToName = {};
    flows.nodes.forEach(function (n) { idToName[n.id] = n.name; });

    // Build nodes — use id as the ECharts node name for uniqueness
    var nodes = flows.nodes.map(function (n) {
      return {
        name: n.id,
        label: n.name,
        itemStyle: {
          color: NODE_COLORS[n.category] || '#38BDF8'
        }
      };
    });

    // Build links with flow colors based on status mix
    var links = flows.links.map(function (l) {
      var total = (l.blocked || 0) + (l.transformed || 0) + (l.clean || 0) || 1;
      var blockedRatio = (l.blocked || 0) / total;
      var transformedRatio = (l.transformed || 0) / total;
      var color = 'rgba(52, 211, 153, 0.4)';   // green — clean
      if (blockedRatio > 0.5) {
        color = 'rgba(248, 113, 113, 0.4)';     // red — mostly blocked
      } else if (transformedRatio > 0.3) {
        color = 'rgba(251, 191, 36, 0.4)';      // yellow — mostly transformed
      }
      return {
        source: l.source,
        target: l.target,
        value: l.value || 1,
        lineStyle: {
          color: color,
          opacity: 0.4
        },
        emphasis: {
          lineStyle: { opacity: 0.8 }
        }
      };
    });

    var option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        backgroundColor: '#141922',
        borderColor: '#1E2633',
        textStyle: { color: '#F0F6FC', fontSize: 12 },
        formatter: function (params) {
          if (params.dataType === 'node') {
            var data = params.data;
            var display = data.label || idToName[data.name] || data.name;
            var tip = '<strong>' + Utils.escHtml(display) + '</strong>';
            if (data.total != null) {
              tip += '<br>Total events: ' + data.total;
            }
            return tip;
          }
          if (params.dataType === 'edge') {
            var srcName = idToName[params.data.source] || params.data.source;
            var tgtName = idToName[params.data.target] || params.data.target;
            return Utils.escHtml(srcName) + ' \u2192 ' + Utils.escHtml(tgtName) + '<br>Events: ' + params.data.value;
          }
          return '';
        }
      },
      series: [{
        type: 'sankey',
        orient: 'horizontal',
        nodeAlign: 'justify',
        layoutIterations: 32,
        data: nodes,
        links: links,
        label: {
          color: '#F0F6FC',
          fontSize: 12,
          fontFamily: 'Inter, system-ui, sans-serif',
          formatter: function (params) {
            return idToName[params.name] || params.name;
          }
        },
        lineStyle: {
          curveness: 0.5
        },
        emphasis: {
          focus: 'adjacency'
        },
        left: '3%',
        right: '15%',
        top: '8%',
        bottom: '8%'
      }]
    };

    chart.setOption(option, true);
  }

  // ---- Start (wait for auth) ----
  if (window.TidewallAuth && window.TidewallAuth.onReady) {
    window.TidewallAuth.onReady(init);
  } else {
    init();
  }
})();
