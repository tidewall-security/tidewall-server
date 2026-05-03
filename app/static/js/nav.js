/**
 * nav.js — Tidewall navigation bar.
 */
function renderNav(activeId) {
  var NAV_ITEMS = [
    { id: 'visibility', label: 'Visibility', href: '/ui/visibility' },
    { id: 'findings',   label: 'Findings',   href: '/ui/findings' },
    { id: 'policies',   label: 'Policies',    href: '/ui/policies' },
    { id: 'sandbox',    label: 'Sandbox',     href: '/ui/sandbox' },
  ];

  var navEl = document.getElementById('nav');
  if (!navEl) return;

  var tabsHtml = NAV_ITEMS.map(function(item) {
    var cls = 'nav-tab' + (item.id === activeId ? ' active' : '');
    return '<a href="' + item.href + '" class="' + cls + '">' + item.label + '</a>';
  }).join('');

  navEl.innerHTML =
    '<nav class="top-nav">' +
      '<div class="nav-brand">' +
        '<span class="nav-logo">&#9670;</span>' +
        '<span class="nav-name">Tidewall</span>' +
        '<span class="nav-badge">Open Source</span>' +
      '</div>' +
      '<div class="nav-search">' +
        '<input type="text" placeholder="Search events, policies, detectors..." disabled title="Coming soon" />' +
      '</div>' +
      '<div class="nav-tabs">' + tabsHtml + '</div>' +
      '<div class="nav-user">' +
        '<span class="nav-status-dot"></span>' +
        '<span class="nav-status-text">Online</span>' +
        '<button class="nav-user-btn" onclick="alert(\'Coming soon\')">Admin &#9662;</button>' +
      '</div>' +
    '</nav>';
}
