function escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escAttr(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function truncate(s, n) {
  if (s == null) return '';
  var str = String(s);
  if (str.length <= n) return str;
  return str.slice(0, n) + '...';
}

function formatTime(ts) {
  if (!ts) return '--';
  var d = new Date(ts);
  return d.toLocaleTimeString();
}

function formatDate(ts) {
  if (!ts) return '--';
  var d = new Date(ts);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

if (typeof window !== 'undefined') {
  window.__tidewall_lib = window.__tidewall_lib || {};
  window.__tidewall_lib.escHtml = escHtml;
  window.__tidewall_lib.escAttr = escAttr;
  window.__tidewall_lib.truncate = truncate;
  window.__tidewall_lib.formatTime = formatTime;
  window.__tidewall_lib.formatDate = formatDate;
}
