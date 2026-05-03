function filterEvents(events, statusFilter, searchTerm) {
  var result = events;

  if (statusFilter && statusFilter !== 'all') {
    result = result.filter(function (e) {
      if (statusFilter === 'blocked') return e.blocked === true;
      if (statusFilter === 'transformed') return !e.blocked && e.transformed === true;
      if (statusFilter === 'clean') return !e.blocked && !e.transformed;
      return true;
    });
  }

  if (searchTerm) {
    var term = searchTerm.toLowerCase();
    result = result.filter(function (e) {
      var fields = [
        e.summary,
        e.user_id,
        e.app_id,
        e.model,
        e.request_id,
      ];
      for (var i = 0; i < fields.length; i++) {
        if (fields[i] && String(fields[i]).toLowerCase().indexOf(term) !== -1) return true;
      }
      // Search input_messages content
      if (e.input_messages && Array.isArray(e.input_messages)) {
        for (var j = 0; j < e.input_messages.length; j++) {
          var msg = e.input_messages[j];
          if (msg && msg.content && String(msg.content).toLowerCase().indexOf(term) !== -1) {
            return true;
          }
        }
      }
      return false;
    });
  }

  return result;
}

function paginateEvents(events, page, pageSize) {
  var start = (page - 1) * pageSize;
  return events.slice(start, start + pageSize);
}

if (typeof window !== 'undefined') {
  window.__tidewall_lib = window.__tidewall_lib || {};
  window.__tidewall_lib.filterEvents = filterEvents;
  window.__tidewall_lib.paginateEvents = paginateEvents;
}
