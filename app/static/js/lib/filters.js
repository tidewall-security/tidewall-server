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
      // Content search is gone with the content. Searching prompts required
      // retaining them, which is the finding this closes; searching a redacted
      // copy would have been worse, because a hit would tell you the term was
      // in a prompt you are not allowed to read.
      var fields = [
        e.user_id,
        e.app_id,
        e.model,
        e.request_id,
        e.policy,
        e.event_type,
        e.status,
      ];
      for (var i = 0; i < fields.length; i++) {
        if (fields[i] && String(fields[i]).toLowerCase().indexOf(term) !== -1) return true;
      }
      // Detector names and entity types are searchable: they are the evidence.
      if (e.evidence && typeof e.evidence === 'object') {
        var names = Object.keys(e.evidence);
        for (var j = 0; j < names.length; j++) {
          if (names[j].toLowerCase().indexOf(term) !== -1) return true;
          var ents = e.evidence[names[j]] && e.evidence[names[j]].entities;
          if (Array.isArray(ents)) {
            for (var k = 0; k < ents.length; k++) {
              if (ents[k] && ents[k].type && String(ents[k].type).toLowerCase().indexOf(term) !== -1) return true;
            }
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
