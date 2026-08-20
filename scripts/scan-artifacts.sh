#!/usr/bin/env bash
# scan-artifacts.sh DB CANARY [CANARY...]
#
# Search a SQLite database and its sidecars for byte sequences that should no
# longer be recoverable from them.
#
#   0 - scanned every present artifact, nothing found
#   1 - found
#   2 - could not scan; NOT a clean result
#
# Exit 2 is deliberately distinct from 0. "The scan did not happen" must never
# be read as "nothing was found", which is the whole reason this is a script
# with three statuses rather than a loop with a boolean.
DB="$1"; shift

# Validated BEFORE the file loop. With these checks inside it, a run with no
# artifacts present skipped every iteration and reported clean.
[ "$#" -gt 0 ] || { echo "no canary supplied"; exit 2; }
for c in "$@"; do
  [ -n "$c" ] || { echo "empty canary supplied"; exit 2; }
done
[ -e "$DB" ] || { echo "no database at $DB"; exit 2; }

found=0
scanned=0
for f in "$DB" "$DB-wal" "$DB-shm"; do
  [ -e "$f" ] || continue
  for c in "$@"; do
    # -F: a canary is a literal, not a pattern. Without it a canary of '.*'
    # reports a find for a string that is absent.
    # The search tool's own stderr is discarded: its wording differs between
    # platforms, so leaving it through makes this script's output contract
    # unpinnable -- and an unpinnable contract is one a reassuring sentence can
    # be added to. Everything an operator needs is in our own message below:
    # which artifact, and the tool's exit status.
    LC_ALL=C grep -qaF -e "$c" -- "$f" 2>/dev/null; rc=$?
    case "$rc" in
      0) echo "FOUND in $f"; found=1 ;;
      1) : ;;
      *) echo "scan FAILED on $f (grep exit $rc)"; exit 2 ;;
    esac
  done
  scanned=$((scanned+1))
done

# Unreachable on a stable filesystem -- the database check above fires first --
# and kept for the case where an artifact disappears between that check and
# this loop. No test binds it, and the test module says so.
[ "$scanned" -gt 0 ] || { echo "scanned nothing"; exit 2; }
exit "$found"
