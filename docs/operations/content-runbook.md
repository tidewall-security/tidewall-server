# Reclaiming deleted content

This describes what to do after upgrading to the release that removed raw
prompt storage, and what that procedure does and does not achieve.

Read section 3 before running anything. The most likely way to be misled here
is to run a procedure that succeeds and conclude something it does not show.

## 1. Upgrading to this release is destructive

The migration deletes every row in `interactions` and drops four columns that
held content: `input_messages`, `output_messages`, `detectors_json` and
`summary`.

There is no data rollback in either direction. `alembic downgrade` recreates
the columns; it does not recreate what was in them, and it deletes the
interactions again on the way. The application and the schema move together —
there is no supported mixed-version state.

Take a backup first, and be aware of what you have made: a complete copy of
every prompt the system held. It is in scope for section 4.

## 2. Reclaiming the space

Run this **after** the migration, and after any rows you intend to remove have
actually been deleted. Not merely after shortening a retention policy —
`expires_at` is stamped when content is captured, and shortening the policy
does not recompute rows that already exist.

### Before you start

- **Every connection to this database must be closed.** Not merely every
  writer. The server, any older release, any `sqlite3` session, any backup
  agent. Tidewall's process lock excludes only a cooperating Tidewall process
  on a filesystem where `flock` works — it is not a check that nothing is
  running, and a successful checkpoint is not one either: a reader that pins no
  WAL frames coexists with a clean result.
- A backup you are prepared to destroy later.
- Free space of at least twice the database size, on the database's filesystem
  **and** wherever SQLite will put its temporary files (see section 4).

> **If the first check fails immediately after migrating**, that is expected.
> `alembic upgrade head` leaves the database in `delete` journal mode; the
> procedure requires WAL. Start the server once, or set
> `PRAGMA journal_mode=WAL` explicitly, then run this again.

<!-- runbook:session -->

```bash
DB=/path/to/tidewall.db
REV=fb6a694ad1fa

out=$(sqlite3 "$DB" -cmd ".param set :rev '$REV'" <<'SQL' 2>&1
.bail on
CREATE TEMP TABLE _assert(what TEXT, ok INT NOT NULL CHECK(ok=1));

INSERT INTO _assert SELECT 'journal mode is wal',
  journal_mode='wal' FROM pragma_journal_mode;

INSERT INTO _assert SELECT 'exactly one expected revision',
  (SELECT count(*) FROM alembic_version WHERE version_num=:rev)=1
  AND (SELECT count(*) FROM alembic_version)=1;

INSERT INTO _assert SELECT 'both are tables, not views',
  (SELECT count(*) FROM sqlite_schema WHERE type='table'
   AND name IN ('interactions','interaction_contents'))=2;

INSERT INTO _assert SELECT 'interactions is the head shape',
  (SELECT count(*) FROM pragma_table_xinfo('interactions'))=20
  AND (SELECT count(*) FROM pragma_table_xinfo('interactions')
       WHERE name IN ('id','request_id','timestamp','event_type','policy_id',
                      'policy_name','api_key_id','blocked','transformed',
                      'latency_ms','app_id','user_id','llm_provider','model',
                      'source_ip','status','device_id','evidence_json',
                      'evidence_schema_version','content_available'))=20;

INSERT INTO _assert SELECT 'interaction_contents is the head shape',
  (SELECT count(*) FROM pragma_table_xinfo('interaction_contents'))=9
  AND (SELECT count(*) FROM pragma_table_xinfo('interaction_contents')
       WHERE name IN ('id','interaction_id','input_json','output_json','matches_json',
                      'byte_size','captured_at','expires_at','policy_id'))=9;

INSERT INTO _assert SELECT 'legacy content columns are gone',
  NOT EXISTS(SELECT 1 FROM pragma_table_info('interactions')
             WHERE name IN ('input_messages','output_messages',
                            'detectors_json','summary'));

INSERT INTO _assert SELECT 'no content rows remain',
  (SELECT count(*) FROM interaction_contents)=0;

PRAGMA wal_checkpoint(TRUNCATE);
VACUUM;
PRAGMA wal_checkpoint(TRUNCATE);

INSERT INTO _assert SELECT 'integrity ok',
  integrity_check='ok' FROM pragma_integrity_check;
SELECT 'SEQUENCE-COMPLETE';
SQL
) || { printf 'the sequence stopped before completing:\n%s\n' "$out"; exit 1; }

printf '%s\n' "$out" | grep -qx 'SEQUENCE-COMPLETE' || { echo "incomplete"; exit 1; }
[ "$(printf '%s\n' "$out" | grep -cx '0|0|0')" -eq 2 ] || {
  printf 'a checkpoint did not complete:\n%s\n' "$out"; exit 1; }
printf '%s\n' "$out"
```

Keep that output. It is the record that the procedure ran, and the only one
you get.

### Why the heredoc is quoted

`<<'SQL'` rather than `<<SQL`. With an unquoted delimiter the shell expands
everything inside the heredoc before SQLite sees any of it — command
substitution included — so every line there is shell input first and SQL
second, *including lines that look like SQL comments*. Quoting it makes the
body inert.

That is why the revision arrives as a bound parameter through `.param set`
rather than being interpolated into the text: interpolation is what would have
required an unquoted delimiter.

### Why two checkpoints

The first does **not** exist to make data visible to `VACUUM` — a reader in WAL
mode already sees a coherent snapshot of the main file plus committed frames.
It clears any WAL residue that was already there, and when it succeeds it
gives the procedure a clean boundary.

It does **not** stop the sequence when it fails. A busy checkpoint reports a
row beginning `1|` and the same session carries straight on into `VACUUM`; only
the shell's row count, after the session has ended, turns that into a refusal.
See "Reading the result" below.

`VACUUM` then rebuilds the database into fresh pages, which is what drops the
free pages still holding deleted content. In WAL mode that rebuild is an
ordinary write transaction, so it is written *into the WAL*.

The second checkpoint moves those rebuilt pages into the main file and
truncates the WAL. Closing the last connection may also do that, but relying on
it means relying on incidental behaviour.

### Reading the result

The first seven `_assert` rows are **preconditions**. A failure stops the
sequence with a `CHECK constraint failed` error and a non-zero exit, before
anything is written.

The last one, `integrity ok`, is a **postcondition**: it runs after `VACUUM`
and the second checkpoint. If it fails, the database has already been
rewritten. That is not a reason to remove it — an integrity failure is exactly
what you want to hear about — but it is not a check that protects the file.

The two `0|0|0` lines are the checkpoint results. Only the first column
matters: `0` means the checkpoint completed, `1` means it did not because
something else held the database. A `0|-1|-1` means the database was not in WAL
mode, where a checkpoint is a documented no-op.

**A busy checkpoint is detected after `VACUUM` has already run**, not before —
the results are checked once the session ends. A refusal on that ground means
the run did not complete cleanly, not that nothing happened. Achieve real
quiescence and run it again.

### After the session has closed

These inspect artifacts that only exist once SQLite has let go of them.

**Run this from the repository root**, not merely from somewhere inside a
checkout: it invokes `scripts/scan-artifacts.sh` by a path relative to that
root. The published container image ships neither `scripts/` nor `docs/` and
does not install the `sqlite3` CLI, so the whole procedure runs on a host with
a checkout, against the database file, rather than inside the container.

Prerequisites:

- `sqlite3` and `grep`;
- **write** access to the database *and its directory*. The session
  checkpoints, runs `VACUUM` and truncates the WAL, and SQLite creates
  temporary and sidecar files alongside the database. Read access is enough
  only for the final scan;
- a path to the database that is reachable and writable from that
  repository-root shell — if it lives in a container volume, that means the
  host-side mount point.

Set `CANARY_*` to a string you know was in a deleted record, in each of its
representations. Worked example, for a prompt containing
`café "acct\\4111"` — chosen because it exercises all four forms, which an
all-ASCII example cannot:

```bash
# As it was written.
CANARY_PLAIN='café "acct\4111"'

# As a JSON string value: the quotes and the backslash are escaped.
CANARY_JSON='café \"acct\\4111\"'

# As some writers encode non-ASCII: the é becomes a \uXXXX escape. Writers
# may also escape ASCII characters, so this form is worth searching for even
# when your canary is plain -- it costs nothing if it is absent.
CANARY_UNICODE='caf\u00e9 \"acct\\4111\"'

# The same characters under a DIFFERENT encoding -- here latin-1, where é is
# the single byte 0xe9 rather than UTF-8's 0xc3 0xa9. This is the form to use
# when the value may have been written by something that did not agree with
# your database about encoding. If everything in the path was UTF-8, this is
# byte-for-byte the plain form.
CANARY_RAW=$'caf\xe9 "acct\\4111"'
```

**Choose a canary long enough not to occur by chance.** These are literal byte
searches over a binary file: a one- or two-character canary will match
something in almost any database, and you will be told `FOUND` for content that
is not there. Verified — a canary of `x` reports `FOUND` against a freshly
migrated, empty database.

That error is in the safe direction: a too-short canary can only produce a
false `FOUND`, never a false clean. But it will send you looking for a leak
that does not exist, so use a distinctive string of a dozen characters or more.

If your canary is pure ASCII, all four forms collapse towards the plain one and
the `\uXXXX` form may not appear at all. That is fine — pass them anyway; the
scan refuses an empty argument, not a redundant one. It is also the reason this
example uses a canary with a non-ASCII character and a backslash: an all-ASCII
one cannot demonstrate the difference between these forms, and an example that
silently passes the same bytes four times teaches the wrong thing.

Single quotes matter: without them the shell will interpret `$`, backslashes
and spaces, and you will scan for something other than what you meant.

<!-- runbook:postclose -->

```bash
: "${DB:?set DB to the database path}"
: "${CANARY_PLAIN:?}" "${CANARY_JSON:?}" "${CANARY_UNICODE:?}" "${CANARY_RAW:?}"

test ! -s "$DB-wal"     || { echo "WAL not truncated"; exit 1; }
test ! -e "$DB-journal" || { echo "a rollback journal exists"; exit 1; }
./scripts/scan-artifacts.sh "$DB" "$CANARY_PLAIN" "$CANARY_JSON" \
                            "$CANARY_UNICODE" "$CANARY_RAW"
```

`scan-artifacts.sh` exits `0` if it scanned and found nothing, `1` if it found
something, and `2` if it could not scan. Treat `2` as "no result", never as
"clean".

If you are not in the repository root you will get exit `127` and
`./scripts/scan-artifacts.sh: No such file or directory`. That is the working
directory, not a problem with your database.

## 3. What this does, and what it does not

**It deletes nothing.** `VACUUM` compacts pages that are already free. If the
content you have in mind is still live, it is faithfully preserved and the
command still succeeds. That is why the preconditions above exist: a run
against an unmigrated database, the wrong copy, or a database that still holds
content **fails** rather than succeeding while reclaiming nothing.

**A zero exit means the sequence and its checks completed.** It does not mean
any byte was reclaimed. Running it twice exits zero the second time with the
file unchanged.

**This procedure is for the destructive migration only.** It requires that no
content rows remain, because that is the only state in which the claim it
supports is checkable. After a routine retention purge, with in-policy content
still live, no scan of the resulting files can distinguish "the expired rows
are gone" from "the expired rows were never there".

Reclaiming space after routine purges is not supported yet. It needs a way for
an operator to state the deletion boundary they mean and for the procedure to
check it. That is open work, recorded as the open question in §9 of
`internal/reviews/2026-08-19-p006-step9-design-v10.md`.

## 4. Where the bytes may still be

Live and untouched in this same database:

- content still within its retention period;
- the content-access audit, which deliberately outlives what it describes;
- export attempts, with their interaction, key, policy and target identifiers,
  destination host and addresses, payload size and outcome;
- reconciliation rows, whose `evidence` field is operator-supplied text that
  nothing stops an operator pasting prompt content into;
- `activity_log.old_value` and `new_value`, which are generic JSON sinks;
- control-plane configuration — prompt-list patterns, detector settings, export
  target URLs and headers;
- the vault, which is outside this procedure entirely.

Outside this database:

- backups and filesystem or volume snapshots;
- replicas;
- **the transient database `VACUUM` creates**, which is as large as the
  original and contains the whole logical database. It may be written outside
  the database directory, under `SQLITE_TMPDIR`, `TMPDIR`, `/var/tmp`,
  `/usr/tmp`, `/tmp`, or the working directory;
- filesystem journals and copy-on-write layers;
- swap and hibernation images; crash dumps; the page cache;
- SSD free space, until it is overwritten;
- every system a record was exported to.

The claim this procedure supports is exactly: *after a successful sequence, the
supplied representations of your canary were not found in the database, WAL and
SHM files.* That is not media sanitisation, and it is not a statement about any
of the above.

## 5. Backup and snapshot disposition

Record what you did with the backup. This project does not delete, rotate or
rewrite backups on your behalf.

| field | value |
|---|---|
| Backup identifiers | |
| Owner | |
| Retention or deletion disposition | |
| Date | |

## 6. Where content crosses the network

- `GET /v1/logs/{id}/content` returns content in its **response**. An inbound
  reverse proxy sees it.
- `POST /v1/logs/{id}/content-export` carries `{view, target_id}` and no
  content in either direction.
- The **outbound** export payload Tidewall builds is where exported content
  crosses the network. Any egress proxy, TLS-inspecting middlebox, and the
  receiving system need their own body-logging, caching and retention controls.

`Cache-Control: no-store` is set on Tidewall's own responses and governs
nothing about a receiver. URL access logs hold interaction identifiers rather
than prompt text, but they disclose who accessed and exported what, and need
their own retention policy.

## 7. Retention

`raw_content_retention_days` is per-policy and prospective. `NULL` means no
time-based expiry. Changing it does not recompute rows already stamped.

The purge runs at startup and then every 300 seconds, and is best effort —
startup continues if the scheduler cannot start at all. Expiry is enforced
independently on the read and export paths, so an expired row is refused before
it is purged.

**There is no size cap.** Growth is unbounded and no endpoint reports usage.
Monitor disk externally.

## 8. Grants

- `interaction:matches:read`
- `interaction:content:read`
- `interaction:content:export`

The admin role implies none of them. Full read implies matches. Export implies
neither. A bound policy is required for content operations.

## 9. Export targets

`allow_content_export`, `content_export_policy_id` and `content_export_views`
are necessary and not sufficient. The target must also be enabled, be a
webhook, and pass destination and header validation, and the caller must be a
policy-bound admin holding the export grant.

## 10. One live server per database

A second server refuses to start with `ProcessLockHeld`. That is deliberate: a
rolling restart that overlaps will fail the new process until the old one
exits.

The lock is cooperative and local-filesystem only. On some network filesystems
`flock` is advisory or emulated and two instances can both acquire it — which
is the dangerous direction, because each will then treat the other's in-flight
export attempts as belonging to a process that is gone. Keep the database on
local storage.

## 11. Export attempts that did not resolve

`indeterminate` and `abandoned_indeterminate` mean delivery was not confirmed
either way. They are not failures. `POST /v1/content-exports/{attempt_id}/reconcile`
records external evidence; it is append-only and never rewrites what the
attempt observed.

Reconciliation is **admin-only, not grant- or policy-scoped**, and its evidence
field retains whatever an operator types into it.

## 12. A required setting: PREF64

On a network running NAT64 with a Network-Specific Prefix, an export target's
hostname can resolve to an address this server accepts as public while the
network translates it to an internal IPv4 destination.

The sender now checks this, against a posture you declare. **`PREF64` is
required: content export refuses every request until it is set.**

Set it to this deployment's translation prefixes, comma-separated, using RFC
6052 lengths `/32`, `/40`, `/48`, `/56`, `/64` or `/96`. If no NAT64
translation is reachable from this server, set it to the value meaning that,
**after confirming it** — the server cannot check the claim, and a wrong
declaration reinstates the defect.

**The control is only as good as the declaration.** It is defeated by a
declaration that is false, incomplete, stale after a network change, mistyped
into a different valid prefix, or by a translator that does not follow RFC
6052.

**The posture is read once per application lifespan and is not refreshed while
it runs.** A Pref64 or routing change requires a restart before it takes
effect.

Denying egress to the Pref64, or applying the embedded IPv4's policy at the
gateway (RFC 6052 §5.3), remains worthwhile defence in depth.

---

## Deviations from the accepted design

Recorded here rather than left for a reader to discover by diffing.

1. **The session block prints its captured output.** The accepted design said
   every line of that output was load-bearing and nothing printed it, so an
   operator had no record and no test could assert one.
2. **`REV` names a concrete revision** rather than a placeholder. The design's
   `REV=<the alembic revision this deployment expects>` is not valid shell, so
   the published block could not be syntax-checked or run as printed.
3. **The explanatory SQL comments were dropped** from the block, and the
   explanation they carried is in the prose above instead. The block is meant
   to be pasted; the reasoning is meant to be read.
4. **§12 carries the NAT64 deployment control.** The design said the release
   blocker is "not a runbook paragraph", and it is not one — the blocker is
   `internal/findings/P1-nat64-nsp-sender-bypass.md`. What is here is the
   operational control an operator needs meanwhile, stated as a requirement
   and explicitly not as a closure.
