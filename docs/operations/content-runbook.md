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
REV=1b42ababed28

out=$(sqlite3 "$DB" <<SQL 2>&1
.bail on
CREATE TEMP TABLE _assert(what TEXT, ok INT NOT NULL CHECK(ok=1));

INSERT INTO _assert SELECT 'journal mode is wal',
  journal_mode='wal' FROM pragma_journal_mode;

INSERT INTO _assert SELECT 'exactly one expected revision',
  (SELECT count(*) FROM alembic_version WHERE version_num='$REV')=1
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

### Reading the result

Each `_assert` row is a precondition. A failure stops the sequence with a
`CHECK constraint failed` error and a non-zero exit, before anything is
written.

The two `0|0|0` lines are the checkpoint results. Only the first column
matters: `0` means the checkpoint completed, `1` means it did not because
something else held the database. A `0|-1|-1` means the database was not in WAL
mode, where a checkpoint is a documented no-op.

**A busy checkpoint is detected after `VACUUM` has already run**, not before —
the results are checked once the session ends. A refusal on that ground means
the run did not complete cleanly, not that nothing happened. Achieve real
quiescence and run it again.

### After the session has closed

These inspect artifacts that only exist once SQLite has let go of them. Set
`CANARY_*` to a string you know was in a deleted record, in each of its
representations — the plain text, its JSON-escaped form, its `\uXXXX`-escaped
form, and its raw bytes.

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
are gone" from "the expired rows were never there". Reclaiming space after
routine purges is not supported yet.

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

## 12. A deployment requirement: NAT64

On a network running NAT64 with a Network-Specific Prefix, an export target's
hostname can resolve to an address this server accepts as public while the
network translates it to an internal IPv4 destination.

Deny egress to the Pref64, or apply to the IPv4-embedded address the same
policy you would apply to the embedded IPv4 (RFC 6052 §5.3).

This is an operational control for a defect in the sender, not a closure of it.
