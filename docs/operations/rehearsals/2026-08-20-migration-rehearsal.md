# Migration rehearsal — 2026-08-20

A rehearsal of the destructive migration and the reclamation procedure in
[the content runbook](../content-runbook.md), run against a database built
through the real Alembic chain.

## What was rehearsed

| step | result |
|---|---|
| Migrated to `d5a71f3c8e02`, the migration's predecessor | all four legacy columns present |
| Planted a canary in the legacy content columns | four representations |
| Froze a copy as the backup | see the hashes below |
| Confirmed all four representations are in the frozen backup | all four found |
| Upgraded to head `1b42ababed28` | migration succeeded |
| Ran the runbook's session block | exit 0; `0\|0\|0`, `0\|0\|0`, `SEQUENCE-COMPLETE` |
| Ran the runbook's post-close block | exit 0; no representation found in the database, WAL or SHM |
| Reclaimed database | see the hashes below |

The four representations were the plain string, its JSON-escaped form, its
`\uXXXX`-escaped form, and its raw bytes. All four were checked by the scan.

### Artifact hashes

- frozen backup:
  `a6629d032d2071f2fb36bf7617930432aaa6ab5cd73ca6a0cc2eca5357b26230`
- reclaimed database:
  `e631231124de2d244d0b3e47b117b8ba472ebf97b6aff6d5ee0ea31db840f358`

## Backup and snapshot disposition

| field | value |
|---|---|
| Backup identifiers | Rehearsal copy; see the frozen-backup hash above |
| Owner | Tidewall maintainers (rehearsal artifact; no production backup taken) |
| Retention or deletion disposition | Discarded with the rehearsal's temporary directory; no production backup involved |
| Date | 2026-08-20 |

## A note on this table

These four fields are the ones the runbook asks an operator to record after a
real upgrade. Here they describe the rehearsal's own throwaway artifact, which
is why the owner is the project rather than a named accountable person and the
disposition is "discarded with the temporary directory".

`test_the_rehearsal_record_is_complete` asserts all four are populated. Its
purpose is to stop the template shipping as empty headings — a table nobody
ever fills in is not a record. It is not a substitute for the judgement an
operator applies to a real backup.
