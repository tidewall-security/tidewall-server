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
| Owner | *OUTSTANDING — see below* |
| Retention or deletion disposition | Discarded with the rehearsal's temporary directory; no production backup involved |
| Date | 2026-08-20 |

## Outstanding

**Owner** is the one field this rehearsal cannot produce. It names the person
accountable for the backup taken before a real upgrade, and it is not something
a test run can invent — inventing it would turn an acceptance record into a
fiction, which is the failure this whole runbook exists to avoid.

`test_the_rehearsal_record_is_complete` asserts every field above is populated.
It fails while this one is outstanding, deliberately: this is the release gate,
and a gate that passes with a missing input is not a gate.

To close it: replace *OUTSTANDING* with the accountable owner, and confirm the
disposition line describes the backup that was actually taken.
