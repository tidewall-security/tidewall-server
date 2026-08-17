# Changelog

All notable changes to Tidewall Server are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Device takeover via fingerprint (P0-11).** `POST /v1/devices/check`
  looked a device up by the caller-supplied `fingerprint` and authorised the
  refresh on the strength of holding *a* registration token. Any holder of
  any registration token who learned or guessed a fingerprint could revoke
  the victim's session and receive an access token bound to their device and
  policy. Fingerprint was acting as both identity and proof of ownership,
  and it is neither.

### Changed — breaking

`POST /v1/devices/check` is **removed** and replaced by two endpoints with
separate credentials. Clients must be updated; there is no compatibility
shim.

| Was | Now |
| --- | --- |
| `POST /v1/devices/check` with `rt_`, for both first contact and refresh | `POST /v1/devices/enrol` with `rt_` — creates only |
| | `POST /v1/devices/{device_id}/refresh` with `at_` — existing device only |

Client contract:

1. Generate a high-entropy `installation_id` once — `crypto.randomUUID()` —
   and store it. This is the device's identity. The server requires 16–128
   characters of `[A-Za-z0-9_.:-]` and rejects anything else with 422, so a
   short or guessable value cannot be squatted to deny someone enrolment.
2. Enrol at `POST /v1/devices/enrol` with the `rt_` token. Store the returned
   `device_id` and access token. A registration token is accepted at this
   path and no other.
3. Refresh at `POST /v1/devices/{device_id}/refresh` with the **current `at_`
   token**, and replace the stored token from the response. Refresh well
   before the one-hour expiry; there is no need to poll every minute.
4. Rotation is one-time. The presented token is marked replaced and expires
   after a 60-second overlap, which exists so a request already in flight
   still succeeds — it is not a window in which to refresh again. Presenting
   an already-replaced token returns 403.
5. `409` from enrol means that `installation_id` is already enrolled. Do not
   retry: refresh instead, or enrol as a new installation.
6. **After losing local storage, generate a new `installation_id` and enrol
   as a new device.** Recovery by fingerprint is exactly the takeover and is
   not offered. The abandoned row remains for an administrator to remove.

`fingerprint` is now optional, non-unique, advisory metadata. Two devices
reporting the same fingerprint both enrol normally.

`POST /v1/registration-tokens` now **requires** `policy_id` and returns it.
Every device enrolled with the token inherits it as an immutable scope. The
field previously existed only in the schema — nothing wrote it — so every
device enrolled unscoped and silently fell back to the default policy.

Existing `devices` and `access_tokens` rows are deleted by migration
`d5a71f3c8e02`. They have no installation ID and no way to prove ownership,
which is the defect. All clients re-enrol.

## [0.1.0] - 2026-05-02

### Added

- Initial public release of Tidewall Server.
- FastAPI-based AI security guard server with the same
  `guard_chat_completions` API contract as AIDR-style platforms.
- 11 detectors covering prompt injection, PII, secrets,
  topics/toxicity, language, code, competitors, malicious entities,
  custom regex patterns, emoji, and MCP tool validation.
- Multi-model prompt-injection detection via a pluggable model system —
  swap any HuggingFace text-classification model via policy config.
- 6 redaction methods: replacement, mask, partial mask, hash,
  format-preserving encryption (AES-FF1-256), and defang.
- Multi-policy engine with per-event-type rule sets
  (`input` / `output` / `tool_input` / `tool_output` / `tool_listing`).
- Access rules: metadata-based pre-filtering with 6 operators.
- 5-value status model (`allowed` / `reported` / `blocked` /
  `alerted` / `transformed`).
- Per-rule-set report-only mode for shadow rollouts.
- API key authentication with role-based access control
  (`admin` / `viewer` / `api`).
- Browser-extension device registration flow with refresh tokens.
- OCSF event export (Data Security Finding, class 2006) with
  MITRE ATLAS technique mapping.
- AIDR-compatible event export format for drop-in SIEM compatibility.
- Webhook + syslog dispatch.
- AES-FF1-256 format-preserving encryption with deterministic and
  non-deterministic modes; stateless unredact endpoint.
- Activity audit log with old/new JSON snapshots for all config changes.
- SQLAlchemy + Alembic with automatic migrations on startup.
- Web dashboard: Visibility (Sankey), Findings (table), Policies
  (editor), Sandbox (prompt tester).
- Comprehensive test suite (pytest) plus an end-to-end Playwright
  test pack.
- Benchmark orchestrator under `bench/` for evaluating multiple
  prompt-injection models against a labelled dataset.

[Unreleased]: https://github.com/tidewall-security/tidewall-server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tidewall-security/tidewall-server/releases/tag/v0.1.0
