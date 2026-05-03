# Changelog

All notable changes to Tidewall Server are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
