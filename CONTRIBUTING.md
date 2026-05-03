# Contributing to Tidewall Server

Thanks for your interest in contributing. Issues, pull requests, and
discussion of new detectors, integrations, and platform features are
all welcome.

## Code of Conduct

Be respectful and constructive. Personal attacks, harassment, or
discriminatory behaviour are not tolerated. By participating, you
agree to abide by the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Reporting Bugs

Open an issue with:

- A short title that names the symptom.
- The exact request or scenario that triggers it.
- What you expected to happen.
- What actually happened, including any tracebacks or relevant log output.
- Versions: `python --version`, `pip show tidewall-server`, OS.

## Suggesting Features

Open an issue describing the use case before opening a PR — features
are easier to discuss when there's a problem statement to anchor to.

## Development Setup

```bash
git clone https://github.com/tidewall-security/tidewall-server
cd tidewall-server
uv sync --group dev
uv run pytest
```

Run the server locally:

```bash
uv run uvicorn app.main:app --reload --port 8080
# Dashboard: http://localhost:8080/ui/visibility
# Swagger:   http://localhost:8080/docs
```

## Pull Requests

1. Fork the repo and create a topic branch from `main`.
2. Keep the diff focused. Multiple unrelated changes belong in
   separate PRs.
3. Add or update tests for any behavioural change. Tests live in
   `tests/` and run with `pytest`.
4. Update documentation if you change anything user-facing
   (env vars, API shape, policy keys, dashboard behaviour).
5. Make sure the test suite, lint, and type-check all pass:
   ```bash
   uv run pytest
   uv run ruff check app/
   uv run mypy app/
   ```
6. Open the PR with a clear description of the problem and the change.

## Adding a New Detector

1. Create `app/detectors/<name>.py` extending `BaseDetector`.
2. Implement the `name` property, `scan()`, and any per-detector config
   parsing in `__init__`.
3. Register the detector in `app/scanner_engine.py` (`_DETECTOR_ORDER`
   and `_DETECTOR_REGISTRY`).
4. Add the detector key to `app/config.py` `PolicyConfig.detectors`.
5. Update `policy.yaml` with a default config block.
6. Add unit tests in `tests/test_<name>_detector.py`.
7. Update the README "Detectors" table.

See `app/detectors/malicious_prompt.py` for a canonical example of a
detector that supports multiple ML model backends.

## Style

- Python 3.12+; use modern type syntax (`str | None`, `dict[str, Any]`).
- Comments explain *why*, not *what*.
- Keep public API surface small. New top-level symbols added to a
  module should be added to `__all__` if defined.
- Run `ruff format` before committing.

## Security Findings

Don't open a public issue for a security vulnerability — see
[SECURITY.md](./SECURITY.md) for the disclosure process.
