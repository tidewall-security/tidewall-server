"""Programmatic entry point — ``python -m app``.

This exists so the bind address has exactly one source of truth.

The insecure-mode guard used to check ``Settings.HOST`` while the container
launched ``uvicorn --host 0.0.0.0`` from the Dockerfile CMD, so the setting the
guard consulted was not the value the server bound. Codex reproduced the gap:
startup logged "Running WITHOUT AUTHENTICATION on 127.0.0.1" while the socket
was listening on ``*``. A guard checking a value nothing consumes is theatre —
the fifth instance of that pattern in this remediation.

Launching uvicorn from validated settings makes HOST authoritative, so the
guard constrains the socket that is actually opened.
"""

from __future__ import annotations

import uvicorn

from app.config import Settings


def serve() -> None:
    settings = Settings.from_env()
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL,
    )


if __name__ == "__main__":
    serve()
