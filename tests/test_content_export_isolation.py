"""Content export is the ONLY path content leaves this system.

Steps 4 to 7 kept it in. This step deliberately opened one controlled way out,
and these tests are what stop a second one appearing by accident.
"""

from __future__ import annotations

import inspect

CANARY = "swordfish-42"


def test_emit_cannot_be_made_to_carry_content():
    """No argument to the ordinary export path may carry a prompt.

    Through the real dispatch, with a real enabled target, so the projection at
    emit()'s boundary is what is being tested rather than a stub.
    """
    import asyncio

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.models import Base, ExportTarget
    from app.services.export_service import ExportService

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    session = Session()
    session.add(
        ExportTarget(
            name="siem",
            type="webhook",
            config={"url": "https://example.invalid/hook"},
            format="ocsf",
            events=["allowed", "blocked", "transformed", "reported"],
            enabled=True,
        )
    )
    session.commit()
    session.close()

    captured: list[dict] = []

    class _Svc(ExportService):
        async def _send_webhook(self, target, event):  # type: ignore[override]
            captured.append(event)

    svc = _Svc(session_factory=Session)
    asyncio.run(
        svc.emit(
            request_id="tw_0000000000000001",
            timestamp="2026-08-19T00:00:00Z",
            event_type="input",
            status="allowed",
            policy_name="policy-a",
            blocked=False,
            transformed=False,
            latency_ms=1.0,
            detectors={"custom_entity": {"data": {"entities": [{"type": "CUSTOM", "value": CANARY}]}}},
            guard_input={"messages": [{"content": CANARY}]},
            guard_output={"messages": [{"content": CANARY}]},
            summary=CANARY,
        )
    )
    assert captured, "the ordinary export path dispatched nothing, so this proves nothing"
    for event in captured:
        assert CANARY not in str(event), "the ordinary export path carried content"


def test_the_export_payload_builder_is_not_reachable_from_ordinary_export():
    """Routing content through the OCSF or AIDR builders would either strip it
    or widen what they can carry. Neither should know this module exists."""
    from app.services import export_service

    source = inspect.getsource(export_service)
    assert "content_export" not in source
    assert "content_projection" not in source


def test_the_content_export_module_does_not_use_the_ordinary_builders():
    from app.routes import content_export

    source = inspect.getsource(content_export)
    assert "ocsf" not in source.lower()
    assert "aidr" not in source.lower()
    assert "ExportService" not in source


def test_there_is_exactly_one_call_site_for_the_sender():
    """A second caller would be a second way out."""
    import pathlib

    root = pathlib.Path(inspect.getfile(inspect.getmodule(test_emit_cannot_be_made_to_carry_content))).parent.parent
    callers = []
    for path in (root / "app").rglob("*.py"):
        text = path.read_text()
        if "send_payload(" in text and path.name != "export_transport.py":
            callers.append(path.name)
    assert callers == ["content_export.py"], f"unexpected senders: {callers}"
