"""Metadata returned by the Sessions dashboard. A reported stage is a reporter's assertion."""

import json
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import NativePromptAssessment, NativePromptDecision, NativePromptDelivery, NativePromptObservation
from app.native_prompt import (
    UUID4,
    Assessed,
    Counter,
    Failed,
    Hex64,
    InputState,
    NotRequested,
    Reason,
    SourceProfile,
    Stage,
    Unavailable,
    Unsupported,
)
from app.utils import as_utc


class ReportSummary(BaseModel):
    evidence_source: Literal["hook", "controlled_observer"]
    stage: Stage
    report_count: Annotated[int, Field(ge=1)]
    received_at: datetime
    tool_count: Counter | None
    token_count: Counter | None
    marker_present: bool | None


class DecisionView(BaseModel):
    decision_id: UUID4
    request_id: UUID4
    status: Literal["pending", "committed", "abandoned"]
    policy_revision: Hex64
    mode: Literal["report", "enforce"]
    input_state: InputState
    reason: Reason | None
    evaluated_action: Literal["allow", "deny", "unknown"] | None
    response_prepared: bool
    prepared_action: Literal["allow", "deny"] | None
    assessment: (
        Annotated[Assessed | NotRequested | Unsupported | Unavailable | Failed, Field(discriminator="status")] | None
    )
    delivery_reports: list[ReportSummary]


class ObservationView(BaseModel):
    event_id: UUID4
    occurrence_id: UUID4
    session_id: UUID4
    agent: Literal["claude-code"]
    agent_version: Literal["2.1.330"]
    native_profile: SourceProfile
    received_at: datetime
    decision: DecisionView | None


class NativePromptPage(BaseModel):
    items: list[ObservationView]
    next_cursor: str | None


def project_native_observation(
    observation: NativePromptObservation,
    decision: NativePromptDecision | None,
    assessment: NativePromptAssessment | None,
) -> dict:
    outcome: dict[str, Any] | None = None
    if decision is not None:
        measured: dict[str, Any] | None = None
        if assessment is not None:
            measured = dict(status=assessment.status, reason=assessment.reason, profile=assessment.profile)
            if assessment.status == "assessed":
                if assessment.model_identity is None:
                    raise ValueError("Assessed record is missing model identity")
                measured.update(
                    model_identity=json.loads(assessment.model_identity),
                    unsafe_score=assessment.unsafe_score,
                    score_kind=assessment.score_kind,
                    input_tokens=assessment.input_tokens,
                )
        outcome = dict(
            decision_id=decision.decision_id,
            request_id=decision.request_id,
            status=decision.status,
            policy_revision=decision.policy_revision,
            mode=decision.mode,
            input_state=decision.input_state,
            reason=decision.reason,
            evaluated_action=decision.evaluated_action,
            response_prepared=decision.response_prepared,
            prepared_action=decision.returned_action,
            assessment=measured,
            delivery_reports=[],
        )
    return dict(
        event_id=observation.event_id,
        occurrence_id=observation.occurrence_id,
        session_id=observation.session_id,
        agent=observation.agent,
        agent_version=observation.agent_version,
        native_profile=observation.native_profile,
        received_at=as_utc(observation.received_at),
        decision=outcome,
    )


def attach_report_summaries(db: Session, items: list[dict], now: datetime) -> None:
    # IDs come exclusively from this scoped, live page in the same SQLite snapshot.
    decisions = {d["decision_id"]: d for item in items if (d := item["decision"]) is not None}
    if not decisions:
        return
    delivery = NativePromptDelivery
    groups = (delivery.decision_id, delivery.evidence_source, delivery.stage)
    ranked = (
        select(
            *groups,
            delivery.received_at,
            delivery.tool_count,
            delivery.token_count,
            delivery.marker_present,
            func.count().over(partition_by=groups).label("report_count"),
            func.row_number()
            .over(partition_by=groups, order_by=(delivery.received_at.desc(), delivery.report_id.desc()))
            .label("rank"),
        )
        .where(delivery.decision_id.in_(list(decisions)), delivery.expires_at > now)
        .subquery()
    )
    rows = db.execute(
        select(ranked).where(ranked.c.rank == 1).order_by(ranked.c.evidence_source, ranked.c.stage)
    ).mappings()
    for row in rows:
        decisions[row["decision_id"]]["delivery_reports"].append(
            dict(
                evidence_source=row["evidence_source"],
                stage=row["stage"],
                received_at=as_utc(row["received_at"]),
                report_count=row["report_count"],
                tool_count=row["tool_count"],
                token_count=row["token_count"],
                marker_present=row["marker_present"],
            )
        )
