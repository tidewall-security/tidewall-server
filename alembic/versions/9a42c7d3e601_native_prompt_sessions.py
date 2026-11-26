"""Store scoped native prompt grants, metadata and decision evidence."""

import sqlalchemy as sa

from alembic import op

revision = "9a42c7d3e601"
down_revision = "c81b0704d921"
branch_labels = None
depends_on = None


def _utc_timestamp(column: str) -> sa.CheckConstraint:
    # SQLite stores the ORM UTC instant as YYYY-MM-DD HH:MM:SS.ffffff.
    # Round trip whole seconds to reject invalid dates; do not round fractions through julianday.
    whole = f"substr({column},1,19)"
    return sa.CheckConstraint(
        f"typeof({column})='text' AND length({column})=26 AND instr({column},char(0))=0 AND "
        f"substr({column},1,4)!='0000' AND {whole} IS datetime(unixepoch({whole}), 'unixepoch') AND "
        f"substr({column},20,1)='.' AND substr({column},21,6) NOT GLOB '*[^0-9]*'"
    )


def _uuid4_check(column: str) -> sa.CheckConstraint:
    digits = f"replace({column},'-','')"
    return sa.CheckConstraint(
        f"typeof({column})='text' AND length({column})=36 AND instr({column},char(0))=0 AND "
        f"length({digits})=32 AND "
        f"{digits} NOT GLOB '*[^0-9a-f]*' AND substr({column},9,1)='-' AND substr({column},14,2)='-4' AND "
        f"substr({column},19,1)='-' AND substr({column},20,1) IN ('8','9','a','b') AND substr({column},24,1)='-'"
    )


_PINNED_MODEL = (
    '{"adapter":"abedegno/prompt-injection-classifier-qwen3-0p6b",'
    '"adapter_revision":"5500c3bef53729ed4661b5cfae1b01adca96ca4c",'
    '"base":"Qwen/Qwen3-0.6B",'
    '"base_revision":"c1899de289a04d12100db370d81485cdf75e47ca",'
    '"class_token_ids":[38157,18675,19860,6092],'
    '"prompt_sha256":"3a0e693064509eb24773ba53af4831ecb4c6ca8cf741a28d2d10080384df5041",'
    '"scoring_implementation":"qwen3_last_token_logits.1",'
    '"tokenizer_revision":"c1899de289a04d12100db370d81485cdf75e47ca"}'
)


def upgrade() -> None:
    """Upgrade schema."""
    op.create_index(
        "uq_native_session_scope",
        "agent_sessions",
        ["session_id", "device_id", "policy_id", "agent", "native_session_token"],
        unique=True,
    )
    op.create_table(
        "native_prompt_policy_configs",
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("profile", sa.String(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.CheckConstraint("enabled IN (0,1) AND profile='tidewall.prompt-injection.1'"),
        sa.CheckConstraint("typeof(generation)='integer' AND generation BETWEEN 1 AND 9007199254740991"),
        sa.CheckConstraint("typeof(threshold) IN ('integer','real') AND threshold BETWEEN 0 AND 1"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("policy_id"),
    )
    op.create_table(
        "native_prompt_grants",
        sa.Column("grant_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("session_token", sa.String(length=64), nullable=False),
        sa.Column("native_profile", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("agent", sa.String(), nullable=False),
        sa.Column("capability_hash", sa.String(length=64), nullable=False),
        sa.Column("grant_generation", sa.Integer(), nullable=False),
        sa.Column("policy_generation", sa.Integer(), nullable=False),
        sa.Column("capture_allowed", sa.Boolean(), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        _utc_timestamp("issued_at"),
        _utc_timestamp("expires_at"),
        sa.CheckConstraint(
            "((unixepoch(substr(expires_at,1,19))-unixepoch(substr(issued_at,1,19)))*1000000 + "
            "CAST(substr(expires_at,21,6) AS INTEGER) - CAST(substr(issued_at,21,6) AS INTEGER)) "
            "BETWEEN 1 AND 1800000000"
        ),
        sa.CheckConstraint("native_profile='claude-code.user-prompt-submit.1' AND agent='claude-code'"),
        sa.CheckConstraint(
            "typeof(capability_hash)='text' AND length(capability_hash)=64 AND "
            "instr(capability_hash,char(0))=0 AND capability_hash NOT GLOB '*[^0-9a-f]*'"
        ),
        sa.CheckConstraint("typeof(grant_generation)='integer' AND grant_generation BETWEEN 1 AND 9007199254740991"),
        _uuid4_check("grant_id"),
        sa.CheckConstraint("typeof(policy_generation)='integer' AND policy_generation BETWEEN 1 AND 9007199254740991"),
        sa.CheckConstraint(
            "typeof(session_token)='text' AND length(session_token)=64 AND "
            "instr(session_token,char(0))=0 AND session_token NOT GLOB '*[^0-9a-f]*'"
        ),
        sa.CheckConstraint(
            "(capture_allowed=1 AND session_id IS NOT NULL) OR (capture_allowed=0 AND session_id IS NULL)"
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_id"], ["native_prompt_policy_configs.policy_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["session_id", "device_id", "policy_id", "agent", "session_token"],
            [
                "agent_sessions.session_id",
                "agent_sessions.device_id",
                "agent_sessions.policy_id",
                "agent_sessions.agent",
                "agent_sessions.native_session_token",
            ],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("grant_id"),
        sa.UniqueConstraint("capability_hash"),
        sa.UniqueConstraint("device_id", "policy_id", "session_token", "native_profile", "grant_generation"),
        sa.UniqueConstraint(
            "grant_id", "device_id", "policy_id", "session_token", "grant_generation", "policy_generation"
        ),
    )
    op.create_table(
        "native_prompt_observations",
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("occurrence_id", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("session_token", sa.String(length=64), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("agent", sa.String(), nullable=False),
        sa.Column("agent_version", sa.String(), nullable=False),
        sa.Column("native_profile", sa.String(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "native_profile='claude-code.user-prompt-submit.1' AND agent='claude-code' AND agent_version='2.1.330'"
        ),
        _uuid4_check("event_id"),
        _uuid4_check("occurrence_id"),
        sa.CheckConstraint(
            "typeof(session_token)='text' AND length(session_token)=64 AND "
            "instr(session_token,char(0))=0 AND session_token NOT GLOB '*[^0-9a-f]*'"
        ),
        sa.ForeignKeyConstraint(
            ["session_id", "device_id", "policy_id", "agent", "session_token"],
            [
                "agent_sessions.session_id",
                "agent_sessions.device_id",
                "agent_sessions.policy_id",
                "agent_sessions.agent",
                "agent_sessions.native_session_token",
            ],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint("device_id", "occurrence_id"),
        sa.UniqueConstraint("event_id", "occurrence_id", "session_id", "device_id", "policy_id", "session_token"),
    )
    op.create_index(
        op.f("ix_native_prompt_observations_expires_at"), "native_prompt_observations", ["expires_at"], unique=False
    )
    op.create_index(
        "ix_native_prompt_observations_session_time",
        "native_prompt_observations",
        ["session_id", "received_at", "event_id"],
        unique=False,
    )
    op.create_table(
        "native_prompt_decisions",
        sa.Column("decision_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("occurrence_id", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("session_token", sa.String(length=64), nullable=False),
        sa.Column("grant_id", sa.String(), nullable=False),
        sa.Column("grant_generation", sa.Integer(), nullable=False),
        sa.Column("policy_generation", sa.Integer(), nullable=False),
        sa.Column("policy_revision", sa.String(length=64), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("input_state", sa.String(), nullable=False),
        sa.Column("process_id", sa.String(), nullable=False),
        sa.Column("owner_nonce", sa.String(), nullable=False),
        sa.Column("inference_request_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("evaluated_action", sa.String(), nullable=True),
        sa.Column("returned_action", sa.String(), nullable=True),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("response_prepared", sa.Boolean(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "(status='pending' AND reason IS NULL AND evaluated_action IS NULL AND returned_action IS NULL AND "
            "response_prepared=0) OR (status='committed' AND reason IS NOT NULL AND evaluated_action IS NOT NULL AND "
            "response_prepared=(returned_action IS NOT NULL)) OR (status='abandoned' AND reason IS NOT NULL AND "
            "returned_action IS NULL AND response_prepared=0)"
        ),
        sa.CheckConstraint("evaluated_action IN ('allow','deny','unknown') AND returned_action IN ('allow','deny')"),
        sa.CheckConstraint(
            "input_state IN ('complete','capture_disabled','input_too_large','unsupported') AND mode IN ('report',"
            "'enforce')"
        ),
        sa.CheckConstraint(
            "reason IN ('clean','classifier_positive','access_rule_block','malicious_list','benign_override',"
            "'capture_disabled','input_too_large','input_unsupported','classifier_unavailable','classifier_invalid',"
            "'prompt_list_failed','deadline_exceeded','policy_changed','policy_unsupported','authority_changed',"
            "'storage_unavailable','request_retired')"
        ),
        sa.CheckConstraint("status IN ('pending','committed','abandoned') AND response_prepared IN (0,1)"),
        _uuid4_check("decision_id"),
        _uuid4_check("inference_request_id"),
        _uuid4_check("owner_nonce"),
        sa.CheckConstraint("typeof(policy_generation)='integer' AND policy_generation BETWEEN 1 AND 9007199254740991"),
        sa.CheckConstraint(
            "typeof(policy_revision)='text' AND length(policy_revision)=64 AND "
            "instr(policy_revision,char(0))=0 AND policy_revision NOT GLOB '*[^0-9a-f]*'"
        ),
        _uuid4_check("process_id"),
        _uuid4_check("request_id"),
        sa.ForeignKeyConstraint(
            ["event_id", "occurrence_id", "session_id", "device_id", "policy_id", "session_token"],
            [
                "native_prompt_observations.event_id",
                "native_prompt_observations.occurrence_id",
                "native_prompt_observations.session_id",
                "native_prompt_observations.device_id",
                "native_prompt_observations.policy_id",
                "native_prompt_observations.session_token",
            ],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["grant_id", "device_id", "policy_id", "session_token", "grant_generation", "policy_generation"],
            [
                "native_prompt_grants.grant_id",
                "native_prompt_grants.device_id",
                "native_prompt_grants.policy_id",
                "native_prompt_grants.session_token",
                "native_prompt_grants.grant_generation",
                "native_prompt_grants.policy_generation",
            ],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("decision_id"),
        sa.UniqueConstraint("decision_id", "device_id", "policy_id"),
        sa.UniqueConstraint(
            "decision_id", "device_id", "policy_id", "request_id", "occurrence_id", "grant_id", "grant_generation"
        ),
        sa.UniqueConstraint("device_id", "request_id"),
        sa.UniqueConstraint("event_id"),
        sa.UniqueConstraint("inference_request_id"),
    )
    op.create_index(
        op.f("ix_native_prompt_decisions_expires_at"), "native_prompt_decisions", ["expires_at"], unique=False
    )
    op.create_table(
        "native_prompt_assessments",
        sa.Column("decision_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("profile", sa.String(), nullable=False),
        sa.Column("model_identity", sa.String(), nullable=True),
        sa.Column("unsafe_score", sa.Float(), nullable=True),
        sa.Column("score_kind", sa.String(), nullable=True),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "(status='assessed' AND model_identity IS NOT NULL AND "
            f"model_identity='{_PINNED_MODEL}' AND score_kind IS NOT NULL AND "
            "score_kind='two_class_softmax_uncalibrated' AND typeof(unsafe_score) IN ('integer','real') "
            "AND unsafe_score BETWEEN 0 AND 1 AND typeof(input_tokens)='integer' "
            "AND input_tokens BETWEEN 1 AND 1024) OR (status!='assessed' AND model_identity IS NULL "
            "AND score_kind IS NULL AND unsafe_score IS NULL AND input_tokens IS NULL)"
        ),
        sa.CheckConstraint(
            "(status='assessed' AND reason IN ('clean','classifier_positive')) OR (status='unsupported' AND reason "
            "IN ('input_unsupported','input_too_large')) OR (status='not_requested' AND reason IN "
            "('capture_disabled','access_rule_block','malicious_list','benign_override')) OR (status='failed' AND "
            "reason IN ('classifier_invalid','prompt_list_failed')) OR (status='unavailable' AND reason IN "
            "('classifier_unavailable','deadline_exceeded','policy_changed','policy_unsupported','authority_changed',"
            "'storage_unavailable','request_retired'))"
        ),
        sa.CheckConstraint("profile='tidewall.prompt-injection.1'"),
        sa.ForeignKeyConstraint(
            ["decision_id", "device_id", "policy_id"],
            [
                "native_prompt_decisions.decision_id",
                "native_prompt_decisions.device_id",
                "native_prompt_decisions.policy_id",
            ],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("decision_id"),
    )
    op.create_table(
        "native_prompt_deliveries",
        sa.Column("report_id", sa.String(), nullable=False),
        sa.Column("decision_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("grant_id", sa.String(), nullable=False),
        sa.Column("grant_generation", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("occurrence_id", sa.String(), nullable=False),
        sa.Column("evidence_source", sa.String(), nullable=False),
        sa.Column("stage", sa.String(), nullable=False),
        sa.Column("tool_count", sa.Integer(), nullable=True),
        sa.Column("token_count", sa.Integer(), nullable=True),
        sa.Column("marker_present", sa.Boolean(), nullable=True),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "evidence_source IN ('hook','controlled_observer') AND stage IN ('stdout_flushed','allow_no_output',"
            "'stdout_failed','native_ack_blocked','effect_allow_marker_verified','effect_deny_no_effect_verified',"
            "'unknown')"
        ),
        sa.CheckConstraint(
            "token_count IS NULL OR (typeof(token_count)='integer' AND token_count BETWEEN 0 AND 2147483647)"
        ),
        sa.CheckConstraint(
            "tool_count IS NULL OR (typeof(tool_count)='integer' AND tool_count BETWEEN 0 AND 2147483647)"
        ),
        _uuid4_check("report_id"),
        sa.CheckConstraint("marker_present IN (0,1)"),
        sa.ForeignKeyConstraint(
            ["decision_id", "device_id", "policy_id", "request_id", "occurrence_id", "grant_id", "grant_generation"],
            [
                "native_prompt_decisions.decision_id",
                "native_prompt_decisions.device_id",
                "native_prompt_decisions.policy_id",
                "native_prompt_decisions.request_id",
                "native_prompt_decisions.occurrence_id",
                "native_prompt_decisions.grant_id",
                "native_prompt_decisions.grant_generation",
            ],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("report_id"),
    )
    op.create_index(
        op.f("ix_native_prompt_deliveries_expires_at"), "native_prompt_deliveries", ["expires_at"], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_native_prompt_deliveries_expires_at"), table_name="native_prompt_deliveries")
    op.drop_table("native_prompt_deliveries")
    op.drop_table("native_prompt_assessments")
    op.drop_index(op.f("ix_native_prompt_decisions_expires_at"), table_name="native_prompt_decisions")
    op.drop_table("native_prompt_decisions")
    op.drop_index("ix_native_prompt_observations_session_time", table_name="native_prompt_observations")
    op.drop_index(op.f("ix_native_prompt_observations_expires_at"), table_name="native_prompt_observations")
    op.drop_table("native_prompt_observations")
    op.drop_table("native_prompt_grants")
    op.drop_table("native_prompt_policy_configs")
    op.drop_index("uq_native_session_scope", table_name="agent_sessions")
