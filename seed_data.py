"""Seed the Tidewall database with realistic demo data."""

import os
import random
import sys
import uuid
from datetime import UTC, datetime, timedelta

# Add app to path
sys.path.insert(0, os.path.dirname(__file__))
from app.interaction_log import InteractionLog
from app.services.safe_export_evidence import project_detectors

USERS = [
    "alice.chen@acme.com",
    "bob.smith@acme.com",
    "charlie.wilson@acme.com",
    "diana.park@acme.com",
    "mallory.jones@external.com",  # The villain
]

APPS = ["customer-chatbot", "internal-copilot", "code-assistant", "research-agent"]
MODELS = ["gpt-4o", "claude-3", "llama-3", "mistral-7b"]


def generate_events(count=80):
    from app.db.engine import get_engine, get_session_factory

    db_url = os.environ.get("DB_URL", "sqlite:///data/tidewall.db")
    os.makedirs("data", exist_ok=True)
    engine = get_engine(db_url)

    # Run Alembic migrations to ensure tables exist
    from pathlib import Path

    from alembic import command
    from alembic.config import Config as AlembicConfig

    alembic_cfg = AlembicConfig(str(Path(__file__).parent / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(alembic_cfg, "head")

    session_factory = get_session_factory(engine)

    # Rows are scoped by policy now, so the seeder needs a real one.
    from app.db.models import Policy

    with session_factory() as session:
        policy = session.query(Policy).filter_by(is_default=True).first() or session.query(Policy).first()
        if policy is None:
            raise SystemExit("no policy in the database — start the server once so it seeds one")
        policy_id = policy.id
    log = InteractionLog(session_factory)
    now = datetime.now(UTC)

    for i in range(count):
        timestamp = now - timedelta(hours=random.uniform(0, 48))
        ts_str = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

        # mallory gets more malicious events
        if random.random() < 0.15:
            user = "mallory.jones@external.com"
            prompt_type = random.choice(["injection", "injection", "secret", "pii", "clean"])
        else:
            user = random.choice(USERS)
            prompt_type = random.choices(
                ["clean", "pii", "injection", "secret"],
                weights=[0.6, 0.2, 0.1, 0.1],
            )[0]

        app = random.choice(APPS)
        model = random.choice(MODELS)

        if prompt_type == "clean":
            blocked, transformed = False, False
            detectors = {"malicious_prompt": {"detected": False, "data": None}}
        elif prompt_type == "injection":
            blocked, transformed = True, False
            detectors = {
                "malicious_prompt": {
                    "detected": True,
                    "data": {
                        "action": "blocked",
                        "analyzer_responses": [
                            {
                                "analyzer": "LLMGuard/deberta-v3",
                                "confidence": round(random.uniform(0.92, 1.0), 4),
                            }
                        ],
                    },
                }
            }
        elif prompt_type == "pii":
            blocked, transformed = False, True
            detectors = {
                "confidential_and_pii_entity": {
                    "detected": True,
                    "data": {
                        "entities": [
                            {
                                "type": "US_SSN",
                                "value": "[REDACTED]",
                                "action": "redacted:replaced",
                                "start_pos": 0,
                            }
                        ]
                    },
                }
            }
        else:  # secret
            blocked, transformed = False, True
            detectors = {
                "secret_and_key_entity": {
                    "detected": True,
                    "data": {
                        "entities": [
                            {
                                "type": "AWS_ACCESS_KEY",
                                "value": "[REDACTED]",
                                "action": "redacted:replaced",
                                "start_pos": 0,
                            }
                        ]
                    },
                }
            }

        log.log_event(
            request_id=f"tw_{uuid.uuid4().hex[:16]}",
            timestamp=ts_str,
            event_type="input",
            policy="default_policy",
            policy_id=policy_id,
            blocked=blocked,
            transformed=transformed,
            latency_ms=round(random.uniform(50, 3000), 1),
            # The demo generator used to write realistic prompts containing
            # PII and secrets straight into the database, which is the exact
            # thing this finding is about — a demo dataset is still a dataset.
            # It now seeds the same evidence without the prompts.
            evidence=project_detectors(detectors),
            app_id=app,
            user_id=user,
            llm_provider=model.split("-")[0] if "-" in model else "openai",
            model=model,
            source_ip=f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}",
        )

    print(f"Seeded {count} events into the database")


if __name__ == "__main__":
    generate_events(int(sys.argv[1]) if len(sys.argv) > 1 else 80)
