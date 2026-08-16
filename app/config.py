"""Configuration loader for Tidewall.

Reads settings from environment variables and parses policy.yaml into
validated Pydantic models.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Settings (environment variables)
# ---------------------------------------------------------------------------


class Settings(BaseModel):
    """Application-level settings sourced from environment variables."""

    POLICY_FILE: str = "policy.yaml"
    DB_URL: str = "sqlite:///data/tidewall.db"
    LOG_LEVEL: str = "info"
    PREWARM: bool = True
    # Authentication defaults ON. It previously defaulted off, and the
    # middleware handled that by assigning every unauthenticated caller the
    # admin role — so the shipped container exposed the whole control plane:
    # log reads, policy mutation, key minting, export targets. Disabling it now
    # requires TIDEWALL_INSECURE_NO_AUTH=1 and a loopback bind.
    AUTH_ENABLED: bool = True
    TIDEWALL_INSECURE_NO_AUTH: bool = False
    # Bind address. Authoritative: the server is launched via ``python -m app``
    # which binds exactly this, so the insecure-mode guard constrains the real
    # socket rather than a setting nothing reads.
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    USE_ONNX: bool = False
    # Operator-supplied first admin credential. Consulted only when
    # AUTH_ENABLED is set and no API keys exist yet; only its hash is stored.
    # Tidewall never generates this, because a generated value would have to be
    # emitted to logs or stdout to reach the operator, where it would persist.
    BOOTSTRAP_KEY: str | None = None

    @classmethod
    def from_env(cls) -> Settings:
        """Build a Settings instance from the current environment."""
        overrides: dict[str, Any] = {}
        for field_name in cls.model_fields:
            env_val = os.environ.get(field_name)
            if env_val is not None:
                overrides[field_name] = env_val
        return cls(**overrides)


# ---------------------------------------------------------------------------
# Policy models
# ---------------------------------------------------------------------------


class DetectorConfig(BaseModel):
    """Configuration for a single detector.

    Extra fields are allowed so that detector-specific parameters (e.g.
    ``threshold``, ``topics``, ``valid_languages``) pass through without
    requiring an exhaustive schema here.
    """

    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    action: str = "report"  # "block" | "report" | "redact"


class OnDetectorFailure(str, Enum):
    """What to do when a blocking or redacting detector cannot run.

    ``BLOCK`` is the correct setting for a security product: a detector that
    failed did not inspect the request, so allowing it returns a clean verdict
    for content nothing looked at.

    ``REPORT`` remains the default only until the activation preflight exists.
    Without a preflight that refuses to *serve* a policy whose required
    detectors cannot construct, defaulting to BLOCK turns an absent spaCy model
    or a gated Hugging Face model into a service that boots healthy and rejects
    100% of traffic. Failing visibly at startup is the right answer; blocking
    every request at runtime is not.
    """

    BLOCK = "block"
    REPORT = "report"


class PolicyConfig(BaseModel):
    """Top-level policy configuration parsed from policy.yaml."""

    name: str
    report_only: bool = False
    on_detector_failure: OnDetectorFailure = OnDetectorFailure.REPORT
    detectors: dict[str, DetectorConfig] = {}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_policy(path: str | Path) -> PolicyConfig:
    """Read a YAML policy file and return a validated PolicyConfig.

    Parameters
    ----------
    path:
        Filesystem path to the policy YAML file.

    Returns
    -------
    PolicyConfig
        The parsed and validated policy.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If the YAML content fails validation.
    """
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    with open(policy_path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping at top level, got {type(raw).__name__}")

    return PolicyConfig(**raw)
