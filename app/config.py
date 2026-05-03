"""Configuration loader for Tidewall.

Reads settings from environment variables and parses policy.yaml into
validated Pydantic models.
"""

from __future__ import annotations

import os
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
    AUTH_ENABLED: bool = False
    USE_ONNX: bool = False

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


class PolicyConfig(BaseModel):
    """Top-level policy configuration parsed from policy.yaml."""

    name: str
    report_only: bool = False
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
