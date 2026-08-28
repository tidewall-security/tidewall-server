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
from pydantic import BaseModel, ConfigDict, model_validator

# ---------------------------------------------------------------------------
# Settings (environment variables)
# ---------------------------------------------------------------------------
from app.services.nat64 import Pref64Posture, parse_pref64


class Settings(BaseModel):
    """Application-level settings sourced from environment variables."""

    POLICY_FILE: str = "policy.yaml"
    DB_URL: str = "sqlite:///data/tidewall.db"
    LOG_LEVEL: str = "info"
    PREWARM: bool = True
    # Bind address and port. Launch configuration, not an authorization
    # control: authentication is unconditional, so where the server listens no
    # longer decides who may administer it.
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    # Operator-supplied first admin credential. Consulted only when no API
    # keys exist yet; only its hash is stored.
    # Tidewall never generates this, because a generated value would have to be
    # emitted to logs or stdout to reach the operator, where it would persist.
    BOOTSTRAP_KEY: str | None = None
    # The deployment's declared NAT64 posture. Unset is not a default: content
    # export refuses rather than assume this network has no translation. See
    # app/services/nat64.py and the finding it names.
    PREF64: str | None = None
    # Bounds on the two device endpoints a stranger can reach. Enrolment is
    # unauthenticated but for the key; refresh is reachable with a credential
    # that does not exist, because its middleware deliberately leaves
    # adjudication to the service.
    ENROLMENT_RATE_PER_MINUTE: int = 10
    #: Pending devices one registration key may have awaiting approval.
    MAX_PENDING_PER_TOKEN: int = 50
    #: How long an unapproved device survives before it is reaped.
    PENDING_DEVICE_TTL_HOURS: int = 72
    #: X-Forwarded-For entries to believe, counted from the right. Zero means
    #: the ASGI peer and nothing else -- the header is caller-supplied, and
    #: trusting it unconditionally lets every request claim a fresh identity.
    TRUSTED_PROXY_HOPS: int = 0

    # The vault keyring. A vault holds the placeholder-to-original mapping that
    # makes redaction reversible, which is to say it holds exactly the values
    # the product exists to protect. It is encrypted at rest under a key the
    # operator supplies; unset means no key, and reversible redaction has
    # nothing to store its mapping in.
    #
    # Both are held here as the operator wrote them and parsed by
    # `app.vault_crypto.Keyring.from_settings`, which runs once at startup: a
    # malformed declaration stops the server there, in front of whoever
    # deployed it, rather than on some later request.
    #
    #: ``id:base64-material`` entries, comma separated. Ids are operator-chosen
    #: labels and must stay stable, because every row names the id it was
    #: sealed under. Material is 32 raw bytes (AES-256), base64 encoded.
    VAULT_ENCRYPTION_KEYS: str | None = None
    #: Which id in VAULT_ENCRYPTION_KEYS new vaults are sealed under. To rotate,
    #: add the new key, repoint this at it, and keep the previous key in KEYS
    #: for at least the vault TTL -- rows naming it are still live until then,
    #: and nothing is re-encrypted.
    VAULT_ENCRYPTION_CURRENT: str | None = None

    @classmethod
    def from_env(cls) -> Settings:
        """Build a Settings instance from the current environment."""
        overrides: dict[str, Any] = {}
        for field_name in cls.model_fields:
            env_val = os.environ.get(field_name)
            if env_val is not None:
                overrides[field_name] = env_val
        return cls(**overrides)

    # Parsed eagerly on construction, not lazily on access. A property would
    # defer the failure to the first export, which is the opposite of the
    # point: a malformed declaration must stop startup, where an operator is
    # watching, not a single request hours later.
    pref64_posture: Pref64Posture = Pref64Posture(is_unset=True)

    @model_validator(mode="after")
    def _parse_pref64(self) -> Settings:
        object.__setattr__(self, "pref64_posture", parse_pref64(self.PREF64))
        return self


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
