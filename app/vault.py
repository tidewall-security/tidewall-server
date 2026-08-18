"""TidewallVault — placeholder→original mapping for reversible PII redaction.

Stores a simple ``str → str`` dict and a per-entity-type counter so each new
value gets the next ``[REDACTED_<TYPE>_<N>]`` placeholder. Identical originals
re-use their existing placeholder so the same name appearing twice in a prompt
doesn't blow up the counter.

Why this exists: the PII detector (Presidio) emits ``RecognizerResult`` spans
identifying the start/end of each entity in the original text. We replace each
span with a placeholder, store the original→placeholder mapping in the vault,
and persist the vault to the ``vaults`` table so /v1/unredact can reverse it
later.

Persistence is JSON bytes via :meth:`to_bytes` / :meth:`from_bytes`, which
avoids the pickle attack surface that storing arbitrary Python objects would
carry.

.. warning::

   :meth:`to_bytes` emits **plaintext** PII. Choosing JSON over pickle was the
   right call, but it is a separate decision from choosing plaintext over
   ciphertext, and only the first was made. This is currently latent rather
   than live: :class:`~app.vault_manager.VaultManager` only ever persists an
   *empty* vault (see its module docstring), so no PII reaches the database
   today. Any change that makes persistence work must encrypt this payload in
   the same commit, or it creates the disclosure it was meant to fix.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict

_PLACEHOLDER_FMT = "[REDACTED_{type}_{n}]"
_PLACEHOLDER_RE = re.compile(r"^\[REDACTED_(.+)_(\d+)\]$")


class TidewallVault:
    """In-memory mapping of redaction placeholders to original PII values."""

    def __init__(self) -> None:
        # placeholder string → original value (e.g. "[REDACTED_PERSON_1]" → "Alice")
        self._placeholder_to_original: dict[str, str] = {}
        # original value → placeholder string (for de-duplication on store())
        self._original_to_placeholder: dict[tuple[str, str], str] = {}
        # next index per entity type
        self._counters: defaultdict[str, int] = defaultdict(int)

    def store(self, entity_type: str, original: str) -> str:
        """Record an original value, returning the placeholder to swap into the text.

        Calling :meth:`store` twice with the same ``(entity_type, original)``
        returns the same placeholder — one Alice in the prompt should not
        consume two slots in the counter.
        """
        key = (entity_type, original)
        if key in self._original_to_placeholder:
            return self._original_to_placeholder[key]

        self._counters[entity_type] += 1
        placeholder = _PLACEHOLDER_FMT.format(type=entity_type, n=self._counters[entity_type])
        self._placeholder_to_original[placeholder] = original
        self._original_to_placeholder[key] = placeholder
        return placeholder

    def unredact(self, text: str) -> str:
        """Replace every placeholder in ``text`` with its original value.

        Order matters: longer placeholders are replaced first so
        ``[REDACTED_PERSON_10]`` doesn't get partially matched by
        ``[REDACTED_PERSON_1]``.
        """
        # Sort by length desc so the longer placeholder wins on overlap.
        for placeholder in sorted(self._placeholder_to_original, key=len, reverse=True):
            text = text.replace(placeholder, self._placeholder_to_original[placeholder])
        return text

    def to_bytes(self) -> bytes:
        """Serialize for persistence (JSON-encoded UTF-8 bytes)."""
        payload = {
            "placeholders": self._placeholder_to_original,
            "counters": dict(self._counters),
        }
        return json.dumps(payload).encode("utf-8")

    @classmethod
    def from_bytes(cls, blob: bytes) -> TidewallVault:
        """Reconstruct a vault from :meth:`to_bytes` output."""
        payload = json.loads(blob.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Vault payload must be a JSON object")
        vault = cls()
        vault._placeholder_to_original = dict(payload.get("placeholders", {}))
        vault._counters = defaultdict(int, payload.get("counters", {}))
        # Rebuild the reverse index from the stored placeholders.
        for placeholder, original in vault._placeholder_to_original.items():
            m = _PLACEHOLDER_RE.match(placeholder)
            if not m:
                raise ValueError(f"Malformed placeholder in vault payload: {placeholder!r}")
            entity_type = m.group(1)
            vault._original_to_placeholder[(entity_type, original)] = placeholder
        return vault
