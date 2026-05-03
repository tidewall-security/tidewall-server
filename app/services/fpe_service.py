"""Format Preserving Encryption service using AES-FF1-256.

Encrypts values while preserving their format (digits stay digits,
length preserved). Uses the ff3 library (FF3-1 algorithm).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re

from sqlalchemy.orm import Session

from app.db.models import FPESettings

logger = logging.getLogger(__name__)

# Minimum plaintext length for ff3 varies by radix
# radix^len >= 1,000,000
# radix 10: min 6 chars, radix 36: min 4 chars
_MIN_LEN = {10: 6, 36: 4, 62: 4}


class FPEService:
    """AES-FF1-256 format-preserving encryption."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._settings: FPESettings | None = None

    def _get_settings(self) -> FPESettings:
        """Get or create FPE settings (auto-generates key on first use)."""
        if self._settings is None:
            self._settings = self._session.query(FPESettings).first()
            if self._settings is None:
                self._settings = FPESettings(
                    id="singleton",
                    key=os.urandom(32),
                )
                self._session.add(self._settings)
                self._session.commit()
                logger.info("FPE key auto-generated")
        return self._settings

    def _get_tweak(self) -> tuple[str, bool]:
        """Return (tweak_hex, is_deterministic).

        If custom tweak set → deterministic. Otherwise → random 7 bytes.
        """
        settings = self._get_settings()
        if settings.default_tweak:
            return settings.default_tweak, True
        return os.urandom(7).hex(), False

    def encrypt(self, plaintext: str, radix: int = 10) -> tuple[str, str]:
        """Encrypt a value preserving format.

        Args:
            plaintext: Value to encrypt (e.g., "234567890")
            radix: 10 for digits, 36 for alphanumeric

        Returns:
            (ciphertext, fpe_context) where fpe_context is base64 JSON
        """
        from ff3 import FF3Cipher

        settings = self._get_settings()
        key_hex = settings.key.hex()
        tweak_hex, deterministic = self._get_tweak()

        # Normalize for radix 36 (lowercase only)
        original = plaintext
        if radix == 36:
            plaintext = plaintext.lower()

        # Pad short values to meet ff3 minimum domain
        min_len = _MIN_LEN.get(radix, 6)
        padded = False
        pad_len = 0
        if len(plaintext) < min_len:
            pad_len = min_len - len(plaintext)
            pad_char = "0" if radix == 10 else "a"
            plaintext = pad_char * pad_len + plaintext
            padded = True

        # Strip non-alphanumeric chars for encryption, track positions
        if radix == 10:
            clean = re.sub(r"[^0-9]", "", plaintext)
            separators = [(i, c) for i, c in enumerate(plaintext) if not c.isdigit()]
        else:
            clean = re.sub(r"[^0-9a-z]", "", plaintext)
            separators = [(i, c) for i, c in enumerate(plaintext) if not c.isalnum()]

        if len(clean) < _MIN_LEN.get(radix, 6):
            # Still too short after cleaning — can't encrypt, fall back
            logger.warning("Value too short for FPE (len=%d, radix=%d)", len(clean), radix)
            return plaintext, ""

        cipher = FF3Cipher(key_hex, tweak_hex)
        if radix != 10:
            cipher = FF3Cipher.withCustomAlphabet(key_hex, tweak_hex, "0123456789abcdefghijklmnopqrstuvwxyz")

        encrypted_clean = cipher.encrypt(clean)

        # Re-insert separators
        result_chars = list(encrypted_clean)
        for pos, sep_char in separators:
            if pos <= len(result_chars):
                result_chars.insert(pos, sep_char)
        encrypted = "".join(result_chars)

        # Keep full ciphertext (including pad prefix) — needed for correct decryption.
        # The pad_len in context tells decrypt how many leading chars to strip from
        # the decrypted plaintext, not from the ciphertext.

        # Build fpe_context
        context = {
            "version": 1,
            "algorithm": "AES-FF1-256",
            "tweak": tweak_hex,
            "radix": radix,
            "original_len": len(original),
            "padded": padded,
            "pad_len": pad_len,
            "separators": separators,
        }
        fpe_context = base64.b64encode(json.dumps(context).encode()).decode()

        return encrypted, fpe_context

    def decrypt(self, ciphertext: str, fpe_context: str) -> str:
        """Decrypt a value using the fpe_context from a previous encrypt."""
        from ff3 import FF3Cipher

        ctx = json.loads(base64.b64decode(fpe_context))
        settings = self._get_settings()
        key_hex = settings.key.hex()
        tweak_hex = ctx["tweak"]
        radix = ctx.get("radix", 10)
        padded = ctx.get("padded", False)
        pad_len = ctx.get("pad_len", 0)
        separators = ctx.get("separators", [])

        # The ciphertext already includes the padding prefix (not stripped on encrypt).
        # We just need to decrypt the full ciphertext and strip pad from the result.
        working = ciphertext

        # Strip separators
        if radix == 10:
            clean = re.sub(r"[^0-9]", "", working)
        else:
            working = working.lower()
            clean = re.sub(r"[^0-9a-z]", "", working)

        cipher = FF3Cipher(key_hex, tweak_hex)
        if radix != 10:
            cipher = FF3Cipher.withCustomAlphabet(key_hex, tweak_hex, "0123456789abcdefghijklmnopqrstuvwxyz")

        decrypted_clean = cipher.decrypt(clean)

        # Re-insert separators
        result_chars = list(decrypted_clean)
        for pos, sep_char in separators:
            if pos <= len(result_chars):
                result_chars.insert(pos, sep_char)
        decrypted = "".join(result_chars)

        # Remove padding
        if padded:
            decrypted = decrypted[pad_len:]

        return decrypted
