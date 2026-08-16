"""Global prompt list CRUD and pattern matching."""

from __future__ import annotations

import logging
import re

from sqlalchemy.orm import Session

from app.db.models import GlobalPromptList
from app.services.policy_validation import validate_prompt_list_entry

logger = logging.getLogger(__name__)


class PromptListService:
    """Manages global benign/malicious prompt lists."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        list_type: str,
        pattern: str,
        match_type: str = "substring",
        description: str | None = None,
        created_by: str | None = None,
    ) -> GlobalPromptList:
        # An invalid stored regex used to be skipped at match time, so a
        # malicious-list entry simply never matched. Reject it here.
        validate_prompt_list_entry(pattern, match_type, where="prompt_list.pattern")
        entry = GlobalPromptList(
            list_type=list_type,
            pattern=pattern,
            match_type=match_type,
            description=description,
            created_by=created_by,
        )
        self._session.add(entry)
        self._session.commit()
        return entry

    def list_entries(self, list_type: str | None = None) -> list[GlobalPromptList]:
        query = self._session.query(GlobalPromptList)
        if list_type:
            query = query.filter_by(list_type=list_type)
        return query.order_by(GlobalPromptList.created_at.desc()).all()

    def get(self, entry_id: str) -> GlobalPromptList | None:
        return self._session.get(GlobalPromptList, entry_id)

    def update(
        self,
        entry_id: str,
        pattern: str | None = None,
        match_type: str | None = None,
        description: str | None = None,
    ) -> GlobalPromptList:
        entry = self._session.get(GlobalPromptList, entry_id)
        if entry is None:
            raise ValueError(f"Prompt list entry {entry_id} not found")
        if pattern is not None:
            entry.pattern = pattern
        if match_type is not None:
            entry.match_type = match_type
        if description is not None:
            entry.description = description
        self._session.commit()
        return entry

    def delete(self, entry_id: str) -> None:
        entry = self._session.get(GlobalPromptList, entry_id)
        if entry is None:
            raise ValueError(f"Prompt list entry {entry_id} not found")
        self._session.delete(entry)
        self._session.commit()

    def check_match(self, text: str, list_type: str) -> bool:
        """Check if text matches any pattern in the given list type.

        Matching is case-insensitive for all match types.
        """
        entries = self.list_entries(list_type=list_type)
        text_lower = text.lower()

        for entry in entries:
            pattern_lower = entry.pattern.lower()

            if entry.match_type == "substring":
                if pattern_lower in text_lower:
                    return True
            elif entry.match_type == "exact":
                if text_lower == pattern_lower:
                    return True
            elif entry.match_type == "regex":
                try:
                    if re.search(entry.pattern, text, re.IGNORECASE):
                        return True
                except re.error as exc:
                    # Skipping meant a malicious-list entry simply never
                    # matched. Raise so the calling detector records a failure
                    # instead of reporting a confident "no match".
                    logger.error("Invalid regex in stored prompt list entry")
                    raise ValueError("invalid regex in prompt list") from exc

        return False
