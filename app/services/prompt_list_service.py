"""Global prompt list CRUD and pattern matching."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.db.models import GlobalPromptList
from app.services.policy_validation import PolicyValidationError, validate_prompt_list_entry
from app.services.safe_regex import MAX_PATTERNS, UnsafePatternError, compile_pattern

logger = logging.getLogger(__name__)


class PromptListConfigError(ValueError):
    """Stored prompt-list configuration that cannot be enforced as written.

    Distinct from an operational failure: the calling detector records this as
    CONFIG_INVALID, because the fix is to correct the row, not to retry.
    """


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

        # Per list type, because check_match scans one type at a time and every
        # regex row is another pass over the text. A linear engine bounds the
        # cost of each pattern, not the number of them.
        existing = self._session.query(GlobalPromptList).filter_by(list_type=list_type).count()
        if existing >= MAX_PATTERNS:
            raise PolicyValidationError(
                f"prompt_list: the {list_type} list already holds {existing} entries, "
                f"at the {MAX_PATTERNS} limit. Each entry is scanned against every message."
            )
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

    def _bounded_entries(self, list_type: str) -> list[GlobalPromptList]:
        """Fetch at most one row past the budget, and fail if it exists.

        Checking the length of a full fetch is not a bound: the scan is capped
        but the query is not, so a direct write of a million rows still makes
        every request retrieve and instantiate a million objects before the cap
        fires. The limit has to be in the SQL.

        The extra row is what distinguishes "at budget" from "over budget"
        without a second COUNT round trip.
        """
        entries = (
            self._session.query(GlobalPromptList)
            .filter_by(list_type=list_type)
            .order_by(GlobalPromptList.created_at.desc())
            .limit(MAX_PATTERNS + 1)
            .all()
        )
        if len(entries) > MAX_PATTERNS:
            # Create-time counting is not a hard invariant — two concurrent
            # inserts can both pass it, and rows can be written directly. The
            # scan path has to fail closed rather than do unbounded work.
            raise PromptListConfigError(f"{list_type} prompt list holds more than the {MAX_PATTERNS}-entry limit")
        return entries

    def preflight(self, list_type: str) -> None:
        """Compile every stored pattern for a list type without scanning.

        Called at detector construction so an unenforceable row is visible to
        activation preflight, rather than being discovered by whichever request
        first happens to scan that list. Raises PromptListConfigError, which the
        caller records as a CONFIG_INVALID component.
        """
        for entry in self._bounded_entries(list_type):
            if entry.match_type == "regex":
                try:
                    compile_pattern(entry.pattern, case_insensitive=True)
                except UnsafePatternError as exc:
                    logger.error("Invalid regex in stored %s prompt list entry", list_type)
                    raise PromptListConfigError("invalid regex in prompt list") from exc

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

        # Creation validates, this did not — so any pattern rejected at create
        # time could simply be introduced by a follow-up update. Validate the
        # *effective* pair, because either half may be unchanged: a new pattern
        # has to be checked against the stored match_type, and switching
        # match_type to "regex" has to re-check the stored pattern.
        effective_pattern = pattern if pattern is not None else entry.pattern
        effective_match_type = match_type if match_type is not None else entry.match_type
        if pattern is not None or match_type is not None:
            validate_prompt_list_entry(effective_pattern, effective_match_type)

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
        entries = self._bounded_entries(list_type)
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
                    # Compiled per read rather than cached: list rows are
                    # mutable independently of the engine cache, so a cache
                    # without invalidation would keep matching a pattern the
                    # administrator has already changed.
                    if compile_pattern(entry.pattern, case_insensitive=True).search(text):
                        return True
                except UnsafePatternError as exc:
                    # Skipping meant a malicious-list entry simply never
                    # matched. Raise so the calling detector records a failure
                    # instead of reporting a confident "no match".
                    #
                    # A distinct type, not a bare ValueError: this is invalid
                    # *configuration*, and the detector must record it as
                    # CONFIG_INVALID rather than as an operational scan failure.
                    # The two say different things to whoever has to fix it.
                    logger.error("Invalid regex in stored prompt list entry")
                    raise PromptListConfigError("invalid regex in prompt list") from exc

        return False
