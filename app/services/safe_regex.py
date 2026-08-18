"""The only place an administrator-supplied regex may be compiled.

Custom-entity patterns and regex prompt-list entries are written by an
administrator and matched against prompt text supplied by whoever is calling
the guard. Python's `re` backtracks, so that combination is a denial of service
waiting to be configured: `(a+)+$` against 41 characters of `"a"*40 + "!"` runs
for over three seconds and does not stop. It needs no crafted megabyte payload
and no malice from the administrator — an ordinary-looking pattern is enough,
and any caller can then take the guard offline (P0-12).

RE2 cannot backtrack. Matching is linear in the length of the input, so the
same pattern and input return in about 0.1ms. That guarantee is a property of
the engine, which is why this module exists: the fix is not a timeout bolted
onto `re`, it is never handing supplied patterns to a backtracking engine at
all.

Two consequences worth stating plainly:

- **There is deliberately no fallback to `re`.** A fallback would route exactly
  the patterns RE2 refuses — the ones using backreferences and lookaround, the
  most complex ones — back onto the vulnerable engine. Refusing them is the
  point.
- **RE2 accepts a narrower language.** Backreferences and lookaround are
  rejected at compile time. Nothing shipped uses them (`policy.yaml` ships
  `patterns: []`), so this constrains only what an administrator writes from
  now on, and it is caught at write time with a 400 rather than at scan time.

Case-insensitive matching is *close to* `re.IGNORECASE` but not identical, and
the difference is a real behaviour change rather than a theoretical one. The
Turkish dotted and dotless I do not fold:

    pattern "i" against "\u0130"   re: matches    RE2: does not
    pattern "\u0131" against "I"   re: matches    RE2: does not

Other folds tested — Kelvin sign, long s, final sigma — agree. So a malicious
prompt-list entry can stop matching a few Unicode I cases it used to catch.
That is the price of the linear guarantee, not a reason to fall back; it is
recorded here and pinned by a test so nobody claims exact `re.IGNORECASE`
compatibility.

Linear is not free: `N` patterns still cost `N × len(text)`, and a pattern like
`.?` can produce a match per character. Hence the budgets below.
"""

from __future__ import annotations

import re2

# A pattern longer than this is not a rule anyone is maintaining, and it bounds
# compilation memory and error-message size. It does NOT detect a dangerous
# pattern — length and danger are unrelated — so it must never be described as
# a backtracking control.
MAX_PATTERN_LENGTH = 1000

# RE2 makes each match linear, not free. Every configured pattern is another
# full pass over the text.
MAX_PATTERNS = 100

# A legal, linear pattern can still match once per character — `.?` against a
# long input produces a span per position. Retaining every span is its own
# exhaustion path, so scanning stops at this many and reports a failure rather
# than a truncated result that would read as a complete scan.
MAX_MATCHES_PER_SCAN = 1000

# Per-pattern compiled program size. RE2's own default is 8MB, which times
# MAX_PATTERNS would let configuration alone reserve most of a gigabyte.
_MAX_PROGRAM_BYTES = 1 << 20


class UnsafePatternError(ValueError):
    """A pattern the linear engine will not accept.

    Raised at write time so the administrator gets a 400 naming the field, and
    at construction time so a row that reached the database another way cannot
    be silently skipped.
    """


def compile_pattern(pattern: str, *, case_insensitive: bool = False):
    """Compile one supplied pattern, or refuse it.

    Every caller matching a supplied pattern against request content must come
    through here. Calling `re.compile` on such a pattern anywhere else
    reintroduces P0-12 at that site.
    """
    if not isinstance(pattern, str):
        raise UnsafePatternError(f"pattern must be a string, got {type(pattern).__name__}")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise UnsafePatternError(f"pattern is {len(pattern)} characters, over the {MAX_PATTERN_LENGTH} limit")

    options = re2.Options()
    options.case_sensitive = not case_insensitive
    # RE2 writes every parse failure to stderr through absl by default. We
    # raise a proper error, so that output is pure noise — and worse, it is
    # attacker-influenced noise: a caller submitting bad patterns could flood
    # the operator's logs.
    options.log_errors = False
    # Bound the compiled program. RE2 is linear in input, not in pattern size,
    # and MAX_PATTERNS of them can be configured at once. The library default
    # is 8MB each, which is far more than a policy rule needs.
    options.max_mem = _MAX_PROGRAM_BYTES

    try:
        return re2.compile(pattern, options)
    except re2.error as exc:
        # RE2 refuses backreferences and lookaround by construction — they
        # cannot be matched in linear time. Say so, rather than reporting it as
        # though the pattern were malformed, because the pattern is very likely
        # valid Python `re` and the author needs to know why it is refused.
        # RE2 surfaces its message as bytes; a raw b'...' repr in an API error
        # is noise for whoever is fixing the pattern.
        detail = exc.args[0] if exc.args else exc
        if isinstance(detail, bytes | bytearray):
            detail = detail.decode("utf-8", "replace")
        detail = str(detail)

        # Distinguish "this is not a regex" from "this is a regex we will not
        # run". Collapsing the two would tell an author their working Python
        # pattern is malformed, which is both wrong and unactionable.
        if "perl operator" in detail or "escape sequence" in detail:
            raise UnsafePatternError(
                f"invalid regex: unsupported construct ({detail}). The safe engine "
                f"cannot run backreferences or lookaround — they cannot be matched "
                f"in linear time, which is what stops a pattern from hanging the "
                f"server. Rewrite the pattern without them."
            ) from None
        raise UnsafePatternError(f"invalid regex ({detail})") from None
