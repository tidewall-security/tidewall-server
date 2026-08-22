"""The seven behaviours that together are "the UI property".

Naming it as one phrase is how an implementation runs some JavaScript,
inspects a complete browser object, and tests ONE of them while reporting the
property as covered. So the seven are enumerated here as data, each canary
asserts exactly one, and a structural oracle -- which needs no browser --
requires every one of them to be asserted and called.

The property is that a policy's content NEVER REACHES THE BROWSER. Its seven
observable consequences:

  1. no request on load;
  2. no request on refresh;
  3. no request on expand;
  4. the DOM is clear of it;
  5. local AND session storage are clear of every representation;
  6. console and analytics/network are clear of every representation;
  7. two policies are isolated from one another.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Behaviour:
    key: str
    why: str


BEHAVIOURS: tuple[Behaviour, ...] = (
    Behaviour("no_request_on_load", "the page must not fetch policy content to render"),
    Behaviour("no_request_on_refresh", "a reload must not fetch it either"),
    Behaviour("no_request_on_expand", "expanding a row must not fetch it lazily"),
    Behaviour("dom_cleared", "no representation of the value in the rendered DOM"),
    Behaviour("storage_cleared", "local AND session storage, every representation"),
    Behaviour("console_and_network_cleared", "console, analytics and browser network"),
    Behaviour("two_policy_isolation", "one policy's content must not appear under another"),
)


class BehaviourNotAsserted(Exception):
    """A behaviour has no assertion, or has one that is never called."""


def assertion_name(behaviour: Behaviour) -> str:
    return f"assert_{behaviour.key}"


def audit(module_path: Path) -> None:
    """Require every behaviour to be both DEFINED and CALLED in the canary.

    Defined-but-never-called is the failure this catches: the function exists,
    a reader counts seven, and the test body invokes four.
    """
    tree = ast.parse(module_path.read_text())

    defined = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)}
    called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}

    missing_definition = [b.key for b in BEHAVIOURS if assertion_name(b) not in defined]
    if missing_definition:
        raise BehaviourNotAsserted(f"no assertion defined for: {missing_definition}")

    never_called = [b.key for b in BEHAVIOURS if assertion_name(b) not in called]
    if never_called:
        raise BehaviourNotAsserted(f"assertion defined but never called for: {never_called}")
