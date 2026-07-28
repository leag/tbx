"""Pure operation-template matchers.

Matchers inspect an operation window and return facts. They do not mutate
decode state or consume a cursor; appliers remain responsible for semantics.
The first matcher is intentionally small and low-risk so the migration can be
validated against the existing timing fixtures before expanding the pattern.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tbx.decode0.cursor import OpCursor
from tbx.decode0.const import _JCC_RELOP_TRUE


@dataclass(frozen=True)
class DelayMatch:
    """The recognized tail of a ``DELAY`` statement."""

    hooks: tuple[tuple[Any, ...], ...]
    loop_back: int
    stop: int


@dataclass(frozen=True)
class BoolTermMatch:
    """Pure recognition result for a compound-boolean first term."""

    operator: str
    deferred: bool


def _same_code_offset(a: int, b: int) -> bool:
    return (a - b) % 0x10000 == 0


def match_bool_term1(ops, index: int | None = None) -> BoolTermMatch | None:
    """Recognize a materialized compound-boolean first term.

    This is the recognition half of the old ``_match_bool_term1`` path. It
    never mutates operations or decoder state; the control handler owns the
    resulting IR fold and cursor consumption.
    """

    if isinstance(ops, OpCursor):
        if index is not None:
            raise TypeError("cursor matcher does not accept a separate index")
        index, ops = ops.index, ops.ops
    if index is None:
        raise TypeError("operation index is required")
    if [o[1] for o in ops[index : index + 6]] != [
        "movax",
        "jcc",
        "incax",
        "orax",
        "jcc",
        "jmp",
    ]:
        return None
    if (
        ops[index + 1][3] != ops[index + 3][0]
        or ops[index + 1][2] not in _JCC_RELOP_TRUE
        or ops[index + 4][3] != ops[index + 5][0] + 3
    ):
        return None
    polarity, short_circuit = ops[index + 4][2], ops[index + 5][2]
    combination = {0x75: ("andaxbx", "AND"), 0x74: ("orax", "OR")}.get(
        polarity
    )
    if combination is None:
        return None
    other = ("orax", "OR") if combination[0] == "andaxbx" else ("andaxbx", "AND")
    seen_materialize = False
    for j in range(index + 6, min(index + 36, len(ops) - 3)):
        if ops[j][1] != "movax" or ops[j][2] != 0xFFFF:
            continue
        next_kinds = [o[1] for o in ops[j + 1 : j + 4]]
        for candidate in (combination, other):
            if next_kinds == ["jcc", "incax", candidate[0]]:
                delta = 2 if candidate[1] == "AND" else 0
                if _same_code_offset(short_circuit, ops[j + 3][0] + delta):
                    return BoolTermMatch(combination[1], seen_materialize)
        seen_materialize = True
    return None


def match_delay(ops, index: int | None = None) -> DelayMatch | None:
    """Match ``delay_init [trap_hook]* delay_poll jcc loop_back``.

    ``None`` means the operation at ``index`` is not this template. A
    malformed template that starts with ``delay_init`` is returned as no match
    here; the applier turns that into the existing fail-loud `ValueError` so
    the public behavior remains unchanged.
    """

    if isinstance(ops, OpCursor):
        if index is not None:
            raise TypeError("cursor matcher does not accept a separate index")
        index, ops = ops.index, ops.ops
    if index is None:
        raise TypeError("operation index is required")
    if index < 0 or index >= len(ops) or ops[index][1] != "delay_init":
        return None
    j = index + 1
    hooks = []
    while j < len(ops) and ops[j][1] == "trap_hook":
        hooks.append(ops[j])
        j += 1
    if j >= len(ops) or ops[j][1] != "delay_poll":
        return None
    poll = ops[j]
    j += 1
    if j >= len(ops):
        return None
    branch = ops[j]
    loop_back = hooks[0][0] if hooks else poll[0]
    if branch[1] != "jcc" or branch[3] != loop_back:
        return None
    return DelayMatch(tuple(hooks), loop_back, j + 1)
