from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FnResult:
    """One recovered DEF FN result expression and its evidence."""

    expression: object
    span: tuple[int, int]
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class FnDefinition:
    """Recovered DEF FN declaration, body, parameters, and locals."""

    declaration: int
    entry: int
    end: int
    returned: int
    result_kind: str
    parameters: tuple[tuple[int, str], ...]
    block: bool
    results: tuple[FnResult, ...]
    evidence: tuple[int, ...]
    locals: tuple[tuple[int, str], ...] = ()
    local_span: tuple[int, int] | None = None
    local_evidence: tuple[int, ...] = ()
    local_bytes: int = 0
