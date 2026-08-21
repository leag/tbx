"""Simple DO/LOOP region facts ported from calibrated operation templates."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, operation_indexes, translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact
from tbd.semantic import combine_evidence, resolve_expression

_RELATIONS = {
    0x77: "<",
    0x73: "<=",
    0x72: ">",
    0x76: ">=",
    0x74: "=",
    0x75: "<>",
    0x7F: ">",
    0x7C: "<",
    0x7D: ">=",
    0x7E: "<=",
}


@dataclass(frozen=True)
class _Loop:
    opener: Fact
    closer: Fact
    branch: int


def loop_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover simple numeric head tests, tail tests, and bare short loops."""

    operations = translate_operations(evidence.instructions)
    indexes, _by_address = operation_indexes(operations)
    statements = _statement_starts(facts)
    loops = []
    for comparison in facts:
        if comparison.kind != "expression.compare" or not comparison.subject:
            continue
        start = comparison.subject[0]
        index = indexes.get(start) if isinstance(start, int) else None
        if index is None:
            continue
        loop = _comparison_loop(operations, index, comparison, facts, statements)
        if loop is not None:
            loops.append(loop)
            yield loop.opener
            yield loop.closer


def _comparison_loop(
    operations: tuple[CompilerOp, ...],
    index: int,
    comparison: Fact,
    facts: frozenset[Fact],
    statements: set[int],
) -> _Loop | None:
    materialization = _materialization(operations, index)
    if materialization is None:
        return None
    first, materialize, exit_branch, after = materialization
    condition = _condition(comparison, materialize, facts)
    if condition is None:
        return None
    support = combine_evidence(
        comparison.evidence,
        tuple(item.offset for item in operations[index:after]),
    )
    if after < len(operations) and operations[after].kind == "jmp":
        exit_jump = operations[after]
        if (
            exit_branch.args[1] != exit_jump.end
            or not isinstance(exit_jump.args[0], int)
        ):
            return None
        back = next(
            (
                operation
                for operation in operations[after + 1 :]
                if operation.offset < exit_jump.args[0]
                and operation.kind == "jmp"
                and operation.args == (first.offset,)
            ),
            None,
        )
        if back is None:
            return None
        kind = "WHILE" if exit_branch.args[0] == 0x75 else "UNTIL"
        return _Loop(
            Fact(
                "semantic.do",
                (first.offset, exit_jump.end),
                (kind, condition),
                combine_evidence(support, (exit_jump.offset,)),
                "anchored",
            ),
            Fact(
                "semantic.loop",
                (back.offset, back.end),
                (None, None),
                (back.offset,),
                "anchored",
            ),
            back.offset,
        )
    target = exit_branch.args[1]
    if not isinstance(target, int) or target >= first.offset or target not in statements:
        return None
    kind = "WHILE" if exit_branch.args[0] == 0x75 else "UNTIL"
    return _Loop(
        Fact(
            "semantic.do_codeless",
            (target,),
            (None, None),
            (exit_branch.offset,),
            "anchored",
        ),
        Fact(
            "semantic.loop",
            (first.offset, exit_branch.end),
            (kind, condition),
            support,
            "anchored",
        ),
        exit_branch.offset,
    )


def _materialization(
    operations: tuple[CompilerOp, ...], index: int
) -> tuple[CompilerOp, CompilerOp, CompilerOp, int] | None:
    if index + 8 > len(operations):
        return None
    window = operations[index : index + 8]
    if [item.kind for item in window] != [
        window[0].kind,
        "fcomp",
        "fstsw",
        "movax",
        "jcc",
        "incax",
        "orax",
        "jcc",
    ]:
        return None
    first, _compare, _status, materialize, true_branch, _increment, test, exit_branch = window
    if (
        first.kind not in {"fild", "fild32", "fld", "fld64"}
        or materialize.args != (0xFFFF,)
        or len(true_branch.args) != 2
        or true_branch.args[0] not in _RELATIONS
        or true_branch.args[1] != test.offset
        or len(exit_branch.args) != 2
        or exit_branch.args[0] not in {0x74, 0x75}
    ):
        return None
    return first, true_branch, exit_branch, index + 8


def _condition(
    comparison: Fact, materialize: CompilerOp, facts: frozenset[Fact]
) -> tuple[object, ...] | None:
    if len(comparison.value) != 2 or not materialize.args:
        return None
    left = resolve_expression(comparison.value[0], facts)
    right = resolve_expression(comparison.value[1], facts)
    relation = _RELATIONS.get(materialize.args[0])
    if left is None or right is None or relation is None:
        return None
    return relation, right.value, left.value


def _statement_starts(facts: frozenset[Fact]) -> set[int]:
    return {
        fact.subject[0]
        for fact in facts
        if fact.kind.startswith("semantic.")
        and fact.kind not in {"semantic.do", "semantic.do_codeless", "semantic.loop"}
        and fact.subject
        and isinstance(fact.subject[0], int)
    }


LOOP_FACT_PASSES: tuple[NamedPass, ...] = (("loops", loop_statement_facts),)
