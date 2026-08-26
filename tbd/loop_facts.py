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
_LOGICAL_GATES = {0x75: ("AND", "andaxbx"), 0x74: ("OR", "orax")}


@dataclass(frozen=True)
class _Loop:
    opener: Fact
    closer: Fact
    branch: int


def loop_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover simple numeric head and tail comparison loops."""

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


def compound_tail_loop_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover a folded boolean condition ending in a direct backedge."""

    operations = translate_operations(evidence.instructions)
    indexes, by_address = operation_indexes(operations)
    relations = sorted(
        (
            fact
            for fact in facts
            if fact.kind == "expression.relation_value"
            and len(fact.subject) == 2
        ),
        key=lambda fact: fact.subject,
    )
    statements = _statement_starts(facts)
    emitted: set[Fact] = set()
    for first in relations:
        loop = _compound_backedge_loop(
            first,
            relations,
            operations,
            indexes,
            by_address,
            statements,
        )
        if loop is None:
            continue
        for fact in (loop.opener, loop.closer):
            if fact not in emitted:
                emitted.add(fact)
                yield fact


def compound_condition_loop_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Own an inverted branch/jump decision whose jump is the backedge."""

    statements = _statement_starts(facts)
    for decision in facts:
        if (
            decision.kind != "control.compound_condition"
            or len(decision.subject) != 2
            or len(decision.value) != 4
        ):
            continue
        start, end = decision.subject
        condition, polarity, target, false_target = decision.value
        if (
            not isinstance(start, int)
            or not isinstance(end, int)
            or polarity not in {0x74, 0x75}
            or not isinstance(target, int)
            or target >= start
            or target not in statements
            or false_target != end
        ):
            continue
        kind = "UNTIL" if polarity == 0x75 else "WHILE"
        yield Fact(
            "semantic.do_codeless",
            (target,),
            (None, None),
            decision.evidence,
            "anchored",
        )
        yield Fact(
            "semantic.loop",
            decision.subject,
            (kind, condition),
            decision.evidence,
            "anchored",
        )


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


def _compound_backedge_loop(
    first: Fact,
    relations: list[Fact],
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_address: dict[int, CompilerOp],
    statements: set[int],
) -> _Loop | None:
    gate = by_address.get(first.subject[1])
    pair = _following(operations, indexes, gate, 2)
    if gate is None or gate.kind != "orax" or pair is None:
        return None
    dispatch, jump = pair
    logical = _logical_pair(dispatch, jump)
    if logical is None:
        return None
    following = _next_relation(relations, by_address, jump, logical)
    if following is None:
        return None
    relation, combine = following
    condition: object = (logical[0], first.value, relation.value)
    support_facts = [first, relation]
    support_ops = [gate, dispatch, jump, combine]
    while True:
        tail = _following(operations, indexes, combine, 2)
        if tail is None:
            return None
        terminal = tail[0]
        if (
            terminal.kind == "jcc"
            and len(terminal.args) == 2
            and terminal.args[0] in {0x74, 0x75}
            and isinstance(terminal.args[1], int)
            and terminal.args[1] < first.subject[0]
            and terminal.args[1] in statements
        ):
            kind = "UNTIL" if terminal.args[0] == 0x74 else "WHILE"
            support = combine_evidence(
                *(fact.evidence for fact in support_facts),
                tuple(operation.offset for operation in (*support_ops, terminal)),
            )
            return _Loop(
                Fact(
                    "semantic.do_codeless",
                    (terminal.args[1],),
                    (None, None),
                    support,
                    "anchored",
                ),
                Fact(
                    "semantic.loop",
                    (first.subject[0], terminal.end),
                    (kind, condition),
                    support,
                    "anchored",
                ),
                terminal.offset,
            )
        dispatch, jump = tail
        logical = _logical_pair(dispatch, jump)
        if logical is None:
            return None
        following = _next_relation(relations, by_address, jump, logical)
        if following is None:
            return None
        relation, combine = following
        condition = (logical[0], condition, relation.value)
        support_facts.append(relation)
        support_ops.extend((dispatch, jump, combine))


def _logical_pair(
    dispatch: CompilerOp, jump: CompilerOp
) -> tuple[str, str] | None:
    if (
        dispatch.kind != "jcc"
        or len(dispatch.args) != 2
        or jump.kind != "jmp"
        or len(jump.args) != 1
        or dispatch.args[1] != jump.end
    ):
        return None
    return _LOGICAL_GATES.get(dispatch.args[0])


def _next_relation(
    relations: list[Fact],
    by_address: dict[int, CompilerOp],
    jump: CompilerOp,
    logical: tuple[str, str],
) -> tuple[Fact, CompilerOp] | None:
    operator, combine_kind = logical
    matches = []
    for relation in relations:
        if relation.subject[0] != jump.end:
            continue
        combine = by_address.get(relation.subject[1])
        if (
            combine is not None
            and combine.kind == combine_kind
            and jump.args[0] == combine.offset + (2 if operator == "AND" else 0)
        ):
            matches.append((relation, combine))
    return matches[0] if len(matches) == 1 else None


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


def _following(
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    operation: CompilerOp | None,
    count: int,
) -> tuple[CompilerOp, ...] | None:
    if operation is None or operation.offset not in indexes:
        return None
    start = indexes[operation.offset] + 1
    result = operations[start : start + count]
    return result if len(result) == count else None


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


LOOP_FACT_PASSES: tuple[NamedPass, ...] = (
    ("loops", loop_statement_facts),
    ("compound-tail-loops", compound_tail_loop_facts),
    ("compound-condition-loops", compound_condition_loop_facts),
)
