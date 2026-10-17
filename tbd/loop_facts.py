from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, operation_indexes, translate_operations
from tbd.facts import Evidence, NamedPass, fact_key, ordered_by_kind, reads
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


@reads(
    "constant",
    "expression.compare",
    "expression.relation_value",
    "expression.system",
    "expression.value",
    "flow.goto",
    "layout.array",
    "semantic.",
    "semantic.do",
    "semantic.do_codeless",
    "semantic.dynamic_dim",
    "semantic.loop",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.je",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
    "x86.or",
)
def loop_statement_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover loop statements from compiler control-flow patterns."""

    operations = translate_operations(evidence.instructions)
    by_kind = ordered_by_kind(facts)
    dynamic_dims = [
        fact
        for fact in by_kind.get("semantic.dynamic_dim", ())
        if len(fact.subject) == 2
    ]
    gotos = [
        fact
        for fact in by_kind.get("flow.goto", ())
        if len(fact.subject) == 2 and len(fact.value) == 1
    ]
    for dynamic in dynamic_dims:
        # The guard that skips the dynamic DIM is the branch nearest before it,
        # and the back edge the one nearest after; several jumps in the program
        # straddle the DIM, so taking any of them picks by set order instead.
        exit_jump = max(
            (
                flow
                for flow in gotos
                if flow.subject[0] < dynamic.subject[0]
                and flow.value[0] > dynamic.subject[1]
            ),
            key=lambda flow: (flow.subject[0], fact_key(flow)),
            default=None,
        )
        back_jump = min(
            (
                flow
                for flow in gotos
                if flow.subject[0] >= dynamic.subject[1]
                and flow.value[0] < dynamic.subject[0]
            ),
            key=lambda flow: (flow.subject[0], fact_key(flow)),
            default=None,
        )
        # The EXIT LOOP lands right after the LOOP; jumps elsewhere belong
        # to other statements, and a LOOP spanning them hides their GOTOs.
        if (
            exit_jump is None
            or back_jump is None
            or exit_jump.value[0] != back_jump.subject[1]
        ):
            continue
        loop_start = back_jump.value[0]
        yield Fact(
            "semantic.do_codeless",
            (loop_start,),
            (None, None),
            (loop_start,),
            "anchored",
        )
        yield Fact(
            "semantic.exit_loop",
            exit_jump.subject,
            (exit_jump.value[0],),
            exit_jump.evidence,
            "anchored",
        )
        yield Fact(
            "semantic.loop",
            back_jump.subject,
            (None, None, loop_start),
            back_jump.evidence,
            "anchored",
        )
    indexes, _by_address = operation_indexes(operations)
    statements = _statement_starts(facts)
    ends = {item.offset: item.end for item in evidence.instructions}
    for index, branch in enumerate(evidence.instructions):
        if (
            branch.kind != "x86.je"
            or len(branch.operands) != 1
            or not isinstance(branch.operands[0], int)
            or branch.operands[0] >= branch.offset
            or index == 0
            or evidence.instructions[index - 1].kind != "x86.or"
        ):
            continue
        # The value tested is the one left in AX right where the test is:
        # a relation materialized there, or a function whose call ends there.
        test = evidence.instructions[index - 1]
        conditions = sorted(
            [
                (fact.value, fact.evidence, fact.subject[0])
                for fact in by_kind.get("expression.relation_value", ())
                if len(fact.subject) == 2 and fact.subject[1] == test.offset
            ]
            + [
                (fact.value[0], fact.evidence, fact.subject[0])
                for fact in by_kind.get("expression.value", ())
                if len(fact.subject) == 1
                and len(fact.value) == 1
                and fact.evidence
                and ends.get(fact.evidence[-1]) == test.offset
            ],
            key=repr,
        )
        if len({(value, start) for value, _evidence, start in conditions}) != 1:
            continue
        value, support, start = conditions[0]
        yield Fact(
            "semantic.do_codeless",
            (branch.operands[0],),
            (None, None),
            support + (branch.offset,),
            "anchored",
        )
        yield Fact(
            "semantic.loop",
            (start, branch.end),
            ("UNTIL", value, branch.operands[0]),
            support + (branch.offset,),
            "anchored",
        )
    loops = []
    for comparison in by_kind.get("expression.compare", ()):
        if not comparison.subject:
            continue
        start = comparison.subject[0]
        comparison_index = indexes.get(start) if isinstance(start, int) else None
        if comparison_index is None:
            continue
        loop = _comparison_loop(
            operations, comparison_index, comparison, facts, statements
        )
        if loop is not None:
            loops.append(loop)
            yield loop.opener
            yield loop.closer


@reads(
    "expression.relation_value",
    "semantic.",
    "semantic.do",
    "semantic.do_codeless",
    "semantic.loop",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def compound_tail_loop_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover loops whose condition is assembled at the loop tail."""

    operations = translate_operations(evidence.instructions)
    indexes, by_address = operation_indexes(operations)
    relations = sorted(
        (
            fact
            for fact in facts
            if fact.kind == "expression.relation_value" and len(fact.subject) == 2
        ),
        key=lambda fact: (fact.subject, fact_key(fact)),
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


@reads(
    "control.compound_condition",
    "flow.",
    "flow.branch",
    "flow.goto",
    "reference.",
    "semantic.",
    "semantic.do",
    "semantic.do_codeless",
    "semantic.if_",
    "semantic.loop",
    "slot",
)
def compound_condition_loop_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover loops with compound boolean conditions."""

    by_kind = ordered_by_kind(facts)
    decisions = by_kind.get("control.compound_condition", ())
    statements = _statement_starts(facts)
    for decision in decisions:
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
            (kind, condition, target),
            decision.evidence,
            "anchored",
        )


@reads(
    "control.condition_prefix",
    "flow.goto",
    "layout.line_table",
    "semantic.assign",
    "semantic.for",
)
def unconditional_backedge_loop_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover loops identified by unconditional back edges."""
    """Recover DO/LOOP forms when the low-level tail is only partly typed."""
    assignments = {
        fact.subject[0]
        for fact in facts
        if fact.kind == "semantic.assign"
        and len(fact.subject) == 2
        and isinstance(fact.subject[0], int)
    }
    condition_prefixes = tuple(
        fact
        for fact in ordered_by_kind(facts).get("control.condition_prefix", ())
        if len(fact.subject) == 2
        and len(fact.value) == 4
        and isinstance(fact.value[2], int)
        and isinstance(fact.value[3], int)
    )
    for_ends = {
        fact.subject[1]
        for fact in facts
        if fact.kind == "semantic.for"
        and len(fact.subject) == 2
        and isinstance(fact.subject[1], int)
    }
    nested_line_tables = any(
        fact.kind == "layout.line_table"
        and len(fact.value) >= 2
        and bool(fact.value[1])
        for fact in facts
    )
    for flow in ordered_by_kind(facts).get("flow.goto", ()):
        if (
            len(flow.subject) == 2
            and len(flow.value) == 1
            and isinstance(flow.subject[0], int)
            and isinstance(flow.value[0], int)
            and flow.value[0] < flow.subject[0]
        ):
            prefix = next(
                (
                    candidate
                    for candidate in condition_prefixes
                    if candidate.value[2] == flow.subject[1]
                    and candidate.value[3] == candidate.subject[1]
                    and flow.value[0] == candidate.subject[0]
                ),
                None,
            )
            if prefix is not None:
                yield Fact(
                    "semantic.do",
                    (prefix.subject[0], prefix.value[3]),
                    ("UNTIL", prefix.value[0]),
                    prefix.evidence,
                    "anchored",
                )
                yield Fact(
                    "semantic.loop",
                    flow.subject,
                    (None, None, flow.value[0]),
                    flow.evidence,
                    "anchored",
                )
                continue
        if (
            flow.kind != "flow.goto"
            or len(flow.subject) != 2
            or len(flow.value) != 1
            or not isinstance(flow.subject[0], int)
            or not isinstance(flow.value[0], int)
            or flow.value[0] >= flow.subject[0]
            or flow.value[0] not in assignments
            or flow.value[0] in for_ends
            or not nested_line_tables
        ):
            continue
        yield Fact(
            "semantic.do_codeless",
            (flow.value[0],),
            (None, None),
            flow.evidence,
            "anchored",
        )
        yield Fact(
            "semantic.loop",
            (flow.value[0], flow.subject[1]),
            (None, None, flow.value[0]),
            flow.evidence,
            "anchored",
        )


@reads("expression.value")
def eof_loop_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover EOF-controlled input loops."""
    """Recognize Turbo Basic's direct ``LOOP UNTIL EOF(n)`` tail."""
    instructions = evidence.instructions
    by_offset = {instruction.offset: instruction for instruction in instructions}
    for expression in facts:
        if (
            expression.kind != "expression.value"
            or len(expression.value) != 1
            or not expression.evidence
            or expression.value[0][:2] != ("call", "EOF")
        ):
            continue
        call = by_offset.get(expression.evidence[-1])
        test = by_offset.get(call.end) if call is not None else None
        branch = by_offset.get(test.end) if test is not None else None
        if (
            test is None
            or test.raw != "09 c0"
            or branch is None
            or branch.raw[:2] != "74"
            or len(branch.operands) != 1
            or not isinstance(branch.operands[0], int)
            or branch.operands[0] >= branch.offset
        ):
            continue
        target = branch.operands[0]
        yield Fact(
            "semantic.do_codeless",
            (target,),
            (None, None),
            combine_evidence(expression.evidence, (test.offset, branch.offset)),
            "anchored",
        )
        yield Fact(
            "semantic.loop",
            (branch.offset, branch.end),
            ("UNTIL", expression.value[0], target),
            combine_evidence(expression.evidence, (test.offset, branch.offset)),
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
        if exit_branch.args[1] != exit_jump.end or not isinstance(
            exit_jump.args[0], int
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
                (None, None, first.offset),
                (back.offset,),
                "anchored",
            ),
            back.offset,
        )
    target = exit_branch.args[1]
    if (
        not isinstance(target, int)
        or target >= first.offset
        or target not in statements
    ):
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
            (kind, condition, target),
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
    pair = _following_compiler(operations, indexes, gate, 2)
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
        tail = _following_compiler(operations, indexes, combine, 2)
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
                    (kind, condition, terminal.args[1]),
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


def _following_compiler(
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    operation: CompilerOp | None,
    count: int,
) -> tuple[CompilerOp, ...] | None:
    if operation is None or operation.offset not in indexes:
        return None
    start = indexes[operation.offset] + 1
    result = operations[start : start + count]
    return tuple(result) if len(result) == count else None


def _logical_pair(dispatch: CompilerOp, jump: CompilerOp) -> tuple[str, str] | None:
    if (
        dispatch.kind != "jcc"
        or len(dispatch.args) != 2
        or jump.kind != "jmp"
        or len(jump.args) != 1
        or dispatch.args[1] != jump.end
    ):
        return None
    if not isinstance(dispatch.args[0], int):
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
    (
        first,
        _compare,
        _status,
        materialize,
        true_branch,
        _increment,
        test,
        exit_branch,
    ) = window
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
    if not isinstance(materialize.args[0], int):
        return None
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
    ("unconditional-backedge-loops", unconditional_backedge_loop_facts),
    ("eof-loops", eof_loop_facts),
)
