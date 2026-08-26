"""Immutable ownership facts for compiler-bracketed source regions."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.compiler_ops import CompilerOp, operation_indexes, translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact
from tbd.semantic import combine_evidence, resolve_expression

_MATERIALIZED_RELATIONS = {
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
_STRING_MATERIALIZED_RELATIONS = {
    0x74: "=",
    0x75: "<>",
    0x73: ">=",
    0x72: "<",
    0x77: ">",
    0x76: "<=",
}
_LOGICAL_GATES = {0x75: ("AND", "andaxbx"), 0x74: ("OR", "orax")}
_VALUE_COMBINERS = {"andaxbx": "AND", "oraxbx": "OR"}
_INTEGER_MATERIALIZED_RELATIONS = {
    0x72: ">",
    0x73: "<=",
    0x74: "=",
    0x75: "<>",
    0x76: ">=",
    0x77: "<",
    0x7C: ">",
    0x7D: "<=",
    0x7E: ">=",
    0x7F: "<",
}


def materialized_relation_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete ``compare; FFFF/Jcc/inc`` boolean values."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for comparison in facts:
        if (
            comparison.kind not in {"expression.compare", "expression.string_compare"}
            or (
                comparison.kind == "expression.compare"
                and len(comparison.subject) != 1
            )
            or (
                comparison.kind == "expression.string_compare"
                and len(comparison.subject) != 2
            )
            or len(comparison.value) != 2
            or not comparison.evidence
        ):
            continue
        is_string = comparison.kind == "expression.string_compare"
        compare = instructions.get(
            comparison.subject[1] - 2
            if is_string
            else comparison.evidence[-1]
        )
        status = (
            None
            if is_string
            else instructions.get(compare.end) if compare is not None else None
        )
        materialize = instructions.get(
            compare.end if is_string and compare is not None else status.end
        ) if (compare is not None and (is_string or status is not None)) else None
        spill = None
        if materialize is not None and materialize.raw in {"89 c3", "8b d8"}:
            spill = materialize
            materialize = instructions.get(materialize.end)
        branch = instructions.get(materialize.end) if materialize is not None else None
        increment = instructions.get(branch.end) if branch is not None else None
        raw = bytes.fromhex(branch.raw) if branch is not None else b""
        relation = (
            _STRING_MATERIALIZED_RELATIONS if is_string else _MATERIALIZED_RELATIONS
        ).get(raw[0]) if raw else None
        if not (
            (is_string or (
                status is not None
                and status.kind == "tb.runtime"
                and status.operands == (0x99,)
            ))
            and materialize is not None
            and materialize.kind == "x86.mov_imm"
            and materialize.operands == ("ax", 0xFFFF)
            and branch is not None
            and branch.kind.startswith("x86.j")
            and increment is not None
            and increment.kind == "x86.inc"
            and increment.operands == ("ax",)
            and branch.operands == (increment.end,)
            and relation is not None
        ):
            continue
        # FP comparisons record stack-top first and memory second. String
        # comparison flags and operands are already in forward source order.
        left_value, right_value = (
            comparison.value
            if is_string
            else (comparison.value[1], comparison.value[0])
        )
        left = resolve_expression(left_value, facts)
        right = resolve_expression(right_value, facts)
        if left is None or right is None:
            continue
        value: object = (relation, left.value, right.value)
        if is_string and any(
            isinstance(operand, tuple) and operand[:1] == ("call",)
            for operand in (left.value, right.value)
        ):
            value = ("group", value)
        support = combine_evidence(
            comparison.evidence,
            (
                *(() if status is None else (status.offset,)),
                materialize.offset,
                branch.offset,
                increment.offset,
            ),
            () if spill is None else (spill.offset,),
            left.evidence,
            right.evidence,
        )
        yield Fact(
            "expression.relation_value",
            (comparison.subject[0], increment.end),
            value,
            support,
            "anchored",
        )


def materialized_system_relation_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete materialized ERR/ERL comparisons as relation values."""

    operations = translate_operations(evidence.instructions)
    for index in range(1, len(operations) - 4):
        load, compare = operations[index : index + 2]
        if (
            load.kind != "movax"
            or compare.kind != "cmpax_m"
            or load.end != compare.offset
            or len(load.args) != 1
            or len(compare.args) != 1
        ):
            continue
        cursor = index + 2
        support = [load, compare]
        preserved = operations[cursor : cursor + 2]
        if [operation.kind for operation in preserved] == ["movaxbx", "movbxax"]:
            if (
                preserved[0].offset != compare.end
                or preserved[0].end != preserved[1].offset
            ):
                continue
            support.extend(preserved)
            cursor += 2
        tail = operations[cursor : cursor + 3]
        if len(tail) != 3:
            continue
        materialize, branch, increment = tail
        if (
            materialize.kind != "movax"
            or materialize.args != (0xFFFF,)
            or branch.kind != "jcc"
            or increment.kind != "incax"
            or support[-1].end != materialize.offset
            or materialize.end != branch.offset
            or branch.end != increment.offset
            or len(branch.args) != 2
            or branch.args[1] != increment.end
        ):
            continue
        relation = _INTEGER_MATERIALIZED_RELATIONS.get(branch.args[0])
        system = resolve_expression(("memory", compare.args[0], "integer"), facts)
        if (
            relation is None
            or system is None
            or not isinstance(system.value, tuple)
            or system.value[:2] not in {("call", "ERR"), ("call", "ERL")}
        ):
            continue
        previous = operations[index - 1]
        start = (
            previous.offset
            if previous.kind == "movbxax" and previous.end == load.offset
            else load.offset
        )
        yield Fact(
            "expression.relation_value",
            (start, increment.end),
            (relation, system.value, ("const", load.args[0])),
            combine_evidence(
                tuple(
                    operation.offset
                    for operation in (*support, materialize, branch, increment)
                ),
                system.evidence,
                () if start == load.offset else (previous.offset,),
            ),
            "anchored",
        )


def compound_condition_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Fold complete materialized relation chains into one branch decision."""

    operations = translate_operations(evidence.instructions)
    indexes, by_offset = operation_indexes(operations)
    relations = sorted(
        (
            fact
            for fact in facts
            if fact.kind == "expression.relation_value"
            and len(fact.subject) == 2
        ),
        key=lambda fact: fact.subject,
    )
    raw_decisions: list[tuple[Fact, bool]] = []
    for first in relations:
        decision = _short_circuit_decision(
            first, relations, operations, indexes, by_offset
        )
        if decision is None:
            decision = _value_group_decision(
                first, relations, operations, indexes, by_offset
            )
        prefix_only = False
        if decision is None:
            decision = _relation_branch_decision(
                first, operations, indexes, by_offset
            )
            prefix_only = decision is not None
        if decision is not None:
            raw_decisions.append((decision, prefix_only))

    emitted: set[Fact] = set()
    decisions = [decision for decision, _prefix_only in raw_decisions]
    for decision, prefix_only in raw_decisions:
        extended = _extend_decision(decision, decisions, by_offset)
        if (
            (not prefix_only or extended != decision)
            and extended not in emitted
            and _complete_decision(extended, facts)
        ):
            emitted.add(extended)
            yield extended


def inline_if_region_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Own forward false-branch regions without owning their body facts."""

    for decision in facts:
        if decision.kind != "control.compound_condition" or len(decision.value) != 4:
            continue
        condition, polarity, target, body_start = decision.value
        if (
            polarity == 0x75
            and isinstance(target, int)
            and isinstance(body_start, int)
            and target > body_start
        ):
            yield Fact(
                "region.if_inline",
                (decision.subject[0], target),
                (condition, body_start, target),
                decision.evidence,
                "anchored",
            )


def compound_if_goto_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Lift terminal true-jump compound decisions as source IF...GOTO."""

    for decision in facts:
        if decision.kind != "control.compound_condition" or len(decision.value) != 4:
            continue
        condition, polarity, target, false_target = decision.value
        if (
            polarity != 0x74
            or not isinstance(condition, tuple)
            or not isinstance(target, int)
            or target < decision.subject[0]
        ):
            continue
        if len(condition) != 3:
            yield Fact(
                "semantic.if_goto_condition",
                decision.subject,
                (condition, target, false_target),
                decision.evidence,
                "anchored",
            )
            continue
        yield Fact(
            "semantic.if_goto",
            decision.subject,
            (*condition, target, false_target),
            decision.evidence,
            "anchored",
        )


def region_body_goto_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Classify an unowned jump following a proven statement inside a region."""

    flows = [
        fact
        for fact in facts
        if fact.kind == "flow.goto"
        and len(fact.subject) == 2
        and len(fact.value) == 1
        and isinstance(fact.value[0], int)
    ]
    semantic = [fact for fact in facts if fact.kind.startswith("semantic.")]
    for region in facts:
        if region.kind != "region.if_inline" or len(region.value) != 3:
            continue
        _condition, body_start, body_end = region.value
        if not isinstance(body_start, int) or not isinstance(body_end, int):
            continue
        for flow in flows:
            source = flow.subject[0]
            if not isinstance(source, int) or not body_start < source < body_end:
                continue
            predecessor = [
                fact
                for fact in semantic
                if fact.kind not in {"semantic.if_inline", "semantic.if_goto"}
                and len(fact.subject) == 2
                and fact.subject[1] == source
                and _inside(fact, body_start, body_end)
            ]
            owned = any(
                fact.kind in {
                    "control.compound_condition",
                    "semantic.if_goto",
                    "semantic.if_goto_condition",
                }
                and source in fact.evidence
                for fact in facts
            )
            if len(predecessor) != 1 or owned:
                continue
            yield Fact(
                "semantic.goto",
                flow.subject,
                flow.value,
                combine_evidence(
                    flow.evidence,
                    predecessor[0].evidence,
                    region.evidence,
                ),
                "anchored",
            )


def inline_if_semantic_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Materialize owned regions once at least one body statement is proven."""

    for region in facts:
        if region.kind != "region.if_inline" or len(region.value) != 3:
            continue
        condition, body_start, body_end = region.value
        if not isinstance(body_start, int) or not isinstance(body_end, int):
            continue
        body = [
            fact
            for fact in facts
            if fact.kind.startswith("semantic.")
            and fact.kind != "semantic.if_inline"
            and _inside(fact, body_start, body_end)
        ]
        if not body:
            continue
        yield Fact(
            "semantic.if_inline",
            region.subject,
            (condition, body_start, body_end, None),
            combine_evidence(region.evidence, *(fact.evidence for fact in body)),
            "anchored",
        )


def _short_circuit_decision(
    first: Fact,
    relations: list[Fact],
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_offset: dict[int, CompilerOp],
) -> Fact | None:
    gate = by_offset.get(first.subject[1])
    tail = _following(operations, indexes, gate, 2)
    if gate is None or gate.kind != "orax" or tail is None:
        return None
    dispatch, jump = tail
    if not _dispatch_pair(dispatch, jump):
        return None
    logical = _LOGICAL_GATES.get(dispatch.args[0])
    if logical is None:
        return None
    operator, _combine_kind = logical
    matched = _next_term(relations, by_offset, jump, logical)
    if matched is None:
        return None
    second, combine = matched
    condition = (operator, first.value, second.value)
    support_facts = [first, second]
    support_ops = [gate, dispatch, jump, combine]
    while True:
        final = _following(operations, indexes, combine, 2)
        if final is None:
            return None
        final_dispatch, final_jump = final
        if not _dispatch_pair(final_dispatch, final_jump):
            return None
        support_ops.extend(final)
        join = _LOGICAL_GATES.get(final_dispatch.args[0])
        continuation = (
            None
            if join is None
            else _next_term(relations, by_offset, final_jump, join)
        )
        if continuation is None:
            return _decision(
                first, support_facts, condition, final_dispatch, final_jump, support_ops
            )
        following, combine = continuation
        condition = (join[0], condition, following.value)
        support_facts.append(following)
        support_ops.append(combine)


def _value_group_decision(
    first: Fact,
    relations: list[Fact],
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_offset: dict[int, CompilerOp],
) -> Fact | None:
    candidates = []
    for second in relations:
        if second.subject[0] != first.subject[1]:
            continue
        combine = by_offset.get(second.subject[1])
        final = _following(operations, indexes, combine, 2)
        if combine is None or combine.kind not in _VALUE_COMBINERS or final is None:
            continue
        final_dispatch, final_jump = final
        if _dispatch_pair(final_dispatch, final_jump):
            candidates.append((second, combine, final_dispatch, final_jump))
    if len(candidates) != 1:
        return None
    second, combine, final_dispatch, final_jump = candidates[0]
    operator = _VALUE_COMBINERS[combine.kind]
    first_string = _uses_operation(first, operations, "strcmp")
    second_string = _uses_operation(second, operations, "strcmp")
    if first_string != second_string:
        return None
    # This value-fold family evaluates the textual right operand first. Numeric
    # relations carry explicit leaf groups; string relations do not.
    left = second.value if first_string else ("group", second.value)
    right = first.value if first_string else ("group", first.value)
    condition = ("group", (operator, left, right))
    return _decision(
        first,
        [first, second],
        condition,
        final_dispatch,
        final_jump,
        [combine, final_dispatch, final_jump],
    )


def _relation_branch_decision(
    relation: Fact,
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_offset: dict[int, CompilerOp],
) -> Fact | None:
    """Retain a relation prefix only so it can acquire a proven right group."""

    gate = by_offset.get(relation.subject[1])
    tail = _following(operations, indexes, gate, 2)
    if gate is None or gate.kind != "orax" or tail is None:
        return None
    dispatch, jump = tail
    if not _dispatch_pair(dispatch, jump) or dispatch.args[0] not in _LOGICAL_GATES:
        return None
    return _decision(
        relation,
        [relation],
        relation.value,
        dispatch,
        jump,
        [gate, dispatch, jump],
    )


def _extend_decision(
    first: Fact,
    decisions: list[Fact],
    by_offset: dict[int, CompilerOp],
) -> Fact:
    """Compose uniquely linked decisions through their observed convergence."""

    decision = first
    consumed = {first.subject}
    while True:
        condition, polarity, target, false_target = decision.value
        logical = _LOGICAL_GATES.get(polarity)
        if logical is None or not isinstance(target, int):
            return decision
        matches = [
            candidate
            for candidate in decisions
            if candidate.subject not in consumed
            and candidate.subject[0] == false_target
            and _decision_converges_at(candidate, target, by_offset)
        ]
        if len(matches) != 1:
            return decision
        following = matches[0]
        next_condition, next_polarity, next_target, next_false = following.value
        decision = Fact(
            "control.compound_condition",
            (decision.subject[0], following.subject[1]),
            (
                (logical[0], condition, next_condition),
                next_polarity,
                next_target,
                next_false,
            ),
            combine_evidence(decision.evidence, following.evidence),
            "anchored",
        )
        consumed.add(following.subject)


def _decision_converges_at(
    decision: Fact,
    target: int,
    by_offset: dict[int, CompilerOp],
) -> bool:
    """Prove that ``target`` is the candidate group's value-combine point."""

    at_target = by_offset.get(target)
    before_target = by_offset.get(target - 2)
    return (
        at_target is not None
        and at_target.kind == "orax"
        and at_target.offset in decision.evidence
    ) or (
        before_target is not None
        and before_target.kind in _VALUE_COMBINERS
        and before_target.end == target
        and before_target.offset in decision.evidence
    )


def _decision(
    first: Fact,
    relations: list[Fact],
    condition: object,
    dispatch: CompilerOp,
    jump: CompilerOp,
    operations: list[CompilerOp],
) -> Fact:
    return Fact(
        "control.compound_condition",
        (first.subject[0], jump.end),
        (condition, dispatch.args[0], jump.args[0], jump.end),
        combine_evidence(
            *(relation.evidence for relation in relations),
            tuple(operation.offset for operation in operations),
        ),
        "anchored",
    )


def _next_term(
    relations: list[Fact],
    by_offset: dict[int, CompilerOp],
    jump: CompilerOp,
    logical: tuple[str, str],
) -> tuple[Fact, CompilerOp] | None:
    operator, combine_kind = logical
    matches = []
    for relation in relations:
        if relation.subject[0] != jump.end:
            continue
        combine = by_offset.get(relation.subject[1])
        if (
            combine is not None
            and combine.kind == combine_kind
            and jump.args[0] == combine.offset + (2 if operator == "AND" else 0)
        ):
            matches.append((relation, combine))
    return matches[0] if len(matches) == 1 else None


def _uses_operation(
    fact: Fact, operations: tuple[CompilerOp, ...], kind: str
) -> bool:
    return any(
        operation.kind == kind and operation.offset in fact.evidence
        for operation in operations
    )


def _complete_decision(decision: Fact, facts: frozenset[Fact]) -> bool:
    """Reject a locally complete group that is owned by a wider condition."""

    start, end = decision.subject
    _condition, _polarity, target, false_target = decision.value
    if not all(isinstance(value, int) for value in (start, end, target, false_target)):
        return False
    # An earlier short-circuit into this span proves that this apparent
    # decision is an inner group whose outer term has not been resolved.
    if any(
        fact.kind == "flow.goto"
        and len(fact.subject) == 2
        and len(fact.value) == 1
        and isinstance(fact.subject[0], int)
        and isinstance(fact.value[0], int)
        and fact.subject[0] < start < fact.value[0] <= end
        for fact in facts
    ):
        return False
    # A new relation beginning on the false fallthrough and converging before
    # this jump target is a differently-precedenced continuation group. The
    # flat matcher cannot yet recover its outer owner, so retain no partial IR.
    return not any(
        fact.kind == "expression.relation_value"
        and len(fact.subject) == 2
        and fact.subject[0] == false_target
        and isinstance(fact.subject[1], int)
        and fact.subject[1] < target
        for fact in facts
    )


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


def _dispatch_pair(branch: CompilerOp, jump: CompilerOp) -> bool:
    return (
        branch.kind == "jcc"
        and len(branch.args) == 2
        and jump.kind == "jmp"
        and len(jump.args) == 1
        and branch.args[1] == jump.end
    )


def _inside(fact: Fact, start: int, end: int) -> bool:
    return (
        len(fact.subject) == 2
        and isinstance(fact.subject[0], int)
        and isinstance(fact.subject[1], int)
        and start <= fact.subject[0] < fact.subject[1] <= end
    )


REGION_FACT_PASSES: tuple[NamedPass, ...] = (
    ("materialized-relations", materialized_relation_facts),
    ("materialized-system-relations", materialized_system_relation_facts),
    ("compound-conditions", compound_condition_facts),
    ("inline-if-regions", inline_if_region_facts),
    ("compound-if-gotos", compound_if_goto_facts),
    ("region-body-gotos", region_body_goto_facts),
    ("inline-if-semantics", inline_if_semantic_facts),
)
