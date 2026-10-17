from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass, fact_key, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import bridged, register_moves
from tbd.semantic import combine_evidence, resolve_expression

_STRING_SKIP_RELATIONS = {
    0x75: "=",
    0x74: "<>",
    0x72: ">=",
    0x73: "<",
    0x76: ">",
    0x77: "<=",
}


@reads(
    "constant",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "layout.array",
    "reference.array_value",
    "signature",
    "slot",
    "tb.runtime",
    "x86.mov_imm",
)
def string_operand_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover string operands used by comparisons and concatenation."""

    direct = (
        *_string_operands(evidence, facts),
        *_array_string_operands(evidence, facts),
    )
    yield from direct
    yield from _string_concat_operands(evidence, facts | frozenset(direct))


def _array_string_operands(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    # A dynamic string array's element is pushed from its segment (0x9D).
    pushes = {
        op.end
        for op in evidence.instructions
        if _runtime(op, 0x9C) or _runtime(op, 0x9D)
    }
    for fact in facts:
        if (
            fact.kind == "reference.array_value"
            and len(fact.subject) == 2
            and fact.subject[1] in pushes
            and len(fact.value) == 2
            and fact.value[1] == "string"
        ):
            yield Fact(
                "expression.string_operand",
                fact.subject,
                (fact.value[0],),
                fact.evidence,
                "anchored",
            )


def _string_concat_operands(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    operands = tuple(
        fact
        for fact in facts
        if fact.kind == "expression.string_operand"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
        and len(fact.value) == 1
    )
    by_start: dict[int, list[Fact]] = {}
    for operand in operands:
        by_start.setdefault(operand.subject[0], []).append(operand)
    instructions = evidence.instructions
    stack: list[Fact] = []
    index = 0
    previous_end: int | None = None
    while index < len(instructions):
        instruction = instructions[index]
        if previous_end is not None and instruction.offset != previous_end:
            stack.clear()
        candidates = by_start.get(instruction.offset, ())
        if candidates:
            farthest = max(candidate.subject[1] for candidate in candidates)
            matches = [
                candidate
                for candidate in candidates
                if candidate.subject[1] == farthest
            ]
            if len(matches) != 1:
                stack.clear()
                previous_end = instruction.end
                index += 1
                continue
            operand = matches[0]
            stack.append(operand)
            while (
                index < len(instructions)
                and instructions[index].offset < operand.subject[1]
            ):
                index += 1
            previous_end = operand.subject[1]
            continue
        if instruction.raw in {"89 c3", "8b d8", "89 d8"}:
            previous_end = instruction.end
            index += 1
            continue
        if _runtime(instruction, 0x9B) and len(stack) >= 2:
            right = stack.pop()
            left = stack.pop()
            combined = Fact(
                "expression.string_operand",
                (left.subject[0], instruction.end),
                (("binary", "+", left.value[0], right.value[0]),),
                combine_evidence(
                    left.evidence,
                    right.evidence,
                    (instruction.offset,),
                ),
                "anchored",
            )
            yield combined
            stack.append(combined)
            previous_end = instruction.end
            index += 1
            continue
        stack.clear()
        previous_end = instruction.end
        index += 1


def _numeric_value(value: object) -> bool:
    """Report a value no string operand can hold.

    A call whose name does not end in ``$`` returns a number.  ``LEN`` of a
    string operand is emitted as an expression at the same offset as the
    operand it measures, so without this the operand pass reads its own
    result back and measures it again on the next round.
    """
    return (
        isinstance(value, tuple)
        and len(value) > 1
        and value[0] == "call"
        and isinstance(value[1], str)
        and not value[1].endswith("$")
    )


def _string_operands(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    for setup, consume in zip(evidence.instructions, evidence.instructions[1:]):
        if setup.end != consume.offset:
            continue
        if (
            consume.kind == "tb.runtime"
            and consume.operands == (0x9D,)
            and bytes.fromhex(setup.raw)[:2] == b"\xc4\x76"
        ):
            values = {
                fact.value[0]
                for fact in facts
                if fact.kind == "expression.value"
                and fact.subject == (setup.offset,)
                and len(fact.value) == 1
                and not _numeric_value(fact.value[0])
            }
            value = next(iter(values)) if len(values) == 1 else None
            if value is not None:
                yield Fact(
                    "expression.string_operand",
                    (setup.offset, consume.end),
                    (value,),
                    (setup.offset, consume.offset),
                    "anchored",
                )
            continue
        address = _string_push(setup, consume)
        if address is not None:
            value = resolve_expression(("memory", address, "string"), facts)
            if value is not None:
                yield Fact(
                    "expression.string_operand",
                    (setup.offset, consume.end),
                    (value.value,),
                    combine_evidence(
                        (setup.offset, consume.offset),
                        value.evidence,
                    ),
                    "anchored",
                )
            continue
        code = None
        if (
            setup.kind == "x86.mov_imm"
            and setup.operands[:1] == ("ax",)
            and len(setup.operands) == 2
            and isinstance(setup.operands[1], int)
        ):
            code = setup.operands[1]
        elif setup.raw == "31 c0":
            # CHR$(0) clears AX rather than loading a zero.
            code = 0
        if code is not None and _runtime(consume, 0xB3):
            yield Fact(
                "expression.string_operand",
                (setup.offset, consume.end),
                (("call", "CHR$", (("const", code),)),),
                (setup.offset, consume.offset),
                "signature",
            )


_OPERAND_REACH = 16
"""How far before a string compare, or before its other operand, a pushed
operand may end."""

# LEFT$, MID$ (three and two arguments) and RIGHT$ take the string on top
# of the string stack as their operand.
_STRING_FUNCTION_VECTORS = (0xAD, 0xB1, 0xB0, 0xB2)


@reads(
    "constant",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "layout.array",
    "signature",
    "slot",
    "tb.runtime",
    "x86.mov_imm",
)
def string_compare_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover string comparison expressions."""

    operands = set(_string_operands(evidence, facts))
    operands.update(
        fact
        for fact in facts
        if fact.kind == "expression.string_operand"
        and len(fact.subject) == 2
        and len(fact.value) == 1
    )
    moves = register_moves(evidence.instructions)
    string_functions = [
        item.offset
        for item in evidence.instructions
        if any(_runtime(item, vector) for vector in _STRING_FUNCTION_VECTORS)
        or (item.kind == "tb.function" and item.operands[:1] == ("string",))
    ]
    for compare in evidence.instructions:
        if not _runtime(compare, 0x9A):
            continue
        pairs = [
            (left, right)
            for right in operands
            if bridged(right.subject[1], compare.offset, moves)
            for left in operands
            if bridged(left.subject[1], right.subject[0], moves)
        ]
        if len(pairs) == 1:
            left, right = pairs[0]
            yield Fact(
                "expression.string_compare",
                (left.subject[0], compare.end),
                (left.value[0], right.value[0]),
                combine_evidence(
                    left.evidence,
                    right.evidence,
                    (compare.offset,),
                ),
                "anchored",
            )
            continue
        prior = sorted(
            (item for item in operands if item.subject[1] <= compare.offset),
            key=lambda item: (item.subject[0], fact_key(item)),
        )
        if len(prior) < 2:
            continue
        right = prior[-1]
        # Both operands are pushed just before the compare; an operand from
        # another statement is not one of them.
        if compare.offset - right.subject[1] > _OPERAND_REACH or any(
            right.subject[1] <= offset < compare.offset for offset in string_functions
        ):
            continue
        left_candidate = next(
            (
                item
                for item in reversed(prior[:-1])
                if item.value[0][0] in {"slot", "proc-param"}
                and item.subject[1] <= right.subject[0]
                and right.subject[0] - item.subject[1] <= _OPERAND_REACH
                # A string function between them consumed this push.
                and not any(
                    item.subject[1] <= offset < right.subject[0]
                    for offset in string_functions
                )
            ),
            None,
        )
        if left_candidate is None:
            continue
        left = left_candidate
        if left is None:
            continue
        yield Fact(
            "expression.string_compare",
            (left.subject[0], compare.end),
            (left.value[0], right.value[0]),
            combine_evidence(left.evidence, right.evidence, (compare.offset,)),
            "anchored",
        )


@reads("expression.string_compare", "x86.jmp")
def direct_string_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover conditional jumps comparing string values directly."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for comparison in facts:
        if comparison.kind != "expression.string_compare" or len(comparison.value) != 2:
            continue
        compare = instructions.get(comparison.subject[1] - 2)
        branch = instructions.get(compare.end) if compare is not None else None
        commit = None
        if branch is not None and _runtime(branch, 0x87):
            # A statement commit can sit between the compare and its branch.
            commit, branch = branch, instructions.get(branch.end)
        jump = instructions.get(branch.end) if branch is not None else None
        relation = _string_relation(branch)
        if (
            relation is None
            or branch is None
            or len(branch.operands) != 1
            or not isinstance(branch.operands[0], int)
        ):
            continue
        if (
            jump is not None
            and jump.kind == "x86.jmp"
            and len(jump.operands) == 1
            and branch.operands == (jump.end,)
        ):
            target, end = jump.operands[0], jump.end
            support = (branch.offset, jump.offset)
        else:
            relation = {
                "=": "<>",
                "<>": "=",
                "<": ">=",
                ">=": "<",
                ">": "<=",
                "<=": ">",
            }[relation]
            target, end = branch.operands[0], branch.end
            support = (branch.offset,)
        yield Fact(
            "semantic.if_goto",
            (comparison.subject[0], end),
            (
                relation,
                comparison.value[0],
                comparison.value[1],
                target,
                end,
            ),
            combine_evidence(
                comparison.evidence,
                support,
                () if commit is None else (commit.offset,),
            ),
            "anchored",
        )


@reads(
    "expression.string_compare",
    "x86.ja",
    "x86.jae",
    "x86.jb",
    "x86.jbe",
    "x86.je",
    "x86.jg",
    "x86.jl",
    "x86.jne",
)
def string_relation_value_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover materialized values produced by string relations."""
    relations = {
        "x86.je": "=",
        "x86.jne": "<>",
        "x86.jg": ">",
        "x86.jl": "<",
        "x86.ja": ">",
        "x86.jae": ">=",
        "x86.jb": "<",
        "x86.jbe": "<=",
    }
    for comparison in facts:
        if comparison.kind != "expression.string_compare" or len(comparison.value) != 2:
            continue
        branch = next(
            (
                item
                for item in evidence.instructions
                if comparison.subject[1] <= item.offset < comparison.subject[1] + 12
                and item.kind in relations
            ),
            None,
        )
        if branch is None:
            continue
        yield Fact(
            "expression.relation_value",
            (comparison.subject[0], branch.end),
            ("group", (relations[branch.kind], *comparison.value)),
            combine_evidence(comparison.evidence, (branch.offset,)),
            "anchored",
        )


def _string_push(setup: Operation, runtime: Operation) -> int | None:
    if (
        setup.kind == "x86.mov_imm"
        and setup.operands[:1] == ("si",)
        and len(setup.operands) == 2
        and isinstance(setup.operands[1], int)
        and _runtime(runtime, 0x9C)
        and setup.end == runtime.offset
    ):
        return setup.operands[1]
    return None


def _string_relation(branch: Operation | None) -> str | None:
    if branch is None or not branch.raw:
        return None
    raw = bytes.fromhex(branch.raw)
    return _STRING_SKIP_RELATIONS.get(raw[0]) if raw else None


def _runtime(operation: Operation, vector: int) -> bool:
    return operation.kind == "tb.runtime" and operation.operands == (vector,)


STRING_CONDITION_FACT_PASSES: tuple[NamedPass, ...] = (
    ("string-operands", string_operand_facts),
    ("string-comparisons", string_compare_facts),
    ("string-relation-values", string_relation_value_facts),
    ("direct-string-if-gotos", direct_string_if_goto_facts),
)
