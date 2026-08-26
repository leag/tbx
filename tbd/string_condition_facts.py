"""String comparison facts from complete runtime-stack scaffolds."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence, resolve_expression

_STRING_SKIP_RELATIONS = {
    0x75: "=",
    0x74: "<>",
    0x72: ">=",
    0x73: "<",
    0x76: ">",
    0x77: "<=",
}


def string_operand_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve one complete descriptor-push or immediate CHR$ operand."""

    yield from _string_operands(evidence, facts)


def _string_operands(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    for setup, consume in zip(evidence.instructions, evidence.instructions[1:]):
        if setup.end != consume.offset:
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
        if (
            setup.kind == "x86.mov_imm"
            and setup.operands[:1] == ("ax",)
            and len(setup.operands) == 2
            and isinstance(setup.operands[1], int)
            and _runtime(consume, 0xB3)
        ):
            yield Fact(
                "expression.string_operand",
                (setup.offset, consume.end),
                (("call", "CHR$", (("const", setup.operands[1]),)),),
                (setup.offset, consume.offset),
                "signature",
            )


def string_compare_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Compose two contiguous string operands with the runtime comparison."""

    operands = set(_string_operands(evidence, facts))
    operands.update(
        fact
        for fact in facts
        if fact.kind == "expression.string_operand"
        and len(fact.subject) == 2
        and len(fact.value) == 1
    )
    for compare in evidence.instructions:
        if not _runtime(compare, 0x9A):
            continue
        pairs = [
            (left, right)
            for right in operands
            if right.subject[1] == compare.offset
            for left in operands
            if left.subject[1] == right.subject[0]
        ]
        if len(pairs) != 1:
            continue
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


def direct_string_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Lift a string compare followed by its complete skip/jump pair."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for comparison in facts:
        if comparison.kind != "expression.string_compare" or len(comparison.value) != 2:
            continue
        compare = instructions.get(comparison.subject[1] - 2)
        branch = instructions.get(compare.end) if compare is not None else None
        jump = instructions.get(branch.end) if branch is not None else None
        relation = _string_relation(branch)
        if (
            relation is None
            or jump is None
            or jump.kind != "x86.jmp"
            or len(jump.operands) != 1
            or branch.operands != (jump.end,)
        ):
            continue
        yield Fact(
            "semantic.if_goto",
            (comparison.subject[0], jump.end),
            (
                relation,
                comparison.value[0],
                comparison.value[1],
                jump.operands[0],
                jump.end,
            ),
            combine_evidence(
                comparison.evidence,
                (branch.offset, jump.offset),
            ),
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
    ("direct-string-if-gotos", direct_string_if_goto_facts),
)
