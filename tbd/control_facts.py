"""Control-flow and source conditional facts over immutable evidence."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence, resolve_expression

_BRANCH_TESTS = {
    "x86.je": "=",
    "x86.jne": "<>",
    "x86.jb": "<u",
    "x86.jae": ">=u",
    "x86.jbe": "<=u",
    "x86.ja": ">u",
    "x86.jl": "<",
    "x86.jge": ">=",
    "x86.jle": "<=",
    "x86.jg": ">",
}
_SOURCE_CONDITIONS = {
    "=": "<>",
    "<>": "=",
    "<u": "<=",
    ">=u": ">",
    "<=u": "<",
    ">u": ">=",
    "<": ">=",
    ">=": ">",
    "<=": "<",
    ">": "<=",
}
_JUMPS = {"x86.jmp", "x86.jmp_far"}
_CALLS = {"x86.call", "x86.call_far"}
_RETURNS = {"x86.ret", "x86.retf", "x86.iret"}


def control_flow_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Describe direct branches, jumps, calls, and returns."""

    for instruction in evidence.instructions:
        fact = _flow_fact(instruction)
        if fact is not None:
            yield fact


def if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recognize a complete compare/status/commit/branch/jump source idiom."""

    instructions = {instruction.offset: instruction for instruction in evidence.instructions}
    flow = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind in {"flow.branch", "flow.goto"} and len(fact.subject) == 2
    }
    for compare in facts:
        if compare.kind != "expression.compare":
            continue
        result = _if_goto(compare, instructions, flow, facts)
        if result is not None:
            yield result


def _flow_fact(instruction: Operation) -> Fact | None:
    if instruction.kind in _BRANCH_TESTS:
        return _flow(
            "flow.branch",
            instruction,
            (_BRANCH_TESTS[instruction.kind], instruction.operands[0]),
        )
    if instruction.kind in _JUMPS:
        return _flow("flow.goto", instruction, (instruction.operands[0],))
    if instruction.kind in _CALLS:
        return _flow("flow.call", instruction, (instruction.operands[0],))
    if instruction.kind in _RETURNS:
        return _flow("flow.return", instruction, instruction.operands)
    return None


def _flow(kind: str, instruction: Operation, value: tuple[object, ...]) -> Fact:
    return Fact(
        kind,
        (instruction.offset, instruction.end),
        value,
        (instruction.offset,),
        "structural",
    )


def _if_goto(
    compare: Fact,
    instructions: dict[int, Operation],
    flow: dict[int, Fact],
    facts: frozenset[Fact],
) -> Fact | None:
    chain = _conditional_chain(compare, instructions, flow)
    if chain is None:
        return None
    status, commit, branch, jump = chain
    condition = _SOURCE_CONDITIONS.get(branch.value[0])
    top = resolve_expression(compare.value[0], facts)
    memory = resolve_expression(compare.value[1], facts)
    if condition is None or top is None or memory is None:
        return None
    support = combine_evidence(
        compare.evidence,
        (status.offset, commit.offset),
        branch.evidence,
        jump.evidence,
        top.evidence,
        memory.evidence,
    )
    return Fact(
        "semantic.if_goto",
        (compare.evidence[0], jump.subject[1]),
        (condition, memory.value, top.value, jump.value[0], branch.value[1]),
        support,
        "anchored",
    )


def _conditional_chain(
    compare: Fact,
    instructions: dict[int, Operation],
    flow: dict[int, Fact],
) -> tuple[Operation, Operation, Fact, Fact] | None:
    runtime_pair = _runtime_pair(compare, instructions)
    if runtime_pair is None:
        return None
    status, commit = runtime_pair
    branch = flow.get(commit.end)
    jump = flow.get(branch.subject[1]) if branch else None
    if branch is None or branch.kind != "flow.branch":
        return None
    if jump is None or jump.kind != "flow.goto":
        return None
    return status, commit, branch, jump


def _runtime_pair(
    compare: Fact, instructions: dict[int, Operation]
) -> tuple[Operation, Operation] | None:
    if not compare.evidence:
        return None
    last_compare = instructions.get(compare.evidence[-1])
    status = instructions.get(last_compare.end) if last_compare else None
    commit = instructions.get(status.end) if status else None
    if not _runtime(status, 0x99) or not _runtime(commit, 0x87):
        return None
    return status, commit


def _runtime(instruction: Operation | None, vector: int) -> bool:
    return (
        instruction is not None
        and instruction.kind == "tb.runtime"
        and instruction.operands == (vector,)
    )


CONTROL_FACT_PASSES: tuple[NamedPass, ...] = (
    ("control-flow", control_flow_facts),
    ("if-gotos", if_goto_facts),
)
