"""Control-flow and source conditional facts over immutable evidence."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.compiler_ops import translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.procedure_facts import inline_procedure_regions
from tbd.semantic import (
    combine_evidence,
    resolve_expression,
    resolve_expression_before,
)

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
_CALLS = {"x86.call", "x86.call_far", "tb.checked_gosub"}
_RETURNS = {"x86.ret", "x86.retf", "x86.iret", "tb.checked_return"}
_INTEGER_SKIP_RELATIONS = {
    0x74: "<>",
    0x75: "=",
    0x7C: "<=",
    0x7D: ">",
    0x7E: "<",
    0x7F: ">=",
}
_INTEGER_DIRECT_RELATIONS = {
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


def direct_integer_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Port the complete ``movax; cmpax_m; jcc skip; jmp target`` idiom."""

    operations = translate_operations(evidence.instructions)
    for index in range(len(operations) - 3):
        load, compare, branch, jump = operations[index : index + 4]
        if (
            load.kind != "movax"
            or compare.kind != "cmpax_m"
            or branch.kind != "jcc"
            or jump.kind != "jmp"
            or load.end != compare.offset
            or compare.end != branch.offset
            or branch.end != jump.offset
            or len(load.args) != 1
            or len(compare.args) != 1
            or len(branch.args) != 2
            or len(jump.args) != 1
            or branch.args[1] != jump.end
        ):
            continue
        relation = _INTEGER_SKIP_RELATIONS.get(branch.args[0])
        memory = resolve_expression(("memory", compare.args[0], "integer"), facts)
        if (
            relation is None
            or memory is None
            or not isinstance(jump.args[0], int)
        ):
            continue
        support = combine_evidence(
            (load.offset, compare.offset, branch.offset, jump.offset),
            memory.evidence,
        )
        yield Fact(
            "semantic.if_goto",
            (load.offset, jump.end),
            (
                relation,
                memory.value,
                ("const", load.args[0]),
                jump.args[0],
                branch.args[1],
            ),
            support,
            "signature",
        )


def direct_system_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Lift a direct true branch comparing a literal with ERR or ERL."""

    operations = translate_operations(evidence.instructions)
    for load, compare, branch in zip(
        operations,
        operations[1:],
        operations[2:],
    ):
        if (
            load.kind != "movax"
            or compare.kind != "cmpax_m"
            or branch.kind != "jcc"
            or load.end != compare.offset
            or compare.end != branch.offset
            or len(load.args) != 1
            or len(compare.args) != 1
            or len(branch.args) != 2
        ):
            continue
        relation = _INTEGER_DIRECT_RELATIONS.get(branch.args[0])
        system = resolve_expression(("memory", compare.args[0], "integer"), facts)
        if (
            relation is None
            or system is None
            or not isinstance(system.value, tuple)
            or system.value[:2] != ("call", "ERR")
            and system.value[:2] != ("call", "ERL")
            or not isinstance(branch.args[1], int)
        ):
            continue
        yield Fact(
            "semantic.if_goto",
            (load.offset, branch.end),
            (
                relation,
                system.value,
                ("const", load.args[0]),
                branch.args[1],
                branch.end,
            ),
            combine_evidence(
                (load.offset, compare.offset, branch.offset),
                system.evidence,
            ),
            "anchored",
        )


def computed_array_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Port the complete computed-INTEGER-element comparison idiom."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    compiler_operations = {
        operation.offset: operation
        for operation in translate_operations(evidence.instructions)
    }
    ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    for address in facts:
        if (
            address.kind != "reference.array_address"
            or len(address.subject) != 2
            or len(address.value) != 4
            or address.value[1] != "integer"
        ):
            continue
        compare = instructions.get(address.subject[1])
        compiler_compare = compiler_operations.get(address.subject[1])
        commit = instructions.get(compare.end) if compare is not None else None
        branch = instructions.get(commit.end) if commit is not None else None
        jump = instructions.get(branch.end) if branch is not None else None
        if (
            compare is None
            or compiler_compare is None
            or compiler_compare.kind != "cmpax_si"
            or not _runtime(commit, 0x87)
            or branch is None
            or branch.kind not in _BRANCH_TESTS
            or jump is None
            or jump.kind != "x86.jmp"
            or not branch.operands
            or not jump.operands
            or branch.operands[0] != jump.end
        ):
            continue
        relation = _INTEGER_SKIP_RELATIONS.get(bytes.fromhex(branch.raw)[0])
        source = resolve_expression_before(address.subject[0], facts, ends)
        if relation is None or source is None:
            continue
        yield Fact(
            "semantic.if_goto",
            (
                source.start if source.start is not None else source.evidence[0],
                jump.end,
            ),
            (
                relation,
                address.value[0],
                source.value,
                jump.operands[0],
                branch.operands[0],
            ),
            combine_evidence(
                address.evidence,
                source.evidence,
                (compare.offset, commit.offset, branch.offset, jump.offset),
            ),
            "anchored",
        )


def direct_expression_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Lift a resolved comparison followed immediately by its true branch."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    branches = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind == "flow.branch" and len(fact.subject) == 2
    }
    for comparison in facts:
        if (
            comparison.kind != "expression.compare"
            or len(comparison.value) != 2
            or not comparison.evidence
        ):
            continue
        compare = instructions.get(comparison.evidence[-1])
        branch = branches.get(compare.end) if compare is not None else None
        relation = branch.value[0] if branch is not None else None
        if (
            compare is None
            or compare.raw != "3b c3"
            or branch is None
            or relation not in _SOURCE_CONDITIONS
            or not isinstance(branch.value[1], int)
        ):
            continue
        left = resolve_expression(comparison.value[0], facts)
        right = resolve_expression(comparison.value[1], facts)
        if left is None or right is None:
            continue
        yield Fact(
            "semantic.if_goto",
            (comparison.subject[0], branch.subject[1]),
            (
                relation,
                left.value,
                right.value,
                branch.value[1],
                branch.subject[1],
            ),
            combine_evidence(
                comparison.evidence,
                branch.evidence,
                left.evidence,
                right.evidence,
            ),
            "anchored",
        )


def function_truth_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Lift a proven boolean intrinsic followed by its true jump pair."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for expression in facts:
        if (
            expression.kind != "expression.value"
            or len(expression.value) != 1
            or not expression.evidence
            or not isinstance(expression.value[0], tuple)
            or expression.value[0][:2] != ("call", "EOF")
        ):
            continue
        call = instructions.get(expression.evidence[-1])
        test = instructions.get(call.end) if call is not None else None
        branch = instructions.get(test.end) if test is not None else None
        jump = instructions.get(branch.end) if branch is not None else None
        if (
            test is None
            or test.raw != "09 c0"
            or branch is None
            or branch.raw[:2] != "74"
            or len(branch.operands) != 1
            or jump is None
            or jump.kind != "x86.jmp"
            or len(jump.operands) != 1
            or branch.operands[0] != jump.end
        ):
            continue
        yield Fact(
            "semantic.if_goto_condition",
            (expression.subject[0], jump.end),
            (("truth", expression.value[0]), jump.operands[0], jump.end),
            combine_evidence(
                expression.evidence,
                (test.offset, branch.offset, jump.offset),
            ),
            "anchored",
        )


def source_subroutine_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Lift compiler-distinct near GOSUB calls and source RETURN opcodes."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    targets = set(instructions)
    inline = inline_procedure_regions(evidence)
    inline_entries = {procedure.entry for procedure in inline}
    for flow in facts:
        if len(flow.subject) != 2:
            continue
        instruction = instructions.get(flow.subject[0])
        if instruction is None:
            continue
        if (
            flow.kind == "flow.call"
            and instruction.kind in _CALLS
            and flow.value
            and flow.value[0] in targets
            and flow.value[0] not in inline_entries
            and instructions[flow.value[0]].kind != "tb.proc_enter"
        ):
            yield Fact(
                "semantic.gosub",
                flow.subject,
                (flow.value[0],),
                flow.evidence,
                "signature",
            )
        elif (
            flow.kind == "flow.return"
            and instruction.kind in _RETURNS
            and not instruction.operands
            and not any(
                procedure.declaration <= instruction.offset < procedure.end
                for procedure in inline
            )
        ):
            yield Fact(
                "semantic.return",
                flow.subject,
                (),
                flow.evidence,
                "signature",
            )
        elif flow.kind == "flow.return_to" and instruction.kind == "tb.return_to":
            yield Fact(
                "semantic.return",
                flow.subject,
                (flow.value[0],),
                flow.evidence,
                "signature",
            )
    for cleanup, jump in zip(evidence.instructions, evidence.instructions[1:]):
        if (
            cleanup.raw == "83 c4 02"
            and cleanup.end == jump.offset
            and jump.kind == "x86.jmp"
            and jump.operands
        ):
            yield Fact(
                "semantic.return",
                (cleanup.offset, jump.end),
                (jump.operands[0],),
                (cleanup.offset, jump.offset),
                "signature",
            )


def source_run_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Lift only profile-classified entry jumps to bare RUN statements."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for instruction in evidence.instructions:
        previous = instructions.get(instruction.offset - 3)
        resume_tail = (
            previous is not None
            and previous.end == instruction.offset
            and previous.kind == "tb.statement"
            and previous.operands[:2] == ("RESUME_BEGIN", 0xBC)
        )
        if instruction.kind == "tb.run" and not resume_tail:
            yield Fact(
                "semantic.run",
                (instruction.offset, instruction.end),
                (),
                (instruction.offset,),
                "signature",
            )


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
    if instruction.kind == "tb.run":
        return _flow("flow.run", instruction, (instruction.operands[0],))
    if instruction.kind == "tb.return_to":
        return _flow("flow.return_to", instruction, (instruction.operands[0],))
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
        (compare.subject[0], jump.subject[1]),
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
    matches = []
    for address in compare.evidence:
        last_compare = instructions.get(address)
        status = instructions.get(last_compare.end) if last_compare else None
        commit = instructions.get(status.end) if status else None
        if _runtime(status, 0x99) and _runtime(commit, 0x87):
            matches.append((status, commit))
    return matches[0] if len(matches) == 1 else None


def _runtime(instruction: Operation | None, vector: int) -> bool:
    return (
        instruction is not None
        and instruction.kind == "tb.runtime"
        and instruction.operands == (vector,)
    )


CONTROL_FACT_PASSES: tuple[NamedPass, ...] = (
    ("control-flow", control_flow_facts),
    ("source-subroutines", source_subroutine_facts),
    ("source-run", source_run_facts),
    ("direct-integer-if-gotos", direct_integer_if_goto_facts),
    ("direct-system-if-gotos", direct_system_if_goto_facts),
    ("computed-array-if-gotos", computed_array_if_goto_facts),
    ("direct-expression-if-gotos", direct_expression_if_goto_facts),
    ("function-truth-if-gotos", function_truth_if_goto_facts),
    ("if-gotos", if_goto_facts),
)
