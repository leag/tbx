from __future__ import annotations

from collections.abc import Iterable

from tbd.compiler_ops import translate_operations
from tbd.facts import Evidence, NamedPass, fact_key, facts_by_kind, indexed_facts, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import bridged, register_moves
from tbd.operation_helpers import contiguous as _contiguous
from tbd.operation_helpers import runtime_call as _runtime
from tbd.procedure_facts import inline_procedure_regions
from tbd.region_facts import (
    AX_BX_RELATIONS,
    function_constant_compare,
    tracked_relation,
)
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
    "<": "<=",
    ">=": ">",
    "<=": "<",
    ">": ">=",
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


@reads(
    "flow.branch",
    "flow.call",
    "flow.goto",
    "flow.return",
    "flow.return_to",
    "flow.run",
    "tb.checked_gosub",
    "tb.checked_return",
    "tb.return_to",
    "tb.run",
    "x86.call",
    "x86.call_far",
    "x86.iret",
    "x86.ja",
    "x86.jae",
    "x86.jb",
    "x86.jbe",
    "x86.je",
    "x86.jg",
    "x86.jge",
    "x86.jl",
    "x86.jle",
    "x86.jmp",
    "x86.jmp_far",
    "x86.jne",
    "x86.ret",
    "x86.retf",
)
def control_flow_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    """Emit low-level branch and jump facts from decoded instructions."""
    for instruction in evidence.instructions:
        fact = _flow_fact(instruction)
        if fact is not None:
            yield fact


@reads(
    "constant",
    "expression.compare",
    "expression.system",
    "expression.value",
    "flow.branch",
    "flow.goto",
    "layout.array",
    "reference.array_value",
    "register.value",
    "semantic.local",
    "semantic.sub_def",
    "slot",
    "tb.runtime",
    "x86.cmp",
    "x86.mov_imm",
)
def if_goto_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover conditional jumps from comparisons and their flow tails."""

    immediates_by_end = {
        instruction.end: instruction
        for instruction in evidence.instructions
        if instruction.kind == "x86.mov_imm"
        and instruction.operands[:1] == ("ax",)
        and instruction.size > 0
    }
    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    flow = indexed_facts(
        (
            fact
            for fact in facts
            if fact.kind in {"flow.branch", "flow.goto"} and len(fact.subject) == 2
        ),
        lambda fact: fact.subject[0],
    )
    comparisons = list(facts)
    # A compiler-generated tail loop may compare a memory slot directly with
    # an immediate loaded in AX.  That shape has no standalone
    # ``expression.compare`` fact, but it is still an ordinary BASIC
    # conditional jump (for example ``C% = C% + 1: IF C% < 10 THEN ...``).
    # Recover the comparison here so the normal branch normalization remains
    # the single source of truth for its target and polarity.
    for instruction in evidence.instructions:
        if instruction.kind != "x86.cmp" or len(instruction.raw.split()) != 4:
            continue
        raw = bytes.fromhex(instruction.raw)
        if raw[:2] != b"\x3b\x06":
            continue
        address = int.from_bytes(raw[2:], "little")
        slot = next(
            (
                fact
                for fact in facts_by_kind(facts).get("slot", ())
                if fact.kind == "slot" and fact.subject == (address,)
            ),
            None,
        )
        previous = immediates_by_end.get(instruction.offset)
        if slot is None or previous is None:
            continue
        immediate = bytes.fromhex(previous.raw)[1:]
        if len(immediate) not in {1, 2, 4}:
            continue
        immediate_value = int.from_bytes(immediate, "little", signed=False)
        comparisons.append(
            Fact(
                "expression.compare",
                (instruction.offset,),
                (("slot", slot.value[0], address), ("const", immediate_value)),
                (instruction.offset,),
                "anchored",
            )
        )
        branch = next(
            (
                fact
                for fact in facts_by_kind(facts).get("flow.branch", ())
                if fact.kind == "flow.branch"
                and fact.subject[0] == instruction.end
                and fact.value[0] == ">"
            ),
            None,
        )
        if branch is not None and branch.value[1] < instruction.offset:
            yield Fact(
                "semantic.if_goto",
                (instruction.offset, branch.subject[1]),
                (
                    "<",
                    ("slot", slot.value[0], address),
                    ("const", immediate_value),
                    branch.value[1],
                    branch.subject[1],
                ),
                (instruction.offset, branch.subject[0]),
                "anchored",
            )
    for compare in comparisons:
        if compare.kind != "expression.compare":
            continue
        result = _if_goto(compare, instructions, flow, facts)
        if result is not None:
            yield result


def _tracked_if_gotos(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """``cmp ax,operand; jcc +3; jmp target``: jump when the relation fails."""
    instructions = evidence.instructions
    position = {item.offset: index for index, item in enumerate(instructions)}
    for compared in facts_by_kind(facts).get("register.compare", ()):
        index = position.get(compared.subject[0])
        if index is None or index + 2 >= len(instructions):
            continue
        branch, jump = instructions[index + 1 : index + 3]
        if (
            not branch.kind.startswith("x86.j")
            or branch.kind in {"x86.jmp", "x86.jmp_far"}
            or branch.operands != (jump.end,)
            or jump.kind != "x86.jmp"
            or len(jump.operands) != 1
            or not isinstance(jump.operands[0], int)
            or not _contiguous(instructions[index : index + 3])
            or _select_arm(instructions, index)
        ):
            continue
        relation = tracked_relation(compared, branch, facts)
        if relation is None or relation.start not in position:
            continue
        if not _contiguous(instructions[position[relation.start] : index + 3]):
            continue
        operator, left, right = relation.value
        yield Fact(
            "semantic.if_goto",
            (relation.start, jump.end),
            (_NEGATED[operator], left, right, jump.operands[0], jump.end),
            combine_evidence(relation.evidence, (branch.offset, jump.offset)),
            "signature",
        )


def _select_arm(instructions: tuple[Operation, ...], compare: int) -> bool:
    """Whether a compare with a zeroed AX is a numeric SELECT arm.

    After a forward jump, the previous arm's jump ahead to END SELECT, it is
    an arm; after a backward jump it is an ordinary statement following the
    program's own GOTO. A value stored and compared again at once is the
    SELECT's own operand.
    """
    if compare < 2 or instructions[compare - 1].raw not in {"31 c0", "33 c0"}:
        return False
    before = instructions[compare - 2]
    if before.kind == "x86.jmp":
        return not (
            before.operands
            and isinstance(before.operands[0], int)
            and before.operands[0] < before.offset
        )
    stored, compared = (
        bytes.fromhex(before.raw),
        bytes.fromhex(instructions[compare].raw),
    )
    return (
        len(stored) == 4
        and stored[:2] == b"\x89\x06"
        and compared[:2] == b"\x3b\x06"
        and stored[2:] == compared[2:]
    )


_NEGATED = {"<": ">=", ">=": "<", ">": "<=", "<=": ">", "=": "<>", "<>": "="}


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "register.compare",
    "semantic.local",
    "semantic.sub_def",
    "signature",
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
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def direct_integer_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover integer comparisons compiled as direct machine operations."""
    yield from _tracked_if_gotos(evidence, facts)


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "signature",
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
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def direct_bitwise_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover a conditional jump that tests a just-computed bitwise value."""
    operations = translate_operations(evidence.instructions)
    for left, combine, branch, jump in zip(
        operations, operations[1:], operations[2:], operations[3:]
    ):
        if (
            left.kind not in {"movax", "movax_m"}
            or combine.kind not in {"andax_m", "orax_m", "xorax_m"}
            or branch.kind != "jcc"
            or jump.kind != "jmp"
            or left.end != combine.offset
            or combine.end != branch.offset
            or branch.end != jump.offset
            or len(left.args) != 1
            or len(combine.args) != 1
            or len(branch.args) != 2
            or len(jump.args) != 1
            or branch.args[1] != jump.end
            or branch.args[0] not in {0x74, 0x75}
            or not isinstance(jump.args[0], int)
        ):
            continue
        left_value = (
            resolve_expression(("const", left.args[0]), facts)
            if left.kind == "movax"
            else resolve_expression(("memory", left.args[0], "integer"), facts)
        )
        memory = resolve_expression(("memory", combine.args[0], "integer"), facts)
        if left_value is None or memory is None:
            continue
        relation = "=" if branch.args[0] == 0x74 else "<>"
        yield Fact(
            "semantic.if_goto",
            (left.offset, jump.end),
            (
                relation,
                (
                    "binary",
                    {"andax_m": "AND", "orax_m": "OR", "xorax_m": "XOR"}[combine.kind],
                    left_value.value,
                    memory.value,
                ),
                ("const", 0),
                jump.args[0],
                branch.args[1],
            ),
            combine_evidence(
                (left.offset, combine.offset, branch.offset, jump.offset),
                left_value.evidence,
                memory.evidence,
            ),
            "signature",
        )
    for index, (left, combine, branch) in enumerate(
        zip(operations, operations[1:], operations[2:])
    ):
        if (
            left.kind not in {"movax", "movax_m"}
            or combine.kind not in {"andax_m", "orax_m", "xorax_m"}
            or branch.kind != "jcc"
            or left.end != combine.offset
            or combine.end != branch.offset
            or len(left.args) != 1
            or len(combine.args) != 1
            or len(branch.args) != 2
            or branch.args[0] not in {0x74, 0x75}
            or not isinstance(branch.args[1], int)
            or (
                index + 3 < len(operations)
                and operations[index + 3].offset == branch.end
                and operations[index + 3].kind == "jmp"
            )
        ):
            continue
        left_value = (
            resolve_expression(("const", left.args[0]), facts)
            if left.kind == "movax"
            else resolve_expression(("memory", left.args[0], "integer"), facts)
        )
        memory = resolve_expression(("memory", combine.args[0], "integer"), facts)
        if left_value is None or memory is None:
            continue
        relation = "=" if branch.args[0] == 0x74 else "<>"
        operator = {"andax_m": "AND", "orax_m": "OR", "xorax_m": "XOR"}[combine.kind]
        yield Fact(
            "semantic.if_goto",
            (left.offset, branch.end),
            (
                relation,
                ("binary", operator, left_value.value, memory.value),
                ("const", 0),
                branch.args[1],
                branch.end,
            ),
            combine_evidence(
                (left.offset, combine.offset, branch.offset),
                left_value.evidence,
                memory.evidence,
            ),
            "signature",
        )
    for index, operation in enumerate(operations):
        if operation.kind != "testw" or len(operation.args) != 2:
            continue
        test_branch = operations[index + 1] if index + 1 < len(operations) else None
        if (
            test_branch is None
            or test_branch.kind != "jcc"
            or not isinstance(test_branch.args[0], int)
            or test_branch.args[0] not in {0x74, 0x75}
            or len(test_branch.args) != 2
        ):
            continue
        test_target: object
        test_jump = operations[index + 2] if index + 2 < len(operations) else None
        if test_jump is not None and test_jump.kind == "jmp":
            if test_branch.args[1] != test_jump.end or not isinstance(
                test_jump.args[0], int
            ):
                continue
            test_target, false_target, end = (
                test_jump.args[0],
                test_branch.args[1],
                test_jump.end,
            )
        else:
            test_target, false_target, end = (
                test_branch.args[1],
                test_branch.end,
                test_branch.end,
            )
        memory = resolve_expression(("memory", operation.args[0], "integer"), facts)
        if memory is None or not isinstance(test_target, int):
            continue
        relation = "=" if test_branch.args[0] == 0x74 else "<>"
        yield Fact(
            "semantic.if_goto",
            (operation.offset, end),
            (
                relation,
                ("binary", "AND", memory.value, ("const", operation.args[1])),
                ("const", 0),
                test_target,
                false_target,
            ),
            combine_evidence(
                (operation.offset, test_branch.offset),
                () if test_jump is None else (test_jump.offset,),
                memory.evidence,
            ),
            "signature",
        )


@reads(
    "constant",
    "expression.system",
    "layout.array",
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
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def direct_system_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover conditional branches driven by system-variable loads."""
    operations = translate_operations(evidence.instructions)
    jump_ends = {
        operation.offset: operation.end
        for operation in operations
        if operation.kind == "jmp"
    }
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
        if not isinstance(branch.args[0], int):
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
            # Skipping the jump that follows is the inverted IF, read by
            # direct_integer_if_goto_facts.
            or jump_ends.get(branch.end) == branch.args[1]
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


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "reference.array_address",
    "reference.array_value",
    "register.value",
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
    "x86.ja",
    "x86.jae",
    "x86.jb",
    "x86.jbe",
    "x86.je",
    "x86.jg",
    "x86.jge",
    "x86.jl",
    "x86.jle",
    "x86.jmp",
    "x86.jne",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def computed_array_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover conditions comparing computed array values."""
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
        assert commit is not None and branch is not None and jump is not None
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


_DIRECT_RELATIONS = {
    "x86.je": "=",
    "x86.jne": "<>",
    "x86.jl": "<",
    "x86.jle": "<=",
    "x86.jg": ">",
    "x86.jge": ">=",
}


def _direct_backward_if_goto(
    facts: frozenset[Fact],
    compare: Operation,
    branch: Operation | None,
    following: Operation | None,
    moves: dict[int, int],
    loads: dict[int, Operation],
) -> Fact | None:
    """Recover ``IF a < b THEN line`` whose branch goes straight to the line.

    A THEN target near and behind the compare needs no jump over a jump, so
    the branch itself names it, with the relation the source wrote.  Only
    operands whose spans meet at the compare are read.
    """
    relation = _DIRECT_RELATIONS.get(branch.kind) if branch is not None else None
    if (
        branch is None
        or relation is None
        or branch.offset != compare.end
        or not branch.operands
        or not isinstance(branch.operands[0], int)
        or branch.operands[0] >= compare.offset
        or (following is not None and following.kind in _JUMPS)
    ):
        return None
    candidates = [
        item
        for item in facts_by_kind(facts).get("expression.value", ())
        if len(item.value) == 1
        and isinstance(item.value[0], tuple)
        and item.value[0][:1] == ("call",)
        and not str(item.value[0][1]).endswith("$")
    ]
    pair = _adjacent_call_operands(candidates, compare, moves, loads)
    if pair is None:
        return None
    left, right = pair
    return Fact(
        "semantic.if_goto",
        (min(left.subject[0], right.subject[0]), branch.end),
        (relation, left.value[0], right.value[0], branch.operands[0], branch.end),
        combine_evidence(
            left.evidence, right.evidence, (compare.offset, branch.offset)
        ),
        "anchored",
    )


def _adjacent_call_operands(
    candidates: list[Fact],
    compare: Operation,
    moves: dict[int, int],
    loads: dict[int, Operation],
) -> tuple[Fact, Fact] | None:
    """Return the values a ``cmp ax,bx`` compares, by their spans.

    The value in AX is computed last and ends at the compare, perhaps past
    the register moves that put the saved one in BX; that one, a call value
    or a constant loaded into AX, ends where the value in AX starts.  A
    value inside either one does not end there.
    """
    spanned = [
        item
        for item in candidates
        if len(item.subject) == 2 and isinstance(item.subject[1], int)
    ]
    last = [item for item in spanned if bridged(item.subject[1], compare.offset, moves)]
    if len({item.value for item in last}) != 1:
        return None
    ax = min(last, key=fact_key)
    first = [item for item in spanned if bridged(item.subject[1], ax.subject[0], moves)]
    load = loads.get(ax.subject[0])
    if not first and load is not None:
        first = [
            Fact(
                "expression.value",
                (load.offset, load.end),
                (("const", load.operands[1]),),
                (load.offset,),
                "anchored",
            )
        ]
    if len({item.value for item in first}) != 1:
        return None
    return ax, min(first, key=fact_key)


@reads(
    "constant",
    "expression.",
    "expression.compare",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "flow.branch",
    "layout.array",
    "reference.",
    "register.value",
    "slot",
    "tb.function",
    "x86.cmp",
    "x86.jbe",
    "x86.je",
    "x86.jg",
    "x86.jge",
    "x86.jl",
    "x86.jle",
    "x86.jmp",
    "x86.jne",
    "x86.mov",
    "x86.mov_imm",
    "x86.or",
)
def direct_expression_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover IF/GOTO conditions built from register expressions."""

    or_by_end = {}
    first_by_offset = {}
    for instruction in evidence.instructions:
        first_by_offset.setdefault(instruction.offset, instruction)
        if instruction.kind == "x86.or":
            or_by_end.setdefault(instruction.end, instruction)
    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    branches = indexed_facts(
        (
            fact
            for fact in facts_by_kind(facts).get("flow.branch", ())
            if len(fact.subject) == 2
        ),
        lambda fact: fact.subject[0],
    )
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
    register_values = indexed_facts(
        (
            fact
            for fact in facts_by_kind(facts).get("register.value", ())
            if len(fact.subject) == 2 and fact.subject[1] == "ax"
        ),
        lambda fact: fact.subject[0],
    )
    for branch_instruction in evidence.instructions:
        if (
            branch_instruction.kind not in {"x86.jne", "x86.je"}
            or branch_instruction.offset == 0
        ):
            continue
        combine_instruction = or_by_end.get(branch_instruction.offset)
        branch_jump = first_by_offset.get(branch_instruction.end)
        value = (
            register_values.get(combine_instruction.offset)
            if combine_instruction is not None
            else None
        )
        if value is None or branch_jump is None or branch_jump.kind != "x86.jmp":
            continue
        relation = "<>" if branch_instruction.kind == "x86.jne" else "="
        expression = value.value[0]
        if (
            isinstance(expression, tuple)
            and len(expression) == 4
            and expression[:2] == ("binary", "OR")
            and expression[2] == expression[3]
        ):
            expression = expression[2]
        resolved = resolve_expression(expression, facts)
        # An unresolved call result names no source expression yet.
        if resolved is not None or _names_call_result(expression):
            continue
        yield Fact(
            "semantic.if_goto_condition",
            (value.subject[0], branch_jump.end),
            (
                (relation, expression, ("const", 0)),
                branch_instruction.operands[0],
                branch_jump.operands[0],
            ),
            combine_evidence(
                value.evidence, (branch_instruction.offset, branch_jump.offset)
            ),
            "anchored",
        )
    yield from _fcompp_call_if_gotos(evidence.instructions, facts)
    moves = register_moves(evidence.instructions)
    loads = {
        item.end: item
        for item in evidence.instructions
        if item.kind == "x86.mov_imm" and item.operands[:1] == ("ax",)
    }
    for position, compare in enumerate(evidence.instructions):
        if compare.kind != "x86.cmp" or compare.raw != "3b c3":
            continue
        cmp_branch_op: Operation | None = next(
            (item for item in evidence.instructions if item.offset == compare.end),
            None,
        )
        cmp_jump_op: Operation | None = next(
            (
                item
                for item in evidence.instructions
                if cmp_branch_op is not None and item.offset == cmp_branch_op.end
            ),
            None,
        )
        direct = _direct_backward_if_goto(
            facts, compare, cmp_branch_op, cmp_jump_op, moves, loads
        )
        if direct is None and position > 0:
            direct = _function_constant_if_goto(
                evidence.instructions, position, facts, cmp_branch_op, cmp_jump_op
            )
        if direct is not None:
            yield direct
            continue
        if (
            cmp_branch_op is None
            or cmp_branch_op.kind not in {"x86.je", "x86.jne", "x86.jg", "x86.jle"}
            or cmp_jump_op is None
            or cmp_jump_op.kind != "x86.jmp"
        ):
            continue
        assert cmp_branch_op is not None and cmp_jump_op is not None
        # The compared values are computed just before the compare; a call
        # value from elsewhere in the program is not one of them.
        candidates = [
            item
            for item in facts
            if item.kind == "expression.value"
            and len(item.value) == 1
            and isinstance(item.value[0], tuple)
            and item.value[0][0] == "call"
            # ``cmp ax,bx`` compares integers; a string function is not one.
            and not str(item.value[0][1]).endswith("$")
            and compare.offset - _COMPARED_REACH <= item.subject[0] < compare.offset
            and any(address < compare.offset for address in item.evidence)
        ]
        preceding_call = next(
            (
                item
                for item in evidence.instructions
                if item.kind == "tb.function"
                and item.operands in {("numeric", 0x1C), ("numeric", 0x22)}
                and item.end == compare.offset
            ),
            None,
        )
        staged_pair = None
        numeric_call = next(
            (
                item
                for item in evidence.instructions
                if item.kind == "tb.function"
                and item.operands[:1] == ("numeric",)
                and item.end == compare.offset
            ),
            None,
        )
        if numeric_call is not None and preceding_call is None:
            staged_pair = _staged_length_comparison(
                evidence, facts, numeric_call, compare
            )
        if preceding_call is not None:
            candidates = []
            if preceding_call.operands == ("numeric", 0x22):
                staged_pair = _staged_length_comparison(
                    evidence, facts, preceding_call, compare
                )
                if staged_pair is None:
                    continue
        # Several expression values can start at one address, and the last two
        # decide the comparison, so the order has to be total.
        candidates = sorted(
            candidates, key=lambda item: (item.subject[0], fact_key(item))
        )
        adjacent = _adjacent_call_operands(candidates, compare, moves, loads)
        if staged_pair is None and adjacent is not None:
            selected_left, selected_right = adjacent
        elif staged_pair is not None:
            selected_left, selected_right = staged_pair
        elif len(candidates) < 2:
            call = next(
                (
                    item
                    for item in evidence.instructions
                    if item.kind == "tb.function"
                    and item.operands in {("numeric", 0x1C), ("numeric", 0x22)}
                    and item.end == compare.offset
                ),
                None,
            )
            if call is None:
                continue
            operands = sorted(
                (
                    item
                    for item in facts
                    if item.kind == "expression.string_operand"
                    and len(item.subject) == 2
                    and item.subject[1] <= call.offset
                    and len(item.value) == 1
                ),
                key=lambda item: (item.subject[0], fact_key(item)),
            )
            if len(operands) < 2:
                continue
            literal = next(
                (item for item in reversed(operands) if item.value[0][0] == "string"),
                None,
            )
            if literal is None:
                continue
            source = operands[-2] if len(operands) >= 2 else None
            if source is None or source.value[0][0] == "string":
                continue
            selected_left = type(
                "Expression",
                (),
                {
                    "subject": (source.subject[0],),
                    "value": (("call", "INSTR", (source.value[0], literal.value[0])),),
                    "evidence": source.evidence + literal.evidence,
                },
            )()
            selected_right = None
        else:
            # The value in AX is computed last; only values whose own span
            # is known, and whose last one runs up to the compare, are the
            # compared pair.
            spanned = [c for c in candidates if len(c.subject) == 2]
            if len(spanned) < 2:
                continue
            selected_left, selected_right = spanned[-2:]
            last = selected_right.subject
            if not isinstance(last[1], int) or not bridged(
                last[1], compare.offset, moves
            ):
                continue
        if selected_right is None:
            length_values = sorted(
                (
                    item
                    for item in facts
                    if item.kind == "expression.value"
                    and len(item.value) == 1
                    and isinstance(item.value[0], tuple)
                    and item.value[0][:2] == ("call", "LEN")
                    and item.subject[0] < compare.offset
                ),
                key=lambda item: (item.subject[0], fact_key(item)),
            )
            comparison_right_value: object = (
                length_values[-1].value[0]
                if preceding_call is not None and length_values
                else ("const", 0)
            )
            comparison_left_value: object = selected_left.value[0]
        else:
            comparison_right_value = selected_right.value[0]
            comparison_left_value = selected_left.value[0]
            if (
                isinstance(comparison_left_value, tuple)
                and isinstance(comparison_right_value, tuple)
                and comparison_left_value[:2] == ("call", "LEN")
                and comparison_right_value[:2] == ("call", "LEN")
            ):
                comparison_left_value, comparison_right_value = (
                    comparison_right_value,
                    comparison_left_value,
                )
        relation = {
            "x86.je": "<>",
            "x86.jne": "=",
            "x86.jg": "<=",
            "x86.jle": ">",
        }.get(cmp_branch_op.kind)
        if relation is None:
            continue
        start = selected_left.subject[0]
        if selected_right is not None:
            start = min(start, selected_right.subject[0])
        yield Fact(
            "semantic.if_goto",
            (start, cmp_jump_op.end),
            (
                relation,
                comparison_left_value,
                comparison_right_value,
                cmp_jump_op.operands[0],
                cmp_branch_op.end,
            ),
            combine_evidence(
                selected_left.evidence,
                () if selected_right is None else selected_right.evidence,
                (
                    compare.offset,
                    cmp_branch_op.offset,
                    cmp_jump_op.offset,
                ),
            ),
            "anchored",
        )


_COMPARED_REACH = 256


def _names_call_result(value: object) -> bool:
    """Whether an expression holds the register tracker's call placeholder."""
    if isinstance(value, tuple):
        return value[:1] == ("result",) or any(_names_call_result(v) for v in value)
    return False


# FCOMPP compares the top of the FP stack (the call) with the value below:
# the branch that skips the false arm's jump, as a relation of top to below.
_FP_TOP_RELATIONS = {
    "x86.jb": "<",
    "x86.jbe": "<=",
    "x86.ja": ">",
    "x86.jae": ">=",
    "x86.je": "=",
    "x86.jne": "<>",
}
# The goto's condition is the negation, written with the lower value first.
_BELOW_NEGATED = {"<": "<=", "<=": "<", ">": ">=", ">=": ">", "=": "<>", "<>": "="}
_CALL_REACH = 64


def _fcomp_memory(compare: Operation) -> tuple[object, ...] | None:
    """Return the memory operand of ``fcomp dword/qword [m]``, if it is one."""
    raw = bytes.fromhex(compare.raw)
    kinds = {0x3A: "float", 0x3C: "double"}
    if len(raw) != 5 or raw[0] != 0xCD or raw[1] not in kinds or raw[2] != 0x1E:
        return None
    return ("memory", int.from_bytes(raw[3:], "little"), kinds[raw[1]])


def _fcompp_call_if_gotos(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover ``IF value REL call`` whose call ends at the FCOMPP.

    A call leaving its result on the FP stack (VAL) ends at the compare; one
    leaving it in AX (POS) reaches it through ``mov [2Ch],ax; fild [2Ch]``.
    The value below it ends where the call's own code starts.
    """
    ends = {instruction.offset: instruction.end for instruction in instructions}
    for index, compare in enumerate(instructions):
        memory = _fcomp_memory(compare)
        if (
            (compare.raw != "cd 3a d9" and memory is None)
            or index < 2
            or index + 4 >= len(instructions)
        ):
            continue
        status, commit, branch, jump = instructions[index + 1 : index + 5]
        relation = _FP_TOP_RELATIONS.get(branch.kind)
        if (
            status.raw != "cd 99"
            or not _runtime(commit, 0x87)
            or relation is None
            or jump.kind != "x86.jmp"
            or branch.operands != (jump.end,)
            or not jump.operands
        ):
            continue
        call = instructions[index - 1]
        bridge: tuple[int, ...] = ()
        if call.raw == "cd 3b 06 2c 00" and instructions[index - 2].raw == "a3 2c 00":
            bridge = (instructions[index - 2].offset, call.offset)
            call = instructions[index - 3] if index >= 3 else call
        if call.kind not in {"tb.function", "tb.runtime"}:
            continue
        values = {
            fact.value[0]: fact
            for fact in facts_by_kind(facts).get("expression.value", ())
            if len(fact.value) == 1
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:1] == ("call",)
            and call.offset in fact.evidence
            and isinstance(fact.subject[0], int)
            and 0 <= call.offset - fact.subject[0] <= _CALL_REACH
        }
        if len(values) != 1:
            continue
        top = next(iter(values.values()))
        if memory is None:
            below = resolve_expression_before(top.subject[0], facts, ends)
            start = below.start if below is not None else None
        else:
            below = resolve_expression(memory, facts)
            start = top.subject[0]
        if below is None or start is None:
            continue
        yield Fact(
            "semantic.if_goto",
            (start, jump.end),
            (
                _BELOW_NEGATED[relation],
                below.value,
                top.value[0],
                jump.operands[0],
                branch.end,
            ),
            combine_evidence(
                below.evidence,
                (top.subject[0], call.offset),
                bridge,
                (compare.offset, status.offset, commit.offset, branch.offset),
                (jump.offset,),
            ),
            "anchored",
        )


_NEGATED = {"=": "<>", "<>": "=", "<": ">=", ">=": "<", "<=": ">", ">": "<="}


def _function_constant_if_goto(
    instructions: tuple[Operation, ...],
    position: int,
    facts: frozenset[Fact],
    branch: Operation | None,
    jump: Operation | None,
) -> Fact | None:
    """Read ``IF function REL constant`` as ``jcc`` over a jump to the false arm."""
    compared = function_constant_compare(instructions, position - 1, facts)
    if (
        compared is None
        or branch is None
        or jump is None
        or jump.kind != "x86.jmp"
        or branch.operands != (jump.end,)
        or not jump.operands
    ):
        return None
    relation = AX_BX_RELATIONS.get(bytes.fromhex(branch.raw)[0])
    if relation is None:
        return None
    start, value, constant = compared
    return Fact(
        "semantic.if_goto",
        (instructions[start].offset, jump.end),
        (
            _NEGATED[relation],
            value.value[0],
            ("const", constant),
            jump.operands[0],
            branch.end,
        ),
        combine_evidence(
            value.evidence,
            tuple(op.offset for op in instructions[start : position + 1]),
            (branch.offset, jump.offset),
        ),
        "anchored",
    )


"""How far before ``cmp ax,bx`` the values it compares may begin."""


def _staged_length_comparison(
    evidence: Evidence, facts: frozenset[Fact], call: Operation, compare: Operation
) -> tuple[Fact, Fact] | None:
    """Return a function's value and the value it is compared with, in BX.

    The compiler loads the right operand into AX, pushes the string, copies AX
    to BX with ``mov bx,ax`` and calls LEN, whose result lands in AX for
    ``cmp ax,bx``.  So the length is the one value ending at the compare, or
    naming the call in its evidence when it records only its start, and
    the right operand is what AX held just before the string was pushed --
    not any other LEN elsewhere in the program.
    """
    lengths = [
        fact
        for fact in facts_by_kind(facts).get("expression.value", ())
        if isinstance(fact.subject[0], int)
        and fact.subject[0] <= call.offset
        and (
            fact.subject[1] == compare.offset
            if len(fact.subject) == 2
            else call.offset in fact.evidence
        )
        and len(fact.value) == 1
        and isinstance(fact.value[0], tuple)
        and fact.value[0][:1] == ("call",)
        and (call.operands != ("numeric", 0x22) or fact.value[0][1] == "LEN")
    ]
    if len({fact.value for fact in lengths}) != 1:
        return None
    length = min(lengths, key=fact_key)
    writes = [
        fact
        for fact in facts_by_kind(facts).get("register.value", ())
        if len(fact.subject) == 2
        and fact.subject[1] == "ax"
        and isinstance(fact.subject[0], int)
        and length.subject[0] - 16 <= fact.subject[0] < length.subject[0]
        and len(fact.value) == 1
    ]
    if not writes:
        return None
    nearest = max(fact.subject[0] for fact in writes)
    at_nearest = [fact for fact in writes if fact.subject[0] == nearest]
    if len({fact.value for fact in at_nearest}) != 1:
        return None
    staged = min(at_nearest, key=fact_key)
    stage = max(
        (
            instruction
            for instruction in evidence.instructions
            if instruction.raw == "89 c3"
            and staged.subject[0] < instruction.offset < call.offset
        ),
        key=lambda instruction: instruction.offset,
        default=None,
    )
    if stage is None:
        return None
    resolved = resolve_expression(staged.value[0], facts)
    if resolved is None:
        return None
    right = Fact(
        "expression.value",
        (staged.subject[0],),
        (resolved.value,),
        combine_evidence(staged.evidence, resolved.evidence, (stage.offset,)),
        "anchored",
    )
    return length, right


@reads("expression.value", "x86.jmp")
def function_truth_if_goto_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover branches testing the truth value of a function result."""
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
        # ``NOT EOF(n)`` negates the result in AX before the same truth test.
        negate = instructions.get(call.end) if call is not None else None
        negated = negate is not None and negate.raw == "f7 d0"
        test = instructions.get(negate.end if negated else call.end) if call else None
        branch = instructions.get(test.end) if test is not None else None
        jump = instructions.get(branch.end) if branch is not None else None
        if (
            test is None
            or test.raw != "09 c0"
            or branch is None
            or branch.raw[:2] not in {"74", "75"}
            or len(branch.operands) != 1
            or jump is None
            or jump.kind != "x86.jmp"
            or len(jump.operands) != 1
            or branch.operands[0] != jump.end
        ):
            continue
        # ``je`` skips the jump when AX is false, so the jump is taken on
        # true; ``jne`` skips it when AX is true, so it is taken on false.
        jumps_on_false = negated != (branch.raw[:2] == "75")
        condition = (
            ("unary", "NOT", expression.value[0])
            if jumps_on_false
            else expression.value[0]
        )
        yield Fact(
            "semantic.if_goto_condition",
            (expression.subject[0], jump.end),
            (("truth", condition), jump.operands[0], jump.end),
            combine_evidence(
                expression.evidence,
                (test.offset, branch.offset, jump.offset)
                + ((negate.offset,) if negated and negate is not None else ()),
            ),
            "anchored",
        )


@reads(
    "flow.call",
    "flow.return",
    "flow.return_to",
    "signature",
    "tb.checked_gosub",
    "tb.checked_return",
    "tb.proc_enter",
    "tb.proc_return",
    "tb.return_to",
    "x86.call",
    "x86.call_far",
    "x86.iret",
    "x86.jmp",
    "x86.jmp_far",
    "x86.ret",
    "x86.retf",
)
def source_subroutine_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover source-level SUB and GOSUB procedure regions."""
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


@reads("signature", "tb.run", "tb.statement")
def source_run_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover compiler-generated transfers corresponding to RUN."""
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
    start = compare.subject[0] if compare.subject else None
    for address in compare.evidence:
        # A slot's evidence names every reference to it; the compare's own
        # status test follows it closely.
        if isinstance(start, int) and not start <= address < start + _COMPARED_REACH:
            continue
        last_compare = instructions.get(address)
        status = instructions.get(last_compare.end) if last_compare else None
        commit = instructions.get(status.end) if status else None
        if _runtime(status, 0x99) and _runtime(commit, 0x87):
            assert status is not None and commit is not None
            matches.append((status, commit))
    return matches[0] if len(matches) == 1 else None


@reads("x86.jmp_far")
def segment_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover ``$SEGMENT``: a far jump to the next paragraph's segment.

    The metacommand closes the code segment with ``jmp far seg:0000`` and
    the next statement starts the new segment, at most 15 bytes of padding
    after the jump.
    """
    for jump in evidence.instructions:
        if (
            jump.kind == "x86.jmp_far"
            and len(jump.operands) == 3
            and jump.operands[2] == 0
            and isinstance(jump.operands[0], int)
            and 0 <= jump.operands[0] - jump.end < 16
        ):
            yield Fact(
                "semantic.statement",
                (jump.offset, jump.end),
                ("SEGMENT", 0),
                (jump.offset,),
                "anchored",
            )


CONTROL_FACT_PASSES: tuple[NamedPass, ...] = (
    ("control-flow", control_flow_facts),
    ("segments", segment_facts),
    ("source-subroutines", source_subroutine_facts),
    ("source-run", source_run_facts),
    ("direct-integer-if-gotos", direct_integer_if_goto_facts),
    ("direct-bitwise-if-gotos", direct_bitwise_if_goto_facts),
    ("direct-system-if-gotos", direct_system_if_goto_facts),
    ("computed-array-if-gotos", computed_array_if_goto_facts),
    ("direct-expression-if-gotos", direct_expression_if_goto_facts),
    ("function-truth-if-gotos", function_truth_if_goto_facts),
    ("if-gotos", if_goto_facts),
)
