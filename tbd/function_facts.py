"""Intrinsic-call expression facts over complete compiler templates."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence, resolve_expression_before
from tbd.slots import VAR_BASE


def function_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover the complete zero-argument INKEY$/LEN comparison scaffold."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for block in evidence.blocks:
        nodes = tuple(
            instructions[offset]
            for offset in block.instruction_offsets
            if offset in instructions
        )
        for index in range(len(nodes) - 4):
            window = nodes[index : index + 5]
            if not _len_inkey_zero(window):
                continue
            zero, string_call, shuttle, numeric_call, compare = window
            value = ("call", "LEN", (("call", "INKEY$", ()),))
            support = tuple(node.offset for node in window)
            yield Fact(
                "expression.value",
                (zero.offset,),
                (value,),
                support[:-1],
                "signature",
            )
            yield Fact(
                "expression.compare",
                (zero.offset,),
                (value, ("const", 0)),
                support,
                "signature",
            )


def _len_inkey_zero(nodes: tuple[Operation, ...]) -> bool:
    if len(nodes) != 5:
        return False
    zero, string_call, shuttle, numeric_call, compare = nodes
    return (
        zero.raw == "31 c0"
        and string_call.kind == "tb.function"
        and string_call.operands == ("string", 0x0E)
        and shuttle.raw in {"89 c3", "8b d8"}
        and numeric_call.kind == "tb.function"
        and numeric_call.operands == ("numeric", 0x22)
        and compare.raw == "3b c3"
        and all(left.end == right.offset for left, right in zip(nodes, nodes[1:]))
    )


def system_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Name the compiler's direct ERR and ERL cells as nullary expressions."""

    cells = {0x74: "ERR", 0x72: "ERL"}
    for address, name in cells.items():
        support = tuple(
            instruction.offset
            for instruction in evidence.instructions
            if instruction.raw
            in {
                f"8b 06 {address:02x} 00",
                f"3b 06 {address:02x} 00",
            }
        )
        if support:
            yield Fact(
                "expression.system",
                (address,),
                (("call", name, ()),),
                support,
                "signature",
            )


def string_function_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Name the complete zero-argument INKEY$ stack producer."""

    for instruction in evidence.instructions:
        if (
            instruction.kind == "tb.function"
            and instruction.operands == ("string", 0x0E)
        ):
            yield Fact(
                "expression.value",
                (instruction.offset,),
                (("call", "INKEY$", ()),),
                (instruction.offset,),
                "signature",
            )


def ax_function_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve calibrated AX-argument/AX-result intrinsic calls."""

    for load, call in zip(evidence.instructions, evidence.instructions[1:]):
        if load.end != call.offset or call.kind != "tb.function":
            continue
        immediate_functions = {0x10: "EOF", 0x24: "LOC", 0x3C: "REG"}
        zero_functions = {
            0x28: "LPOS",
            0x2E: "PEN",
            0x48: "STICK",
            0x4A: "STRIG",
        }
        sub = (
            call.operands[1]
            if len(call.operands) == 2
            and call.operands[0] == "numeric"
            and isinstance(call.operands[1], int)
            else None
        )
        name = None
        argument = None
        if (
            sub in immediate_functions
            and load.kind == "x86.mov_imm"
            and load.operands[:1] == ("ax",)
            and len(load.operands) == 2
            and isinstance(load.operands[1], int)
        ):
            name, argument = immediate_functions[sub], load.operands[1]
        elif sub in zero_functions and load.raw == "31 c0":
            name, argument = zero_functions[sub], 0
        if name is None or argument is None:
            continue
        yield Fact(
            "expression.value",
            (load.offset,),
            (("call", name, (("const", argument),)),),
            (load.offset, call.offset),
            "signature",
        )


def zero_ax_function_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve calibrated no-setup AX-result intrinsic calls."""

    functions = {
        0x0A: ("CSRLIN", ()),
        0x1A: ("INSTAT", ()),
        0x30: ("PLAY", (("const", 0),)),
        0x38: ("POS", (("const", 0),)),
    }
    for instruction in evidence.instructions:
        if (
            instruction.kind != "tb.function"
            or len(instruction.operands) != 2
            or instruction.operands[0] != "numeric"
        ):
            continue
        function = functions.get(instruction.operands[1])
        if function is None:
            continue
        name, arguments = function
        yield Fact(
            "expression.value",
            (instruction.offset,),
            (("call", name, arguments),),
            (instruction.offset,),
            "signature",
        )


def screen_function_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve the exact two-immediate SCREEN(x, y) register scaffold."""

    for index in range(len(evidence.instructions) - 3):
        first, preserve, second, call = evidence.instructions[index : index + 4]
        if (
            first.kind != "x86.mov_imm"
            or first.operands[:1] != ("ax",)
            or len(first.operands) != 2
            or preserve.raw not in {"89 c3", "8b d8"}
            or second.kind != "x86.mov_imm"
            or second.operands[:1] != ("ax",)
            or len(second.operands) != 2
            or call.kind != "tb.function"
            or call.operands != ("numeric", 0x42)
            or any(
                left.end != right.offset
                for left, right in zip(
                    (first, preserve, second),
                    (preserve, second, call),
                )
            )
        ):
            continue
        yield Fact(
            "expression.value",
            (first.offset,),
            (
                (
                    "call",
                    "SCREEN",
                    (
                        ("const", first.operands[1]),
                        ("const", second.operands[1]),
                    ),
                ),
            ),
            (first.offset, preserve.offset, second.offset, call.offset),
            "signature",
        )


def fp_argument_ax_function_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Compose a uniquely pending FP argument with the AX-result PEEK call."""

    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    functions = {0x2C: "PEEK", 0x46: "SGN"}
    for call in evidence.instructions:
        if (
            call.kind != "tb.function"
            or len(call.operands) != 2
            or call.operands[0] != "numeric"
            or call.operands[1] not in functions
        ):
            continue
        argument = resolve_expression_before(call.offset, facts, instruction_ends)
        if argument is None:
            continue
        start = argument.start if argument.start is not None else argument.evidence[0]
        yield Fact(
            "expression.value",
            (start, call.end),
            (("call", functions[call.operands[1]], (argument.value,)),),
            combine_evidence(argument.evidence, (call.offset,)),
            "anchored",
        )


def transient_constant_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve a uniquely written compiler scratch cell to its literal value."""

    addresses = {
        fact.subject[0]
        for fact in facts
        if fact.kind == "machine.store"
        and fact.subject
        and isinstance(fact.subject[0], int)
        and fact.subject[0] < VAR_BASE
    }
    for address in addresses:
        stores = [
            fact
            for fact in facts
            if fact.kind == "machine.store" and fact.subject == (address,)
        ]
        reads = [
            fact
            for fact in facts
            if fact.kind == "memory.read" and fact.subject == (address,)
        ]
        if (
            len(stores) != 1
            or not reads
            or len(stores[0].value) != 1
            or not stores[0].evidence
            or not any(
                read.evidence and stores[0].evidence[-1] < read.evidence[0]
                for read in reads
            )
        ):
            continue
        value = stores[0].value[0]
        value_evidence: tuple[int, ...] = ()
        if (
            isinstance(value, tuple)
            and value == ("register", "ax")
        ):
            resolved = resolve_expression_before(
                stores[0].evidence[-1],
                facts,
                {
                    instruction.offset: instruction.end
                    for instruction in evidence.instructions
                },
            )
            if resolved is None:
                continue
            value = resolved.value
            value_evidence = resolved.evidence
        elif not (
            isinstance(value, tuple) and value[:1] == ("const",)
        ):
            continue
        yield Fact(
            "constant",
            ("memory", address),
            value,
            combine_evidence(
                stores[0].evidence,
                value_evidence,
                *(read.evidence for read in reads),
            ),
            "anchored",
        )


FUNCTION_FACT_PASSES: tuple[NamedPass, ...] = (
    ("function-expressions", function_expression_facts),
    ("system-expressions", system_expression_facts),
    ("string-function-expressions", string_function_expression_facts),
    ("ax-function-expressions", ax_function_expression_facts),
    ("zero-ax-function-expressions", zero_ax_function_expression_facts),
    ("screen-function-expressions", screen_function_expression_facts),
    ("fp-argument-ax-functions", fp_argument_ax_function_facts),
    ("transient-constants", transient_constant_facts),
)
