from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.compiler_ops import translate_operations
from tbd.facts import Evidence, NamedPass, fact_key, facts_by_kind, indexed_facts, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import contiguous as _contiguous
from tbd.operation_helpers import raw_bytes
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_array_element,
    resolve_expression,
    resolve_expression_before,
    resolve_slot,
    result_starts,
)


@reads(
    "constant",
    "expression.compare",
    "expression.relation_value",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "layout.array",
    "machine.store",
    "machine.update",
    "reference.array_address",
    "reference.array_store",
    "reference.array_value",
    "register.value",
    "semantic.assign",
    "semantic.dynamic_dim",
    "semantic.local",
    "semantic.sub_def",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.function",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov",
    "x86.mov_acc_mem",
    "x86.mov_imm",
    "x86.op_f7",
)
def assignment_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover assignments from compiler-generated value flows."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    targets: dict[object, Resolved | None] = {}
    values: dict[tuple[object, ...], Resolved | None] = {}
    for effect in facts:
        if effect.kind not in {"machine.store", "machine.update"}:
            continue
        assignment = _assignment(
            effect, facts, instructions, instruction_ends, targets, values
        )
        if assignment is not None:
            yield assignment
    yield from _relation_assignments(evidence, facts)
    yield from _loop_array_assignments(facts)
    yield from _computed_array_assignments(evidence.instructions, facts)
    yield from _adjacent_array_assignments(facts)
    yield from _computed_value_assignments(evidence.instructions, facts)
    yield from _string_function_assignments(evidence.instructions, facts)
    yield from _varptr_string_assignments(evidence.instructions, facts)
    yield from _direct_fp_function_assignments(evidence.instructions, facts)
    yield from _numeric_function_assignments(evidence.instructions, facts)
    yield from _integer_result_float_assignments(evidence.instructions, facts)
    yield from _expression_result_assignments(evidence.instructions, facts)
    yield from _eradr_assignments(evidence.instructions, facts)


def _eradr_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover the dedicated ERADR runtime value assignment."""
    operations = translate_operations(instructions)
    for index in range(len(operations) - 4):
        fild, convert, wait, load, store = operations[index : index + 5]
        if (
            fild.kind != "fild32"
            or fild.args != (0x6E,)
            or convert.kind != "fistp"
            or wait.kind != "fwait"
            or load.kind != "movaxmem"
            or load.args != (0x2C,)
            or store.kind != "movm_ax"
            or len(store.args) != 1
        ):
            continue
        target = resolve_slot(store.args[0], facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (fild.offset, store.end),
            (target.value, ("call", "ERADR", ())),
            combine_evidence(
                tuple(item.offset for item in operations[index : index + 5]),
                target.evidence,
            ),
            "anchored",
        )


def _expression_result_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover a memory assignment whose value is a preceding expression fact."""
    ends = {instruction.offset: instruction.end for instruction in instructions}
    expressions = [
        fact
        for fact in facts
        if fact.kind == "expression.value"
        and len(fact.subject) == 1
        and len(fact.value) == 1
        and _contains_screen_call(fact.value[0])
    ]
    for store in facts:
        if store.kind != "machine.store" or len(store.subject) != 1:
            continue
        target = resolve_slot(store.subject[0], facts)
        if target is None or not store.evidence:
            continue
        expression = next(
            (fact for fact in expressions if fact.subject[0] < store.evidence[0]),
            None,
        )
        if expression is None:
            continue
        end = ends.get(store.evidence[-1])
        if end is None:
            continue
        yield Fact(
            "semantic.assign",
            (expression.subject[0], end),
            (target.value, expression.value[0]),
            combine_evidence(expression.evidence, store.evidence, target.evidence),
            "anchored",
        )


def _call_argument_start(
    instructions: tuple[Operation, ...], call: Operation, expression: Fact
) -> int:
    """Return where the assignment's expression evaluation begins.

    The runtime call is only the tail of the expression; a branch into the
    statement lands on the instruction that loads its argument.  The earlier
    start is used only when the expression fact names a decoded instruction
    that runs into the call without a gap.
    """
    if len(expression.subject) != 1 or not isinstance(expression.subject[0], int):
        return call.offset
    start = expression.subject[0]
    if start >= call.offset:
        return call.offset
    window = [item for item in instructions if start <= item.offset <= call.offset]
    if not window or window[0].offset != start or not _contiguous(window):
        return call.offset
    return start


def _contains_screen_call(value: object) -> bool:
    """Return whether an expression tree contains a ``SCREEN`` call."""
    if not isinstance(value, tuple):
        return False
    if value[:2] == ("call", "SCREEN"):
        return True
    return any(_contains_screen_call(item) for item in value[1:])


def _numeric_function_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover assignments produced by numeric intrinsics such as ``FIX``."""
    for call in instructions:
        if call.kind != "tb.function" or call.operands != ("numeric", 0x14):
            continue
        source = next(
            (
                fact
                for fact in facts
                if fact.kind == "expression.value"
                and fact.subject == (call.offset - 5,)
                and len(fact.value) == 1
                and isinstance(fact.value[0], tuple)
                and fact.value[0][:2] == ("call", "FIX")
            ),
            None,
        )
        store = next(
            (
                instruction
                for instruction in instructions
                if instruction.offset >= call.end
                and instruction.kind == "tb.fp"
                and instruction.operands == (53, 30)
            ),
            None,
        )
        if source is None or store is None or len(store.raw.split()) < 5:
            continue
        address = int.from_bytes(
            bytes.fromhex("".join(store.raw.split())[-4:]), "little"
        )
        target = resolve_slot(address, facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (source.subject[0], store.end),
            (target.value, source.value[0]),
            combine_evidence(source.evidence, target.evidence, (store.offset,)),
            "anchored",
        )


def _integer_result_float_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover ``R = CSRLIN`` where R is a single- or double-precision variable.

    An integer result in AX reaches a real variable through the scratch word:
    ``mov [2Ch],ax; fild word [2Ch]; fstp [R]``, with ``int 35h`` storing a
    single and ``int 39h`` a double.  The value is the one expression that
    ends where that sequence begins.
    """
    by_end = {instruction.end: instruction for instruction in instructions}
    values: dict[int, list[Fact]] = {}
    for fact in facts_by_kind(facts).get("expression.value", ()):
        if len(fact.subject) == 1 and isinstance(fact.subject[0], int):
            values.setdefault(fact.subject[0], []).append(fact)
    for index in range(len(instructions) - 2):
        spill, load, store = instructions[index : index + 3]
        if (
            spill.raw != "a3 2c 00"
            or load.raw != "cd 3b 06 2c 00"
            or store.raw.split()[:1] != ["cd"]
            or store.raw.split()[1:3] not in (["35", "1e"], ["39", "1e"])
            or len(store.raw.split()) != 5
            or spill.end != load.offset
            or load.end != store.offset
        ):
            continue
        call = by_end.get(spill.offset)
        if call is None or call.kind != "tb.function":
            continue
        candidates = [
            fact
            for fact in values.get(call.offset, ())
            if len(fact.value) == 1
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:1] == ("call",)
        ]
        if len({fact.value for fact in candidates}) != 1:
            continue
        source = min(candidates, key=fact_key)
        displacement = bytes.fromhex("".join(store.raw.split()[3:]))
        address = int.from_bytes(displacement, "little")
        target = resolve_slot(address, facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (call.offset, store.end),
            (target.value, source.value[0]),
            combine_evidence(
                source.evidence,
                target.evidence,
                (call.offset, spill.offset, load.offset, store.offset),
            ),
            "anchored",
        )


def _loop_array_assignments(facts: frozenset[Fact]) -> Iterable[Fact]:
    """Pair an array store with the one value computed where it starts."""
    for reference in facts:
        if reference.kind != "reference.array_store" or len(reference.value) != 2:
            continue
        target = reference.value[0]
        if not isinstance(target, tuple) or len(target) != 3:
            continue
        value_facts = [
            fact
            for fact in facts
            if fact.kind == "expression.value"
            and fact.subject == (reference.subject[0],)
            and len(fact.value) == 1
        ]
        if len(value_facts) != 1:
            continue
        value = resolve_expression(value_facts[0].value[0], facts)
        if value is None:
            continue
        # A string element's value is on the string stack; a number computed
        # where its store starts is the index.
        if reference.value[1] == "string" and _numeric(value.value):
            continue
        yield Fact(
            "semantic.assign",
            reference.subject,
            (target, value.value),
            combine_evidence(reference.evidence, value.evidence),
            "anchored",
        )


def _numeric(value: object) -> bool:
    """Whether a value is a number: a numeric constant, variable or call."""
    if not isinstance(value, tuple) or not value:
        return False
    if value[0] == "const":
        return not isinstance(value[1], str)
    if value[0] in {"slot", "proc-local", "proc-param", "var", "memory"}:
        return value[-1] in {"integer", "long", "float", "double"}
    if value[0] == "call":
        return isinstance(value[1], str) and not value[1].endswith("$")
    return False


def _direct_fp_function_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:

    def contains_fre(value: object) -> bool:
        if not isinstance(value, tuple):
            return False
        if value[:2] == ("call", "FRE"):
            return True
        return any(contains_fre(item) for item in value[2:])

    by_offset = {instruction.offset: instruction for instruction in instructions}
    for expression in facts:
        if (
            expression.kind != "expression.value"
            or len(expression.value) != 1
            or not isinstance(expression.value[0], tuple)
            or not (
                (expression.value[0][0] == "binary" and expression.value[0][1] == "^")
                or (
                    expression.value[0][0] == "binary"
                    and contains_fre(expression.value[0])
                )
                or (
                    expression.value[0][0] == "call"
                    and expression.value[0][1] in {"LOC", "FRE", "POINT", "PMAP"}
                )
            )
            or not expression.evidence
        ):
            continue
        if (
            expression.value[0][0] == "call"
            and expression.value[0][1] == "FRE"
            and any(
                other.kind == "expression.value"
                and len(other.value) == 1
                and isinstance(other.value[0], tuple)
                and other.value[0][0] == "binary"
                and contains_fre(other.value[0])
                and expression.subject[0] == other.subject[0]
                for other in facts
            )
        ):
            continue
        call = by_offset.get(expression.evidence[-1])
        if call is None:
            call = next(
                (
                    instruction
                    for instruction in instructions
                    if instruction.offset in expression.evidence
                    and instruction.kind == "tb.function"
                ),
                None,
            )
        if (
            expression.value[0][0] == "call"
            and expression.value[0][1] == "FRE"
            and any(
                instruction.kind == "tb.fp"
                and instruction.raw == "cd 3a c1"
                and call is not None
                and call.end <= instruction.offset <= call.end + 3
                for instruction in instructions
            )
        ):
            continue
        store = next(
            (
                instruction
                for instruction in instructions
                if call is not None
                and instruction.kind == "tb.fp"
                and call.end <= instruction.offset <= call.end + 3
                and bytes.fromhex(instruction.raw).startswith(b"\xcd\x35\x1e")
            ),
            None,
        )
        raw = bytes.fromhex(store.raw) if store is not None else b""
        if store is None or len(raw) != 5 or raw[:3] != b"\xcd\x35\x1e":
            continue
        address = struct.unpack_from("<H", raw, 3)[0]
        target = resolve_slot(address, facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (expression.subject[0], store.end),
            (target.value, expression.value[0]),
            combine_evidence(expression.evidence, target.evidence, (store.offset,)),
            "anchored",
        )


_RELATIONS = {"=", "<>", "<", "<=", ">", ">="}


def _relation_assignments(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """``R% = (W% = 3)``: a relation materialized in AX, then stored."""
    by_offset = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for relation in facts_by_kind(facts).get("expression.relation_value", ()):
        if (
            len(relation.subject) != 2
            or len(relation.value) != 3
            or relation.value[0] not in _RELATIONS
        ):
            continue
        store = by_offset.get(relation.subject[1])
        raw = bytes.fromhex(store.raw) if store is not None else b""
        if len(raw) == 4 and raw[:2] == b"\x89\x06":
            address = int.from_bytes(raw[2:], "little")
        elif len(raw) == 3 and raw[0] == 0xA3:
            address = int.from_bytes(raw[1:], "little")
        else:
            continue
        target = resolve_slot(address, facts)
        if target is None or store is None:
            continue
        yield Fact(
            "semantic.assign",
            (relation.subject[0], store.end),
            (target.value, ("binary", *relation.value)),
            combine_evidence(relation.evidence, target.evidence, (store.offset,)),
            "anchored",
        )


def _varptr_string_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover VARPTR$ assignments emitted through the string runtime."""
    arrays = indexed_facts(
        (
            fact
            for fact in facts
            if fact.kind == "layout.array" and len(fact.value) >= 7
        ),
        lambda fact: fact.value[4],
        lambda fact: fact.value,
    )
    for index, runtime in enumerate(instructions):
        if runtime.kind != "tb.runtime" or runtime.operands != (0xCD,):
            continue
        store_setup = instructions[index + 1] if index + 1 < len(instructions) else None
        store = instructions[index + 2] if index + 2 < len(instructions) else None
        if (
            store_setup is None
            or store_setup.kind != "x86.mov_imm"
            or store_setup.operands[:1] != ("si",)
            or store is None
            or store.kind != "tb.runtime"
            or store.operands != (0xA0,)
        ):
            continue
        target = resolve_slot(store_setup.operands[1], facts)
        if target is None:
            continue
        argument: object | None = None
        for prior in reversed(instructions[max(0, index - 8) : index]):
            if prior.kind == "x86.mov_imm" and prior.operands[:1] == ("si",):
                array = arrays.get(prior.operands[1])
                if array is not None:
                    argument = ("array", array[1], (("const", 0),))
                    break
                continue
            raw = bytes.fromhex(prior.raw)
            if raw[:2] == b"\xc7\x06" and len(raw) >= 6:
                source = resolve_slot(struct.unpack_from("<H", raw, 2)[0], facts)
                if source is not None:
                    argument = source.value
                    break
                continue
        if argument is None:
            continue
        yield Fact(
            "semantic.assign",
            (runtime.offset, store.end),
            (target.value, ("call", "VARPTR$", (argument,))),
            (runtime.offset, store_setup.offset, store.offset),
            "anchored",
        )


_CALL_REACH = 64


def _own_call(expression: Fact, call: Operation) -> bool:
    """Whether ``call`` belongs to the value's own code, not to another use.

    A value's evidence also names every reference to the slots it reads, so
    a call is only the value's when it follows the value's start closely.
    """
    start = expression.subject[0]
    return isinstance(start, int) and start <= call.offset < start + _CALL_REACH


def _string_function_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover string-returning assignments, including ``INPUT$`` calls."""

    by_offset = {instruction.offset: instruction for instruction in instructions}
    for index, function in enumerate(instructions):
        if function.kind != "tb.runtime" or function.operands != (0xB3,):
            continue
        load = instructions[index - 1] if index else None
        setup = instructions[index + 1] if index + 1 < len(instructions) else None
        store = instructions[index + 2] if index + 2 < len(instructions) else None
        if not (
            load is not None
            and load.kind == "x86.mov_imm"
            and load.operands[:1] == ("ax",)
            and setup is not None
            and setup.kind == "x86.mov_imm"
            and setup.operands[:1] == ("si",)
            and store is not None
            and store.kind == "tb.runtime"
            and store.operands == (0xA0,)
        ):
            continue
        target = resolve_slot(setup.operands[1], facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (load.offset, store.end),
            (target.value, ("call", "CHR$", (("const", load.operands[1]),))),
            combine_evidence(
                target.evidence,
                (load.offset, function.offset, setup.offset, store.offset),
            ),
            "anchored",
        )
    for index, runtime in enumerate(instructions):
        if runtime.kind != "tb.runtime" or runtime.operands != (0xB5,):
            continue
        load = instructions[index - 1] if index else None
        setup = instructions[index + 1] if index + 1 < len(instructions) else None
        store = instructions[index + 2] if index + 2 < len(instructions) else None
        if (
            load is None
            or load.kind != "x86.mov_imm"
            or load.operands[:1] != ("ax",)
            or setup is None
            or setup.kind != "x86.mov_imm"
            or setup.operands[:1] != ("si",)
            or store is None
            or store.kind != "tb.runtime"
            or store.operands != (0xA0,)
        ):
            continue
        target = resolve_slot(setup.operands[1], facts)
        if target is not None:
            yield Fact(
                "semantic.assign",
                (load.offset, store.end),
                (target.value, ("call", "MKI$", (("const", load.operands[1]),))),
                combine_evidence(
                    target.evidence,
                    (load.offset, runtime.offset, setup.offset, store.offset),
                ),
                "anchored",
            )
    for index, runtime in enumerate(instructions):
        if runtime.kind != "tb.runtime" or runtime.operands != (0xB3,):
            continue
        if index + 5 >= len(instructions):
            continue
        setup, read, concat, target_setup, store = instructions[index + 1 : index + 6]
        if not (
            setup.kind == "x86.mov_imm"
            and setup.operands[:1] == ("si",)
            and read.kind == "tb.runtime"
            and read.operands == (0x9C,)
            and concat.kind == "tb.runtime"
            and concat.operands == (0x9B,)
            and target_setup.kind == "x86.mov_imm"
            and target_setup.operands[:1] == ("si",)
            and store.kind == "tb.runtime"
            and store.operands == (0xA0,)
        ):
            continue
        string_value = resolve_expression(
            ("memory", setup.operands[1], "string"), facts
        )
        target = resolve_slot(target_setup.operands[1], facts)
        if string_value is None or target is None:
            continue
        yield Fact(
            "semantic.assign",
            (runtime.offset, store.end),
            (
                target.value,
                ("binary", "+", ("call", "CHR$", (("const", 0),)), string_value.value),
            ),
            combine_evidence(
                target.evidence,
                string_value.evidence,
                (runtime.offset, setup.offset, concat.offset, store.offset),
            ),
            "anchored",
        )
    # ``A$ = CHR$(B%)``: ``mov ax,[B%]; CHR$; mov si,A$; store``.
    for index, load in enumerate(instructions):
        raw = raw_bytes(load.raw)
        if len(raw) != 4 or raw[:2] != b"\x8b\x06":
            continue
        runtime_function = (
            instructions[index + 1] if index + 1 < len(instructions) else None
        )
        setup = instructions[index + 2] if index + 2 < len(instructions) else None
        store = instructions[index + 3] if index + 3 < len(instructions) else None
        if (
            runtime_function is None
            or runtime_function.kind != "tb.runtime"
            or runtime_function.operands != (0xB3,)
            or setup is None
            or setup.kind != "x86.mov_imm"
            or setup.operands[:1] != ("si",)
            or len(setup.operands) != 2
            or store is None
            or store.kind != "tb.runtime"
            or store.operands != (0xA0,)
        ):
            continue
        target = resolve_slot(setup.operands[1], facts)
        argument = resolve_expression(
            ("memory", int.from_bytes(raw[2:], "little"), "integer"), facts
        )
        if target is None or argument is None:
            continue
        yield Fact(
            "semantic.assign",
            (load.offset, store.end),
            (target.value, ("call", "CHR$", (argument.value,))),
            combine_evidence(
                target.evidence,
                argument.evidence,
                (load.offset, runtime_function.offset, setup.offset, store.offset),
            ),
            "anchored",
        )
    for index, function in enumerate(instructions):
        if function.kind != "tb.function" or function.operands != ("string", 36):
            continue
        loads = [
            node
            for node in instructions[max(0, index - 6) : index]
            if node.kind == "x86.mov_imm" and node.operands[:1] == ("ax",)
        ]
        setup = instructions[index + 1] if index + 1 < len(instructions) else None
        store = instructions[index + 2] if index + 2 < len(instructions) else None
        if not loads or setup is None or store is None:
            continue
        if setup.kind != "x86.mov_imm" or setup.operands[:1] != ("si",):
            continue
        if store.kind != "tb.runtime" or store.operands != (0xA0,):
            continue
        string_setup = next(
            (
                node
                for node in reversed(instructions[max(0, index - 4) : index])
                if node.kind == "x86.mov_imm" and node.operands[:1] == ("si",)
            ),
            None,
        )
        string_value = (
            None
            if string_setup is None
            else resolve_expression(
                ("memory", string_setup.operands[1], "string"), facts
            )
        )
        if string_value is None:
            continue
        target = resolve_slot(setup.operands[1], facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (function.offset, store.end),
            (
                target.value,
                (
                    "call",
                    "STRING$",
                    (("const", loads[-1].operands[1]), string_value.value),
                ),
            ),
            combine_evidence(
                target.evidence,
                string_value.evidence,
                (function.offset, setup.offset, store.offset),
            ),
            "anchored",
        )
    # INPUT$ is represented by a string runtime function rather than an
    # expression.value fact.  Its numeric arguments are the immediately
    # preceding AX loads, followed by the usual SI/result store pair.
    for index, instruction in enumerate(instructions):
        if instruction.kind != "tb.function" or instruction.operands not in {
            ("string", 0x10),
            ("string", 0x12),
        }:
            continue
        needed = 1 if instruction.operands[1] == 0x10 else 2
        loads = [
            node
            for node in instructions[max(0, index - 5) : index]
            if node.kind == "x86.mov_imm" and node.operands[:1] == ("ax",)
        ]
        if len(loads) < needed:
            continue
        setup = by_offset.get(instruction.end)
        store = by_offset.get(setup.end) if setup is not None else None
        if (
            setup is None
            or setup.kind != "x86.mov_imm"
            or setup.operands[:1] != ("si",)
            or store is None
            or store.kind != "tb.runtime"
            or store.operands != (0xA0,)
        ):
            continue
        target = resolve_slot(setup.operands[1], facts)
        if target is None:
            continue
        args = tuple(("const", int(node.operands[1])) for node in loads[-needed:])
        # A branch into the statement lands on the first argument load, so the
        # statement starts there when the loads run straight into the call.
        first = loads[-needed]
        run = instructions[instructions.index(first) : index + 1]
        start = first.offset if _contiguous(run) else instruction.offset
        yield Fact(
            "semantic.assign",
            (start, store.end),
            (target.value, ("call", "INPUT$", args)),
            combine_evidence(
                target.evidence, (instruction.offset, setup.offset, store.offset)
            ),
            "anchored",
        )
    for expression in facts:
        if (
            expression.kind != "expression.value"
            or not (
                isinstance(expression.value, tuple)
                and len(expression.value) == 1
                and isinstance(expression.value[0], tuple)
                and expression.value[0][:1] == ("call",)
            )
            or not expression.evidence
        ):
            continue
        call_name = expression.value[0][1]
        if not (isinstance(call_name, str) and call_name.endswith("$")):
            continue
        for position, instruction in enumerate(instructions):
            if (
                instruction.offset not in expression.evidence
                or instruction.kind not in {"tb.function", "tb.runtime"}
                or not _own_call(expression, instruction)
            ):
                continue
            setup = (
                instructions[position + 1] if position + 1 < len(instructions) else None
            )
            store = (
                instructions[position + 2] if position + 2 < len(instructions) else None
            )
            if (
                setup is None
                or setup.kind != "x86.mov_imm"
                or setup.operands[:1] != ("si",)
                or store is None
                or store.kind != "tb.runtime"
                or store.operands != (0xA0,)
            ):
                continue
            target = resolve_slot(setup.operands[1], facts)
            if target is None:
                continue
            start = _call_argument_start(instructions, instruction, expression)
            yield Fact(
                "semantic.assign",
                (start, store.end),
                (target.value, expression.value[0]),
                combine_evidence(
                    expression.evidence,
                    target.evidence,
                    (instruction.offset, setup.offset, store.offset),
                ),
                "anchored",
            )
            break
        source = by_offset.get(expression.evidence[-1])
        if source is None:
            source = next(
                (
                    instruction
                    for instruction in instructions
                    if instruction.offset in expression.evidence
                    and instruction.kind == "tb.runtime"
                    and instruction.operands == (0xB0,)
                ),
                None,
            )
        if (
            source is not None
            and source.kind == "tb.runtime"
            and source.operands == (0xB0,)
            and expression.subject[0] < source.offset - 10
        ):
            continue
        if source is None:
            source = next(
                (
                    instruction
                    for instruction in instructions
                    if instruction.offset in expression.evidence
                    and (
                        instruction.kind == "tb.function"
                        or (
                            instruction.kind == "tb.runtime"
                            and instruction.operands == (0xB2,)
                        )
                    )
                ),
                None,
            )
        if source is None or not _own_call(expression, source):
            continue
        setup = by_offset.get(source.end)
        store = by_offset.get(setup.end) if setup is not None else None
        if (
            setup is None
            or setup.kind != "x86.mov_imm"
            or setup.operands[:1] != ("si",)
            or len(setup.operands) != 2
            or store is None
            or store.kind != "tb.runtime"
            or store.operands != (0xA0,)
        ):
            continue
        target = resolve_slot(setup.operands[1], facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (_call_argument_start(instructions, source, expression), store.end),
            (target.value, expression.value[0]),
            combine_evidence(
                expression.evidence,
                target.evidence,
                (setup.offset, store.offset),
            ),
            "anchored",
        )


def _computed_value_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    operations = {
        operation.offset: operation for operation in translate_operations(instructions)
    }
    stores = {
        "fistp": "integer",
        "fistp32": "long",
        "fstp": "float",
        "fstp64": "double",
    }
    for value in facts:
        if (
            value.kind != "reference.array_value"
            or len(value.subject) != 2
            or len(value.value) != 2
        ):
            continue
        terminal = operations.get(value.subject[1])
        target_kind = stores.get(terminal.kind) if terminal is not None else None
        if terminal is None or target_kind != value.value[1] or len(terminal.args) != 1:
            continue
        target = resolve_slot(terminal.args[0], facts) or resolve_array_element(
            terminal.args[0], facts
        )
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (value.subject[0], terminal.end),
            (target.value, value.value[0]),
            combine_evidence(value.evidence, target.evidence, (terminal.offset,)),
            "anchored",
        )


def _computed_array_assignments(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions
    }
    expressions: dict[int, list[Fact]] = {}
    for fact in facts:
        if fact.kind not in {"expression.value", "register.value"} or not fact.evidence:
            continue
        if fact.kind == "register.value" and fact.subject[1:] != ("ax",):
            continue
        end = instruction_ends.get(fact.evidence[-1])
        if end is not None:
            expressions.setdefault(end, []).append(fact)
    for target in facts:
        if (
            target.kind != "reference.array_store"
            or len(target.subject) != 2
            or len(target.value) != 2
        ):
            continue
        source = None
        source_start = None
        # Candidates that agree on the value are one value.
        resolved = {
            (value.value, expression.evidence[0]): value
            for expression in expressions.get(target.subject[0], ())
            if (value := resolve_expression(expression.value[0], facts)) is not None
        }
        if len({value for value, _start in resolved}) == 1:
            (_value, source_start), source = min(resolved.items())
        load = by_end.get(target.subject[0])
        if source is None and target.value[1] == "integer" and load is not None:
            # ``mov ax,[slot]`` just before the address computation.
            raw = raw_bytes(load.raw)
            if len(raw) == 4 and raw[:2] == b"\x8b\x06":
                address = int.from_bytes(raw[2:], "little")
                source = resolve_expression(("memory", address, "integer"), facts)
                source_start = load.offset
        if source is None and target.value[1] == "string":
            read = by_end.get(target.subject[0])
            setup = by_end.get(read.offset) if read is not None else None
            if (
                setup is not None
                and read is not None
                and setup.kind == "x86.mov_imm"
                and setup.operands[:1] == ("si",)
                and len(setup.operands) == 2
                and read.kind == "tb.runtime"
                and read.operands == (0x9C,)
            ):
                source = resolve_expression(
                    ("memory", setup.operands[1], "string"), facts
                )
                source_start = setup.offset
        if source is None or not isinstance(source_start, int):
            continue
        yield Fact(
            "semantic.assign",
            (source_start, target.subject[1]),
            (target.value[0], source.value),
            combine_evidence(target.evidence, source.evidence, (source_start,)),
            "anchored",
        )


def _adjacent_array_assignments(facts: frozenset[Fact]) -> Iterable[Fact]:
    """Turn a value that ends where an element store begins into its value.

    An element read works for any element kind; for a string element, the
    operand the string stack holds (a function result, a concatenation)
    works as well.
    """
    reads = indexed_facts(
        (
            fact
            for fact in facts
            if fact.kind == "reference.array_value"
            and len(fact.subject) == 2
            and len(fact.value) == 2
        ),
        lambda fact: fact.subject[1],
    )
    operands = indexed_facts(
        (
            fact
            for fact in facts_by_kind(facts).get("expression.string_operand", ())
            if len(fact.subject) == 2 and len(fact.value) == 1
        ),
        lambda fact: fact.subject[1],
    )
    for target in facts:
        if target.kind != "reference.array_store" or len(target.subject) != 2:
            continue
        source = reads.get(target.subject[0])
        if source is None and target.value[1:] == ("string",):
            source = operands.get(target.subject[0])
        if source is None:
            continue
        yield Fact(
            "semantic.assign",
            (source.subject[0], target.subject[1]),
            (target.value[0], source.value[0]),
            combine_evidence(target.evidence, source.evidence),
            "anchored",
        )


def _assignment(
    effect: Fact,
    facts: frozenset[Fact],
    instructions: dict[int, Operation],
    instruction_ends: dict[int, int],
    targets: dict[object, Resolved | None],
    values: dict[tuple[object, ...], Resolved | None],
) -> Fact | None:
    address = effect.subject[0] if effect.subject else None
    if address not in targets:
        targets[address] = resolve_slot(address, facts) or resolve_array_element(
            address, facts
        )
    target = targets[address]
    if target is None:
        return None
    value_key = effect.kind, effect.value, target.value, effect.evidence
    if value_key not in values:
        direct = (
            resolve_expression_before(
                effect.evidence[-1],
                facts,
                instruction_ends,
            )
            if effect.kind == "machine.store"
            and effect.value == (("register", "ax"),)
            and effect.evidence
            else None
        )
        values[value_key] = direct or _effect_value(effect, target.value, facts)
    value = values[value_key]
    if value is None:
        return None
    support = combine_evidence(effect.evidence, target.evidence, value.evidence)
    end = _effect_end(effect, instructions)
    if end is None:
        return None
    start = _stored_operand_start(effect, facts, value.value)
    if start is None and _spans_to(facts, value.start, effect.evidence[-1]):
        # An element read or a spanned value runs up to the store.
        start = value.start
    if start is None and effect.kind == "machine.store" and effect.value:
        # A stored value starts where a call result it holds does.
        calls = result_starts(effect.value[0], facts)
        if calls and min(calls) < effect.evidence[0]:
            start = min(calls)
    last = instructions.get(effect.evidence[-1]) if effect.evidence else None
    if start is None and last is not None and last.kind == "tb.runtime":
        # A string store's evidence names every reference to the slots its
        # value reads; until the operand it stores is known, its first
        # evidence is no start, and a guess would persist across rounds.
        return None
    return Fact(
        "semantic.assign",
        (effect.evidence[0] if start is None else start, end),
        (target.value, value.value),
        support,
        "anchored",
    )


def _spans_to(facts: frozenset[Fact], start: object, end: int) -> bool:
    """Whether a value fact covers exactly ``start`` up to ``end``."""
    by_kind = facts_by_kind(facts)
    return isinstance(start, int) and any(
        fact.subject == (start, end)
        for kind in ("reference.array_value", "expression.value")
        for fact in by_kind.get(kind, ())
    )


def _stored_operand_start(
    effect: Fact, facts: frozenset[Fact], value: object = None
) -> int | None:
    """Return where the operand a string store writes was built, if unique.

    A store's evidence also names instructions elsewhere -- the statement that
    assigned an index slot, for one -- so its earliest address is not where
    this statement starts.  The value is the operand that ends at the store's
    ``mov si`` setup, and the statement starts where that operand does.
    """
    if effect.kind != "machine.store" or len(effect.evidence) < 2:
        return None
    setup = effect.evidence[-2]
    starts = {
        fact.subject[0]
        for kind in ("expression.string_operand", "reference.array_value")
        for fact in facts_by_kind(facts).get(kind, ())
        if len(fact.subject) == 2
        and fact.subject[1] == setup
        and isinstance(fact.subject[0], int)
        # The store names memory where the operand names the slot.
        and fact.value[:1] in (effect.value[:1], (value,))
    }
    return next(iter(starts)) if len(starts) == 1 else None


def _effect_end(effect: Fact, instructions: dict[int, Operation]) -> int | None:
    last = instructions.get(effect.evidence[-1]) if effect.evidence else None
    return last.end if last is not None else None


def _effect_value(
    effect: Fact, target: object, facts: frozenset[Fact]
) -> Resolved | None:
    if effect.kind == "machine.store":
        if effect.value == (("register", "ax"),) and effect.evidence:
            matches = [
                fact
                for fact in facts
                if fact.kind == "reference.array_value"
                and fact.subject[1:] == (effect.evidence[-1],)
            ]
            if len(matches) == 1:
                return Resolved(matches[0].value[0], matches[0].evidence)
        return resolve_expression(effect.value[0], facts)
    operator, operand = effect.value
    right = resolve_expression(operand, facts)
    if right is None:
        return None
    return Resolved(("binary", operator, target, right.value), right.evidence)


ASSIGNMENT_FACT_PASSES: tuple[NamedPass, ...] = (("assignments", assignment_facts),)
