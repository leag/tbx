from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass, facts_by_kind, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import fp_constant as _fp_constant
from tbd.profile import FP_ARITHMETIC_TYPES, FP_TRANSFER_TYPES
from tbd.semantic import has_frame_word, orient_memory_fold, resolve_expression_before
from tbd.slots import VAR_BASE


@dataclass(frozen=True)
class _Value:
    expression: object
    evidence: tuple[int, ...]


@reads(
    "machine.store",
    "machine.update",
    "signature",
    "tb.bounds",
    "tb.fp",
    "tb.fp_function",
    "tb.function",
    "tb.proc_enter",
    "tb.proc_return",
    "tb.runtime",
    "tb.statement",
    "x86.mov_acc_mem",
    "x86.mov_imm",
    "x86.wait",
)
def symbolic_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover symbolic values from register and stack effects."""

    instructions = {item.offset: item for item in evidence.instructions}
    frames = _frames(evidence.instructions)
    for block in evidence.blocks:
        block_nodes = tuple(
            instructions[offset]
            for offset in block.instruction_offsets
            if offset in instructions
        )
        frame = next(
            (entry for entry, end in frames if entry <= block.start < end), None
        )
        yield from _interpret_block(block_nodes, frame)


def _frames(instructions: tuple[Operation, ...]) -> tuple[tuple[int, int], ...]:
    """Each procedure's entry and the end of the return that closes it."""
    frames = []
    entry = None
    for instruction in instructions:
        if instruction.kind == "tb.proc_enter":
            entry = instruction.offset
        elif instruction.kind == "tb.proc_return" and entry is not None:
            frames.append((entry, instruction.end))
            entry = None
    return tuple(frames)


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "machine.store",
    "reference.array_value",
    "register.value",
    "signature",
    "slot",
    "tb.function",
    "tb.runtime",
    "x86.mov_imm",
)
def string_store_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover string stores and their symbolic destinations."""

    instructions = {item.offset: item for item in evidence.instructions}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    for block in evidence.blocks:
        block_nodes = tuple(
            instructions[offset]
            for offset in block.instruction_offsets
            if offset in instructions
        )
        yield from _string_stores(block_nodes, facts, instruction_ends)


def _string_stores(
    instructions: tuple[Operation, ...],
    facts: frozenset[Fact],
    instruction_ends: dict[int, int],
) -> Iterable[Fact]:
    stack: list[_Value] = []
    index = 0
    while index < len(instructions):
        instruction = instructions[index]
        if instruction.kind == "tb.function" and instruction.operands == (
            "string",
            0x20,
        ):
            argument = resolve_expression_before(
                instruction.offset,
                facts,
                instruction_ends,
            )
            if (
                argument is not None
                and isinstance(argument.value, tuple)
                and argument.value[:1] == ("fn-call",)
            ):
                start = (
                    argument.start
                    if argument.start is not None
                    else argument.evidence[0]
                )
                stack.append(
                    _Value(
                        ("call", "STR$", (argument.value,)),
                        _evidence(
                            (start,),
                            argument.evidence,
                            (instruction.offset,),
                        ),
                    )
                )
            else:
                stack.clear()
            index += 1
            continue
        element = _string_element_operand(instructions, index, facts)
        if element is not None:
            value, resume = element
            stack.append(value)
            index = resume
            continue
        pair = instructions[index : index + 2]
        access = _direct_string_access(pair)
        if access is None:
            if _is_runtime(instructions[index], 0x9B) and len(stack) >= 2:
                right = stack.pop()
                left = stack.pop()
                evidence = _evidence(
                    left.evidence, right.evidence, (instructions[index].offset,)
                )
                stack.append(
                    _Value(
                        ("binary", "+", left.expression, right.expression),
                        evidence,
                    )
                )
                index += 1
                continue
            stack.clear()
            index += 1
            continue
        action, address = access
        setup, runtime = pair
        if action == "read":
            stack.append(
                _Value(
                    ("memory", address, "string"),
                    (setup.offset, runtime.offset),
                )
            )
        elif stack:
            value = stack.pop()
            evidence = _evidence(value.evidence, (setup.offset, runtime.offset))
            yield _effect(
                "machine.store", address, (value.expression,), evidence, "signature"
            )
        index += 2


def _string_element_operand(
    instructions: tuple[Operation, ...], index: int, facts: frozenset[Fact]
) -> tuple[_Value, int] | None:
    """Push a recovered string array element instead of dropping the stack.

    Indexed element addressing is several arithmetic instructions long, which
    the pair-based string interpreter cannot read.  When the array passes have
    already recovered exactly one string element spanning this exact
    instruction run, its value is the operand the runtime pushed.
    """
    start = instructions[index].offset
    matches = [
        fact
        for fact in facts_by_kind(facts).get("reference.array_value", ())
        if fact.kind == "reference.array_value"
        and len(fact.subject) == 2
        and fact.subject[0] == start
        and len(fact.value) == 2
        and fact.value[1] == "string"
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    resume = next(
        (
            cursor
            for cursor in range(index + 1, len(instructions))
            if instructions[cursor].offset == match.subject[1]
        ),
        None,
    )
    if resume is None:
        return None
    return _Value(match.value[0], _evidence(match.evidence, (start,))), resume


def _direct_string_access(pair: tuple[Operation, ...]) -> tuple[str, int] | None:
    if len(pair) != 2:
        return None
    setup, runtime = pair
    if (
        setup.kind != "x86.mov_imm"
        or setup.operands[0] != "si"
        or not isinstance(setup.operands[1], int)
        or runtime.kind != "tb.runtime"
        or setup.end != runtime.offset
    ):
        return None
    action = {(0x9C,): "read", (0xA0,): "write"}.get(runtime.operands)
    return (action, setup.operands[1]) if action is not None else None


def _is_runtime(instruction: Operation, vector: int) -> bool:
    return instruction.kind == "tb.runtime" and instruction.operands == (vector,)


def _interpret_block(
    instructions: tuple[Operation, ...], frame: int | None = None
) -> Iterable[Fact]:
    registers: dict[str, _Value] = {}
    transient: dict[int, _Value] = {}
    stack: list[_Value] = []
    for instruction in instructions:
        if instruction.kind == "x86.wait" and instruction.raw == "9b":
            continue
        if instruction.kind == "tb.bounds":
            continue
        if _apply_fp_function(instruction, stack):
            continue
        action = _fp_action(instruction, frame)
        if action is None:
            action = _native_fp_action(instruction)
        if action is not None:
            effects = tuple(_apply_fp(action, instruction, stack, transient))
            yield from effects
            _update_transient(effects, transient)
            continue
        yield from _flush(stack)
        if instruction.kind in {"tb.runtime", "tb.function"}:
            yield from _call_registers(instruction, registers)
        effects = tuple(_cpu_facts(instruction, registers, transient, frame))
        yield from effects
        _update_transient(effects, transient)
        if instruction.kind in {"tb.runtime", "tb.statement"}:
            transient.clear()
        if _returns_ax(instruction):
            # The call's value, named by its call; resolve_expression finds
            # the value the function passes recovered for it. The compiler
            # keeps other values in BX and CX across such a call.
            registers["ax"] = _Value(
                ("result", instruction.offset), (instruction.offset,)
            )
        elif _preserves_registers(instruction):
            pass
        elif instruction.kind == "tb.runtime":
            # A runtime call returns in AX; the compiler holds values in BX
            # and CX across it and reads them back only when they survive.
            for register in [r for r in registers if r not in {"bx", "cx"}]:
                del registers[register]
        else:
            registers.clear()
    yield from _flush(stack)


def _apply_fp_function(instruction: Operation, stack: list[_Value]) -> bool:

    zero_functions = {0x2A: "MTIMER", 0x4C: "TIMER"}
    if instruction.kind == "tb.runtime" and instruction.operands == (0xAC,):
        # VAL takes its string from the string stack and leaves its value on
        # the x87 stack, named by the call like any function result.
        stack.append(_Value(("result", instruction.offset), (instruction.offset,)))
        return True
    if instruction.kind == "tb.runtime" and instruction.operands == (0xAB,) and stack:
        argument = stack.pop()
        stack.append(
            _Value(
                ("call", "INT", (argument.expression,)),
                _evidence(argument.evidence, (instruction.offset,)),
            )
        )
        return True
    if (
        instruction.kind == "tb.function"
        and len(instruction.operands) == 2
        and instruction.operands[0] == "numeric"
        and instruction.operands[1] in zero_functions
    ):
        stack.append(
            _Value(
                ("call", zero_functions[instruction.operands[1]], ()),
                (instruction.offset,),
            )
        )
        return True
    if instruction.kind == "tb.function" and instruction.operands == (
        "numeric",
        0x3E,
    ):
        stack.append(_Value(("call", "RND", ()), (instruction.offset,)))
        return True
    if (
        instruction.kind == "tb.fp_function"
        and len(instruction.operands) == 1
        and isinstance(instruction.operands[0], str)
        and stack
    ):
        name = instruction.operands[0]
    elif (
        instruction.kind == "tb.function"
        and instruction.operands in {("numeric", 0x40), ("numeric", 0x14)}
        and stack
    ):
        name = "RND" if instruction.operands[1] == 0x40 else "FIX"
    else:
        return False
    argument = stack.pop()
    stack.append(
        _Value(
            ("call", name, (argument.expression,)),
            _evidence(argument.evidence, (instruction.offset,)),
        )
    )
    return True


def _fp_action(
    instruction: Operation, frame: int | None = None
) -> tuple[str, object] | None:
    if instruction.kind != "tb.fp":
        return None
    raw = bytes.fromhex(instruction.raw)
    if raw[:2] == b"\xcd\x3e":
        return "stack_binary", "^"
    if len(raw) < 3:
        return None
    vector, modrm = raw[1], raw[2]
    reg, mod = (modrm >> 3) & 7, modrm >> 6
    address = _direct_address(raw, modrm, mod)
    if (
        address is None
        and frame is not None
        and mod == 1
        and modrm & 7 == 6
        and len(raw) == 4
    ):
        # A procedure's frame word, ``[bp+d]``, read as a push or an operand.
        displacement = struct.unpack_from("<b", raw, 3)[0]
        kind = FP_TRANSFER_TYPES.get(vector) if reg == 0 else None
        if kind is not None:
            return "push", ("frame", frame, displacement, kind)
        kind = FP_ARITHMETIC_TYPES.get(vector)
        operand = ("frame", frame, displacement, kind)
        if kind is not None and reg in {4, 6}:
            return "binary_top", ({4: "-", 6: "/"}[reg], operand)
        operator = {0: "+", 1: "*", 5: "-", 7: "/"}.get(reg)
        if kind is not None and operator is not None:
            return "binary", (operator, operand)
        return None
    if constant := _fp_constant(vector, modrm, mod):
        return "push", constant
    if stack_action := _fp_stack_action(vector, modrm, mod):
        return stack_action
    if transfer := _fp_transfer(vector, reg, address):
        return transfer
    return _fp_arithmetic(vector, reg, address)


def _native_fp_action(instruction: Operation) -> tuple[str, object] | None:
    """Return the shared symbolic action for direct native-8087 forms."""
    raw = bytes.fromhex(instruction.raw)
    if len(raw) < 2 or raw[0] not in range(0xD8, 0xE0):
        return None
    modrm = raw[1]
    if raw[0] == 0xD9 and modrm in (0xE8, 0xEE):
        return "push", ("const", 1 if modrm == 0xE8 else 0)
    if len(raw) != 4 or modrm >> 6 or modrm & 7 != 6:
        return None
    address = struct.unpack_from("<H", raw, 2)[0]
    register = (modrm >> 3) & 7
    if raw[0] == 0xDF and register == 0:
        return "push", ("memory", address, "integer")
    if raw[0] == 0xDF and register == 3:
        return "store", (address, "integer")
    if raw[0] == 0xDD and register == 0:
        return "push", ("memory", address, "double")
    if raw[0] == 0xDD and register == 3:
        return "store", (address, "double")
    if raw[0] == 0xD9 and register == 0:
        return "push", ("memory", address, "float")
    if raw[0] == 0xD9 and register == 3:
        return "store", (address, "float")
    if raw[0] == 0xD8 and register == 3:
        return "compare", ("memory", address)
    operator = {0: "+", 1: "*", 5: "-", 7: "/"}.get(register)
    if raw[0] == 0xD8 and operator is not None:
        return "binary", (operator, ("memory", address, "float"))
    return None


def _direct_address(raw: bytes, modrm: int, mod: int) -> int | None:
    if mod != 0 or modrm & 7 != 6 or len(raw) < 5:
        return None
    return struct.unpack_from("<H", raw, 3)[0]


def _fp_stack_action(vector: int, modrm: int, mod: int) -> tuple[str, object] | None:
    if vector == 0x3E:
        return "stack_binary", "^"
    if vector == 0x35 and mod == 3 and modrm == 0xE0:
        return "unary", "-"
    if vector == 0x35 and mod == 3 and modrm in {0xE1, 0xFA}:
        return "call_unary", {0xE1: "ABS", 0xFA: "SQR"}[modrm]
    if vector != 0x3A or mod != 3:
        return None
    if modrm == 0xD9:
        return "compare_stack", None
    operator = {0xC1: "+", 0xC9: "*", 0xE1: "-", 0xF1: "/"}.get(modrm)
    return ("stack_binary", operator) if operator is not None else None


def _fp_transfer(
    vector: int, reg: int, address: int | None
) -> tuple[str, object] | None:
    if vector not in FP_TRANSFER_TYPES or address is None:
        return None
    if reg == 0:
        kind = FP_TRANSFER_TYPES[vector]
        return "push", ("memory", address, kind)
    if reg == 3:
        return "store", (address, FP_TRANSFER_TYPES[vector])
    return None


def _fp_arithmetic(
    vector: int, reg: int, address: int | None
) -> tuple[str, object] | None:
    if vector == 0x3B and reg == 3 and address is not None:
        return "compare", ("memory", address, "integer")
    if vector not in FP_ARITHMETIC_TYPES or address is None:
        return None
    if reg == 3:
        return "compare", ("memory", address)
    # FSUB and FDIV (4, 6) take the stack top first; FSUBR and FDIVR (5, 7)
    # the memory operand.
    reversed_operator = {4: "-", 6: "/"}.get(reg)
    if reversed_operator is not None:
        return "binary_top", (reversed_operator, ("memory", address))
    operator = {0: "+", 1: "*", 5: "-", 7: "/"}.get(reg)
    return ("binary", (operator, ("memory", address))) if operator else None


def _apply_fp(
    action: tuple[str, object],
    instruction: Operation,
    stack: list[_Value],
    transient: dict[int, _Value],
) -> Iterable[Fact]:
    kind, operand = action
    if kind == "push":
        value = _transient_value(operand, transient)
        expression = value.expression if value is not None else operand
        if (
            isinstance(expression, tuple)
            and len(expression) == 3
            and expression[0] == "conversion"
        ):
            name = {"integer": "CINT", "long": "CLNG"}.get(expression[1])
            if name is None:
                return
            expression = ("call", name, (expression[2],))
        stack.append(
            _Value(
                expression,
                _evidence(
                    () if value is None else value.evidence,
                    (instruction.offset,),
                ),
            )
        )
        return
    if kind == "unary":
        if not stack:
            return
        value = stack.pop()
        stack.append(
            _Value(
                ("unary", operand, value.expression),
                _evidence(value.evidence, (instruction.offset,)),
            )
        )
        return
    if kind == "call_unary":
        if not stack:
            return
        value = stack.pop()
        stack.append(
            _Value(
                ("call", operand, (value.expression,)),
                _evidence(value.evidence, (instruction.offset,)),
            )
        )
        return
    if kind == "stack_binary":
        if len(stack) < 2:
            return
        top = stack.pop()
        lower = stack.pop()
        stack.append(
            _Value(
                ("binary", operand, top.expression, lower.expression),
                _evidence(
                    lower.evidence,
                    top.evidence,
                    (instruction.offset,),
                ),
            )
        )
        return
    if kind == "compare_stack":
        if len(stack) < 2:
            return
        top = stack.pop()
        lower = stack.pop()
        yield Fact(
            "expression.compare",
            (lower.evidence[0],),
            (top.expression, lower.expression),
            _evidence(
                lower.evidence,
                top.evidence,
                (instruction.offset,),
            ),
            "anchored",
        )
        return
    if not stack:
        return
    value = stack.pop()
    evidence = _evidence(value.evidence, (instruction.offset,))
    if kind == "binary" and isinstance(operand, tuple) and len(operand) == 2:
        operator, left = operand
        expression = orient_memory_fold(operator, left, value.expression)
        stack.append(_Value(expression, evidence))
        return
    if kind == "binary_top" and isinstance(operand, tuple) and len(operand) == 2:
        operator, right = operand
        stack.append(_Value(("binary", operator, value.expression, right), evidence))
        return
    if kind == "store" and isinstance(operand, tuple) and len(operand) == 2:
        address, target_kind = operand
        fact = _effect(
            "machine.store",
            address,
            (value.expression,),
            evidence,
            "signature",
        )
        yield fact
        _update_transient((fact,), transient)
        if (
            isinstance(address, int)
            and address < VAR_BASE
            and target_kind in {"integer", "long"}
        ):
            transient[address] = _Value(
                ("conversion", target_kind, value.expression),
                evidence,
            )
        return
    yield Fact(
        "expression.compare",
        (value.evidence[0],),
        (value.expression, operand),
        evidence,
        "signature",
    )


def _cpu_facts(
    instruction: Operation,
    registers: dict[str, _Value],
    transient: dict[int, _Value],
    frame: int | None = None,
) -> Iterable[Fact]:
    value: _Value | None
    if instruction.kind == "x86.mov_imm":
        register, immediate = instruction.operands
        value = _Value(("const", immediate), (instruction.offset,))
        registers[register] = value
        yield Fact(
            "register.value",
            (instruction.offset, register),
            (value.expression,),
            value.evidence,
            "structural",
        )
        return
    raw = bytes.fromhex(instruction.raw)
    if raw in {b"\x31\xc0", b"\x33\xc0"}:
        registers["ax"] = _Value(("const", 0), (instruction.offset,))
        return
    if instruction.kind == "x86.cmp":
        compared = _compared(instruction, raw, registers, frame)
        if compared is not None:
            yield compared
        return
    if (
        frame is not None
        and (fact := _frame_access(instruction, raw, registers, frame)) is not None
    ):
        if isinstance(fact, Fact):
            yield fact
        return
    move = _register_move(raw)
    if move is not None:
        target, source = move
        value = registers.get(source)
        if value is None:
            # Whatever the target held is gone; an unknown moved in.
            registers.pop(target, None)
            return
        registers[target] = _Value(
            value.expression,
            _evidence(value.evidence, (instruction.offset,)),
        )
        yield Fact(
            "register.value",
            (instruction.offset, target),
            (value.expression,),
            _evidence(value.evidence, (instruction.offset,)),
            "structural",
        )
        return
    arithmetic = _register_arithmetic(raw)
    if arithmetic is not None:
        operator, source = arithmetic
        left, right = registers.get("ax"), registers.get(source)
        if left is None or right is None:
            registers.pop("ax", None)
            return
        expression = ("binary", operator, left.expression, right.expression)
        registers["ax"] = _Value(
            expression, _evidence(left.evidence, right.evidence, (instruction.offset,))
        )
        yield Fact(
            "register.value",
            (instruction.offset, "ax"),
            (expression,),
            registers["ax"].evidence,
            "structural",
        )
        return
    boolean_ops = {
        b"\x09\xc0": ("OR", "ax", "ax"),
        b"\x0b\xc3": ("OR", "ax", "bx"),
        b"\x23\xc3": ("AND", "ax", "bx"),
    }
    if raw in boolean_ops:
        operator, target, source = boolean_ops[raw]
        left = registers.get(target)
        right = registers.get(source)
        if left is None or right is None:
            return
        expression = ("binary", operator, left.expression, right.expression)
        registers[target] = _Value(
            expression,
            _evidence(left.evidence, right.evidence, (instruction.offset,)),
        )
        yield Fact(
            "register.value",
            (instruction.offset, target),
            (expression,),
            registers[target].evidence,
            "structural",
        )
        return
    if raw == b"\xf7\xd8" and (value := registers.get("ax")) is not None:
        if (
            isinstance(value.expression, tuple)
            and len(value.expression) == 2
            and value.expression[0] == "const"
            and isinstance(value.expression[1], (int, float))
        ):
            negated = _Value(
                ("const", -value.expression[1]),
                _evidence(value.evidence, (instruction.offset,)),
            )
            registers["ax"] = negated
            yield Fact(
                "register.value",
                (instruction.offset, "ax"),
                (negated.expression,),
                negated.evidence,
                "structural",
            )
        else:
            negated = _Value(
                ("negated", value.expression),
                _evidence(value.evidence, (instruction.offset,)),
            )
            registers["ax"] = negated
        return
    if (
        len(raw) == 4
        and raw[:2] == b"\x03\x06"
        and (value := registers.get("ax")) is not None
    ):
        address = struct.unpack_from("<H", raw, 2)[0]
        memory = ("memory", address, "integer")
        expression = (
            ("binary", "-", memory, value.expression[1])
            if (
                isinstance(value.expression, tuple)
                and len(value.expression) == 2
                and value.expression[0] == "negated"
            )
            else ("binary", "+", value.expression, memory)
        )
        yield _register_value(instruction, registers, expression, value.evidence)
        return
    if (
        len(raw) == 4
        and raw[:2] == b"\xf7\x2e"
        and (value := registers.get("ax")) is not None
    ):
        address = struct.unpack_from("<H", raw, 2)[0]
        expression = (
            "binary",
            "*",
            value.expression,
            ("memory", address, "integer"),
        )
        yield _register_value(instruction, registers, expression, value.evidence)
        return
    if fact := _direct_store(instruction, raw, registers):
        yield fact
        return
    if fact := _direct_update(instruction, raw, registers):
        yield fact
        return
    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
        address = struct.unpack_from("<H", raw, 2)[0]
        value = transient.get(address)
        registers["ax"] = _Value(
            value.expression if value is not None else ("memory", address, "integer"),
            _evidence(
                () if value is None else value.evidence,
                (instruction.offset,),
            ),
        )
        return
    if instruction.kind == "x86.mov_acc_mem":
        address, action = instruction.operands
        if not isinstance(address, int):
            return
        if action == "load":
            value = transient.get(address)
            registers["ax"] = _Value(
                (
                    value.expression
                    if value is not None
                    else ("memory", address, "integer")
                ),
                _evidence(
                    () if value is None else value.evidence,
                    (instruction.offset,),
                ),
            )
            if value is not None:
                # A value parked in a temporary, now in AX for its store.
                yield Fact(
                    "register.value",
                    (instruction.offset, "ax"),
                    (registers["ax"].expression,),
                    registers["ax"].evidence,
                    "structural",
                )
        elif action == "store":
            value = registers.get(
                "ax", _Value(("register", "ax"), (instruction.offset,))
            )
            yield _effect(
                "machine.store",
                address,
                (_ordinary_store_value(address, value.expression),),
                _evidence(value.evidence, (instruction.offset,)),
                "structural",
            )


def _direct_store(
    instruction: Operation,
    raw: bytes,
    registers: dict[str, _Value],
) -> Fact | None:
    if len(raw) == 6 and raw[:2] == b"\xc7\x06":
        address, immediate = struct.unpack_from("<HH", raw, 2)
        return _effect(
            "machine.store",
            address,
            (("const", immediate),),
            (instruction.offset,),
            "structural",
        )
    if len(raw) == 4 and raw[:2] == b"\x89\x06":
        address = struct.unpack_from("<H", raw, 2)[0]
        value = registers.get("ax", _Value(("register", "ax"), (instruction.offset,)))
        evidence = _evidence(value.evidence, (instruction.offset,))
        return _effect(
            "machine.store",
            address,
            (_ordinary_store_value(address, value.expression),),
            evidence,
            "structural",
        )
    return None


_REGISTERS = ("ax", "cx", "dx", "bx")


def _frame_displacement(raw: bytes, opcode: bytes, register: int) -> int | None:
    """Return d of ``opcode reg,[bp+d]`` when the ModRM names ``register``."""
    if len(raw) < 3 or raw[: len(opcode)] != opcode:
        return None
    modrm = raw[len(opcode)]
    if modrm & 7 != 6 or (modrm >> 3) & 7 != register:
        return None
    rest = raw[len(opcode) + 1 :]
    if modrm >> 6 == 1 and len(rest) == 1:
        return struct.unpack("<b", rest)[0]
    if modrm >> 6 == 2 and len(rest) == 2:
        return struct.unpack("<h", rest)[0]
    return None


def _compared(
    instruction: Operation,
    raw: bytes,
    registers: dict[str, _Value],
    frame: int | None,
) -> Fact | None:
    """Record what ``cmp ax,operand`` compares AX with.

    The operand is BX, a DGROUP word, a frame word or the integer a frame
    pointer in SI points to; the value names which, as ``"bx"`` or
    ``"memory"``. ``cmp [m],ax`` compares the other way round, ``"first"``.
    """
    left = registers.get("ax")
    if left is None:
        return None
    right: _Value | None = None
    form = "bx" if raw == b"\x3b\xc3" else "memory"
    if raw == b"\x3b\xc3":
        right = registers.get("bx")
    elif len(raw) == 4 and raw[:2] == b"\x3b\x06":
        address = struct.unpack_from("<H", raw, 2)[0]
        right = _Value(("memory", address, "integer"), ())
    elif raw == b"\x26\x3b\x04" and frame is not None:
        pointer = registers.get("si")
        if pointer is not None and pointer.expression[0] == "frame-pointer":
            right = _Value(
                ("frame-param", frame, pointer.expression[1], "integer"),
                pointer.evidence,
            )
    elif (
        frame is not None
        and (displacement := _frame_displacement(raw, b"\x3b", 0)) is not None
    ):
        right = _Value(("frame", frame, displacement, "integer"), ())
    elif len(raw) == 4 and raw[:2] == b"\x39\x06":
        address = struct.unpack_from("<H", raw, 2)[0]
        right, form = _Value(("memory", address, "integer"), ()), "first"
    elif (
        frame is not None
        and (displacement := _frame_displacement(raw, b"\x39", 0)) is not None
    ):
        right, form = _Value(("frame", frame, displacement, "integer"), ()), "first"
    if right is None:
        return None
    return Fact(
        "register.compare",
        (instruction.offset,),
        (left.expression, right.expression, form),
        _evidence(left.evidence, right.evidence, (instruction.offset,)),
        "structural",
    )


def _frame_word(raw: bytes) -> bool:
    """Whether ``raw`` reads, stores or points at a frame word, keeping AX."""
    return (
        raw in {b"\x26\x8b\x04", b"\x26\x03\x04"}
        or _frame_displacement(raw, b"\xc4", 6) is not None
        or any(
            _frame_displacement(raw, opcode, 0) is not None
            for opcode in (b"\x8b", b"\x03", b"\x89")
        )
    )


def _frame_access(
    instruction: Operation, raw: bytes, registers: dict[str, _Value], frame: int
) -> Fact | bool | None:
    """Track a procedure frame's integers through AX.

    A local is a word at ``[bp+d]``; a parameter is a far pointer there,
    loaded with ``les si,[bp+d]`` and read through ``es:[si]``. The values
    name the procedure entered at ``frame`` and the displacement, which
    ``resolve_expression`` turns into its local or parameter. Return ``True``
    for an access that yields no value of its own and ``None`` for any other
    instruction.
    """
    pointer = _frame_displacement(raw, b"\xc4", 6)
    if pointer is not None:
        registers["si"] = _Value(("frame-pointer", pointer), (instruction.offset,))
        return True
    operand: tuple[object, ...] | None = None
    support: tuple[int, ...] = ()
    load = raw[:1] == b"\x8b" or raw == b"\x26\x8b\x04"
    if raw in {b"\x26\x8b\x04", b"\x26\x03\x04"}:
        target = registers.get("si")
        if target is None or target.expression[0] != "frame-pointer":
            return None
        operand = ("frame-param", frame, target.expression[1], "integer")
        support = target.evidence
    else:
        for opcode in (b"\x8b", b"\x03"):
            displacement = _frame_displacement(raw, opcode, 0)
            if displacement is not None:
                operand = ("frame", frame, displacement, "integer")
    if operand is None:
        return None
    if load:
        return _register_value(instruction, registers, operand, support)
    value = registers.get("ax")
    if value is None:
        return True
    expression = (
        ("binary", "-", operand, value.expression[1])
        if isinstance(value.expression, tuple) and value.expression[:1] == ("negated",)
        else ("binary", "+", value.expression, operand)
    )
    return _register_value(
        instruction, registers, expression, _evidence(value.evidence, support)
    )


def _register_move(raw: bytes) -> tuple[str, str] | None:
    """Return (target, source) of ``mov r16,r16`` among AX, CX, DX, BX."""
    if len(raw) != 2 or raw[0] not in {0x89, 0x8B} or raw[1] >> 6 != 3:
        return None
    reg, rm = (raw[1] >> 3) & 7, raw[1] & 7
    if reg > 3 or rm > 3 or reg == rm:
        return None
    first, second = _REGISTERS[rm], _REGISTERS[reg]
    return (first, second) if raw[0] == 0x89 else (second, first)


def _register_arithmetic(raw: bytes) -> tuple[str, str] | None:
    """Return (operator, source) of ``add/sub ax,r16`` or ``imul r16``.

    The source is CX, DX or BX; ``imul r16`` leaves AX times it in AX.
    """
    if (
        len(raw) == 2
        and raw[0] == 0xF7
        and raw[1] >> 3 == 0x1D
        and 1 <= raw[1] & 7 <= 3
    ):
        return "*", _REGISTERS[raw[1] & 7]
    operators = {0x03: "+", 0x2B: "-"}
    if len(raw) != 2 or raw[0] not in operators or raw[1] >> 6 != 3:
        return None
    reg, rm = (raw[1] >> 3) & 7, raw[1] & 7
    if reg != 0 or not 1 <= rm <= 3:
        return None
    return operators[raw[0]], _REGISTERS[rm]


def _register_value(
    instruction: Operation,
    registers: dict[str, _Value],
    expression: object,
    support: tuple[int, ...],
) -> Fact:
    value = _Value(expression, _evidence(support, (instruction.offset,)))
    registers["ax"] = value
    return Fact(
        "register.value",
        (instruction.offset, "ax"),
        (value.expression,),
        value.evidence,
        "structural",
    )


def _transient_value(operand: object, transient: dict[int, _Value]) -> _Value | None:
    if (
        isinstance(operand, tuple)
        and len(operand) >= 2
        and operand[0] == "memory"
        and isinstance(operand[1], int)
    ):
        return transient.get(operand[1])
    return None


def _ordinary_store_value(address: int, expression: object) -> object:
    if (
        address >= VAR_BASE
        and isinstance(expression, tuple)
        and len(expression) == 3
        and expression[0] == "conversion"
    ):
        return expression[2]
    return expression


def _update_transient(effects: tuple[Fact, ...], transient: dict[int, _Value]) -> None:
    for effect in effects:
        if (
            effect.kind != "machine.store"
            or not effect.subject
            or not isinstance(effect.subject[0], int)
            or effect.subject[0] >= VAR_BASE
            or len(effect.value) != 1
        ):
            continue
        expression = effect.value[0]
        if expression == ("register", "ax"):
            transient.pop(effect.subject[0], None)
            continue
        previous = transient.get(effect.subject[0])
        if (
            previous is not None
            and isinstance(previous.expression, tuple)
            and previous.expression[:1] == ("conversion",)
            and previous.expression[2] == expression
        ):
            continue
        transient[effect.subject[0]] = _Value(expression, effect.evidence)


def _direct_update(
    instruction: Operation,
    raw: bytes,
    registers: dict[str, _Value],
) -> Fact | None:
    if len(raw) == 4 and raw[:2] in {b"\xff\x0e", b"\xff\x06"}:
        address = struct.unpack_from("<H", raw, 2)[0]
        return _effect(
            "machine.update",
            address,
            ("-" if raw[1] == 0x0E else "+", ("const", 1)),
            (instruction.offset,),
            "structural",
        )
    if len(raw) != 4 or raw[:2] not in {b"\x01\x06", b"\x29\x06"}:
        return None
    address = struct.unpack_from("<H", raw, 2)[0]
    value = registers.get("ax", _Value(("register", "ax"), (instruction.offset,)))
    operator = "+" if raw[0] == 0x01 else "-"
    evidence = _evidence(value.evidence, (instruction.offset,))
    return _effect(
        "machine.update", address, (operator, value.expression), evidence, "structural"
    )


def _flush(stack: list[_Value]) -> Iterable[Fact]:
    while stack:
        value = stack.pop(0)
        # A frame word is named by the procedure passes; a value holding one
        # reaches its statement through AX and ``frame_value_facts``.
        if has_frame_word(value.expression):
            continue
        # A call's result alone is the function passes' value, which starts
        # at the call's operand, not at the call.
        if isinstance(value.expression, tuple) and value.expression[:1] == ("result",):
            continue
        yield Fact(
            "expression.value",
            (value.evidence[0],),
            (value.expression,),
            value.evidence,
            "signature",
        )


def _effect(
    kind: str,
    address: object,
    value: tuple[object, ...],
    evidence: tuple[int, ...],
    confidence: str,
) -> Fact:
    return Fact(kind, (address,), value, evidence, confidence)


def _call_registers(
    instruction: Operation, registers: dict[str, _Value]
) -> Iterable[Fact]:
    """Record what AX and BX hold when a runtime call is made.

    The evidence is the tracker's own: the instructions that computed them.
    """
    ax, bx = registers.get("ax"), registers.get("bx")
    if ax is None or bx is None:
        return
    yield Fact(
        "register.at_call",
        (instruction.offset,),
        (ax.expression, bx.expression),
        _evidence(ax.evidence, bx.evidence),
        "structural",
    )


def _returns_ax(instruction: Operation) -> bool:
    """Whether a call leaves an integer result in AX."""
    if instruction.kind == "tb.function":
        return instruction.operands[:1] == ("numeric",)
    return instruction.kind == "tb.runtime" and instruction.operands == (0xA6,)


def _preserves_registers(instruction: Operation) -> bool:
    if instruction.kind in {"x86.mov_imm", "x86.mov_acc_mem"}:
        return True
    # A string push keeps the registers: the compiler holds a start, a
    # length or a saved partial result in them across it.
    if instruction.kind == "tb.runtime" and instruction.operands in {(0x9C,), (0x9D,)}:
        return True
    raw = bytes.fromhex(instruction.raw)
    if _register_move(raw) is not None or _register_arithmetic(raw) is not None:
        return True
    raw = bytes.fromhex(instruction.raw)
    if raw in {b"\xf7\xd8", b"\x31\xc0", b"\x33\xc0"} or _frame_word(raw):
        return True
    if raw == b"\xce":
        return True
    return raw[:2] in {
        b"\x8b\x06",
        b"\x03\x06",
        b"\xf7\x2e",
        b"\xc7\x06",
        b"\x89\x06",
        b"\x01\x06",
        b"\x29\x06",
    }


def _evidence(*groups: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(dict.fromkeys(address for group in groups for address in group))


SYMBOLIC_FACT_PASSES: tuple[NamedPass, ...] = (
    ("symbolic-effects", symbolic_facts),
    ("string-stores", string_store_facts),
)
