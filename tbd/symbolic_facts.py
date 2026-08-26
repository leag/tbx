"""Local register and emulated FP-stack facts over immutable instructions."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.profile import FP_ARITHMETIC_TYPES, FP_TRANSFER_TYPES
from tbd.semantic import orient_memory_fold
from tbd.slots import VAR_BASE


@dataclass(frozen=True)
class _Value:
    expression: object
    evidence: tuple[int, ...]


def symbolic_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Interpret each basic block independently and emit additive effects."""

    instructions = {item.offset: item for item in evidence.instructions}
    for block in evidence.blocks:
        block_nodes = tuple(
            instructions[offset]
            for offset in block.instruction_offsets
            if offset in instructions
        )
        yield from _interpret_block(block_nodes)


def string_store_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover complete direct string-stack assignments within one block."""

    instructions = {item.offset: item for item in evidence.instructions}
    for block in evidence.blocks:
        block_nodes = tuple(
            instructions[offset]
            for offset in block.instruction_offsets
            if offset in instructions
        )
        yield from _string_stores(block_nodes)


def _string_stores(instructions: tuple[Operation, ...]) -> Iterable[Fact]:
    stack: list[_Value] = []
    index = 0
    while index < len(instructions):
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
            evidence = _evidence(
                value.evidence, (setup.offset, runtime.offset)
            )
            yield _effect(
                "machine.store", address, (value.expression,), evidence, "signature"
            )
        index += 2


def _direct_string_access(
    pair: tuple[Operation, ...]
) -> tuple[str, int] | None:
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


def _interpret_block(instructions: tuple[Operation, ...]) -> Iterable[Fact]:
    registers: dict[str, _Value] = {}
    transient: dict[int, _Value] = {}
    stack: list[_Value] = []
    for instruction in instructions:
        if _apply_fp_function(instruction, stack):
            continue
        action = _fp_action(instruction)
        if action is not None:
            yield from _apply_fp(action, instruction, stack, transient)
            continue
        yield from _flush(stack)
        effects = tuple(_cpu_facts(instruction, registers, transient))
        yield from effects
        _update_transient(effects, transient)
        if instruction.kind in {"tb.runtime", "tb.statement"}:
            transient.clear()
        if not _preserves_registers(instruction):
            registers.clear()
    yield from _flush(stack)


def _apply_fp_function(instruction: Operation, stack: list[_Value]) -> bool:
    """Push complete calibrated numeric intrinsic results onto the FP stack."""

    zero_functions = {0x2A: "MTIMER", 0x4C: "TIMER"}
    if (
        instruction.kind == "tb.runtime"
        and instruction.operands == (0xAB,)
        and stack
    ):
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
        stack.append(
            _Value(("call", "RND", ()), (instruction.offset,))
        )
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
        and instruction.operands == ("numeric", 0x40)
        and stack
    ):
        name = "RND"
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


def _fp_action(instruction: Operation) -> tuple[str, object] | None:
    if instruction.kind != "tb.fp":
        return None
    raw = bytes.fromhex(instruction.raw)
    if len(raw) < 3:
        return None
    vector, modrm = raw[1], raw[2]
    reg, mod = (modrm >> 3) & 7, modrm >> 6
    address = _direct_address(raw, modrm, mod)
    if constant := _fp_constant(vector, modrm, mod):
        return "push", constant
    if stack_action := _fp_stack_action(vector, modrm, mod):
        return stack_action
    if transfer := _fp_transfer(vector, reg, address):
        return transfer
    return _fp_arithmetic(vector, reg, address)


def _direct_address(raw: bytes, modrm: int, mod: int) -> int | None:
    if mod != 0 or modrm & 7 != 6 or len(raw) < 5:
        return None
    return struct.unpack_from("<H", raw, 3)[0]


def _fp_constant(vector: int, modrm: int, mod: int) -> object | None:
    if vector == 0x35 and mod == 3 and modrm in (0xE8, 0xEE):
        return "const", 1 if modrm == 0xE8 else 0
    return None


def _fp_stack_action(
    vector: int, modrm: int, mod: int
) -> tuple[str, object] | None:
    if vector == 0x35 and mod == 3 and modrm == 0xE0:
        return "unary", "-"
    if vector == 0x35 and mod == 3 and modrm in {0xE1, 0xFA}:
        return "call_unary", {0xE1: "ABS", 0xFA: "SQR"}[modrm]
    if vector != 0x3A or mod != 3:
        return None
    if modrm == 0xD9:
        return "compare_stack", None
    operator = {0xC9: "*", 0xE1: "-", 0xF1: "/"}.get(modrm)
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
    if vector not in FP_ARITHMETIC_TYPES or address is None:
        return None
    if reg == 3:
        return "compare", ("memory", address)
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
    if kind == "binary":
        operator, left = operand
        expression = orient_memory_fold(operator, left, value.expression)
        stack.append(_Value(expression, evidence))
        return
    if kind == "store":
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
) -> Iterable[Fact]:
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
                value.expression
                if value is not None
                else ("memory", address, "integer"),
                _evidence(
                    () if value is None else value.evidence,
                    (instruction.offset,),
                ),
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


def _transient_value(
    operand: object, transient: dict[int, _Value]
) -> _Value | None:
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


def _update_transient(
    effects: tuple[Fact, ...], transient: dict[int, _Value]
) -> None:
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
        transient[effect.subject[0]] = _Value(expression, effect.evidence)


def _direct_update(
    instruction: Operation,
    raw: bytes,
    registers: dict[str, _Value],
) -> Fact | None:
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


def _preserves_registers(instruction: Operation) -> bool:
    if instruction.kind in {"x86.mov_imm", "x86.mov_acc_mem"}:
        return True
    raw = bytes.fromhex(instruction.raw)
    if raw == b"\xf7\xd8":
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
