"""Local register and emulated FP-stack facts over immutable instructions."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation


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
    stack: list[_Value] = []
    for instruction in instructions:
        action = _fp_action(instruction)
        if action is not None:
            yield from _apply_fp(action, instruction, stack)
            continue
        yield from _flush(stack)
        yield from _cpu_facts(instruction, registers)
        if not _preserves_registers(instruction):
            registers.clear()
    yield from _flush(stack)


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


def _fp_transfer(
    vector: int, reg: int, address: int | None
) -> tuple[str, object] | None:
    if vector not in (0x35, 0x3B) or address is None:
        return None
    if reg == 0:
        kind = "integer" if vector == 0x3B else "float"
        return "push", ("memory", address, kind)
    return ("store", address) if reg == 3 else None


def _fp_arithmetic(
    vector: int, reg: int, address: int | None
) -> tuple[str, object] | None:
    if vector not in (0x34, 0x36) or address is None:
        return None
    if reg == 3:
        return "compare", ("memory", address)
    operator = {0: "+", 1: "*", 5: "-", 7: "/"}.get(reg)
    return ("binary", (operator, ("memory", address))) if operator else None


def _apply_fp(
    action: tuple[str, object], instruction: Operation, stack: list[_Value]
) -> Iterable[Fact]:
    kind, operand = action
    if kind == "push":
        stack.append(_Value(operand, (instruction.offset,)))
        return
    if not stack:
        return
    value = stack.pop()
    evidence = _evidence(value.evidence, (instruction.offset,))
    if kind == "binary":
        operator, right = operand
        expression = "binary", operator, value.expression, right
        stack.append(_Value(expression, evidence))
        return
    if kind == "store":
        yield _effect("machine.store", operand, (value.expression,), evidence, "signature")
        return
    yield Fact(
        "expression.compare",
        (value.evidence[0],),
        (value.expression, operand),
        evidence,
        "signature",
    )


def _cpu_facts(
    instruction: Operation, registers: dict[str, _Value]
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
    if fact := _direct_store(instruction, raw, registers):
        yield fact
        return
    if fact := _direct_update(instruction, raw, registers):
        yield fact
        return
    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
        address = struct.unpack_from("<H", raw, 2)[0]
        registers["ax"] = _Value(("memory", address, "integer"), (instruction.offset,))


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
            "machine.store", address, (value.expression,), evidence, "structural"
        )
    return None


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
    if instruction.kind == "x86.mov_imm":
        return True
    raw = bytes.fromhex(instruction.raw)
    return raw[:2] in {
        b"\x8b\x06",
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
