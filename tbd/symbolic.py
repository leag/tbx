"""Small symbolic evaluator for compiler-generated register and FP idioms."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from tbd.ir import Operation


@dataclass
class _Value:
    expression: object
    origins: list[Operation]


def evaluate(
    nodes: list[Operation], protected: set[int]
) -> tuple[list[Operation], int]:
    """Evaluate local machine effects, resetting state at block boundaries."""

    result: list[Operation] = []
    stack: list[_Value] = []
    registers: dict[str, object] = {}
    changes = 0
    previous_end = None
    for node in nodes:
        if node.offset in protected or previous_end not in (None, node.offset):
            _flush(stack, result)
            registers.clear()
        action = _fp_action(node)
        if action:
            changes += _apply_fp(action, node, stack, result)
        else:
            _flush(stack, result)
            replacement = _cpu_effect(node, registers)
            result.extend(replacement)
            changes += replacement != [node]
        if node.kind.startswith("flow.") or node.kind == "tb.epilogue":
            registers.clear()
        previous_end = node.end
    _flush(stack, result)
    return result, changes


def _fp_action(node: Operation) -> tuple[str, object] | None:
    if node.kind != "tb.fp":
        return None
    raw = bytes.fromhex(node.raw)
    vector, modrm = raw[1], raw[2]
    reg, mod = (modrm >> 3) & 7, modrm >> 6
    address = struct.unpack_from("<H", raw, 3)[0] if mod == 0 and modrm & 7 == 6 else None
    return _memory_fp_action(vector, modrm, reg, mod, address)


def _memory_fp_action(
    vector: int, modrm: int, reg: int, mod: int, address: int | None
) -> tuple[str, object] | None:
    if constant := _fp_constant(vector, modrm, mod):
        return "push", constant
    if transfer := _fp_transfer(vector, reg, address):
        return transfer
    if vector in (0x34, 0x36) and address is not None:
        return _arithmetic_fp_action(reg, address)
    return None


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
        value = ("memory", address, "integer" if vector == 0x3B else "float")
        return "push", value
    return ("store", address) if reg == 3 else None


def _arithmetic_fp_action(reg: int, address: int) -> tuple[str, object] | None:
    if reg == 3:
        return "compare", ("memory", address)
    operators = {0: "+", 1: "*", 5: "-", 7: "/"}
    if operator := operators.get(reg):
        return "binary", (operator, ("memory", address))
    return None


def _apply_fp(
    action: tuple[str, object],
    node: Operation,
    stack: list[_Value],
    result: list[Operation],
) -> int:
    kind, operand = action
    if kind == "push":
        stack.append(_Value(operand, [node]))
        return 1
    if not stack:
        result.append(node)
        return 0
    value = stack.pop()
    if kind == "binary":
        operator, right = operand
        stack.append(_Value(("binary", operator, value.expression, right), value.origins + [node]))
        return 1
    if kind == "store":
        result.append(_merge(value.origins + [node], "machine.store", (operand, value.expression)))
        return 1
    result.append(_merge(value.origins + [node], "expr.compare", (value.expression, operand)))
    return 1


def _cpu_effect(node: Operation, registers: dict[str, object]) -> list[Operation]:
    if node.kind == "x86.mov_imm":
        registers[node.operands[0]] = ("const", node.operands[1])
        return [node]
    raw = bytes.fromhex(node.raw)
    if replacement := _direct_store(node, raw, registers):
        return [replacement]
    if raw[:2] in (b"\x01\x06", b"\x29\x06") and len(raw) == 4:
        address = struct.unpack_from("<H", raw, 2)[0]
        value = registers.get("ax", ("register", "ax"))
        operator = "+" if raw[0] == 0x01 else "-"
        return [_replace(node, "machine.update", (address, operator, value))]
    if raw[:2] == b"\x8b\x06" and len(raw) == 4:
        registers["ax"] = ("memory", struct.unpack_from("<H", raw, 2)[0])
    return [node]


def _direct_store(
    node: Operation, raw: bytes, registers: dict[str, object]
) -> Operation | None:
    if raw[:2] == b"\xc7\x06" and len(raw) == 6:
        address, value = struct.unpack_from("<HH", raw, 2)
        return _replace(node, "machine.store", (address, ("const", value)))
    if raw[:2] == b"\x89\x06" and len(raw) == 4:
        address = struct.unpack_from("<H", raw, 2)[0]
        value = registers.get("ax", ("register", "ax"))
        return _replace(node, "machine.store", (address, value))
    return None


def _flush(stack: list[_Value], result: list[Operation]) -> None:
    while stack:
        value = stack.pop(0)
        result.append(_merge(value.origins, "expr.value", (value.expression,)))


def _merge(nodes: list[Operation], kind: str, operands: tuple[object, ...]) -> Operation:
    raw = " ".join(node.raw for node in nodes)
    return Operation(
        nodes[0].offset,
        nodes[-1].end - nodes[0].offset,
        kind,
        operands,
        raw,
        "semantic",
    )


def _replace(node: Operation, kind: str, operands: tuple[object, ...]) -> Operation:
    return Operation(node.offset, node.size, kind, operands, node.raw, "semantic")
