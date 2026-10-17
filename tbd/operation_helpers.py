"""Small operation-shape helpers shared by fact recognizers."""

from __future__ import annotations

import struct
from collections.abc import Sequence
from functools import lru_cache
from typing import Any, Protocol, TypeVar

from tbd.ir import Operation


class _Located(Protocol):
    @property
    def offset(self) -> int: ...


Located = TypeVar("Located", bound=_Located)


@lru_cache(maxsize=8192)
def raw_bytes(raw: str) -> bytes:
    """Decode an operation's canonical hex payload, reusing common opcodes."""
    return bytes.fromhex(raw)


def movsi_runtime(nodes: tuple[Operation, ...], vector: int) -> bool:
    """Return whether ``nodes`` load SI and immediately call ``vector``."""
    return (
        len(nodes) == 2
        and nodes[0].kind == "x86.mov_imm"
        and nodes[0].operands[:1] == ("si",)
        and len(nodes[0].operands) == 2
        and nodes[1].kind == "tb.runtime"
        and nodes[1].operands == (vector,)
        and nodes[0].end == nodes[1].offset
    )


def slot_address(value: object) -> int | None:
    """Extract the address from a symbolic slot expression."""
    if (
        isinstance(value, tuple)
        and len(value) >= 3
        and value[0] == "slot"
        and isinstance(value[2], int)
    ):
        return value[2]
    return None


def ax_reload_scratch(reload: Operation | None) -> int | None:
    """Return the scratch address used by an AX reload operation."""
    if reload is None:
        return None
    if (
        reload.kind == "x86.mov_acc_mem"
        and len(reload.operands) == 2
        and isinstance(reload.operands[0], int)
        and reload.operands[1] == "load"
    ):
        return reload.operands[0]
    if reload.kind != "tb.fp":
        return None
    raw = bytes.fromhex(reload.raw)
    if len(raw) != 5 or raw[:3] != b"\xcd\x3d\xa1":
        return None
    return struct.unpack_from("<H", raw, 3)[0]


def following(
    operations: Sequence[Located],
    indexes: dict[int, int],
    operation: Located | None,
    count: int,
) -> tuple[Located, ...] | None:
    """Return the next ``count`` operations after ``operation``."""
    if operation is None or operation.offset not in indexes:
        return None
    start = indexes[operation.offset] + 1
    result = operations[start : start + count]
    return tuple(result) if len(result) == count else None


def merge(nodes: Sequence[Any], kind: str, operands: tuple[object, ...]) -> Operation:
    """Merge contiguous operation metadata into one semantic operation."""
    raw = " ".join(node.raw for node in nodes)
    return Operation(
        nodes[0].offset,
        nodes[-1].end - nodes[0].offset,
        kind,
        operands,
        raw,
        "semantic",
    )


def contiguous(operations: Sequence[Operation]) -> bool:
    """Return whether operation spans touch without gaps."""
    return all(
        left.end == right.offset for left, right in zip(operations, operations[1:])
    )


def statement_name(operation: Operation) -> str | None:
    """Return the source statement name carried by an operation."""
    if operation.kind != "tb.statement" or not operation.operands:
        return None
    name = operation.operands[0]
    return name if isinstance(name, str) else None


def runtime_vector(operation: Operation | None) -> int | None:
    """Return a runtime vector operand, when the operation is a runtime call."""
    if operation is None or operation.kind != "tb.runtime" or not operation.operands:
        return None
    vector = operation.operands[0]
    return vector if isinstance(vector, int) else None


def runtime_call(operation: Operation | None, vector: int) -> bool:
    """Return whether an operation is exactly the requested runtime call."""
    return runtime_vector(operation) == vector and operation is not None


def fp_constant(vector: int, modrm: int, mod: int) -> object | None:
    """Decode the boolean constants returned by the FP runtime vector."""
    if vector == 0x35 and mod == 3 and modrm in (0xE8, 0xEE):
        return "const", 1 if modrm == 0xE8 else 0
    return None


def unresolved_call_arguments(value: object) -> bool:
    """Return whether a value marks unresolved procedure-call arguments."""
    return (
        isinstance(value, tuple)
        and bool(value)
        and value[0] == "unresolved-call-arguments"
    )


def fact_inside(fact: object, start: int, end: int) -> bool:
    """Return whether a fact's two-offset subject lies within a region."""
    subject = getattr(fact, "subject", ())
    if not isinstance(subject, tuple):
        return False
    return (
        len(subject) == 2
        and isinstance(subject[0], int)
        and isinstance(subject[1], int)
        and start <= subject[0] < subject[1] <= end
    )


def register_moves(instructions: tuple[Operation, ...]) -> dict[int, int]:
    """Map each two-byte register-to-register ``mov`` to where it ends."""
    return {
        item.offset: item.end
        for item in instructions
        if item.kind == "x86.mov"
        and len(item.raw.split()) == 2
        and item.raw.startswith("89 ")
    }


def bridged(end: object, start: object, moves: dict[int, int]) -> bool:
    """Return whether only register moves lie between ``end`` and ``start``.

    A compound condition saves the previous term's truth value in another
    register between a compare's operands; those moves carry no operand.
    """
    if not isinstance(end, int) or not isinstance(start, int):
        return False
    while end < start and end in moves:
        end = moves[end]
    return end == start
