"""Identify stable synthetic names for DGROUP memory references."""

from __future__ import annotations

from typing import Any

from tbd.ir import Operation, Slot

VAR_BASE = 0x120
SLOT_WIDTH = 4


def identify(
    nodes: list[Operation], _protected: set[int]
) -> tuple[list[Operation], int]:
    result = []
    changes = 0
    for node in nodes:
        operands = _rewrite_operands(node)
        if operands != node.operands:
            node = Operation(
                node.offset, node.size, node.kind, operands, node.raw, node.confidence
            )
            changes += 1
        result.append(node)
    return result, changes


def collect(nodes: tuple[Operation, ...]) -> tuple[Slot, ...]:
    found: dict[int, set[str]] = {}
    for node in nodes:
        _collect_from(node.operands, found)
    return tuple(
        Slot(offset, slot_name(offset), tuple(sorted(types)))
        for offset, types in sorted(found.items())
    )


def _rewrite_operands(node: Operation) -> tuple[Any, ...]:
    operands = tuple(_rewrite(value) for value in node.operands)
    if node.kind.startswith("machine.") and operands and isinstance(operands[0], int):
        target = operands[0]
        if is_slot(target):
            operands = ((_slot(target),) + operands[1:])
    return operands


def _rewrite(value: Any) -> Any:
    if isinstance(value, tuple):
        if (
            len(value) >= 2
            and value[0] == "memory"
            and isinstance(value[1], int)
            and is_slot(value[1])
        ):
            return _slot(value[1]) + tuple(_rewrite(item) for item in value[2:])
        return tuple(_rewrite(item) for item in value)
    if isinstance(value, list):
        return [_rewrite(item) for item in value]
    return value


def _slot(offset: int) -> tuple[str, str, int]:
    return "slot", slot_name(offset), offset


def slot_name(offset: int) -> str:
    index = (offset - VAR_BASE) // SLOT_WIDTH + 1
    return f"V{index:04d}"


def is_slot(offset: int) -> bool:
    return offset >= VAR_BASE and (offset - VAR_BASE) % SLOT_WIDTH == 0


def _collect_from(value: Any, found: dict[int, set[str]]) -> None:
    if isinstance(value, tuple):
        if len(value) >= 3 and value[0] == "slot":
            types = found.setdefault(value[2], set())
            if len(value) >= 4 and isinstance(value[3], str):
                types.add(value[3])
        for item in value:
            _collect_from(item, found)
    elif isinstance(value, list):
        for item in value:
            _collect_from(item, found)
