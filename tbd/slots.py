"""Infer and name compiler variable slots in operation operands."""

from __future__ import annotations

from typing import Any

VAR_BASE = 0x120
SLOT_WIDTH = 4


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
    """Return the stable source name for a compiler slot offset."""
    index = (offset - VAR_BASE) // SLOT_WIDTH + 1
    return f"V{index:04d}"


def is_slot(offset: int) -> bool:
    """Return whether ``offset`` falls on the compiler slot grid."""
    return offset >= VAR_BASE and (offset - VAR_BASE) % SLOT_WIDTH == 0


"""Infer and name compiler variable slots in operation operands."""
