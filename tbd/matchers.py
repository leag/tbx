"""Shared immutable matchers for complete compiler instruction templates."""

from __future__ import annotations

import struct

from tbd.ir import Operation
from tbd.profile import FP_TRANSFER_TYPES


def fp_ax_bridge(
    reload: Operation | None, by_end: dict[int, Operation]
) -> tuple[object, tuple[int, ...]] | None:
    """Match a direct FP load converted through scratch storage into AX."""

    scratch = _ax_reload_scratch(reload)
    if reload is None or scratch is None:
        return None
    store, synchronization = _bridge_store(reload, by_end)
    source = by_end.get(store.offset) if store is not None else None
    if not _stores_ax_scratch(store, scratch):
        return None
    expression = _direct_fp_source(source)
    if expression is None or store is None or source is None:
        return None
    return expression, (
        source.offset,
        store.offset,
        *(item.offset for item in synchronization),
        reload.offset,
    )


def _ax_reload_scratch(reload: Operation | None) -> int | None:
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


def _bridge_store(
    reload: Operation, by_end: dict[int, Operation]
) -> tuple[Operation | None, tuple[Operation, ...]]:
    previous = by_end.get(reload.offset)
    if previous is None:
        return None, ()
    if previous.kind == "tb.fwait" or bytes.fromhex(previous.raw) == b"\x9b":
        return by_end.get(previous.offset), (previous,)
    if bytes.fromhex(previous.raw) == b"\x90":
        first = by_end.get(previous.offset)
        if first is not None and bytes.fromhex(first.raw) == b"\x90":
            return by_end.get(first.offset), (first, previous)
    return previous, ()


def _stores_ax_scratch(store: Operation | None, scratch: int) -> bool:
    if store is None:
        return False
    store_raw = bytes.fromhex(store.raw)
    return (
        len(store_raw) == 5
        and store_raw[:3] == b"\xcd\x3b\x1e"
        and struct.unpack_from("<H", store_raw, 3)[0] == scratch
    )


def _direct_fp_source(source: Operation | None) -> object | None:
    if source is None or source.kind != "tb.fp":
        return None
    raw = bytes.fromhex(source.raw)
    if (
        len(raw) != 5
        or raw[0] != 0xCD
        or raw[2] != 0x06
        or raw[1] not in FP_TRANSFER_TYPES
    ):
        return None
    address = struct.unpack_from("<H", raw, 3)[0]
    return "memory", address, FP_TRANSFER_TYPES[raw[1]]


def string_push_scaffold(
    commit: Operation, by_end: dict[int, Operation]
) -> tuple[Operation, Operation] | None:
    """Match ``mov si,address; runtime string push`` before a commit."""

    runtime = by_end.get(commit.offset)
    setup = by_end.get(runtime.offset) if runtime is not None else None
    if (
        runtime is None
        or runtime.kind != "tb.runtime"
        or runtime.operands != (0x9C,)
        or setup is None
        or setup.kind != "x86.mov_imm"
        or len(setup.operands) != 2
        or setup.operands[0] != "si"
        or not isinstance(setup.operands[1], int)
    ):
        return None
    return setup, runtime
