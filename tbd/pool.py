"""Conservative scalar and string constant-pool recovery."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any

from tbd.ir import Operation
from tbd.slots import VAR_BASE

_MARKER = b"\x00\x80\x16\x00"
_POOL_EOF_GAP = 0x2C


@dataclass(frozen=True)
class _Layout:
    ds: int
    pool_base: int
    descriptors: dict[int, tuple[int, int]]
    string_base: int | None


def resolve(
    nodes: list[Operation], _protected: set[int], image: bytes
) -> tuple[list[Operation], int]:
    """Replace supported pool references with literals when layout is anchored."""

    layout = _layout(nodes, image)
    if layout is None:
        return nodes, 0
    result = []
    changes = 0
    for node in nodes:
        operands = tuple(_rewrite(value, layout, image) for value in node.operands)
        if operands != node.operands:
            node = Operation(
                node.offset, node.size, node.kind, operands, node.raw, node.confidence
            )
            changes += 1
        result.append(node)
    return result, changes


def _layout(nodes: list[Operation], image: bytes) -> _Layout | None:
    marker = _pool_marker(image)
    if marker is None:
        return None
    targets = _assigned_targets(nodes)
    scalar_end = max((address + 4 for address in targets), default=VAR_BASE)
    first_base = _align16(scalar_end) + 4
    references = _reference_addresses(nodes)
    highest_reference = max((address for address, _kind in references), default=first_base)
    last_base = max(first_base, _align16(highest_reference + 4) + 4)
    candidates = [
        layout
        for pool_base in range(first_base, last_base + 1, 16)
        if (layout := _candidate_layout(image, marker, pool_base)) is not None
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda layout: _evidence_score(layout, references))


def _pool_marker(image: bytes) -> int | None:
    marker = image.rfind(_MARKER)
    if marker < 0 or marker + 4 != len(image) - _POOL_EOF_GAP:
        return None
    return marker


def _assigned_targets(nodes: list[Operation]) -> set[int]:
    targets = set()
    kinds = {"machine.store", "machine.update", "ir.assign"}
    for node in nodes:
        if node.kind in kinds and (address := _target_address(node.operands[0])):
            targets.add(address)
    return targets


def _candidate_layout(image: bytes, marker: int, pool_base: int) -> _Layout | None:
    ds = marker - (pool_base - 4)
    if ds < 0 or image[ds + pool_base - 4 : ds + pool_base] != _MARKER:
        return None
    descriptors, after = _descriptors(image, ds, pool_base)
    string_base = _string_base(image, ds, descriptors, after)
    return _Layout(ds, pool_base, descriptors, string_base)


def _reference_addresses(nodes: list[Operation]) -> tuple[tuple[int, str], ...]:
    found = []
    for node in nodes:
        _collect_references(node.operands, found)
    return tuple(found)


def _collect_references(value: object, found: list[tuple[int, str]]) -> None:
    if not isinstance(value, (tuple, list)):
        return
    if isinstance(value, tuple):
        if (
            len(value) >= 2
            and value[0] == "string-address"
            and isinstance(value[1], int)
        ):
            found.append((value[1], "string"))
        elif memory := _memory_reference(value):
            found.append(memory)
    for item in value:
        _collect_references(item, found)


def _evidence_score(layout: _Layout, references: tuple[tuple[int, str], ...]) -> int:
    score = 0
    for address, kind in references:
        if kind == "string" and address in layout.descriptors:
            score += 4 if layout.string_base is not None else 2
        elif kind in {"integer", "float"} and address >= layout.pool_base:
            score += 1
    return score


def _target_address(value: object) -> int | None:
    if isinstance(value, int) and value >= VAR_BASE:
        return value
    if (
        isinstance(value, tuple)
        and len(value) >= 3
        and value[0] == "slot"
        and isinstance(value[2], int)
    ):
        return value[2]
    return None


def _rewrite(value: Any, layout: _Layout, image: bytes) -> Any:
    if not isinstance(value, tuple):
        if isinstance(value, list):
            return [_rewrite(item, layout, image) for item in value]
        return value
    literal = _literal(value, layout, image)
    if literal is not None:
        return literal
    return tuple(_rewrite(item, layout, image) for item in value)


def _literal(value: tuple[Any, ...], layout: _Layout, image: bytes) -> object | None:
    if len(value) >= 2 and value[0] == "string-address":
        return _string_literal(value[1], layout, image)
    memory = _memory_reference(value)
    if memory is None:
        return None
    address, kind = memory
    if address < layout.pool_base:
        return None
    offset = layout.ds + address
    if kind == "integer" and offset + 2 <= len(image):
        return "const", struct.unpack_from("<H", image, offset)[0]
    if kind == "float" and offset + 4 <= len(image):
        number = struct.unpack_from("<f", image, offset)[0]
        return ("const", number) if math.isfinite(number) else None
    return None


def _memory_reference(value: tuple[Any, ...]) -> tuple[int, str] | None:
    if (
        len(value) >= 3
        and value[0] == "memory"
        and isinstance(value[1], int)
        and isinstance(value[2], str)
    ):
        return value[1], value[2]
    if (
        len(value) >= 4
        and value[0] == "slot"
        and isinstance(value[2], int)
        and isinstance(value[3], str)
    ):
        return value[2], value[3]
    return None


def _descriptors(
    image: bytes, ds: int, pool_base: int
) -> tuple[dict[int, tuple[int, int]], int]:
    descriptors = {}
    address = pool_base
    expected = struct.unpack_from("<H", _MARKER, 2)[0]
    while ds + address + 4 <= len(image):
        length_word, pointer = struct.unpack_from("<HH", image, ds + address)
        if not length_word & 0x8000 or pointer != expected:
            break
        length = length_word & 0x7FFF
        descriptors[address] = length, pointer
        expected += length
        address += 4
    return descriptors, address


def _string_base(
    image: bytes,
    ds: int,
    descriptors: dict[int, tuple[int, int]],
    after: int,
) -> int | None:
    if not descriptors:
        return None
    total = sum(length for length, _pointer in descriptors.values())
    header = struct.pack("<H", 0x8000 | total)
    for candidate in range(_align16(after), len(image) - ds, 16):
        position = ds + candidate + 0x10
        if _is_string_record(image, position, header, total):
            return candidate
    return None


def _is_string_record(image: bytes, position: int, header: bytes, total: int) -> bool:
    return (
        image[position : position + 2] == header
        and image[position + 2 : position + 6] == b"\x00\x00\x00\x00"
        and image[position + 6 + total : position + 8 + total] == header
    )


def _string_literal(address: object, layout: _Layout, image: bytes) -> object | None:
    if not isinstance(address, int) or layout.string_base is None:
        return None
    descriptor = layout.descriptors.get(address)
    if descriptor is None:
        return None
    length, pointer = descriptor
    start = layout.ds + layout.string_base + pointer
    stop = start + length
    if not 0 <= start <= stop <= len(image):
        return None
    return "string", image[start:stop].decode("latin-1")


def _align16(value: int) -> int:
    return (value + 15) & ~15
