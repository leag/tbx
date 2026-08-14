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
_ARRAY_BLOCK = 0x36
_ARRAY_TYPES = {
    0x00: "integer",
    0x02: "long",
    0x04: "float",
    0x06: "double",
    0x0A: "string",
}


@dataclass(frozen=True)
class StaticArrayLayout:
    record: int
    slot: int
    base: int
    kind: str
    bounds: tuple[tuple[int, int], ...]
    element_size: int
    count: int


@dataclass(frozen=True)
class PoolLayout:
    marker: int
    ds: int
    pool_base: int
    descriptors: dict[int, tuple[int, int]]
    string_base: int | None
    arrays: tuple[StaticArrayLayout, ...] = ()


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


def _layout(nodes: list[Operation], image: bytes) -> PoolLayout | None:
    targets = _assigned_targets(nodes)
    references = _reference_addresses(nodes)
    return infer_layout(image, targets, references)


def infer_layout(
    image: bytes,
    targets: set[int],
    references: tuple[tuple[int, str], ...],
) -> PoolLayout | None:
    """Choose the best anchored pool candidate for observed memory evidence."""

    marker = _pool_marker(image)
    if marker is None:
        return None
    observed = {*targets, *(address for address, _kind in references)}
    scalar_end = max((address + 4 for address in targets), default=VAR_BASE)
    legacy_first = _align16(scalar_end) + 4
    highest_reference = max(observed, default=legacy_first)
    last_base = max(legacy_first, _align16(highest_reference + 4) + 4)
    legacy_candidates = [
        layout
        for pool_base in range(legacy_first, last_base + 1, 16)
        if (layout := _candidate_layout(image, marker, pool_base)) is not None
    ]
    legacy = (
        max(legacy_candidates, key=lambda layout: _literal_score(layout, references))
        if legacy_candidates
        else None
    )
    array_first = _align16(VAR_BASE) + 4
    array_candidates = [
        layout
        for pool_base in range(array_first, last_base + 1, 16)
        if (layout := _candidate_layout(image, marker, pool_base)) is not None
        and layout.arrays
        and _supports_observations(layout, targets, references)
        and any(_array_at(layout, address) is not None for address in observed)
    ]
    if not array_candidates:
        return legacy
    scored = [
        (layout, _evidence_score(layout, targets, references))
        for layout in array_candidates
    ]
    best = max(score for _layout, score in scored)
    winners = [layout for layout, score in scored if score == best]
    return winners[0] if len(winners) == 1 else None


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


def _candidate_layout(
    image: bytes, marker: int, pool_base: int
) -> PoolLayout | None:
    ds = marker - (pool_base - 4)
    if ds < 0 or image[ds + pool_base - 4 : ds + pool_base] != _MARKER:
        return None
    descriptors, after = _descriptors(image, ds, pool_base)
    string_base = _string_base(image, ds, descriptors, after)
    arrays = _static_arrays(image, ds, pool_base)
    return PoolLayout(marker, ds, pool_base, descriptors, string_base, arrays)


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


def _evidence_score(
    layout: PoolLayout,
    targets: set[int],
    references: tuple[tuple[int, str], ...],
) -> tuple[int, int, int]:
    array_accesses = sum(
        _array_at(layout, address) is not None
        for address in {*targets, *(item[0] for item in references)}
    )
    return array_accesses, len(layout.arrays), _literal_score(layout, references)


def _literal_score(
    layout: PoolLayout, references: tuple[tuple[int, str], ...]
) -> int:
    score = 0
    for address, kind in references:
        if kind == "string" and address in layout.descriptors:
            score += 4 if layout.string_base is not None else 2
        elif kind in {"integer", "float"} and address >= layout.pool_base:
            score += 1
    return score


def _supports_observations(
    layout: PoolLayout,
    targets: set[int],
    references: tuple[tuple[int, str], ...],
) -> bool:
    scalar_base = VAR_BASE + _ARRAY_BLOCK * len(layout.arrays)
    for address in targets:
        if _array_at(layout, address) is not None:
            continue
        if not _is_scalar(address, scalar_base, layout.pool_base):
            return False
    for address, kind in references:
        if _array_at(layout, address) is not None:
            continue
        if _is_scalar(address, scalar_base, layout.pool_base):
            continue
        if kind == "string" and (
            address == layout.pool_base - 4 or address in layout.descriptors
        ):
            continue
        if kind in {"integer", "float"} and address >= layout.pool_base:
            continue
        return False
    return True


def _is_scalar(address: int, scalar_base: int, pool_base: int) -> bool:
    return (
        scalar_base <= address
        and address + 4 <= pool_base - 4
        and (address - scalar_base) % 4 == 0
    )


def _array_at(layout: PoolLayout, address: int) -> StaticArrayLayout | None:
    return next(
        (
            array
            for array in layout.arrays
            if array.base <= address < array.base + array.count * array.element_size
        ),
        None,
    )


def _static_arrays(
    image: bytes, ds: int, pool_base: int
) -> tuple[StaticArrayLayout, ...]:
    arrays = []
    cursor = ds + VAR_BASE
    stop = min(len(image), ds + pool_base)
    while cursor + 8 <= stop:
        slot = VAR_BASE + _ARRAY_BLOCK * len(arrays)
        array = _static_array(image, cursor, slot)
        if array is None:
            cursor += 2
            continue
        arrays.append(array)
        cursor += 6 * len(array.bounds) + 6
    return tuple(arrays)


def _static_array(
    image: bytes, record: int, slot: int
) -> StaticArrayLayout | None:
    if record < 0 or record + 8 > len(image):
        return None
    paragraph, typed_rank, count, element_size = struct.unpack_from(
        "<4H", image, record
    )
    rank, type_code = typed_rank >> 8, typed_rank & 0xFF
    kind = _ARRAY_TYPES.get(type_code)
    if (
        paragraph == 0
        or rank not in (1, 2, 3, 4)
        or kind is None
        or count <= 1
        or element_size not in (2, 4, 8)
    ):
        return None
    bounds = []
    cursor = record + 8
    span = 1
    for dimension in range(rank):
        if cursor + 4 > len(image):
            return None
        low, high = struct.unpack_from("<2H", image, cursor)
        if high < low:
            return None
        bounds.append((low, high))
        cursor += 4
        if dimension < rank - 1:
            if cursor + 2 > len(image):
                return None
            (stored_span,) = struct.unpack_from("<H", image, cursor)
            span *= high - low + 1
            if stored_span != span:
                return None
            cursor += 2
    expected = span * (bounds[-1][1] - bounds[-1][0] + 1)
    if count != expected:
        return None
    return StaticArrayLayout(
        record,
        slot,
        paragraph << 4,
        kind,
        tuple(bounds),
        element_size,
        count,
    )


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


def _rewrite(value: Any, layout: PoolLayout, image: bytes) -> Any:
    if not isinstance(value, tuple):
        if isinstance(value, list):
            return [_rewrite(item, layout, image) for item in value]
        return value
    literal = _literal(value, layout, image)
    if literal is not None:
        return literal
    return tuple(_rewrite(item, layout, image) for item in value)


def _literal(
    value: tuple[Any, ...], layout: PoolLayout, image: bytes
) -> object | None:
    if len(value) >= 2 and value[0] == "string-address":
        return decode_literal(image, layout, value[1], "string")
    memory = _memory_reference(value)
    if memory is None:
        return None
    return decode_literal(image, layout, *memory)


def decode_literal(
    image: bytes, layout: PoolLayout, address: object, kind: str
) -> object | None:
    """Decode one supported reference under an already anchored layout."""

    if kind == "string":
        return _string_literal(address, layout, image)
    if not isinstance(address, int):
        return None
    if address < layout.pool_base:
        return None
    offset = layout.ds + address
    if kind == "integer" and offset + 2 <= len(image):
        return "const", struct.unpack_from("<H", image, offset)[0]
    if kind == "float" and offset + 4 <= len(image):
        number = struct.unpack_from("<f", image, offset)[0]
        return ("const", number) if math.isfinite(number) else None
    return None


def array_at(
    layout: PoolLayout, address: object
) -> StaticArrayLayout | None:
    """Return the uniquely containing static array element span, if any."""

    if not isinstance(address, int):
        return None
    return _array_at(layout, address)


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


def _string_literal(
    address: object, layout: PoolLayout, image: bytes
) -> object | None:
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
