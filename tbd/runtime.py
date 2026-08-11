"""Lift small, signature-proven Turbo Basic runtime call chains."""

from __future__ import annotations

from collections.abc import Callable

from tbd.ir import Operation

_NUMERIC_ITEMS = {0xBB: "console", 0xBD: "file", 0xBC: "printer"}
_STRING_ITEMS = {0xBE: "console", 0xC0: "file", 0xBF: "printer"}
_FLUSHES = {0xB8: "console", 0xBA: "file", 0xB9: "printer"}


def lift_runtime(
    nodes: list[Operation], protected: set[int]
) -> tuple[list[Operation], int]:
    nodes, named = _name_helpers(nodes)
    nodes, numeric = _rewrite_pairs(nodes, protected, _numeric_item)
    nodes, strings = _rewrite_triples(nodes, protected, _string_item)
    nodes, combined = _rewrite_pairs(nodes, protected, _combine_items)
    nodes, flushed = _rewrite_pairs(nodes, protected, _flush_print)
    return nodes, named + numeric + strings + combined + flushed


def _name_helpers(nodes: list[Operation]) -> tuple[list[Operation], int]:
    result = []
    changes = 0
    names = {0x87: "tb.commit", 0x99: "expr.status"}
    for node in nodes:
        vector = _runtime_vector(node)
        kind = names.get(vector)
        if kind:
            node = _replace(node, kind, ())
            changes += 1
        result.append(node)
    return result, changes


def _numeric_item(value: Operation, runtime: Operation) -> Operation | None:
    vector = _runtime_vector(runtime)
    if value.kind != "expr.value" or vector not in _NUMERIC_ITEMS:
        return None
    return _merge((value, runtime), "print.item", (_NUMERIC_ITEMS[vector], value.operands[0]))


def _string_item(
    setup: Operation, push: Operation, runtime: Operation
) -> Operation | None:
    vector = _runtime_vector(runtime)
    if setup.kind != "x86.mov_imm" or setup.operands[0] != "si":
        return None
    if _runtime_vector(push) != 0x9C or vector not in _STRING_ITEMS:
        return None
    value = ("string-address", setup.operands[1])
    return _merge((setup, push, runtime), "print.item", (_STRING_ITEMS[vector], value))


def _combine_items(left: Operation, right: Operation) -> Operation | None:
    if left.kind not in ("print.item", "print.items") or right.kind != "print.item":
        return None
    if left.operands[0] != right.operands[0]:
        return None
    old = left.operands[1:] if left.kind == "print.items" else (left.operands[1],)
    return _merge((left, right), "print.items", (left.operands[0], *old, right.operands[1]))


def _flush_print(items: Operation, flush: Operation) -> Operation | None:
    vector = _runtime_vector(flush)
    if items.kind not in ("print.item", "print.items") or vector not in _FLUSHES:
        return None
    mode = items.operands[0]
    if mode != _FLUSHES[vector]:
        return None
    values = items.operands[1:] if items.kind == "print.items" else (items.operands[1],)
    return _merge((items, flush), "ir.print", (mode, values, True))


def _rewrite_pairs(
    nodes: list[Operation],
    protected: set[int],
    rule: Callable[[Operation, Operation], Operation | None],
) -> tuple[list[Operation], int]:
    return _rewrite_windows(nodes, protected, 2, lambda window: rule(*window))


def _rewrite_triples(
    nodes: list[Operation],
    protected: set[int],
    rule: Callable[[Operation, Operation, Operation], Operation | None],
) -> tuple[list[Operation], int]:
    return _rewrite_windows(nodes, protected, 3, lambda window: rule(*window))


def _rewrite_windows(
    nodes: list[Operation],
    protected: set[int],
    width: int,
    rule: Callable[[list[Operation]], Operation | None],
) -> tuple[list[Operation], int]:
    result = []
    changes = 0
    index = 0
    while index < len(nodes):
        window = nodes[index : index + width]
        contiguous = len(window) == width and all(
            left.end == right.offset for left, right in zip(window, window[1:])
        )
        safe = contiguous and all(node.offset not in protected for node in window[1:])
        replacement = rule(window) if safe else None
        if replacement:
            result.append(replacement)
            changes += 1
            index += width
        else:
            result.append(nodes[index])
            index += 1
    return result, changes


def _runtime_vector(node: Operation) -> int | None:
    if node.kind != "tb.runtime" or not node.operands:
        return None
    vector = node.operands[0]
    return vector if isinstance(vector, int) else None


def _merge(
    nodes: tuple[Operation, ...], kind: str, operands: tuple[object, ...]
) -> Operation:
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
