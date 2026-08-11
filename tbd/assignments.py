"""Lift proven machine stores into source-shaped assignments."""

from __future__ import annotations

from tbd.ir import Operation


def lift_assignments(
    nodes: list[Operation], protected: set[int]
) -> tuple[list[Operation], int]:
    nodes, consumed = _consume_register_setups(nodes, protected)
    result = []
    converted = 0
    for node in nodes:
        replacement = _assignment(node)
        result.append(replacement)
        converted += replacement is not node
    return result, consumed + converted


def _consume_register_setups(
    nodes: list[Operation], protected: set[int]
) -> tuple[list[Operation], int]:
    result = []
    consumed = 0
    index = 0
    while index < len(nodes):
        pair = nodes[index : index + 2]
        if len(pair) == 2 and _feeds_update(*pair) and pair[1].offset not in protected:
            result.append(_merge(pair, pair[1]))
            consumed += 1
            index += 2
        else:
            result.append(nodes[index])
            index += 1
    return result, consumed


def _feeds_update(setup: Operation, update: Operation) -> bool:
    if setup.kind != "x86.mov_imm" or setup.operands[0] != "ax":
        return False
    if update.kind != "machine.update":
        return False
    return update.operands[2] == ("const", setup.operands[1])


def _assignment(node: Operation) -> Operation:
    if node.kind == "machine.store":
        return _replace(node, "ir.assign", node.operands)
    if node.kind == "machine.update":
        target, operator, value = node.operands
        expression = ("binary", operator, target, value)
        return _replace(node, "ir.assign", (target, expression))
    return node


def _merge(nodes: list[Operation], update: Operation) -> Operation:
    raw = " ".join(node.raw for node in nodes)
    return Operation(
        nodes[0].offset,
        nodes[-1].end - nodes[0].offset,
        update.kind,
        update.operands,
        raw,
        update.confidence,
    )


def _replace(node: Operation, kind: str, operands: tuple[object, ...]) -> Operation:
    return Operation(node.offset, node.size, kind, operands, node.raw, "semantic")
