"""Normalize compiler branch pairs into source-shaped conditional jumps."""

from __future__ import annotations

from tbd.ir import Operation

_FALSE_TESTS = {
    "=": "<>",
    "<>": "=",
    "<u": "<=",
    ">=u": ">",
    "<=u": "<",
    ">u": ">=",
    "<": ">=",
    ">=": ">",
    "<=": "<",
    ">": "<=",
}


def lift_if_gotos(
    nodes: list[Operation], _protected: set[int]
) -> tuple[list[Operation], int]:
    result = []
    changes = 0
    index = 0
    while index < len(nodes):
        window = nodes[index : index + 5]
        if replacement := _if_goto(window):
            result.append(replacement)
            changes += 1
            index += 5
        else:
            result.append(nodes[index])
            index += 1
    return result, changes


def _if_goto(nodes: list[Operation]) -> Operation | None:
    if len(nodes) != 5 or not _contiguous(nodes):
        return None
    compare, status, commit, branch, jump = nodes
    if [status.kind, commit.kind, branch.kind, jump.kind] != [
        "expr.status", "tb.commit", "flow.branch", "flow.goto"
    ]:
        return None
    if compare.kind != "expr.compare":
        return None
    false_test, false_target = branch.operands
    condition = _FALSE_TESTS.get(false_test)
    if condition is None:
        return None
    top, memory = compare.operands
    operands = (condition, memory, top, jump.operands[0], false_target)
    return _merge(nodes, "ir.if_goto", operands)


def _contiguous(nodes: list[Operation]) -> bool:
    return all(left.end == right.offset for left, right in zip(nodes, nodes[1:]))


def _merge(
    nodes: list[Operation], kind: str, operands: tuple[object, ...]
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
