"""Reconstruct source-level statement boundaries from lifted operations."""

from __future__ import annotations

from tbd.ir import Operation, Statement

_SIMPLE_KINDS = {
    "ir.assign": "Assign",
    "ir.delay": "Delay",
    "ir.defseg": "DefSeg",
    "ir.dim": "Dim",
    "ir.print": "Print",
    "ir.if_goto": "IfGoto",
    "ir.inline": "Inline",
    "ir.out": "Out",
    "ir.wait": "Wait",
    "ir.gosub": "Gosub",
    "ir.return": "Return",
    "ir.resume": "Resume",
    "ir.run": "Run",
    "ir.call": "CallStmt",
    "ir.tron": "Tron",
    "ir.troff": "Troff",
    "flow.goto": "Goto",
    "flow.call": "Call",
    "flow.return": "Return",
}


def reconstruct(operations: tuple[Operation, ...]) -> tuple[Statement, ...]:
    candidates = _statement_operations(list(operations))
    return _reconstruct_scope(candidates)


def _reconstruct_scope(candidates: list[Operation]) -> tuple[Statement, ...]:
    visible = _visible_operations(candidates)
    addresses = [operation.offset for operation in visible]
    statements = []
    for index, operation in enumerate(visible):
        kind, operands = _statement(operation, candidates)
        operands = _resolve_operands(kind, operands, addresses)
        statements.append(Statement(index, operation.offset, kind, operands))
    return tuple(statements)


def _visible_operations(candidates: list[Operation]) -> list[Operation]:
    procedures = [node for node in candidates if node.kind == "ir.sub_def"]
    inline = [node for node in candidates if node.kind == "ir.inline"]
    return [
        node
        for node in candidates
        if (
            node.kind == "ir.sub_def"
            or not any(_inside(node, procedure) for procedure in procedures)
        )
        and (
            node.kind == "ir.inline"
            or not any(_covered_by_inline(node, region) for region in inline)
        )
    ]


def _inside(node: Operation, procedure: Operation) -> bool:
    return procedure.offset < node.offset and node.end <= procedure.end


def _covered_by_inline(node: Operation, region: Operation) -> bool:
    return region.offset <= node.offset and node.end <= region.end


def _statement_operations(nodes: list[Operation]) -> list[Operation]:
    result = []
    index = 0
    while index < len(nodes):
        window = nodes[index : index + 5]
        if delay := _delay(window):
            result.append(delay)
            index += 5
            continue
        node = nodes[index]
        if node.kind in _SIMPLE_KINDS or node.kind in {"ir.sub_def", "tb.statement"}:
            result.append(node)
        index += 1
    return result


def _delay(nodes: list[Operation]) -> Operation | None:
    if len(nodes) != 5:
        return None
    value, begin, poll, commit, branch = nodes
    if [value.kind, begin.kind, poll.kind, commit.kind, branch.kind] != [
        "expr.value", "tb.statement", "tb.statement", "tb.commit", "flow.branch"
    ]:
        return None
    if begin.operands[0] != "DELAY_INIT" or poll.operands[0] != "DELAY_POLL":
        return None
    if branch.operands[1] != poll.offset:
        return None
    raw = " ".join(node.raw for node in nodes)
    return Operation(
        value.offset,
        branch.end - value.offset,
        "ir.delay",
        value.operands,
        raw,
        "semantic",
    )


def _statement(
    operation: Operation, candidates: list[Operation]
) -> tuple[str, tuple[object, ...]]:
    if operation.kind == "ir.sub_def":
        entry, parameters = operation.operands
        body = _reconstruct_scope(
            [node for node in candidates if _inside(node, operation)]
        )
        return "SubDef", (entry, parameters, body)
    if operation.kind == "ir.delay":
        return "Delay", operation.operands
    if operation.kind == "ir.dim":
        return "Dim", operation.operands[1:]
    if operation.kind == "tb.statement":
        name = operation.operands[0]
        kind = "End" if name == "END" else str(name).title().replace("_", "")
        return kind, operation.operands[2:]
    return _SIMPLE_KINDS[operation.kind], operation.operands


def _resolve_operands(
    kind: str, operands: tuple[object, ...], addresses: list[int]
) -> tuple[object, ...]:
    if kind == "IfGoto":
        condition, left, right, target, _false_target = operands
        return condition, left, right, _resolve(target, addresses)
    if kind == "Goto":
        return (_resolve(operands[0], addresses),)
    if kind == "Gosub":
        return (_resolve(operands[0], addresses),)
    if kind == "Return" and operands:
        return (_resolve(operands[0], addresses),)
    if kind == "Resume" and operands and isinstance(operands[0], int):
        return (_resolve(operands[0], addresses),)
    if kind == "OnError" and operands and operands[0] is not None:
        return (_resolve(operands[0], addresses),)
    if kind == "OnTrap" and len(operands) == 2:
        return operands[0], _resolve(operands[1], addresses)
    if kind in {"OnGoto", "OnGosub"}:
        return tuple(_resolve(target, addresses) for target in operands)
    return operands


def _resolve(target: object, addresses: list[int]) -> object:
    if not isinstance(target, int):
        return target
    for index, address in enumerate(addresses):
        if address >= target:
            return index
    return "address", target
