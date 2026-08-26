"""Reconstruct source-level statement boundaries from lifted operations."""

from __future__ import annotations

from tbd.ir import Operation, Statement

_SIMPLE_KINDS = {
    "ir.assign": "Assign",
    "ir.delay": "Delay",
    "ir.defseg": "DefSeg",
    "ir.def_type": "DefType",
    "ir.data": "Data",
    "ir.dim": "Dim",
    "ir.dynamic_dim": "Dim",
    "ir.common": "Common",
    "ir.option_base": "OptionBase",
    "ir.print": "Print",
    "ir.if_goto": "IfGoto",
    "ir.if_goto_condition": "IfGoto",
    "ir.goto": "Goto",
    "ir.if_inline": "IfInline",
    "ir.inline": "Inline",
    "ir.out": "Out",
    "ir.wait": "Wait",
    "ir.lprint": "Lprint",
    "ir.print_using": "PrintUsing",
    "ir.write": "Write",
    "ir.lset": "Lset",
    "ir.rset": "Rset",
    "ir.field": "Field",
    "ir.mid_assign": "MidAssign",
    "ir.swap": "Swap",
    "ir.locate": "Locate",
    "ir.read": "Read",
    "ir.input_file": "InputFile",
    "ir.input": "Input",
    "ir.open": "Open",
    "ir.close": "Close",
    "ir.color": "Color",
    "ir.screen": "Screen",
    "ir.files": "Files",
    "ir.for": "For",
    "ir.next": "NextStmt",
    "ir.do": "Do",
    "ir.loop": "Loop",
    "ir.trap_ctl": "TrapCtl",
    "ir.on_trap": "OnTrap",
    "ir.on_goto": "OnGoto",
    "ir.on_gosub": "OnGosub",
    "ir.gosub": "Gosub",
    "ir.return": "Return",
    "ir.resume": "Resume",
    "ir.run": "Run",
    "ir.call": "CallStmt",
    "ir.fn_result": "FnResult",
    "ir.exit_def": "ExitDef",
    "ir.tron": "Tron",
    "ir.troff": "Troff",
    "flow.goto": "Goto",
    "flow.call": "Call",
    "flow.return": "Return",
}


def reconstruct(operations: tuple[Operation, ...]) -> tuple[Statement, ...]:
    candidates = _statement_operations(list(operations))
    return _reconstruct_scope(candidates)


def _reconstruct_scope(
    candidates: list[Operation],
    resolution_operations: list[Operation] | None = None,
) -> tuple[Statement, ...]:
    visible = _visible_operations(candidates)
    targets = visible if resolution_operations is None else resolution_operations
    statements = []
    for index, operation in enumerate(visible):
        kind, operands = _statement(operation, candidates, targets)
        operands = _resolve_operands(kind, operands, targets)
        statements.append(Statement(index, operation.offset, kind, operands))
    return tuple(statements)


def _visible_operations(candidates: list[Operation]) -> list[Operation]:
    procedures = [
        node for node in candidates if node.kind in {"ir.sub_def", "ir.def_fn"}
    ]
    inline = [node for node in candidates if node.kind == "ir.inline"]
    structured = [node for node in candidates if node.kind == "ir.if_inline"]
    covered_regions = [
        node
        for node in candidates
        if node.kind in {"ir.for", "ir.next", "ir.dynamic_dim"}
    ]
    return [
        node
        for node in candidates
        if (
            node.kind in {"ir.sub_def", "ir.def_fn"}
            or not any(_inside(node, procedure) for procedure in procedures)
        )
        and (
            node.kind == "ir.inline"
            or not any(_covered_by_inline(node, region) for region in inline)
        )
        and (
            node.kind == "ir.if_inline"
            or not any(_owned_by_region(node, region) for region in structured)
        )
        and (
            node.kind in {"ir.for", "ir.next", "ir.dynamic_dim"}
            or not any(_covered_by_inline(node, region) for region in covered_regions)
        )
    ]


def _inside(node: Operation, procedure: Operation) -> bool:
    return procedure.offset < node.offset and node.end <= procedure.end


def _covered_by_inline(node: Operation, region: Operation) -> bool:
    return (
        region.offset <= node.offset
        and node.offset < region.end
        and node.end <= region.end
    )


def _owned_by_region(node: Operation, region: Operation) -> bool:
    if len(region.operands) != 4:
        return False
    _condition, body_start, body_end, _else_bounds = region.operands
    return (
        isinstance(body_start, int)
        and isinstance(body_end, int)
        and body_start <= node.offset < node.end <= body_end
    )


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
        if node.kind in _SIMPLE_KINDS or node.kind in {
            "ir.sub_def",
            "ir.def_fn",
            "tb.statement",
        }:
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
    operation: Operation,
    candidates: list[Operation],
    resolution_operations: list[Operation],
) -> tuple[str, tuple[object, ...]]:
    if operation.kind == "ir.sub_def":
        entry, parameters = operation.operands
        body = _reconstruct_scope(
            [node for node in candidates if _inside(node, operation)]
        )
        return "SubDef", (entry, parameters, body)
    if operation.kind == "ir.def_fn":
        entry, result_kind, parameters, body_or_marker, is_block = operation.operands
        body = (
            _reconstruct_scope(
                [node for node in candidates if _inside(node, operation)]
            )
            if is_block
            else body_or_marker
        )
        return "DefFn", (entry, result_kind, parameters, body, is_block)
    if operation.kind == "ir.if_inline":
        condition, body_start, body_end, else_bounds = operation.operands
        body = _reconstruct_scope(
            [
                node
                for node in candidates
                if node is not operation
                and isinstance(body_start, int)
                and isinstance(body_end, int)
                and body_start <= node.offset < node.end <= body_end
            ],
            resolution_operations,
        )
        return "IfInline", (condition, body, else_bounds)
    if operation.kind == "ir.if_goto_condition":
        condition, target, _false_target = operation.operands
        return "IfGoto", (*condition, target)
    if operation.kind == "ir.delay":
        return "Delay", operation.operands
    if operation.kind == "ir.dim":
        return "Dim", operation.operands[1:]
    if operation.kind == "ir.def_type":
        return "DefType", ()
    if operation.kind == "ir.data":
        return "Data", operation.operands[1:]
    if operation.kind == "ir.common":
        return "Common", operation.operands[1:]
    if operation.kind == "ir.option_base":
        return "OptionBase", operation.operands[1:]
    if operation.kind == "tb.statement":
        name = operation.operands[0]
        kind = "End" if name == "END" else str(name).title().replace("_", "")
        return kind, operation.operands[2:]
    return _SIMPLE_KINDS[operation.kind], operation.operands


def _resolve_operands(
    kind: str, operands: tuple[object, ...], operations: list[Operation]
) -> tuple[object, ...]:
    if kind == "IfGoto":
        if len(operands) == 5:
            condition, left, right, target, _false_target = operands
            return condition, left, right, _resolve(target, operations)
        return (*operands[:-1], _resolve(operands[-1], operations))
    if kind == "Goto":
        return (_resolve(operands[0], operations),)
    if kind == "Gosub":
        return (_resolve(operands[0], operations),)
    if kind == "Return" and operands:
        return (_resolve(operands[0], operations),)
    if kind == "Resume" and operands and isinstance(operands[0], int):
        return (_resolve(operands[0], operations),)
    if kind == "OnError" and operands and operands[0] is not None:
        return (_resolve(operands[0], operations),)
    if kind == "OnTrap" and len(operands) == 3:
        return operands[0], operands[1], _resolve(operands[2], operations)
    if kind in {"OnGoto", "OnGosub"}:
        return operands[:1] + tuple(
            _resolve(target, operations) for target in operands[1:]
        )
    return operands


def _resolve(target: object, operations: list[Operation]) -> object:
    if not isinstance(target, int):
        return target
    for index, operation in enumerate(operations):
        if operation.offset < target:
            continue
        if operation.offset == target and operation.size == 0 and any(
            candidate.offset == target and candidate.size > 0
            for candidate in operations[index + 1 :]
        ):
            continue
        if operation.offset >= target:
            return index
    return "address", target
