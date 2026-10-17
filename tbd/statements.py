from __future__ import annotations

from collections import Counter
from dataclasses import replace

from tbd.ir import Operation, Statement

_SIMPLE_KINDS = {
    "ir.assign": "Assign",
    "ir.local": "Local",
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
    "ir.exit_loop": "ExitLoop",
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
    "ir.exit_sub": "ExitSub",
    "ir.tron": "Tron",
    "ir.troff": "Troff",
    "flow.goto": "Goto",
    "flow.call": "Call",
    "flow.return": "Return",
}


def _within(node: Operation, start: int, end: int) -> bool:
    """Whether a node lies in ``[start, end)``; a codeless DO takes no bytes."""
    return start <= node.offset < end and node.end <= end


def reconstruct(operations: tuple[Operation, ...]) -> tuple[Statement, ...]:
    """Reconstruct source-level statements from ordered semantic operations."""
    candidates = _statement_operations(list(operations))
    return _reconstruct_scope(candidates)


def _reconstruct_scope(candidates: list[Operation]) -> tuple[Statement, ...]:
    visible = _pair_loops(_visible_operations(candidates))
    statements = []
    for index, operation in enumerate(visible):
        kind, operands = _statement(operation, candidates)
        operands = _resolve_operands(kind, operands, visible)
        statements.append(Statement(index, operation.offset, kind, operands))
    return tuple(statements)


def _pair_loops(operations: list[Operation]) -> list[Operation]:
    """Keep a DO/LOOP pair only where the LOOP is the one jump back to its DO.

    A LOOP compiles to a jump back to its DO, and a codeless DO to nothing.
    When several jumps return to one place, or a jump returns out of its own
    block, the pair does not exist in BASIC, so each LOOP is written as its
    jump and a codeless DO left without a LOOP is dropped.  A DO with its own
    condition is kept, since its exit test would be lost with it, and pairs
    with the LOOP that nests with it.
    """
    closers = Counter(
        operation.operands[2]
        for operation in operations
        if operation.kind == "ir.loop" and len(operation.operands) == 3
    )
    conditional = {
        operation.offset
        for operation in operations
        if operation.kind == "ir.do" and operation.operands[:2] != (None, None)
    }
    open_dos: list[Operation] = []
    paired: set[int] = set()
    result = []
    for operation in operations:
        if operation.kind == "ir.do":
            open_dos.append(operation)
        elif operation.kind in {"ir.sub_def", "ir.def_fn"}:
            # A procedure cannot be defined inside a DO, so none open spans it.
            open_dos.clear()
        elif operation.kind == "ir.loop" and len(operation.operands) == 3:
            target = operation.operands[2]
            # A DO with its own test stays, so the jump back that nests with
            # it is its LOOP; a codeless one is a LOOP only for its one jump.
            if (
                open_dos
                and open_dos[-1].offset == target
                and (target in conditional or closers[target] == 1)
            ):
                paired.add(id(open_dos.pop()))
                result.append(replace(operation, operands=operation.operands[:2]))
                continue
            result.append(_loop_jump(operation))
            continue
        elif operation.kind == "ir.loop" and open_dos:
            paired.add(id(open_dos.pop()))
        result.append(operation)
    return [
        operation
        for operation in result
        if not (
            operation.kind == "ir.do"
            and id(operation) not in paired
            and operation.offset not in conditional
        )
    ]


_INVERSE = {"=": "<>", "<>": "=", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def _negated(condition: object) -> object | None:
    """Return the condition that holds exactly when ``condition`` does not."""
    if not isinstance(condition, tuple) or not condition:
        return None
    head = condition[0]
    if head == "group" and len(condition) == 2:
        inner = _negated(condition[1])
        return None if inner is None else ("group", inner)
    # ``IF e`` tests ``e <> 0``; ``NOT e`` is true for most non-zero ``e``.
    if head == "truth" and len(condition) == 2:
        return ("=", condition[1], ("const", 0))
    if head in _INVERSE and len(condition) == 3:
        return (_INVERSE[head], condition[1], condition[2])
    if head in {"AND", "OR"} and len(condition) == 3:
        left, right = _negated(condition[1]), _negated(condition[2])
        if left is None or right is None:
            return None
        return ("OR" if head == "AND" else "AND", ("group", left), ("group", right))
    # Any other value is tested for truth, as ``UNTIL EOF(1)`` is.
    return ("=", condition, ("const", 0))


def _loop_jump(loop: Operation) -> Operation:
    """Write a LOOP as the jump back it compiles to, or keep it unchanged."""
    kind, condition, target = loop.operands
    if kind is None:
        return replace(loop, kind="ir.goto", operands=(target,))
    if kind == "UNTIL":
        condition = _negated(condition)
        if condition is None:
            return replace(loop, operands=loop.operands[:2])
    return replace(
        loop, kind="ir.if_goto_condition", operands=(condition, target, None)
    )


def _visible_operations(candidates: list[Operation]) -> list[Operation]:
    procedures = [
        node for node in candidates if node.kind in {"ir.sub_def", "ir.def_fn"}
    ]
    inline = [node for node in candidates if node.kind == "ir.inline"]
    structured = [
        node for node in candidates if node.kind in {"ir.if_inline", "ir.if_block"}
    ]
    covered_regions = [
        node
        for node in candidates
        if node.kind in {"ir.for", "ir.next", "ir.dynamic_dim", "ir.input_file"}
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
            not any(
                node is not region and _owned_by_region(node, region)
                for region in structured
            )
        )
        and not (
            node.kind == "tb.statement"
            and node.operands
            and node.operands[0] == "INCR"
            and any(
                region.kind == "ir.next"
                and node.offset < region.end
                and region.offset < node.end
                for region in covered_regions
            )
        )
        and (
            node.kind in {"ir.for", "ir.next", "ir.dynamic_dim", "ir.input_file"}
            or not any(_covered_by_inline(node, region) for region in covered_regions)
        )
        # Nothing starts inside a FOR or NEXT's code: a NEXT tests the step's
        # sign both ways, and the second test also reads as an IF reaching
        # past the NEXT into the next statement.
        and not any(
            region.kind in {"ir.for", "ir.next"}
            and node is not region
            and region.offset < node.offset < region.end
            for region in covered_regions
        )
    ]


def _used_locals(body: tuple[Statement, ...]) -> tuple[Statement, ...]:
    """Declare only the locals the SUB's statements name.

    A local is typed from the code that uses it, so one no statement names
    is a slot the compiler used for itself, such as the copy of a FOR limit
    (``probes/for_to_parameter_in_sub.bas``). Declaring it would add a
    local the source did not have.
    """
    others = repr(tuple(statement for statement in body if statement.kind != "Local"))
    result = []
    for statement in body:
        if statement.kind == "Local" and statement.operands:
            (locals_,) = statement.operands
            kept = tuple(local for local in locals_ if repr(local) in others)
            if not kept:
                continue
            statement = replace(statement, operands=(kept,))
        result.append(statement)
    return tuple(result)


def _inside(node: Operation, procedure: Operation) -> bool:
    return procedure.offset < node.offset and node.end <= procedure.end


def _covered_by_inline(node: Operation, region: Operation) -> bool:
    return (
        region.offset <= node.offset
        and node.offset < region.end
        and node.end <= region.end
    )


def _owned_by_region(node: Operation, region: Operation) -> bool:
    if region.kind == "ir.if_inline" and len(region.operands) == 4:
        _condition, body_start, body_end, _else_bounds = region.operands
        ranges = ((body_start, body_end),)
    elif region.kind == "ir.if_block" and len(region.operands) == 2:
        arms, else_bounds = region.operands
        if not isinstance(arms, tuple):
            return False
        ranges = tuple(
            (arm[1], arm[2]) for arm in arms if isinstance(arm, tuple) and len(arm) == 3
        ) + (() if else_bounds is None else (else_bounds,))
    else:
        return False
    return any(
        isinstance(start, int) and isinstance(end, int) and _within(node, start, end)
        for start, end in ranges
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
            "ir.if_block",
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
        "expr.value",
        "tb.statement",
        "tb.statement",
        "tb.commit",
        "flow.branch",
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
) -> tuple[str, tuple[object, ...]]:
    if operation.kind == "ir.sub_def":
        entry, parameters = operation.operands
        body = _used_locals(
            _reconstruct_scope(
                [node for node in candidates if _inside(node, operation)]
            )
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
                and _within(node, body_start, body_end)
            ]
        )
        return "IfInline", (condition, body, else_bounds)
    if operation.kind == "ir.if_block":
        arm_bounds, else_bounds = operation.operands
        arms = tuple(
            (
                condition,
                _reconstruct_scope(
                    [
                        node
                        for node in candidates
                        if node is not operation and _within(node, body_start, body_end)
                    ]
                ),
            )
            for condition, body_start, body_end in arm_bounds
        )
        else_body = (
            None
            if else_bounds is None
            else _reconstruct_scope(
                [
                    node
                    for node in candidates
                    if node is not operation and _within(node, *else_bounds)
                ]
            )
        )
        return "IfBlock", (arms, else_body)
    if operation.kind == "ir.if_goto_condition":
        condition, target, _false_target = operation.operands
        return "IfGoto", (*condition, target)
    if operation.kind == "ir.delay":
        return "Delay", operation.operands
    if operation.kind == "ir.dim":
        return "Dim", operation.operands[1:]
    if operation.kind == "ir.def_type":
        return "DefType", operation.operands[1:]
    if operation.kind == "ir.data":
        return "Data", operation.operands[1:]
    if operation.kind == "ir.common":
        return "Common", operation.operands[1:]
    if operation.kind == "ir.option_base":
        return "OptionBase", operation.operands[1:]
    if operation.kind == "tb.statement":
        richer = [
            node
            for node in candidates
            if node is not operation
            and node.kind == "tb.statement"
            and node.offset == operation.offset
            and len(node.operands) > len(operation.operands)
            and node.operands[:1] == operation.operands[:1]
        ]
        if richer:
            operation = max(richer, key=lambda node: len(node.operands))
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
    if operations and target < operations[0].offset:
        return "address", target
    if any(
        operation.kind == "ir.if_block" and operation.offset < target < operation.end
        for operation in operations
    ):
        return "address", target
    for index, operation in enumerate(operations):
        if operation.offset < target:
            continue
        if (
            operation.offset == target
            and operation.size == 0
            and any(
                candidate.offset == target and candidate.size > 0
                for candidate in operations[index + 1 :]
            )
        ):
            continue
        if operation.offset >= target:
            return index
    return "address", target
