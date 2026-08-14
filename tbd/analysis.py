"""Recursive code discovery and small fixed-point lifting passes."""

from __future__ import annotations

import heapq
import struct
from collections.abc import Callable

from tbd.assignments import lift_assignments
from tbd.branches import lift_if_gotos
from tbd.ir import BasicBlock, CrossReference, Diagnostic, Operation, PassReport
from tbd.pool import resolve as resolve_pool
from tbd.runtime import lift_runtime
from tbd.slots import identify
from tbd.symbolic import evaluate
from tbd.x86 import decode_instruction

_CONDITIONAL = {
    *(f"x86.{name}" for name in (
        "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
        "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
        "loopne", "loope", "loop", "jcxz",
    )),
}
_JUMPS = {"x86.jmp", "x86.jmp_far"}
_CALLS = {"x86.call", "x86.call_far"}
_RETURNS = {"x86.ret", "x86.retf", "x86.iret"}
_TERMINALS = _RETURNS | {"tb.epilogue", "tb.proc_return", "x86.hlt"}
_CONDITIONS = {
    "x86.je": "=", "x86.jne": "<>", "x86.jb": "<u",
    "x86.jae": ">=u", "x86.jbe": "<=u", "x86.ja": ">u",
    "x86.jl": "<", "x86.jge": ">=", "x86.jle": "<=", "x86.jg": ">",
}
Rewrite = Callable[[list[Operation], set[int]], tuple[list[Operation], int]]


def discover(
    exe: bytes,
    start: int,
    stop: int,
    dialect: str | None,
) -> tuple[
    tuple[Operation, ...],
    tuple[BasicBlock, ...],
    tuple[CrossReference, ...],
    tuple[Diagnostic, ...],
]:
    """Follow control flow from *start*, like a small auto-analysis queue."""

    pending = [start]
    queued = {start}
    leaders = {start}
    instructions: dict[int, Operation] = {}
    occupied: dict[int, int] = {}
    xrefs: set[CrossReference] = set()
    conflicts = 0
    reached_limit = False
    while pending:
        cursor = heapq.heappop(pending)
        while start <= cursor < stop and cursor not in instructions:
            if cursor in occupied:
                conflicts += 1
                break
            operation = decode_instruction(exe, cursor, stop, start, dialect)
            if any(byte in occupied for byte in range(cursor, operation.end)):
                conflicts += 1
                break
            instructions[cursor] = operation
            for byte in range(cursor, operation.end):
                occupied[byte] = cursor
            cursor, end_path = _follow(
                operation, pending, queued, leaders, xrefs, start, stop, dialect
            )
            if end_path:
                break
        reached_limit |= cursor == stop
    ordered = tuple(instructions[offset] for offset in sorted(instructions))
    blocks = _build_blocks(instructions, leaders)
    diagnostics = _discovery_diagnostics(ordered, conflicts, reached_limit)
    return ordered, blocks, tuple(sorted(xrefs, key=_xref_key)), diagnostics


def lift(
    instructions: tuple[Operation, ...],
    blocks: tuple[BasicBlock, ...],
    xrefs: tuple[CrossReference, ...],
    *,
    image: bytes,
    rounds: int = 8,
) -> tuple[tuple[Operation, ...], tuple[PassReport, ...]]:
    """Apply simple rewrites until a round makes no further progress."""

    nodes = list(instructions)
    protected = {block.start for block in blocks} | {xref.target for xref in xrefs}
    signature_count = sum(node.confidence == "signature" for node in nodes)
    reports = [PassReport(0, "signatures", signature_count, len(nodes))]
    rewrites: tuple[tuple[str, Rewrite], ...] = (
        ("symbols", evaluate),
        ("constant-pool", lambda nodes, protected: resolve_pool(nodes, protected, image)),
        ("dgroup-slots", identify),
        ("assignments", lift_assignments),
        ("runtime", lift_runtime),
        ("register-arguments", _fold_register_arguments),
        ("stack-arguments", _fold_stack_arguments),
        ("conditions", _fold_conditions),
        ("control-flow", _lift_control_flow),
        ("if-gotos", lift_if_gotos),
    )
    for round_number in range(1, rounds + 1):
        changed = 0
        for name, rewrite in rewrites:
            nodes, count = rewrite(nodes, protected)
            reports.append(PassReport(round_number, name, count, len(nodes)))
            changed += count
        if changed == 0:
            break
    nodes, count = _group_unknown(nodes, {block.start for block in blocks})
    reports.append(PassReport(round_number, "unknown-regions", count, len(nodes)))
    return tuple(nodes), tuple(reports)


def _follow(
    operation: Operation,
    pending: list[int],
    queued: set[int],
    leaders: set[int],
    xrefs: set[CrossReference],
    start: int,
    stop: int,
    dialect: str | None,
) -> tuple[int, bool]:
    next_offset = operation.end
    if operation.kind in _CALLS:
        _add_target(operation, "call", pending, queued, leaders, xrefs, start, stop)
        return next_offset, False
    if operation.kind in _CONDITIONAL:
        _add_target(operation, "branch", pending, queued, leaders, xrefs, start, stop)
        _queue(next_offset, pending, queued, leaders, start, stop)
        xrefs.add(CrossReference(operation.offset, next_offset, "fallthrough"))
        return next_offset, True
    if operation.kind in _JUMPS:
        _add_target(operation, "jump", pending, queued, leaders, xrefs, start, stop)
        if dialect is not None and _wrapped_forward_gap(operation, start, stop):
            _queue(next_offset, pending, queued, leaders, start, stop)
            xrefs.add(CrossReference(operation.offset, next_offset, "orphan"))
        return next_offset, True
    return next_offset, operation.kind in _TERMINALS


def _wrapped_forward_gap(operation: Operation, start: int, stop: int) -> bool:
    raw = bytes.fromhex(operation.raw)
    if operation.kind != "x86.jmp" or len(raw) != 3 or raw[0] != 0xE9:
        return False
    flat_target = operation.end + struct.unpack_from("<h", raw, 1)[0]
    target = operation.operands[0] if operation.operands else None
    return (
        flat_target < start
        and isinstance(target, int)
        and operation.end < target < stop
    )


def _add_target(
    operation: Operation,
    kind: str,
    pending: list[int],
    queued: set[int],
    leaders: set[int],
    xrefs: set[CrossReference],
    start: int,
    stop: int,
) -> None:
    target = operation.operands[0]
    if not isinstance(target, int):
        return
    xrefs.add(CrossReference(operation.offset, target, kind))
    _queue(target, pending, queued, leaders, start, stop)


def _queue(
    target: int,
    pending: list[int],
    queued: set[int],
    leaders: set[int],
    start: int,
    stop: int,
) -> None:
    if not start <= target < stop:
        return
    leaders.add(target)
    if target not in queued:
        heapq.heappush(pending, target)
        queued.add(target)


def _build_blocks(
    instructions: dict[int, Operation], leaders: set[int]
) -> tuple[BasicBlock, ...]:
    blocks = []
    for leader in sorted(leaders & instructions.keys()):
        offsets = _block_offsets(leader, instructions, leaders)
        if not offsets:
            continue
        last = instructions[offsets[-1]]
        successors = _successors(last, instructions)
        blocks.append(BasicBlock(leader, last.end, tuple(offsets), successors))
    return tuple(blocks)


def _block_offsets(
    leader: int, instructions: dict[int, Operation], leaders: set[int]
) -> list[int]:
    offsets = []
    cursor = leader
    while cursor in instructions:
        operation = instructions[cursor]
        offsets.append(cursor)
        if operation.kind in _CONDITIONAL | _JUMPS | _TERMINALS:
            break
        cursor = operation.end
        if cursor in leaders:
            break
    return offsets


def _successors(
    operation: Operation, instructions: dict[int, Operation]
) -> tuple[int, ...]:
    target = operation.operands[0] if operation.operands else None
    if operation.kind in _CONDITIONAL:
        return tuple(value for value in (target, operation.end) if value in instructions)
    if operation.kind in _JUMPS:
        return (target,) if target in instructions else ()
    if operation.kind in _TERMINALS:
        return ()
    return (operation.end,) if operation.end in instructions else ()


def _fold_register_arguments(
    nodes: list[Operation], protected: set[int]
) -> tuple[list[Operation], int]:
    def replacement(left: Operation, right: Operation) -> Operation | None:
        if left.kind != "x86.mov_imm" or not right.kind.startswith("tb."):
            return None
        argument = ("register", left.operands[0], left.operands[1])
        return _merge((left, right), right.kind, right.operands + (argument,), right.confidence)

    return _rewrite_pairs(nodes, protected, replacement)


def _fold_stack_arguments(
    nodes: list[Operation], protected: set[int]
) -> tuple[list[Operation], int]:
    def replacement(left: Operation, right: Operation) -> Operation | None:
        if left.kind != "x86.push_imm" or not right.kind.startswith("tb."):
            return None
        argument = ("stack", left.operands[0])
        return _merge((left, right), right.kind, right.operands + (argument,), right.confidence)

    return _rewrite_pairs(nodes, protected, replacement)


def _fold_conditions(
    nodes: list[Operation], protected: set[int]
) -> tuple[list[Operation], int]:
    def replacement(left: Operation, right: Operation) -> Operation | None:
        if left.kind not in ("x86.cmp", "x86.or") or right.kind not in _CONDITIONAL:
            return None
        condition = _CONDITIONS.get(right.kind, right.kind.removeprefix("x86."))
        operands = (condition, right.operands[0], ("flags-from", left.kind))
        return _merge((left, right), "flow.if", operands)

    return _rewrite_pairs(nodes, protected, replacement)


def _lift_control_flow(
    nodes: list[Operation], _protected: set[int]
) -> tuple[list[Operation], int]:
    result = []
    changed = 0
    for node in nodes:
        replacement = _flow_operation(node)
        result.append(replacement)
        changed += replacement is not node
    return result, changed


def _flow_operation(node: Operation) -> Operation:
    if node.kind in _CONDITIONAL:
        condition = _CONDITIONS.get(node.kind, node.kind.removeprefix("x86."))
        return _replace(node, "flow.branch", (condition, node.operands[0]))
    if node.kind in _JUMPS:
        return _replace(node, "flow.goto", (node.operands[0],))
    if node.kind in _CALLS:
        return _replace(node, "flow.call", (node.operands[0],))
    if node.kind in _RETURNS:
        return _replace(node, "flow.return", node.operands)
    return node


def _rewrite_pairs(
    nodes: list[Operation],
    protected: set[int],
    replacement: Callable[[Operation, Operation], Operation | None],
) -> tuple[list[Operation], int]:
    result = []
    changed = 0
    index = 0
    while index < len(nodes):
        if index + 1 < len(nodes):
            left, right = nodes[index : index + 2]
            if left.end == right.offset and right.offset not in protected:
                if merged := replacement(left, right):
                    result.append(merged)
                    changed += 1
                    index += 2
                    continue
        result.append(nodes[index])
        index += 1
    return result, changed


def _group_unknown(
    nodes: list[Operation], boundaries: set[int]
) -> tuple[list[Operation], int]:
    result = []
    group: list[Operation] = []
    changes = 0
    for node in nodes:
        if _is_unknown(node) and _can_join(group, node, boundaries):
            group.append(node)
            continue
        changes += _flush_unknown(group, result)
        group = [node] if _is_unknown(node) else []
        if not group:
            result.append(node)
    changes += _flush_unknown(group, result)
    return result, changes


def _is_unknown(node: Operation) -> bool:
    high_level = ("tb.prologue", "tb.statement", "tb.epilogue", "tb.commit")
    semantic = ("flow.", "ir.", "expr.", "machine.")
    return not (node.kind in high_level or node.kind.startswith(semantic))


def _can_join(group: list[Operation], node: Operation, boundaries: set[int]) -> bool:
    return not group or (group[-1].end == node.offset and node.offset not in boundaries)


def _flush_unknown(group: list[Operation], result: list[Operation]) -> int:
    if not group:
        return 0
    kinds = tuple(dict.fromkeys(node.kind for node in group))
    result.append(_merge(group, "unknown.region", (len(group), kinds), "opaque"))
    return max(0, len(group) - 1)


def _merge(
    nodes: list[Operation] | tuple[Operation, ...],
    kind: str,
    operands: tuple[object, ...],
    confidence: str = "semantic",
) -> Operation:
    raw = " ".join(node.raw for node in nodes)
    return Operation(nodes[0].offset, nodes[-1].end - nodes[0].offset, kind, operands, raw, confidence)


def _replace(node: Operation, kind: str, operands: tuple[object, ...]) -> Operation:
    return Operation(node.offset, node.size, kind, operands, node.raw, "semantic")


def _discovery_diagnostics(
    instructions: tuple[Operation, ...], conflicts: int, reached_limit: bool
) -> tuple[Diagnostic, ...]:
    diagnostics = []
    opaque = sum(item.size for item in instructions if item.confidence == "opaque")
    if opaque:
        diagnostics.append(Diagnostic(f"preserved {opaque} unrecognized byte(s)"))
    if conflicts:
        diagnostics.append(Diagnostic(f"ignored {conflicts} overlapping code target(s)"))
    if reached_limit:
        diagnostics.append(Diagnostic("code discovery reached the scan limit"))
    return tuple(diagnostics)


def _xref_key(xref: CrossReference) -> tuple[int, int, str]:
    return xref.source, xref.target, xref.kind
