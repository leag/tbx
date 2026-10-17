from __future__ import annotations

import bisect
import heapq
import struct

from tbd.ir import BasicBlock, CrossReference, Diagnostic, Operation
from tbd.profile import EC_RELATIVE_TARGET_SUBS
from tbd.x86 import decode_instruction, rebase_near_target

_CONDITIONAL = {
    *(
        f"x86.{name}"
        for name in (
            "jo",
            "jno",
            "jb",
            "jae",
            "je",
            "jne",
            "jbe",
            "ja",
            "js",
            "jns",
            "jp",
            "jnp",
            "jl",
            "jge",
            "jle",
            "jg",
            "loopne",
            "loope",
            "loop",
            "jcxz",
        )
    ),
}
_JUMPS = {"x86.jmp", "x86.jmp_far"}
_CALLS = {"x86.call", "x86.call_far", "tb.checked_gosub", "tb.fn_call"}
_RETURNS = {"x86.ret", "x86.retf", "x86.iret", "tb.checked_return"}
_TARGETED_RETURNS = {"tb.return_to"}
_TERMINALS = _RETURNS | {
    "tb.epilogue",
    "tb.proc_return",
    "tb.fn_return",
    "x86.hlt",
}


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
    """Discover reachable instructions, blocks, cross-references, and diagnostics."""

    pending = [start]
    queued = {start}
    leaders = {start}
    instructions: dict[int, Operation] = {}
    occupied: dict[int, int] = {}
    xrefs: set[CrossReference] = set()
    conflicts = 0
    reached_limit = False
    # Bases of the code segments far transfers have named so far.  A near
    # jump's rel16 wraps within the segment it sits in, and code past the
    # first 64 KB lives in segments that only a far jump or call names.
    segment_bases = [start]
    while pending:
        cursor = heapq.heappop(pending)
        while start <= cursor < stop and cursor not in instructions:
            if cursor in occupied:
                conflicts += 1
                break
            operation = decode_instruction(exe, cursor, stop, start, dialect)
            base = segment_bases[bisect.bisect_right(segment_bases, cursor) - 1]
            if base != start:
                operation = rebase_near_target(exe, operation, base)
            if operation.kind in {"x86.jmp_far", "x86.call_far"}:
                named = start + operation.operands[1] * 16
                if start < named < stop and named not in segment_bases:
                    bisect.insort(segment_bases, named)
            if any(byte in occupied for byte in range(cursor, operation.end)):
                conflicts += 1
                break
            instructions[cursor] = operation
            for byte in range(cursor, operation.end):
                occupied[byte] = cursor
            cursor, end_path = _follow(
                exe,
                operation,
                instructions,
                pending,
                queued,
                leaders,
                xrefs,
                start,
                stop,
                dialect,
            )
            if end_path:
                break
        reached_limit |= cursor == stop
    ordered = tuple(instructions[offset] for offset in sorted(instructions))
    blocks = _build_blocks(instructions, leaders)
    diagnostics = _discovery_diagnostics(ordered, conflicts, reached_limit)
    return ordered, blocks, tuple(sorted(xrefs, key=_xref_key)), diagnostics


def _follow(
    exe: bytes,
    operation: Operation,
    instructions: dict[int, Operation],
    pending: list[int],
    queued: set[int],
    leaders: set[int],
    xrefs: set[CrossReference],
    start: int,
    stop: int,
    dialect: str | None,
) -> tuple[int, bool]:
    next_offset = operation.end
    handler = _handler_target(operation)
    if handler is not None:
        xrefs.add(CrossReference(operation.offset, handler, "handler"))
        _queue(handler, pending, queued, leaders, start, stop)
    if operation.kind in _CALLS:
        _add_target(operation, "call", pending, queued, leaders, xrefs, start, stop)
        return next_offset, False
    if operation.kind in _CONDITIONAL:
        _add_target(operation, "branch", pending, queued, leaders, xrefs, start, stop)
        _queue(next_offset, pending, queued, leaders, start, stop)
        xrefs.add(CrossReference(operation.offset, next_offset, "fallthrough"))
        return next_offset, True
    if operation.kind in _TARGETED_RETURNS:
        _add_target(operation, "return", pending, queued, leaders, xrefs, start, stop)
        if operation.kind in {"x86.ret", "x86.retf"} and next_offset < stop:
            declaration = decode_instruction(exe, next_offset, stop, start, dialect)
            if (
                declaration is not None
                and dialect is not None
                and _function_declaration_fallthrough(
                    exe, declaration, start, stop, dialect
                )
            ):
                _queue(next_offset, pending, queued, leaders, start, stop)
                xrefs.add(CrossReference(operation.offset, next_offset, "orphan"))
        return next_offset, True
    if operation.kind == "tb.run":
        _add_target(operation, "run", pending, queued, leaders, xrefs, start, stop)
        _queue(next_offset, pending, queued, leaders, start, stop)
        xrefs.add(CrossReference(operation.offset, next_offset, "orphan"))
        return next_offset, True
    if _is_multi_target_dispatch(operation):
        edge = "call" if operation.operands[0] == "ON_GOSUB" else "branch"
        for target in operation.operands[2:]:
            if isinstance(target, int):
                xrefs.add(CrossReference(operation.offset, target, edge))
                _queue(target, pending, queued, leaders, start, stop)
        _queue(next_offset, pending, queued, leaders, start, stop)
        xrefs.add(CrossReference(operation.offset, next_offset, "fallthrough"))
        return next_offset, False
    if operation.kind in _JUMPS:
        _add_target(operation, "jump", pending, queued, leaders, xrefs, start, stop)
        if dialect is not None and (
            _wrapped_forward_gap(operation, start, stop)
            or _resume_jump_fallthrough(operation, instructions)
            or _backward_jump_fallthrough(operation)
            or _procedure_declaration_fallthrough(exe, operation, start, stop, dialect)
            or _function_declaration_fallthrough(exe, operation, start, stop, dialect)
        ):
            _queue(next_offset, pending, queued, leaders, start, stop)
            xrefs.add(CrossReference(operation.offset, next_offset, "orphan"))
        return next_offset, True
    if operation.kind in _RETURNS and next_offset < stop:
        declaration = decode_instruction(exe, next_offset, stop, start, dialect)
        if (
            declaration is not None
            and dialect is not None
            and _function_declaration_fallthrough(
                exe, declaration, start, stop, dialect
            )
        ):
            _queue(next_offset, pending, queued, leaders, start, stop)
            xrefs.add(CrossReference(operation.offset, next_offset, "orphan"))
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


def _resume_jump_fallthrough(
    operation: Operation, instructions: dict[int, Operation]
) -> bool:
    begin = instructions.get(operation.offset - 3)
    return (
        begin is not None
        and begin.end == operation.offset
        and begin.kind == "tb.statement"
        and begin.operands[:2] == ("RESUME_BEGIN", 0xBC)
    )


def _backward_jump_fallthrough(operation: Operation) -> bool:
    raw = bytes.fromhex(operation.raw)
    target = operation.operands[0] if operation.operands else None
    return (
        operation.kind == "x86.jmp"
        and raw[:1] == b"\xeb"
        and isinstance(target, int)
        and target < operation.offset
    )


def _procedure_declaration_fallthrough(
    exe: bytes,
    operation: Operation,
    start: int,
    stop: int,
    dialect: str,
) -> bool:

    target = operation.operands[0] if operation.operands else None
    if not isinstance(target, int) or target <= operation.end:
        return False
    successor = decode_instruction(exe, operation.end, stop, start, dialect)
    return successor.kind == "tb.proc_enter"


def _function_declaration_fallthrough(
    exe: bytes,
    operation: Operation,
    start: int,
    stop: int,
    dialect: str,
) -> bool:

    target = operation.operands[0] if operation.operands else None
    if (
        operation.kind != "x86.jmp"
        or not isinstance(target, int)
        or target <= operation.end + 2
        or target > stop
    ):
        return False
    returned = decode_instruction(exe, target - 2, stop, start, dialect)
    return returned.kind == "tb.fn_return" and returned.end == target


def _handler_target(operation: Operation) -> int | None:
    if (
        operation.kind == "tb.statement"
        and len(operation.operands) == 3
        and operation.operands[1] in EC_RELATIVE_TARGET_SUBS
        and isinstance(operation.operands[2], int)
    ):
        return operation.operands[2]
    return None


def _is_multi_target_dispatch(operation: Operation) -> bool:
    return (
        operation.kind == "tb.statement"
        and len(operation.operands) >= 2
        and operation.operands[0] in {"ON_GOSUB", "ON_GOTO"}
        and operation.operands[1] in {0x72, 0x74}
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
        if operation.kind in _CONDITIONAL | _JUMPS | _TARGETED_RETURNS | _TERMINALS | {
            "tb.run"
        } or _is_multi_target_dispatch(operation):
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
        return tuple(
            value for value in (target, operation.end) if value in instructions
        )
    if operation.kind in _JUMPS:
        return (target,) if target in instructions else ()
    if operation.kind in _TARGETED_RETURNS:
        return (target,) if target in instructions else ()
    if operation.kind == "tb.run":
        return (target,) if target in instructions else ()
    if _is_multi_target_dispatch(operation):
        return tuple(
            value
            for value in (*operation.operands[2:], operation.end)
            if value in instructions
        )
    if operation.kind in _TERMINALS:
        return ()
    return (operation.end,) if operation.end in instructions else ()


def _discovery_diagnostics(
    instructions: tuple[Operation, ...], conflicts: int, reached_limit: bool
) -> tuple[Diagnostic, ...]:
    diagnostics = []
    opaque = sum(item.size for item in instructions if item.confidence == "opaque")
    if opaque:
        diagnostics.append(Diagnostic(f"preserved {opaque} unrecognized byte(s)"))
    if conflicts:
        diagnostics.append(
            Diagnostic(f"ignored {conflicts} overlapping code target(s)")
        )
    if reached_limit:
        diagnostics.append(Diagnostic("code discovery reached the scan limit"))
    return tuple(diagnostics)


def _xref_key(xref: CrossReference) -> tuple[int, int, str]:
    return xref.source, xref.target, xref.kind
