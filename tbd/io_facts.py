from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import contiguous as _contiguous
from tbd.semantic import Resolved, combine_evidence, resolve_expression


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "signature",
    "slot",
    "x86.and",
    "x86.in_al_dx",
    "x86.je",
    "x86.mov_imm",
    "x86.out_dx_al",
    "x86.xor",
)
def io_statement_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover console, printer, and timing I/O statements."""
    instructions = {item.offset: item for item in evidence.instructions}
    for block in evidence.blocks:
        nodes = tuple(
            instructions[offset]
            for offset in block.instruction_offsets
            if offset in instructions
        )
        for index in range(len(nodes) - 4):
            statement = _out_statement(nodes[index : index + 5], _facts)
            if statement is not None:
                yield statement
    nodes = tuple(sorted(evidence.instructions, key=lambda item: item.offset))
    edges = {(xref.source, xref.target, xref.kind) for xref in evidence.xrefs}
    for index in range(len(nodes) - 10):
        statement = _wait3_statement(nodes[index : index + 11], edges)
        if statement is not None:
            yield statement
    for index in range(len(nodes) - 6):
        statement = _wait_statement(nodes[index : index + 7], edges)
        if statement is not None:
            yield statement


def _out_statement(
    window: tuple[Operation, ...], facts: frozenset[Fact]
) -> Fact | None:
    port_load, port_stage, value_load, dx_stage, terminal = window
    if (
        not _contiguous(window)
        or bytes.fromhex(port_stage.raw) != b"\x89\xc3"
        or bytes.fromhex(dx_stage.raw) != b"\x8b\xd3"
        or terminal.kind != "x86.out_dx_al"
        or bytes.fromhex(terminal.raw) != b"\xee"
    ):
        return None
    port = _ax_value(port_load, facts)
    value = _ax_value(value_load, facts)
    if port is None or value is None:
        return None
    return Fact(
        "semantic.out",
        (port_load.offset, terminal.end),
        (port.value, value.value),
        combine_evidence(
            tuple(instruction.offset for instruction in window),
            port.evidence,
            value.evidence,
        ),
        "signature",
    )


def _wait_statement(
    window: tuple[Operation, ...],
    edges: set[tuple[int, int, str]],
) -> Fact | None:
    mask_load, mask_stage, port_load, port_to_dx, poll, and_al, branch = window
    if (
        not _contiguous(window)
        or bytes.fromhex(mask_stage.raw) != b"\x89\xc3"
        or bytes.fromhex(port_to_dx.raw) != b"\x8b\xd0"
        or (poll.kind, bytes.fromhex(poll.raw)) != ("x86.in_al_dx", b"\xec")
        or (and_al.kind, bytes.fromhex(and_al.raw)) != ("x86.and", b"\x20\xd8")
        or (branch.kind, bytes.fromhex(branch.raw)) != ("x86.je", b"\x74\xfb")
        or branch.operands != (poll.offset,)
        or (branch.offset, poll.offset, "branch") not in edges
        or (branch.offset, branch.end, "fallthrough") not in edges
    ):
        return None
    mask = _ax_constant(mask_load)
    port = _ax_constant(port_load)
    if mask is None or port is None:
        return None
    return Fact(
        "semantic.wait",
        (mask_load.offset, branch.end),
        (("const", port), ("const", mask)),
        tuple(instruction.offset for instruction in window),
        "signature",
    )


def _wait3_statement(
    window: tuple[Operation, ...],
    edges: set[tuple[int, int, str]],
) -> Fact | None:
    (
        mask_load,
        mask_stage,
        xor_load,
        mask_to_cx,
        xor_to_bx,
        port_load,
        port_to_dx,
        poll,
        xor_al,
        and_al,
        branch,
    ) = window
    if (
        not _contiguous(window)
        or bytes.fromhex(mask_stage.raw) != b"\x89\xc3"
        or bytes.fromhex(mask_to_cx.raw) != b"\x89\xd9"
        or bytes.fromhex(xor_to_bx.raw) != b"\x89\xc3"
        or bytes.fromhex(port_to_dx.raw) != b"\x8b\xd0"
        or (poll.kind, bytes.fromhex(poll.raw)) != ("x86.in_al_dx", b"\xec")
        or (xor_al.kind, bytes.fromhex(xor_al.raw)) != ("x86.xor", b"\x30\xd8")
        or (and_al.kind, bytes.fromhex(and_al.raw)) != ("x86.and", b"\x20\xc8")
        or (branch.kind, bytes.fromhex(branch.raw)) != ("x86.je", b"\x74\xf9")
        or branch.operands != (poll.offset,)
        or (branch.offset, poll.offset, "branch") not in edges
        or (branch.offset, branch.end, "fallthrough") not in edges
    ):
        return None
    mask = _ax_constant(mask_load)
    xor_value = _ax_constant(xor_load)
    port = _ax_constant(port_load)
    if mask is None or xor_value is None or port is None:
        return None
    return Fact(
        "semantic.wait",
        (mask_load.offset, branch.end),
        (("const", port), ("const", mask), ("const", xor_value)),
        tuple(instruction.offset for instruction in window),
        "signature",
    )


def _ax_constant(instruction: Operation) -> object | None:
    if (
        instruction.kind == "x86.mov_imm"
        and len(instruction.operands) == 2
        and instruction.operands[0] == "ax"
    ):
        return instruction.operands[1]
    return None


def _ax_value(instruction: Operation, facts: frozenset[Fact]) -> Resolved | None:
    constant = _ax_constant(instruction)
    if constant is not None:
        return resolve_expression(("const", constant), facts)
    raw = bytes.fromhex(instruction.raw)
    if raw == b"\x31\xc0":
        return resolve_expression(("const", 0), facts)
    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
        address = struct.unpack_from("<H", raw, 2)[0]
        return resolve_expression(("memory", address, "integer"), facts)
    return None


IO_FACT_PASSES: tuple[NamedPass, ...] = (("device-io", io_statement_facts),)
