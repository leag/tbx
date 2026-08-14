"""Source device-I/O facts over complete compiler instruction scaffolds."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation


def io_statement_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover calibrated I/O statements only from complete scaffolds."""

    instructions = {item.offset: item for item in evidence.instructions}
    for block in evidence.blocks:
        nodes = tuple(
            instructions[offset]
            for offset in block.instruction_offsets
            if offset in instructions
        )
        for index in range(len(nodes) - 4):
            statement = _out_statement(nodes[index : index + 5])
            if statement is not None:
                yield statement
    nodes = tuple(sorted(evidence.instructions, key=lambda item: item.offset))
    edges = {
        (xref.source, xref.target, xref.kind)
        for xref in evidence.xrefs
    }
    for index in range(len(nodes) - 10):
        statement = _wait3_statement(nodes[index : index + 11], edges)
        if statement is not None:
            yield statement


def _out_statement(window: tuple[Operation, ...]) -> Fact | None:
    port_load, port_stage, value_load, dx_stage, terminal = window
    if (
        not _contiguous(window)
        or bytes.fromhex(port_stage.raw) != b"\x89\xc3"
        or bytes.fromhex(dx_stage.raw) != b"\x8b\xd3"
        or terminal.kind != "x86.out_dx_al"
        or bytes.fromhex(terminal.raw) != b"\xee"
    ):
        return None
    port = _ax_constant(port_load)
    value = _ax_constant(value_load)
    if port is None or value is None:
        return None
    return Fact(
        "semantic.out",
        (port_load.offset, terminal.end),
        (("const", port), ("const", value)),
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


def _contiguous(instructions: tuple[Operation, ...]) -> bool:
    return all(
        left.end == right.offset
        for left, right in zip(instructions, instructions[1:])
    )


IO_FACT_PASSES: tuple[NamedPass, ...] = (("device-io", io_statement_facts),)
