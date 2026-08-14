"""Source device-I/O facts over complete compiler instruction scaffolds."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation


def io_statement_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover constant OUT only from its complete register scaffold."""

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
