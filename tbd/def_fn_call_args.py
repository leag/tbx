from __future__ import annotations

from tbd.compiler_ops import CompilerOp
from tbd.ir import Fact, Operation
from tbd.operation_helpers import movsi_runtime as _movsi_runtime
from tbd.semantic import (
    combine_evidence,
    resolve_expression,
    resolve_expression_before,
)


def stage_call_arguments(
    body: tuple[Operation, ...],
    parameters: tuple[tuple[int, str], ...],
    compiler_by_offset: dict[int, CompilerOp],
    facts: frozenset[Fact],
    instruction_ends: dict[int, int],
) -> tuple[dict[int, object], tuple[tuple[int, ...], ...]] | None:
    """Recover arguments staged before a DEF FN call."""
    parameter_kinds = dict(parameters)
    staged: dict[int, object] = {}
    support: list[tuple[int, ...]] = []
    for index, instruction in enumerate(body):
        operation = compiler_by_offset.get(instruction.offset)
        direct = _direct_integer_argument(operation, parameter_kinds)
        if direct is not None:
            offset, value = direct
            if offset in staged:
                return None
            staged[offset] = value
            if operation is None:
                return None
            support.append((operation.offset,))
            continue
        immediate = _immediate_ax_argument(
            body,
            index,
            operation,
            parameter_kinds,
            compiler_by_offset,
        )
        if immediate is not None:
            offset, value, evidence = immediate
            if offset in staged:
                return None
            staged[offset] = value
            support.append(evidence)
            continue
        numeric = _numeric_argument(
            body,
            index,
            operation,
            parameter_kinds,
            compiler_by_offset,
            facts,
            instruction_ends,
        )
        if numeric is not None:
            offset, value, evidence = numeric
            if offset in staged:
                return None
            staged[offset] = value
            support.append(evidence)
            continue
        string = _string_argument(body, index, parameter_kinds, facts)
        if string is None:
            continue
        offset, value, evidence = string
        if offset in staged:
            return None
        staged[offset] = value
        support.append(evidence)
    return staged, tuple(support)


def numeric_call_result_tail(
    instructions: tuple[Operation, ...],
    call_index: int,
    result_kind: str,
    expected_size: int,
    compiler_by_offset: dict[int, CompilerOp],
) -> tuple[Operation, Operation, tuple[int, ...]] | None:
    """Recover the result and cleanup tail of a numeric DEF FN call."""
    load_kinds = {
        "integer": "movax_bp",
        "long": "fild32_bp",
        "float": "fld_bp",
        "double": "fld64_bp",
    }
    load_kind = load_kinds.get(result_kind)
    wait_count = 0 if result_kind == "integer" else 1
    tail_size = 3 + wait_count
    if load_kind is None or call_index + tail_size >= len(instructions):
        return None
    tail = instructions[call_index + 1 : call_index + 1 + tail_size]
    result_load = tail[0]
    wait = tail[1] if wait_count else None
    release, pop = tail[1 + wait_count :]
    result_operation = compiler_by_offset.get(result_load.offset)
    if not (
        result_operation is not None
        and result_operation.kind == load_kind
        and result_operation.args == (0,)
        and (wait is None or wait.kind == "tb.fwait")
        and bytes.fromhex(release.raw) == bytes((0x83, 0xC4, expected_size))
        and bytes.fromhex(pop.raw) == b"\x5d"
        and all(left.end == right.offset for left, right in zip(tail, tail[1:]))
    ):
        return None
    return result_load, pop, tuple(instruction.offset for instruction in tail)


def _direct_integer_argument(
    operation: CompilerOp | None,
    parameter_kinds: dict[int, str],
) -> tuple[int, object] | None:
    if not (
        operation is not None
        and operation.kind == "mov_bp_imm"
        and len(operation.args) == 2
        and isinstance(operation.args[0], int)
        and parameter_kinds.get(operation.args[0]) == "integer"
    ):
        return None
    return operation.args[0], ("const", operation.args[1])


def _immediate_ax_argument(
    body: tuple[Operation, ...],
    index: int,
    operation: CompilerOp | None,
    parameter_kinds: dict[int, str],
    compiler_by_offset: dict[int, CompilerOp],
) -> tuple[int, object, tuple[int, ...]] | None:
    """Recover a constant integer argument staged through AX.

    A constant is loaded into AX and stored into the frame slot by the very
    next instruction, so only an adjacent pair is evidence of one argument.
    Zero is emitted as ``xor ax, ax`` rather than an immediate load.
    """
    if (
        operation is None
        or operation.kind != "movm_ax_bp"
        or len(operation.args) != 1
        or not isinstance(operation.args[0], int)
        or parameter_kinds.get(operation.args[0]) != "integer"
        or index < 1
    ):
        return None
    load = body[index - 1]
    if load.end != body[index].offset:
        return None
    if bytes.fromhex(load.raw) == b"\x31\xc0":
        value = 0
    else:
        loaded = compiler_by_offset.get(load.offset)
        if (
            loaded is None
            or loaded.kind != "movax"
            or len(loaded.args) != 1
            or not isinstance(loaded.args[0], int)
        ):
            return None
        value = loaded.args[0]
    return operation.args[0], ("const", value), (load.offset, operation.offset)


def _numeric_argument(
    body: tuple[Operation, ...],
    index: int,
    operation: CompilerOp | None,
    parameter_kinds: dict[int, str],
    compiler_by_offset: dict[int, CompilerOp],
    facts: frozenset[Fact],
    instruction_ends: dict[int, int],
) -> tuple[int, object, tuple[int, ...]] | None:
    store_kinds = {
        "fstp_bp": "float",
        "fstp64_bp": "double",
        "fistp_bp": "integer",
        "fistp32_bp": "long",
    }
    if operation is None:
        return None
    kind = store_kinds.get(operation.kind)
    if (
        kind is not None
        and len(operation.args) == 1
        and isinstance(operation.args[0], int)
        and parameter_kinds.get(operation.args[0]) == kind
    ):
        resolved = resolve_expression_before(
            operation.offset,
            facts,
            instruction_ends,
        )
        if resolved is None:
            return None
        return (
            operation.args[0],
            resolved.value,
            combine_evidence(resolved.evidence, (operation.offset,)),
        )
    if (
        operation is None
        or operation.kind != "movm_ax_bp"
        or len(operation.args) != 1
        or not isinstance(operation.args[0], int)
        or parameter_kinds.get(operation.args[0]) != "integer"
        or index < 3
    ):
        return None
    convert, wait, load = body[index - 3 : index]
    convert_operation = compiler_by_offset.get(convert.offset)
    load_operation = compiler_by_offset.get(load.offset)
    if not (
        convert_operation is not None
        and convert_operation.kind == "fistp"
        and len(convert_operation.args) == 1
        and wait.kind == "tb.fwait"
        and load_operation is not None
        and load_operation.kind == "movaxmem"
        and load_operation.args == convert_operation.args
        and convert.end == wait.offset
        and wait.end == load.offset
        and load.end == operation.offset
    ):
        return None
    resolved = resolve_expression_before(convert.offset, facts, instruction_ends)
    if resolved is None:
        return None
    return (
        operation.args[0],
        resolved.value,
        combine_evidence(
            resolved.evidence,
            (convert.offset, wait.offset, load.offset, operation.offset),
        ),
    )


def _string_argument(
    body: tuple[Operation, ...],
    index: int,
    parameter_kinds: dict[int, str],
    facts: frozenset[Fact],
) -> tuple[int, object, tuple[int, ...]] | None:
    if index == 0 or not _movsi_runtime(body[index - 1 : index + 1], 0xA2):
        return None
    destination, copy = body[index - 1 : index + 1]
    offset = destination.operands[1]
    if not isinstance(offset, int):
        return None
    if parameter_kinds.get(offset) != "string":
        return None
    source = next(
        (
            body[position : position + 2]
            for position in range(index - 2, -1, -1)
            if _movsi_runtime(body[position : position + 2], 0x9C)
        ),
        None,
    )
    if source is None:
        return None
    resolved = resolve_expression(("memory", source[0].operands[1], "string"), facts)
    if resolved is None:
        return None
    return (
        offset,
        resolved.value,
        combine_evidence(
            resolved.evidence,
            (source[0].offset, source[1].offset, destination.offset, copy.offset),
        ),
    )
