from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.def_fn_numeric_facts import bp_kinds, local_initialization, result_prefix
from tbd.facts import Evidence
from tbd.ir import Fact, Operation
from tbd.operation_helpers import movsi_runtime as _movsi_runtime
from tbd.semantic import (
    combine_evidence,
    resolve_expression,
    resolve_expression_before,
)


@dataclass(frozen=True)
class StringStore:
    """One symbolic string store inside a DEF FN body."""

    target: int
    expression: object
    span: tuple[int, int]
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class StringBlock:
    """Recovered string DEF FN body and its frame metadata."""

    results: tuple[StringStore, ...]
    parameters: tuple[tuple[int, str], ...]
    locals: tuple[tuple[int, str], ...]
    local_span: tuple[int, int] | None
    local_evidence: tuple[int, ...]
    local_bytes: int
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class _StackValue:
    value: object
    evidence: tuple[int, ...]
    start: int


def string_body_expression(
    instructions: tuple[Operation, ...], entry: int, returned: int
) -> (
    tuple[
        object,
        str,
        tuple[int, int],
        tuple[tuple[int, str], ...],
        tuple[int, ...],
    ]
    | None
):
    """Recover the expression returned by a string DEF FN body."""
    scanned = _scan_string_stores(
        _body_nodes(instructions, entry, returned),
        entry,
    )
    if scanned is None:
        return None
    stores, parameters, _locals = scanned
    results = tuple(store for store in stores if store.target == 0)
    if len(results) != 1:
        return None
    result = results[0]
    return (
        result.expression,
        "string",
        result.span,
        tuple(sorted(parameters.items())),
        result.evidence,
    )


def string_call_scaffold(
    instructions: tuple[Operation, ...],
    call_index: int,
    *,
    result_kind: str,
    parameters: tuple[tuple[int, str], ...],
    definition_evidence: tuple[int, ...],
    compiler_by_offset: dict[int, CompilerOp],
    facts: frozenset[Fact],
    local_bytes: int,
) -> tuple[int, int, tuple[object, ...], tuple[int, ...]] | None:
    """Match the call-site frame scaffold for a string DEF FN."""
    if call_index < 8 or call_index + 3 >= len(instructions):
        return None
    expected_size = (
        _frame_width(result_kind)
        + sum(_frame_width(kind) for _offset, kind in parameters)
        + local_bytes
    )
    frame_index = next(
        (
            index
            for index in range(call_index - 1, max(-1, call_index - 30), -1)
            if bytes.fromhex(instructions[index].raw) == b"\x8b\xec"
        ),
        None,
    )
    if frame_index is None or frame_index < 3:
        return None
    push, save, reserve = instructions[frame_index - 3 : frame_index]
    if not (
        bytes.fromhex(push.raw) == b"\x55"
        and bytes.fromhex(save.raw)[:2] == b"\x89\x26"
        and bytes.fromhex(reserve.raw) == bytes((0x83, 0xEC, expected_size))
    ):
        return None
    staged: dict[int, object] = {}
    stage_support: list[tuple[int, ...]] = []
    parameter_kinds = dict(parameters)
    body = instructions[frame_index + 1 : call_index]
    instruction_ends = {item.offset: item.end for item in instructions}
    for position, instruction in enumerate(body):
        operation = compiler_by_offset.get(instruction.offset)
        if (
            operation is not None
            and operation.kind == "mov_bp_imm"
            and len(operation.args) == 2
            and isinstance(operation.args[0], int)
            and parameter_kinds.get(operation.args[0]) == "integer"
            and isinstance(operation.args[1], int)
        ):
            staged[operation.args[0]] = ("const", operation.args[1])
            stage_support.append((operation.offset,))
            continue
        if (
            operation is not None
            and operation.kind in {"fstp_bp", "fstp64_bp", "fistp_bp", "fistp32_bp"}
            and len(operation.args) == 1
            and isinstance(operation.args[0], int)
        ):
            resolved = resolve_expression_before(
                instruction.offset, facts, instruction_ends
            )
            if resolved is None:
                return None
            staged[operation.args[0]] = resolved.value
            stage_support.append(
                combine_evidence(resolved.evidence, (instruction.offset,))
            )
            continue
        if not (
            instruction.kind == "tb.runtime"
            and instruction.operands == (0xA2,)
            and position > 0
        ):
            continue
        destination = body[position - 1]
        if not (
            destination.kind == "x86.mov_imm"
            and destination.operands[:1] == ("si",)
            and len(destination.operands) == 2
            and isinstance(destination.operands[1], int)
        ):
            return None
        source_pair = next(
            (
                body[source : source + 2]
                for source in range(position - 2, -1, -1)
                if _movsi_runtime(body[source : source + 2], 0x9C)
            ),
            None,
        )
        if source_pair is None:
            return None
        resolved = resolve_expression(
            ("memory", source_pair[0].operands[1], "string"), facts
        )
        if resolved is None:
            return None
        staged[destination.operands[1]] = resolved.value
        stage_support.append(
            combine_evidence(
                resolved.evidence,
                (source_pair[0].offset, source_pair[1].offset),
                (destination.offset, instruction.offset),
            )
        )
    expected_offsets = tuple(offset for offset, _kind in parameters)
    if tuple(sorted(staged)) != expected_offsets:
        return None
    result_push, release, pop = instructions[call_index + 1 : call_index + 4]
    if not (
        result_push.kind == "tb.runtime"
        and result_push.operands == (0x9F,)
        and bytes.fromhex(release.raw) == bytes((0x83, 0xC4, expected_size))
        and bytes.fromhex(pop.raw) == b"\x5d"
        and result_push.end == release.offset
        and release.end == pop.offset
    ):
        return None
    arguments = tuple(staged[offset] for offset in expected_offsets)
    support = combine_evidence(
        tuple(
            instruction.offset
            for instruction in instructions[frame_index - 3 : call_index + 4]
        ),
        *stage_support,
        definition_evidence,
    )
    return push.offset, pop.end, arguments, support


def string_block_body(
    instructions: tuple[Operation, ...], entry: int, returned: int
) -> StringBlock | None:
    """Recover a string DEF FN body and its local frame."""
    nodes = _body_nodes(instructions, entry, returned)
    prefix = result_prefix(nodes)
    if prefix != 2:
        return None
    init_nodes, local_range, local_bytes = _string_local_frame(nodes[prefix:])
    scanned = _scan_string_stores(nodes, entry, local_range)
    if scanned is None:
        return None
    stores, scanned_parameters, scanned_locals = scanned
    classified = _classify_string_references(
        nodes,
        local_range,
        scanned_parameters,
        scanned_locals,
    )
    if classified is None:
        return None
    parameters, locals_by_offset = classified
    results = tuple(store for store in stores if store.target == 0)
    string_references = tuple(
        sorted(
            offset
            for offset, kind in {**parameters, **locals_by_offset}.items()
            if kind == "string"
        )
    )
    if not results or _cleanup_offsets(nodes) != string_references:
        return None
    support = combine_evidence(
        (nodes[0].offset, nodes[1].offset),
        tuple(node.offset for node in init_nodes),
        *(result.evidence for result in results),
        tuple(node.offset for node in nodes[-2 * len(string_references) :]),
    )
    return StringBlock(
        results,
        tuple(sorted(parameters.items())),
        tuple(sorted(locals_by_offset.items())),
        (init_nodes[0].offset, init_nodes[-1].end) if init_nodes else None,
        tuple(node.offset for node in init_nodes),
        local_bytes,
        support,
    )


def _string_local_frame(
    nodes: tuple[Operation, ...],
) -> tuple[tuple[Operation, ...], tuple[int, int] | None, int]:
    initialization = local_initialization(nodes)
    if initialization is None:
        return (), None, 0
    init_nodes, local_start, local_bytes = initialization
    return init_nodes, (local_start, local_start + local_bytes), local_bytes


def _classify_string_references(
    nodes: tuple[Operation, ...],
    local_range: tuple[int, int] | None,
    scanned_parameters: dict[int, str],
    scanned_locals: dict[int, str],
) -> tuple[dict[int, str], dict[int, str]] | None:
    if local_range is None:
        return scanned_parameters, {}
    local_start, local_stop = local_range
    kinds = bp_kinds(nodes, translate_operations(nodes))
    local_kinds = {
        offset: found
        for offset, found in kinds.items()
        if local_start <= offset < local_stop
    }
    parameter_kinds = {
        offset: found for offset, found in kinds.items() if 2 < offset < local_start
    }
    if any(
        len(found) != 1 for found in (*local_kinds.values(), *parameter_kinds.values())
    ):
        return None
    locals_by_offset = {
        offset: next(iter(found)) for offset, found in local_kinds.items()
    }
    parameters = {
        offset: next(iter(found)) for offset, found in parameter_kinds.items()
    }
    if any(
        parameters.get(offset) != kind for offset, kind in scanned_parameters.items()
    ) or any(
        locals_by_offset.get(offset) != kind for offset, kind in scanned_locals.items()
    ):
        return None
    return parameters, locals_by_offset


def string_reference_assignment_facts(
    evidence: Evidence,
    facts: frozenset[Fact],
    *,
    entry: int,
    returned: int,
    parameters: tuple[tuple[int, str], ...],
    locals: tuple[tuple[int, str], ...],
    local_bytes: int,
    envelope_evidence: tuple[int, ...],
) -> Iterable[Fact]:
    """Recover assignments to string parameters and locals."""
    string_references = {
        offset: ("fn-param", entry, offset, "string")
        for offset, kind in parameters
        if kind == "string"
    }
    string_references.update(
        {
            offset: ("fn-local", entry, offset, "string")
            for offset, kind in locals
            if kind == "string"
        }
    )
    if not string_references:
        return
    nodes = _body_nodes(evidence.instructions, entry, returned)
    local_range = (
        (
            min(offset for offset, _kind in locals),
            min(offset for offset, _kind in locals) + local_bytes,
        )
        if locals
        else None
    )
    scanned = _scan_string_stores(nodes, entry, local_range)
    if scanned is None:
        return
    stores, _inferred_parameters, _inferred_locals = scanned
    for store in stores:
        target = string_references.get(store.target)
        if target is None:
            continue
        resolved = resolve_expression(store.expression, facts)
        if resolved is None:
            continue
        yield Fact(
            "semantic.assign",
            store.span,
            (
                target,
                resolved.value,
            ),
            combine_evidence(
                envelope_evidence,
                store.evidence,
                resolved.evidence,
            ),
            "anchored",
        )


def _body_nodes(
    instructions: tuple[Operation, ...], entry: int, returned: int
) -> tuple[Operation, ...]:
    return tuple(
        instruction
        for instruction in instructions
        if entry <= instruction.offset < returned
    )


def _scan_string_stores(
    nodes: tuple[Operation, ...],
    entry: int,
    local_range: tuple[int, int] | None = None,
) -> tuple[tuple[StringStore, ...], dict[int, str], dict[int, str]] | None:
    compiler = {
        operation.offset: operation for operation in translate_operations(nodes)
    }
    stack: list[_StackValue] = []
    stores = []
    parameters: dict[int, str] = {}
    locals_by_offset: dict[int, str] = {}
    cursor = 0
    while cursor < len(nodes):
        if stack and nodes[cursor - 1].end != nodes[cursor].offset:
            stack.clear()
        pair = nodes[cursor : cursor + 2]
        pushed = _pushed_string(pair, entry, parameters, locals_by_offset, local_range)
        if pushed is not None:
            stack.append(pushed)
            cursor += 2
            continue
        converted = _converted_parameter(
            pair,
            compiler,
            entry,
            parameters,
            locals_by_offset,
            local_range,
        )
        if converted is not None:
            stack.append(converted)
            cursor += 2
            continue
        instruction = nodes[cursor]
        if instruction.kind == "tb.runtime" and instruction.operands == (0x9B,):
            if len(stack) < 2:
                stack.clear()
            else:
                right = stack.pop()
                left = stack.pop()
                stack.append(
                    _StackValue(
                        ("binary", "+", left.value, right.value),
                        combine_evidence(
                            left.evidence,
                            right.evidence,
                            (instruction.offset,),
                        ),
                        left.start,
                    )
                )
            cursor += 1
            continue
        function = _stack_string_function(instruction)
        if function is not None:
            if not stack:
                stack.clear()
            else:
                argument = stack.pop()
                stack.append(
                    _StackValue(
                        ("call", function, (argument.value,)),
                        combine_evidence(argument.evidence, (instruction.offset,)),
                        argument.start,
                    )
                )
            cursor += 1
            continue
        if len(pair) == 2 and _movsi_runtime(pair, 0xA2):
            target = pair[0].operands[1]
            if not isinstance(target, int):
                return None
            if (
                target > 2
                and _record_reference(
                    entry,
                    parameters,
                    locals_by_offset,
                    local_range,
                    target,
                    "string",
                )
                is None
            ):
                return None
            if len(stack) == 1:
                value = stack.pop()
                stores.append(
                    StringStore(
                        target,
                        value.value,
                        (value.start, pair[1].end),
                        combine_evidence(
                            value.evidence,
                            (pair[0].offset, pair[1].offset),
                        ),
                    )
                )
            else:
                stack.clear()
            cursor += 2
            continue
        stack.clear()
        cursor += 1
    return tuple(stores), parameters, locals_by_offset


def _stack_string_function(instruction: Operation) -> str | None:
    if instruction.kind != "tb.function" or len(instruction.operands) != 2:
        return None
    if instruction.operands[0] != "string":
        return None
    return {
        0x08: "ENVIRON$",
        0x16: "LCASE$",
        0x28: "UCASE$",
    }.get(instruction.operands[1])


def _pushed_string(
    pair: tuple[Operation, ...],
    entry: int,
    parameters: dict[int, str],
    locals_by_offset: dict[int, str],
    local_range: tuple[int, int] | None,
) -> _StackValue | None:
    if len(pair) != 2:
        return None
    if _movsi_runtime(pair, 0x9E):
        offset = pair[0].operands[1]
        if not isinstance(offset, int) or offset < 4:
            return None
        reference = _record_reference(
            entry,
            parameters,
            locals_by_offset,
            local_range,
            offset,
            "string",
        )
        if reference is None:
            return None
        return _StackValue(
            reference,
            (pair[0].offset, pair[1].offset),
            pair[0].offset,
        )
    if not _movsi_runtime(pair, 0x9C):
        return None
    return _StackValue(
        ("memory", pair[0].operands[1], "string"),
        (pair[0].offset, pair[1].offset),
        pair[0].offset,
    )


def _converted_parameter(
    pair: tuple[Operation, ...],
    compiler: dict[int, CompilerOp],
    entry: int,
    parameters: dict[int, str],
    locals_by_offset: dict[int, str],
    local_range: tuple[int, int] | None,
) -> _StackValue | None:
    if len(pair) != 2:
        return None
    operation = compiler.get(pair[0].offset)
    if not (
        operation is not None
        and operation.kind == "fld_bp"
        and len(operation.args) == 1
        and isinstance(operation.args[0], int)
        and operation.args[0] >= 4
        and pair[1].kind == "tb.function"
        and pair[1].operands == ("string", 0x20)
    ):
        return None
    offset = operation.args[0]
    reference = _record_reference(
        entry,
        parameters,
        locals_by_offset,
        local_range,
        offset,
        "float",
    )
    if reference is None:
        return None
    return _StackValue(
        ("call", "STR$", (reference,)),
        (pair[0].offset, pair[1].offset),
        pair[0].offset,
    )


def _record_reference(
    entry: int,
    parameters: dict[int, str],
    locals_by_offset: dict[int, str],
    local_range: tuple[int, int] | None,
    offset: int,
    kind: str,
) -> object | None:
    is_local = local_range is not None and local_range[0] <= offset < local_range[1]
    references = locals_by_offset if is_local else parameters
    previous = references.get(offset)
    if previous is not None and previous != kind:
        return None
    references[offset] = kind
    return (
        "fn-local" if is_local else "fn-param",
        entry,
        offset,
        kind,
    )


def _cleanup_offsets(nodes: tuple[Operation, ...]) -> tuple[int, ...]:
    offsets = []
    cursor = len(nodes)
    while cursor >= 2:
        load, release = nodes[cursor - 2 : cursor]
        raw = bytes.fromhex(load.raw)
        if not (
            len(raw) == 4
            and raw[:2] == b"\xc4\xb6"
            and release.kind == "tb.runtime"
            and release.operands == (0xD3,)
            and load.end == release.offset
        ):
            break
        offsets.append(int.from_bytes(raw[2:], "little", signed=True))
        cursor -= 2
    offsets.reverse()
    return tuple(offsets)


def _frame_width(kind: str) -> int:
    return 8 if kind == "double" else 4 if kind in {"float", "long", "string"} else 2
