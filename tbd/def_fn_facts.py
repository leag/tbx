"""Fact-owned user DEF FN definitions, frames, results, and invocations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import (
    combine_evidence,
    orient_memory_fold,
    resolve_expression,
    resolve_expression_before,
)


@dataclass(frozen=True)
class FnDefinition:
    """One compiler-bracketed function body and its immutable frame signature."""

    declaration: int
    entry: int
    end: int
    returned: int
    result_kind: str
    parameters: tuple[tuple[int, str], ...]
    block: bool
    expression: object
    result_span: tuple[int, int]
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class _StackValue:
    value: object
    evidence: tuple[int, ...]
    start: int


def def_fn_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover definitions only from an exact declaration/body/return bracket."""

    for definition in _definitions(evidence):
        resolved = resolve_expression(definition.expression, facts)
        if resolved is None:
            continue
        parameters = tuple(
            ("fn-param", definition.entry, offset, kind)
            for offset, kind in definition.parameters
        )
        support = combine_evidence(definition.evidence, resolved.evidence)
        value = (
            definition.entry,
            definition.result_kind,
            parameters,
            resolved.value if not definition.block else True,
            definition.block,
        )
        yield Fact(
            "semantic.def_fn",
            (definition.declaration, definition.end),
            value,
            support,
            "signature",
        )
        if definition.block:
            yield Fact(
                "semantic.fn_result",
                definition.result_span,
                (resolved.value,),
                support,
                "anchored",
            )
        yield from _exit_def_facts(evidence, definition)


def def_fn_call_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Compose complete caller frames into value-producing user-function calls."""

    definitions = {definition.entry: definition for definition in _definitions(evidence)}
    instructions = evidence.instructions
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions
    }
    compiler = translate_operations(instructions)
    compiler_by_offset = {operation.offset: operation for operation in compiler}
    for index, call in enumerate(instructions):
        if call.kind != "tb.fn_call" or not call.operands:
            continue
        target = call.operands[0]
        definition = definitions.get(target) if isinstance(target, int) else None
        if definition is None:
            continue
        compact = _compact_integer_call(
            instructions,
            index,
            definition,
            compiler_by_offset,
        )
        if compact is not None:
            start, end, value, support = compact
            yield Fact(
                "expression.value",
                (start, end),
                (value,),
                support,
                "signature",
            )
            continue
        matched = _call_scaffold(
            instructions,
            index,
            definition,
            compiler_by_offset,
            facts,
            instruction_ends,
        )
        if matched is None:
            continue
        start, end, arguments, support = matched
        call_value = (
            ("fn-call", definition.entry, arguments, "string")
            if definition.result_kind == "string"
            else ("fn-call", definition.entry, arguments)
        )
        yield Fact(
            "expression.value",
            (start, end),
            (call_value,),
            support,
            "signature",
        )


def _definitions(evidence: Evidence) -> tuple[FnDefinition, ...]:
    instructions = evidence.instructions
    by_offset = {instruction.offset: instruction for instruction in instructions}
    compiler = translate_operations(instructions)
    compiler_by_offset = {operation.offset: operation for operation in compiler}
    result = []
    for declaration in instructions:
        target = declaration.operands[0] if declaration.operands else None
        if (
            declaration.kind != "x86.jmp"
            or not isinstance(target, int)
            or target <= declaration.end + 2
        ):
            continue
        returned = by_offset.get(target - 2)
        entry = declaration.end
        if returned is None or returned.kind != "tb.fn_return" or returned.end != target:
            continue
        body = tuple(
            compiler_by_offset[instruction.offset]
            for instruction in instructions
            if entry <= instruction.offset < returned.offset
            and instruction.offset in compiler_by_offset
        )
        parsed = _body_expression(body, entry, returned.offset)
        if parsed is None:
            parsed = _string_body_expression(
                evidence.instructions, entry, returned.offset
            )
        if parsed is None:
            continue
        expression, result_kind, result_span, parameters, support = parsed
        block = _block_prefix(body, result_kind)
        if not _supported_body(
            evidence,
            entry,
            returned.offset,
            result_span[0],
            result_span[1],
            block,
            result_kind,
        ):
            continue
        evidence_addresses = combine_evidence(
            (declaration.offset, returned.offset), support
        )
        result.append(
            FnDefinition(
                declaration.offset,
                entry,
                returned.end,
                returned.offset,
                result_kind,
                parameters,
                block,
                expression,
                result_span,
                evidence_addresses,
            )
        )
    return tuple(result)


def _body_expression(
    operations: tuple[CompilerOp, ...], entry: int, returned: int
) -> tuple[
    object,
    str,
    tuple[int, int],
    tuple[tuple[int, str], ...],
    tuple[int, ...],
] | None:
    result_indexes = [
        index
        for index, operation in enumerate(operations)
        if operation.kind in {"fstp_bp", "fstp64_bp", "fistp_bp", "fistp32_bp"}
        and operation.args == (0,)
    ]
    if len(result_indexes) != 1:
        return _integer_body_expression(operations, entry)
    result_index = result_indexes[0]
    expression_start = result_index
    while expression_start > 0 and _expression_operation(
        operations[expression_start - 1]
    ):
        expression_start -= 1
    expression_operations = operations[expression_start : result_index + 1]
    stack: list[_StackValue] = []
    parameters = _body_parameters(operations)
    result: tuple[object, str, tuple[int, int], tuple[int, ...]] | None = None
    support = []
    for operation in expression_operations:
        loaded = _load_value(operation, parameters, entry)
        if loaded is not None:
            stack.append(loaded)
            support.append(operation.offset)
            continue
        if operation.kind.startswith("fold") and operation.kind.endswith("_bp"):
            if not stack or len(operation.args) != 2:
                return None
            operator, offset = operation.args
            if not isinstance(operator, str) or not isinstance(offset, int) or offset <= 2:
                return None
            parameters.setdefault(offset, _operand_kind(operation.kind))
            top = stack.pop()
            memory = ("fn-param", entry, offset, parameters[offset])
            value = orient_memory_fold(operator, memory, top.value)
            stack.append(
                _StackValue(value, combine_evidence(top.evidence, (operation.offset,)), top.start)
            )
            support.append(operation.offset)
            continue
        if operation.kind in {"fstp_bp", "fstp64_bp", "fistp_bp", "fistp32_bp"}:
            if len(operation.args) != 1 or operation.args[0] != 0 or len(stack) != 1:
                return None
            value = stack.pop()
            kind = _result_kind(operation.kind)
            result = (
                value.value,
                kind,
                (value.start, operation.end),
                combine_evidence(value.evidence, (operation.offset,)),
            )
            support.append(operation.offset)
            continue
        return None
    if result is None or stack:
        return None
    expression, result_kind, result_span, expression_support = result
    return (
        expression,
        result_kind,
        result_span,
        tuple(sorted(parameters.items())),
        combine_evidence(tuple(support), expression_support),
    )


def _integer_body_expression(
    operations: tuple[CompilerOp, ...], entry: int
) -> tuple[
    object,
    str,
    tuple[int, int],
    tuple[tuple[int, str], ...],
    tuple[int, ...],
] | None:
    stores = [
        (index, operation)
        for index, operation in enumerate(operations)
        if (
            operation.kind == "movm_ax_bp" and operation.args == (0,)
        )
        or (
            operation.kind == "mov_bp_imm"
            and len(operation.args) == 2
            and operation.args[0] == 0
            and operation.args[1] != 0
        )
    ]
    if len(stores) != 1:
        return None
    result_index, store = stores[0]
    parameters: dict[int, str] = {}
    if store.kind == "mov_bp_imm":
        value = ("const", store.args[1])
        start = store.offset
        support = (store.offset,)
    else:
        if result_index == 0:
            return None
        cursor = result_index - 1
        arithmetic = []
        while cursor >= 0 and operations[cursor].kind in {
            "movax",
            "addax_bp",
            "andax_m",
        }:
            arithmetic.append(operations[cursor])
            cursor -= 1
        arithmetic.reverse()
        if not arithmetic or arithmetic[0].kind != "movax" or len(arithmetic[0].args) != 1:
            return None
        if arithmetic[-1].end != store.offset or any(
            left.end != right.offset
            for left, right in zip(arithmetic, arithmetic[1:])
        ):
            return None
        value = ("const", arithmetic[0].args[0])
        for operation in arithmetic[1:]:
            if len(operation.args) != 1:
                return None
            if operation.kind == "addax_bp":
                offset = operation.args[0]
                if not isinstance(offset, int) or offset < 2:
                    return None
                parameters[offset] = "integer"
                value = (
                    "binary",
                    "+",
                    ("fn-param", entry, offset, "integer"),
                    value,
                )
            elif operation.kind == "andax_m":
                value = (
                    "binary",
                    "AND",
                    ("memory", operation.args[0], "integer"),
                    value,
                )
            else:
                return None
        start = arithmetic[0].offset
        support = tuple(operation.offset for operation in (*arithmetic, store))
    return value, "integer", (start, store.end), tuple(sorted(parameters.items())), support


def _string_body_expression(
    instructions: tuple[Operation, ...], entry: int, returned: int
) -> tuple[
    object,
    str,
    tuple[int, int],
    tuple[tuple[int, str], ...],
    tuple[int, ...],
] | None:
    nodes = tuple(
        instruction
        for instruction in instructions
        if entry <= instruction.offset < returned
    )
    compiler = {
        operation.offset: operation
        for operation in translate_operations(instructions)
    }
    stack: list[_StackValue] = []
    parameters: dict[int, str] = {}
    result: tuple[object, tuple[int, int], tuple[int, ...]] | None = None
    cursor = 0
    while cursor < len(nodes):
        instruction = nodes[cursor]
        if (
            instruction.raw in {"c7 46 00 00 00", "c7 46 02 00 00"}
            and not stack
            and result is None
        ):
            cursor += 1
            continue
        pair = nodes[cursor : cursor + 2]
        if len(pair) == 2 and _movsi_runtime(pair, 0x9E):
            offset = pair[0].operands[1]
            if not isinstance(offset, int) or offset < 4:
                return None
            parameters[offset] = "string"
            stack.append(
                _StackValue(
                    ("fn-param", entry, offset, "string"),
                    (pair[0].offset, pair[1].offset),
                    pair[0].offset,
                )
            )
            cursor += 2
            continue
        if len(pair) == 2 and _movsi_runtime(pair, 0x9C):
            address = pair[0].operands[1]
            stack.append(
                _StackValue(
                    ("memory", address, "string"),
                    (pair[0].offset, pair[1].offset),
                    pair[0].offset,
                )
            )
            cursor += 2
            continue
        operation = compiler.get(instruction.offset)
        following = nodes[cursor + 1] if cursor + 1 < len(nodes) else None
        if (
            operation is not None
            and operation.kind == "fld_bp"
            and len(operation.args) == 1
            and isinstance(operation.args[0], int)
            and operation.args[0] >= 4
            and following is not None
            and following.kind == "tb.function"
            and following.operands == ("string", 0x20)
        ):
            offset = operation.args[0]
            parameters[offset] = "float"
            stack.append(
                _StackValue(
                    (
                        "call",
                        "STR$",
                        (("fn-param", entry, offset, "float"),),
                    ),
                    (instruction.offset, following.offset),
                    instruction.offset,
                )
            )
            cursor += 2
            continue
        if instruction.kind == "tb.runtime" and instruction.operands == (0x9B,):
            if len(stack) < 2:
                return None
            right = stack.pop()
            left = stack.pop()
            stack.append(
                _StackValue(
                    ("binary", "+", left.value, right.value),
                    combine_evidence(
                        left.evidence, right.evidence, (instruction.offset,)
                    ),
                    left.start,
                )
            )
            cursor += 1
            continue
        if len(pair) == 2 and _movsi_runtime(pair, 0xA2):
            if pair[0].operands[1] != 0 or len(stack) != 1 or result is not None:
                return None
            value = stack.pop()
            support = combine_evidence(
                value.evidence, (pair[0].offset, pair[1].offset)
            )
            result = value.value, (value.start, pair[1].end), support
            cursor += 2
            break
        return None
    if result is None:
        return None
    value, span, support = result
    return value, "string", span, tuple(sorted(parameters.items())), support


def _movsi_runtime(nodes: tuple[Operation, ...], vector: int) -> bool:
    return (
        len(nodes) == 2
        and nodes[0].kind == "x86.mov_imm"
        and nodes[0].operands[:1] == ("si",)
        and len(nodes[0].operands) == 2
        and nodes[1].kind == "tb.runtime"
        and nodes[1].operands == (vector,)
        and nodes[0].end == nodes[1].offset
    )


def _expression_operation(operation: CompilerOp) -> bool:
    return operation.kind in {
        "fld",
        "fld64",
        "fild",
        "fild32",
        "fld_bp",
        "fld64_bp",
        "fild_bp",
        "fild32_bp",
        "fld1",
        "fldz",
    } or operation.kind.startswith("fold") and operation.kind.endswith("_bp")


def _body_parameters(
    operations: tuple[CompilerOp, ...],
) -> dict[int, str]:
    parameters: dict[int, str] = {}
    for operation in operations:
        if not operation.kind.endswith("_bp") or not operation.args:
            continue
        offset = operation.args[-1]
        if isinstance(offset, int) and offset > 2:
            parameters.setdefault(offset, _operand_kind(operation.kind))
    return parameters


def _load_value(
    operation: CompilerOp, parameters: dict[int, str], entry: int
) -> _StackValue | None:
    if operation.kind in {"fld1", "fldz"}:
        return _StackValue(
            ("const", 1 if operation.kind == "fld1" else 0),
            (operation.offset,),
            operation.offset,
        )
    direct = {
        "fld": "float",
        "fld64": "double",
        "fild": "integer",
        "fild32": "long",
    }
    if operation.kind in direct and len(operation.args) == 1:
        return _StackValue(
            ("memory", operation.args[0], direct[operation.kind]),
            (operation.offset,),
            operation.offset,
        )
    bp = {
        "fld_bp": "float",
        "fld64_bp": "double",
        "fild_bp": "integer",
        "fild32_bp": "long",
    }
    kind = bp.get(operation.kind)
    if kind is None or len(operation.args) != 1:
        return None
    offset = operation.args[0]
    if not isinstance(offset, int) or offset <= 2:
        return None
    parameters.setdefault(offset, kind)
    return _StackValue(
        ("fn-param", entry, offset, kind),
        (operation.offset,),
        operation.offset,
    )


def _block_prefix(operations: tuple[CompilerOp, ...], result_kind: str) -> bool:
    if result_kind == "integer":
        return (
            bool(operations)
            and operations[0].kind == "mov_bp_imm"
            and operations[0].args == (0, 0)
        )
    return (
        len(operations) >= 2
        and operations[0].kind == operations[1].kind == "mov_bp_imm"
        and operations[0].args == (0, 0)
        and operations[1].args == (2, 0)
    )


def _supported_body(
    evidence: Evidence,
    entry: int,
    returned: int,
    result_start: int,
    result_end: int,
    block: bool,
    result_kind: str,
) -> bool:
    """Reject partial block recovery when statements before the result are opaque."""

    prefix = tuple(
        instruction
        for instruction in evidence.instructions
        if entry <= instruction.offset < result_start
    )
    if result_kind == "string":
        suffix = tuple(
            instruction
            for instruction in evidence.instructions
            if result_end <= instruction.offset < returned
        )
        if not (
            len(suffix) == 2
            and bytes.fromhex(suffix[0].raw) == b"\xc4\xb6\x04\x00"
            and suffix[1].kind == "tb.runtime"
            and suffix[1].operands == (0xD3,)
            and suffix[0].offset == result_end
            and suffix[0].end == suffix[1].offset
            and suffix[1].end == returned
        ):
            return False
    if not block:
        if result_kind == "string":
            return (
                len(prefix) == 1
                and bytes.fromhex(prefix[0].raw) == b"\xc7\x46\x02\x00\x00"
            )
        return not prefix
    if result_kind == "integer":
        return (
            len(prefix) == 1
            and bytes.fromhex(prefix[0].raw) == b"\xc7\x46\x00\x00\x00"
        )
    if result_kind == "string":
        return (
            len(prefix) == 2
            and bytes.fromhex(prefix[0].raw) == b"\xc7\x46\x00\x00\x00"
            and bytes.fromhex(prefix[1].raw) == b"\xc7\x46\x02\x00\x00"
        )
    if len(prefix) < 2 or not (
        bytes.fromhex(prefix[0].raw) == b"\xc7\x46\x00\x00\x00"
        and bytes.fromhex(prefix[1].raw) == b"\xc7\x46\x02\x00\x00"
    ):
        return False
    if len(prefix) == 2:
        return True
    tail = prefix[2:]
    if len(tail) != 7:
        return False
    top, compare, status, commit, branch, skip, exit_jump = tail
    compare_op = {
        operation.offset: operation
        for operation in translate_operations(evidence.instructions)
    }.get(compare.offset)
    return (
        top.raw == "cd 35 ee"
        and compare_op is not None
        and compare_op.kind == "fcomp_bp"
        and status.kind == "tb.runtime"
        and status.operands == (0x99,)
        and commit.kind == "tb.runtime"
        and commit.operands == (0x87,)
        and branch.kind.startswith("x86.j")
        and branch.operands == (exit_jump.offset,)
        and skip.kind == "x86.jmp"
        and skip.operands == (result_start,)
        and skip.end == exit_jump.offset
        and exit_jump.kind == "x86.jmp"
        and exit_jump.end == result_start
        and exit_jump.operands == (returned,)
    )


def _exit_def_facts(
    evidence: Evidence, definition: FnDefinition
) -> Iterable[Fact]:
    if not definition.block:
        return
    instructions = tuple(
        instruction
        for instruction in evidence.instructions
        if definition.entry <= instruction.offset < definition.returned
    )
    compiler = {
        operation.offset: operation
        for operation in translate_operations(evidence.instructions)
    }
    relations = {
        0x77: "<",
        0x73: "<=",
        0x72: ">",
        0x76: ">=",
        0x74: "=",
        0x75: "<>",
    }
    for index in range(len(instructions) - 6):
        top, compare, status, commit, branch, skip, exit_jump = instructions[
            index : index + 7
        ]
        compare_op = compiler.get(compare.offset)
        raw_branch = bytes.fromhex(branch.raw)
        relation = relations.get(raw_branch[0]) if raw_branch else None
        body_start = branch.operands[0] if branch.operands else None
        body_end = skip.operands[0] if skip.operands else None
        exit_target = exit_jump.operands[0] if exit_jump.operands else None
        if not (
            top.raw == "cd 35 ee"
            and compare_op is not None
            and compare_op.kind == "fcomp_bp"
            and len(compare_op.args) == 1
            and isinstance(compare_op.args[0], int)
            and compare_op.args[0] > 2
            and status.kind == "tb.runtime"
            and status.operands == (0x99,)
            and commit.kind == "tb.runtime"
            and commit.operands == (0x87,)
            and branch.kind.startswith("x86.j")
            and skip.kind == "x86.jmp"
            and exit_jump.kind == "x86.jmp"
            and relation is not None
            and body_start == skip.end == exit_jump.offset
            and body_end == exit_jump.end
            and exit_target == definition.returned
        ):
            continue
        parameter = (
            "fn-param",
            definition.entry,
            compare_op.args[0],
            _operand_kind(compare_op.kind),
        )
        condition = (relation, parameter, ("const", 0))
        support = combine_evidence(
            definition.evidence,
            tuple(item.offset for item in instructions[index : index + 7]),
        )
        yield Fact(
            "semantic.exit_def",
            (exit_jump.offset, exit_jump.end),
            (),
            support,
            "signature",
        )
        yield Fact(
            "semantic.if_inline",
            (top.offset, exit_jump.end),
            (condition, exit_jump.offset, exit_jump.end, None),
            support,
            "anchored",
        )


def _operand_kind(operation_kind: str) -> str:
    if "64" in operation_kind:
        return "double"
    if "32" in operation_kind:
        return "long"
    if operation_kind.startswith(("fild", "fistp")):
        return "integer"
    return "float"


def _result_kind(operation_kind: str) -> str:
    return _operand_kind(operation_kind)


def _call_scaffold(
    instructions: tuple[Operation, ...],
    call_index: int,
    definition: FnDefinition,
    compiler_by_offset: dict[int, CompilerOp],
    facts: frozenset[Fact],
    instruction_ends: dict[int, int],
) -> tuple[int, int, tuple[object, ...], tuple[int, ...]] | None:
    if definition.result_kind == "string":
        return _string_call_scaffold(
            instructions,
            call_index,
            definition,
            compiler_by_offset,
            facts,
        )
    if definition.result_kind == "integer":
        return _integer_call_scaffold(
            instructions, call_index, definition, compiler_by_offset
        )
    if call_index < 6 or call_index + 4 >= len(instructions):
        return None
    frame_index = next(
        (
            index
            for index in range(call_index - 1, max(-1, call_index - 24), -1)
            if bytes.fromhex(instructions[index].raw) == b"\x8b\xec"
        ),
        None,
    )
    if frame_index is None or frame_index < 3:
        return None
    push, save, reserve = instructions[frame_index - 3 : frame_index]
    frame = instructions[frame_index]
    if not (
        bytes.fromhex(push.raw) == b"\x55"
        and bytes.fromhex(save.raw)[:2] == b"\x89\x26"
        and bytes.fromhex(reserve.raw)[:2] == b"\x83\xec"
        and push.end == save.offset
        and save.end == reserve.offset
        and reserve.end == frame.offset
    ):
        return None
    expected_size = _frame_width(definition.result_kind) + sum(
        _frame_width(kind) for _offset, kind in definition.parameters
    )
    reserve_raw = bytes.fromhex(reserve.raw)
    if len(reserve_raw) != 3 or reserve_raw[2] != expected_size:
        return None
    staged: dict[int, object] = {}
    argument_evidence = []
    for instruction in instructions[frame_index + 1 : call_index]:
        operation = compiler_by_offset.get(instruction.offset)
        if operation is None or operation.kind not in {
            "fstp_bp",
            "fstp64_bp",
            "fistp_bp",
            "fistp32_bp",
        }:
            continue
        if len(operation.args) != 1 or not isinstance(operation.args[0], int):
            return None
        offset = operation.args[0]
        resolved = resolve_expression_before(
            instruction.offset, facts, instruction_ends
        )
        if resolved is None or offset in staged:
            return None
        staged[offset] = resolved.value
        argument_evidence.extend((resolved.evidence, (instruction.offset,)))
    expected_offsets = tuple(offset for offset, _kind in definition.parameters)
    if tuple(sorted(staged)) != expected_offsets:
        return None
    result_load, wait, release, pop = instructions[call_index + 1 : call_index + 5]
    result_operation = compiler_by_offset.get(result_load.offset)
    if not (
        result_operation is not None
        and result_operation.kind in {"fld_bp", "fld64_bp", "fild_bp", "fild32_bp"}
        and result_operation.args == (0,)
        and wait.kind == "tb.fwait"
        and result_load.end == wait.offset
        and bytes.fromhex(release.raw) == bytes((0x83, 0xC4, expected_size))
        and bytes.fromhex(pop.raw) == b"\x5d"
        and wait.end == release.offset
        and release.end == pop.offset
    ):
        return None
    arguments = tuple(staged[offset] for offset in expected_offsets)
    support = combine_evidence(
        tuple(item.offset for item in instructions[frame_index - 3 : call_index + 5]),
        *(group for group in argument_evidence),
        definition.evidence,
    )
    return push.offset, pop.end, arguments, support


def _integer_call_scaffold(
    instructions: tuple[Operation, ...],
    call_index: int,
    definition: FnDefinition,
    compiler_by_offset: dict[int, CompilerOp],
) -> tuple[int, int, tuple[object, ...], tuple[int, ...]] | None:
    if call_index < 8 or call_index + 3 >= len(instructions):
        return None
    expected_size = _frame_width(definition.result_kind) + sum(
        _frame_width(kind) for _offset, kind in definition.parameters
    )
    frame_index = next(
        (
            index
            for index in range(call_index - 1, max(-1, call_index - 16), -1)
            if bytes.fromhex(instructions[index].raw) == b"\x8b\xec"
        ),
        None,
    )
    if frame_index is None:
        return None
    reserve_index = next(
        (
            index
            for index in range(frame_index - 1, max(-1, frame_index - 10), -1)
            if bytes.fromhex(instructions[index].raw)
            == bytes((0x83, 0xEC, expected_size))
        ),
        None,
    )
    if reserve_index is None or reserve_index < 2:
        return None
    push, save = instructions[reserve_index - 2 : reserve_index]
    if not (
        bytes.fromhex(push.raw) == b"\x55"
        and bytes.fromhex(save.raw)[:2] == b"\x89\x26"
        and push.end == save.offset
        and save.end == instructions[reserve_index].offset
    ):
        return None
    staged: dict[int, object] = {}
    cursor = reserve_index + 1
    while cursor + 2 < frame_index:
        offset_load, add_sp, store = instructions[cursor : cursor + 3]
        raw_store = bytes.fromhex(store.raw)
        if not (
            offset_load.kind == "x86.mov_imm"
            and offset_load.operands[:1] == ("si",)
            and len(offset_load.operands) == 2
            and isinstance(offset_load.operands[1], int)
            and bytes.fromhex(add_sp.raw) == b"\x01\xe6"
            and len(raw_store) == 5
            and raw_store[:3] == b"\x36\xc7\x04"
            and offset_load.end == add_sp.offset
            and add_sp.end == store.offset
        ):
            return None
        offset = offset_load.operands[1]
        immediate = int.from_bytes(raw_store[3:5], "little")
        if offset in staged:
            return None
        staged[offset] = ("const", immediate)
        cursor += 3
    expected_offsets = tuple(offset for offset, _kind in definition.parameters)
    if cursor != frame_index or tuple(sorted(staged)) != expected_offsets:
        return None
    result_load, release, pop = instructions[call_index + 1 : call_index + 4]
    result_operation = compiler_by_offset.get(result_load.offset)
    if not (
        result_operation is not None
        and result_operation.kind == "movax_bp"
        and result_operation.args == (0,)
        and bytes.fromhex(release.raw) == bytes((0x83, 0xC4, expected_size))
        and bytes.fromhex(pop.raw) == b"\x5d"
        and result_load.end == release.offset
        and release.end == pop.offset
    ):
        return None
    arguments = tuple(staged[offset] for offset in expected_offsets)
    support = combine_evidence(
        tuple(
            instruction.offset
            for instruction in instructions[reserve_index - 2 : call_index + 4]
        ),
        definition.evidence,
    )
    return push.offset, pop.end, arguments, support


def _string_call_scaffold(
    instructions: tuple[Operation, ...],
    call_index: int,
    definition: FnDefinition,
    compiler_by_offset: dict[int, CompilerOp],
    facts: frozenset[Fact],
) -> tuple[int, int, tuple[object, ...], tuple[int, ...]] | None:
    if call_index < 8 or call_index + 3 >= len(instructions):
        return None
    expected_size = _frame_width(definition.result_kind) + sum(
        _frame_width(kind) for _offset, kind in definition.parameters
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
    body = instructions[frame_index + 1 : call_index]
    instruction_ends = {item.offset: item.end for item in instructions}
    for position, instruction in enumerate(body):
        operation = compiler_by_offset.get(instruction.offset)
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
        source_address = source_pair[0].operands[1]
        resolved = resolve_expression(
            ("memory", source_address, "string"), facts
        )
        if resolved is None:
            return None
        offset = destination.operands[1]
        staged[offset] = resolved.value
        stage_support.append(
            combine_evidence(
                resolved.evidence,
                (source_pair[0].offset, source_pair[1].offset),
                (destination.offset, instruction.offset),
            )
        )
    expected_offsets = tuple(offset for offset, _kind in definition.parameters)
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
        definition.evidence,
    )
    return push.offset, pop.end, arguments, support


def _compact_integer_call(
    instructions: tuple[Operation, ...],
    call_index: int,
    definition: FnDefinition,
    compiler_by_offset: dict[int, CompilerOp],
) -> tuple[int, int, object, tuple[int, ...]] | None:
    """Recover the no-argument integer call kept between an AX literal and fold."""

    if (
        definition.result_kind != "integer"
        or definition.parameters
        or call_index < 4
        or call_index + 5 >= len(instructions)
    ):
        return None
    literal, push, reserve, frame = instructions[call_index - 4 : call_index]
    shuttle, result_load, release, pop, combine = instructions[
        call_index + 1 : call_index + 6
    ]
    literal_op = compiler_by_offset.get(literal.offset)
    result_op = compiler_by_offset.get(result_load.offset)
    operator = {b"\x2b\xc3": "-", b"\x03\xc3": "+"}.get(
        bytes.fromhex(combine.raw)
    )
    if not (
        literal_op is not None
        and literal_op.kind == "movax"
        and len(literal_op.args) == 1
        and bytes.fromhex(push.raw) == b"\x55"
        and bytes.fromhex(reserve.raw) == b"\x83\xec\x02"
        and bytes.fromhex(frame.raw) == b"\x8b\xec"
        and bytes.fromhex(shuttle.raw) in {b"\x89\xc3", b"\x8b\xd8"}
        and result_op is not None
        and result_op.kind == "movax_bp"
        and result_op.args == (0,)
        and bytes.fromhex(release.raw) == b"\x83\xc4\x02"
        and bytes.fromhex(pop.raw) == b"\x5d"
        and operator is not None
        and all(
            left.end == right.offset
            for left, right in zip(
                (literal, push, reserve, frame, instructions[call_index], shuttle, result_load, release, pop),
                (push, reserve, frame, instructions[call_index], shuttle, result_load, release, pop, combine),
            )
        )
    ):
        return None
    call_value = ("fn-call", definition.entry, ())
    value = ("binary", operator, call_value, ("const", literal_op.args[0]))
    support = combine_evidence(
        tuple(
            instruction.offset
            for instruction in instructions[call_index - 4 : call_index + 6]
        ),
        definition.evidence,
    )
    return literal.offset, combine.end, value, support


def _frame_width(kind: str) -> int:
    return 8 if kind == "double" else 4 if kind in {"float", "long", "string"} else 2


DEF_FN_FACT_PASSES: tuple[NamedPass, ...] = (
    ("def-fn-definitions", def_fn_facts),
    ("def-fn-calls", def_fn_call_facts),
)
