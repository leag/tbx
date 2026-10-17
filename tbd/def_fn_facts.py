from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.def_fn_array_facts import local_array_body_facts
from tbd.def_fn_call_args import numeric_call_result_tail, stage_call_arguments
from tbd.def_fn_model import FnDefinition, FnResult
from tbd.def_fn_numeric_facts import (
    numeric_block_body,
    numeric_body_facts,
    numeric_bridge_body_expression,
)
from tbd.def_fn_string_facts import (
    string_block_body,
    string_body_expression,
    string_call_scaffold,
    string_reference_assignment_facts,
)
from tbd.facts import Evidence, NamedPass, reads
from tbd.ir import Fact, Operation
from tbd.semantic import (
    combine_evidence,
    orient_memory_fold,
    resolve_expression,
)


@dataclass(frozen=True)
class _StackValue:
    value: object
    evidence: tuple[int, ...]
    start: int


@reads(
    "constant",
    "control.compound_condition",
    "control.condition_prefix",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "layout.array",
    "layout.pool",
    "reference.array_value",
    "register.value",
    "semantic.statement",
    "signature",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.function",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def def_fn_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover DEF FN declarations and their body parameters."""

    for definition in _definitions(evidence, facts):
        results = tuple(
            (resolve_expression(result.expression, facts), result)
            for result in definition.results
        )
        if any(resolved is None for resolved, _result in results):
            continue
        resolved_results = tuple(
            (resolved, result) for resolved, result in results if resolved is not None
        )
        parameters = tuple(
            ("fn-param", definition.entry, offset, kind)
            for offset, kind in definition.parameters
        )
        support = combine_evidence(
            definition.evidence,
            *(
                combine_evidence(result.evidence, resolved.evidence)
                for resolved, result in resolved_results
            ),
        )
        value = (
            definition.entry,
            definition.result_kind,
            parameters,
            resolved_results[0][0].value if not definition.block else True,
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
            for resolved, result in resolved_results:
                yield Fact(
                    "semantic.fn_result",
                    result.span,
                    (resolved.value,),
                    combine_evidence(
                        definition.evidence,
                        result.evidence,
                        resolved.evidence,
                    ),
                    "anchored",
                )
        yield from string_reference_assignment_facts(
            evidence,
            facts,
            entry=definition.entry,
            returned=definition.returned,
            parameters=definition.parameters,
            locals=definition.locals,
            local_bytes=definition.local_bytes,
            envelope_evidence=(definition.declaration, definition.returned),
        )
        yield from numeric_body_facts(
            evidence,
            facts,
            entry=definition.entry,
            returned=definition.returned,
            parameters=definition.parameters,
            locals=definition.locals,
            local_span=definition.local_span,
            local_evidence=definition.local_evidence,
        )
        yield from local_array_body_facts(
            evidence,
            facts,
            entry=definition.entry,
            returned=definition.returned,
            parameters=definition.parameters,
            locals=definition.locals,
        )
        yield from _exit_def_facts(evidence, facts, definition)


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "reference.array_value",
    "register.value",
    "semantic.statement",
    "signature",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.function",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def def_fn_call_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover calls to previously identified DEF FN declarations."""

    definitions = {
        definition.entry: definition for definition in _definitions(evidence, facts)
    }
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


def _definitions(
    evidence: Evidence, facts: frozenset[Fact]
) -> tuple[FnDefinition, ...]:
    """Find function bodies and infer parameters used by their statements."""

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
        if (
            returned is None
            or returned.kind != "tb.fn_return"
            or returned.end != target
        ):
            continue
        body = tuple(
            compiler_by_offset[instruction.offset]
            for instruction in instructions
            if entry <= instruction.offset < returned.offset
            and instruction.offset in compiler_by_offset
        )
        parsed = _body_expression(body, entry, returned.offset)
        if parsed is None:
            parsed = string_body_expression(
                evidence.instructions, entry, returned.offset
            )
        bridge = numeric_bridge_body_expression(
            evidence.instructions,
            facts,
            entry,
            returned.offset,
        )
        if bridge is not None:
            parsed = bridge
        if parsed is not None:
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
                facts,
            ):
                parsed = None
        if parsed is None:
            block_body = _integer_block_body(body, entry)
            if block_body is None:
                string_body = string_block_body(
                    evidence.instructions,
                    entry,
                    returned.offset,
                )
                if string_body is not None:
                    results = tuple(
                        FnResult(
                            result.expression,
                            result.span,
                            result.evidence,
                        )
                        for result in string_body.results
                    )
                    result_kind = "string"
                    parameters = string_body.parameters
                    support = string_body.evidence
                    locals_by_offset = string_body.locals
                    local_span = string_body.local_span
                    local_evidence = string_body.local_evidence
                    local_bytes = string_body.local_bytes
                else:
                    numeric_body = numeric_block_body(
                        evidence.instructions,
                        entry,
                        returned.offset,
                    )
                    if numeric_body is None:
                        continue
                    results = tuple(
                        FnResult(
                            result.expression,
                            result.span,
                            result.evidence,
                        )
                        for result in numeric_body.results
                    )
                    result_kind = numeric_body.results[0].kind
                    parameters = numeric_body.parameters
                    support = numeric_body.evidence
                    locals_by_offset = numeric_body.locals
                    local_span = numeric_body.local_span
                    local_evidence = numeric_body.local_evidence
                    local_bytes = numeric_body.local_bytes
            else:
                results, parameters, support = block_body
                result_kind = "integer"
                locals_by_offset = ()
                local_span = None
                local_evidence = ()
                local_bytes = 0
            block = True
        else:
            results = (FnResult(expression, result_span, support),)
            locals_by_offset = ()
            local_span = None
            local_evidence = ()
            local_bytes = 0
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
                results,
                evidence_addresses,
                locals_by_offset,
                local_span,
                local_evidence,
                local_bytes,
            )
        )
    return tuple(result)


def _integer_block_body(
    operations: tuple[CompilerOp, ...], entry: int
) -> (
    tuple[
        tuple[FnResult, ...],
        tuple[tuple[int, str], ...],
        tuple[int, ...],
    ]
    | None
):
    """Parse independent integer result stores inside a block DEF FN.

    The first ``[bp+0] = 0`` store is the block-function marker. Every later
    store to that reserved cell is a source-level ``FNname% = value`` even
    when its value is also zero. Control flow and other statements may occur
    between stores, so each result is decoded from its own local expression
    window rather than treating the whole body as one expression.
    """

    if not operations or not (
        operations[0].kind == "mov_bp_imm" and operations[0].args == (0, 0)
    ):
        return None
    stores = [
        index
        for index, operation in enumerate(operations[1:], start=1)
        if (operation.kind == "movm_ax_bp" and operation.args == (0,))
        or (
            operation.kind == "mov_bp_imm"
            and len(operation.args) == 2
            and operation.args[0] == 0
        )
    ]
    if not stores:
        return None
    results = []
    parameters: dict[int, str] = {}
    for index in stores:
        parsed = _integer_result_at(operations, index, entry)
        if parsed is None:
            return None
        value, span, result_parameters, support = parsed
        results.append(FnResult(value, span, support))
        parameters.update(result_parameters)
    return (
        tuple(results),
        tuple(sorted(parameters.items())),
        combine_evidence(
            (operations[0].offset,),
            *(result.evidence for result in results),
        ),
    )


def _integer_result_at(
    operations: tuple[CompilerOp, ...], index: int, entry: int
) -> (
    tuple[
        object,
        tuple[int, int],
        dict[int, str],
        tuple[int, ...],
    ]
    | None
):
    store = operations[index]
    if store.kind == "mov_bp_imm":
        return (
            ("const", store.args[1]),
            (store.offset, store.end),
            {},
            (store.offset,),
        )
    cursor = index - 1
    arithmetic = []
    while cursor >= 0 and operations[cursor].kind in {
        "movax",
        "negax",
        "addax_bp",
        "andax_m",
    }:
        arithmetic.append(operations[cursor])
        cursor -= 1
    arithmetic.reverse()
    if (
        not arithmetic
        or arithmetic[0].kind != "movax"
        or len(arithmetic[0].args) != 1
        or arithmetic[-1].end != store.offset
        or any(
            left.end != right.offset for left, right in zip(arithmetic, arithmetic[1:])
        )
    ):
        return None
    value: object = ("const", arithmetic[0].args[0])
    parameters: dict[int, str] = {}
    for operation in arithmetic[1:]:
        # ``FNX% = -1``: ``mov ax,1; neg ax``.
        if operation.kind == "negax" and value[:1] == ("const",):
            value = ("const", -value[1])
            continue
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
    support = tuple(operation.offset for operation in (*arithmetic, store))
    return value, (arithmetic[0].offset, store.end), parameters, support


def _body_expression(
    operations: tuple[CompilerOp, ...], entry: int, returned: int
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
            if (
                not isinstance(operator, str)
                or not isinstance(offset, int)
                or offset <= 2
            ):
                return None
            parameters.setdefault(offset, _operand_kind(operation.kind))
            top = stack.pop()
            memory = ("fn-param", entry, offset, parameters[offset])
            value = orient_memory_fold(operator, memory, top.value)
            stack.append(
                _StackValue(
                    value,
                    combine_evidence(top.evidence, (operation.offset,)),
                    top.start,
                )
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
    stores = [
        (index, operation)
        for index, operation in enumerate(operations)
        if (operation.kind == "movm_ax_bp" and operation.args == (0,))
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
    value: object
    support: tuple[int, ...]
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
        if (
            not arithmetic
            or arithmetic[0].kind != "movax"
            or len(arithmetic[0].args) != 1
        ):
            return None
        if arithmetic[-1].end != store.offset or any(
            left.end != right.offset for left, right in zip(arithmetic, arithmetic[1:])
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
    return (
        value,
        "integer",
        (start, store.end),
        tuple(sorted(parameters.items())),
        support,
    )


def _expression_operation(operation: CompilerOp) -> bool:
    return (
        operation.kind
        in {
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
        }
        or operation.kind.startswith("fold")
        and operation.kind.endswith("_bp")
    )


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
    facts: frozenset[Fact],
) -> bool:

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
            len(prefix) == 1 and bytes.fromhex(prefix[0].raw) == b"\xc7\x46\x00\x00\x00"
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
    if _covered_block_prefix(tail, facts):
        return True
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


def _covered_block_prefix(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> bool:
    spans = tuple(
        fact.subject
        for fact in facts
        if fact.kind == "semantic.statement"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    )
    return bool(instructions) and all(
        instruction.kind == "tb.runtime"
        and instruction.operands == (0x87,)
        or any(
            span[0] <= instruction.offset and instruction.end <= span[1]
            for span in spans
        )
        for instruction in instructions
    )


def _exit_def_facts(
    evidence: Evidence,
    facts: frozenset[Fact],
    definition: FnDefinition,
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
    condition_spans = tuple(
        fact.subject
        for fact in facts
        if fact.kind in {"control.condition_prefix", "control.compound_condition"}
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    )
    exit_targets = {definition.returned}
    # Before it returns, the function releases its string locals, whatever
    # its result's type; a jump to the first release leaves it too.
    cleanup = _string_cleanup_start(instructions)
    if cleanup is not None:
        exit_targets.add(cleanup)
    exits = tuple(
        instruction
        for instruction in instructions
        if instruction.kind == "x86.jmp"
        and len(instruction.operands) == 1
        and instruction.operands[0] in exit_targets
        and not any(
            start <= instruction.offset < instruction.end <= end
            for start, end in condition_spans
        )
    )
    for exit_jump in exits:
        yield Fact(
            "semantic.exit_def",
            (exit_jump.offset, exit_jump.end),
            (),
            combine_evidence(definition.evidence, (exit_jump.offset,)),
            "signature",
        )
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
            "semantic.if_inline",
            (top.offset, exit_jump.end),
            (condition, exit_jump.offset, exit_jump.end, None),
            support,
            "anchored",
        )


def _string_cleanup_start(
    instructions: tuple[Operation, ...],
) -> int | None:
    for index in range(len(instructions) - 1):
        suffix = instructions[index:]
        if len(suffix) % 2:
            continue
        if all(
            bytes.fromhex(load.raw)[:2] in {b"\xc4\xb6", b"\xc4\x76"}
            and release.kind == "tb.runtime"
            and release.operands == (0xD3,)
            and load.end == release.offset
            for load, release in zip(suffix[::2], suffix[1::2])
        ):
            return suffix[0].offset
    return None


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
        return string_call_scaffold(
            instructions,
            call_index,
            result_kind=definition.result_kind,
            parameters=definition.parameters,
            definition_evidence=definition.evidence,
            compiler_by_offset=compiler_by_offset,
            facts=facts,
            local_bytes=definition.local_bytes,
        )
    if all(kind == "integer" for _offset, kind in definition.parameters):
        integer_arguments = _integer_call_scaffold(
            instructions, call_index, definition, compiler_by_offset
        )
        if integer_arguments is not None:
            return integer_arguments
    if call_index < 6 or call_index + 4 >= len(instructions):
        return None
    expected_size = (
        _frame_width(definition.result_kind)
        + sum(_frame_width(kind) for _offset, kind in definition.parameters)
        + definition.local_bytes
    )
    frame_index = next(
        (
            index
            for index in range(call_index - 1, max(-1, call_index - 48), -1)
            if index >= 3
            and bytes.fromhex(instructions[index].raw) == b"\x8b\xec"
            and bytes.fromhex(instructions[index - 1].raw)
            == bytes((0x83, 0xEC, expected_size))
            and bytes.fromhex(instructions[index - 2].raw)[:2] == b"\x89\x26"
            and bytes.fromhex(instructions[index - 3].raw) == b"\x55"
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
    reserve_raw = bytes.fromhex(reserve.raw)
    if len(reserve_raw) != 3 or reserve_raw[2] != expected_size:
        return None
    staged_arguments = stage_call_arguments(
        instructions[frame_index + 1 : call_index],
        definition.parameters,
        compiler_by_offset,
        facts,
        instruction_ends,
    )
    if staged_arguments is None:
        return None
    staged, argument_evidence = staged_arguments
    expected_offsets = tuple(offset for offset, _kind in definition.parameters)
    if tuple(sorted(staged)) != expected_offsets:
        return None
    result_tail = numeric_call_result_tail(
        instructions,
        call_index,
        definition.result_kind,
        expected_size,
        compiler_by_offset,
    )
    if result_tail is None:
        return None
    _result_load, pop, tail_evidence = result_tail
    arguments = tuple(staged[offset] for offset in expected_offsets)
    support = combine_evidence(
        tuple(item.offset for item in instructions[frame_index - 3 : call_index + 1]),
        tail_evidence,
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
    if call_index < 8:
        return None
    expected_size = (
        _frame_width(definition.result_kind)
        + sum(_frame_width(kind) for _offset, kind in definition.parameters)
        + definition.local_bytes
    )
    result_tail = numeric_call_result_tail(
        instructions,
        call_index,
        definition.result_kind,
        expected_size,
        compiler_by_offset,
    )
    if result_tail is None:
        return None
    result_load, pop, tail_evidence = result_tail
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
    if not definition.parameters:
        push = instructions[reserve_index - 1]
        if (
            bytes.fromhex(push.raw) == b"\x55"
            and push.end == instructions[reserve_index].offset
            and instructions[reserve_index].end == instructions[frame_index].offset
            and instructions[frame_index].end == instructions[call_index].offset
        ):
            return (
                push.offset,
                pop.end,
                (),
                combine_evidence(
                    tuple(
                        instruction.offset
                        for instruction in instructions[
                            reserve_index - 1 : call_index + 1
                        ]
                    ),
                    tail_evidence,
                    definition.evidence,
                ),
            )
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
    arguments = tuple(staged[offset] for offset in expected_offsets)
    support = combine_evidence(
        tuple(
            instruction.offset
            for instruction in instructions[reserve_index - 2 : call_index + 1]
        ),
        tail_evidence,
        definition.evidence,
    )
    return push.offset, pop.end, arguments, support


def _compact_integer_call(
    instructions: tuple[Operation, ...],
    call_index: int,
    definition: FnDefinition,
    compiler_by_offset: dict[int, CompilerOp],
) -> tuple[int, int, object, tuple[int, ...]] | None:

    if (
        definition.result_kind != "integer"
        or definition.parameters
        or definition.local_bytes
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
    operator = {b"\x2b\xc3": "-", b"\x03\xc3": "+"}.get(bytes.fromhex(combine.raw))
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
                (
                    literal,
                    push,
                    reserve,
                    frame,
                    instructions[call_index],
                    shuttle,
                    result_load,
                    release,
                    pop,
                ),
                (
                    push,
                    reserve,
                    frame,
                    instructions[call_index],
                    shuttle,
                    result_load,
                    release,
                    pop,
                    combine,
                ),
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
