from __future__ import annotations

import struct
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.def_fn_array_facts import local_array_len_result, local_arrays
from tbd.facts import Evidence
from tbd.for_templates import FpForTemplate, match_fp_for_test
from tbd.input_facts import input_header, input_prompt
from tbd.ir import Fact, Operation
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_expression,
    resolve_expression_before,
)


@dataclass(frozen=True)
class NumericResult:
    """Numeric result expression and its supporting compiler operations."""

    expression: object
    kind: str
    span: tuple[int, int]
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class NumericBlock:
    """Numeric DEF FN body classification and result information."""

    results: tuple[NumericResult, ...]
    parameters: tuple[tuple[int, str], ...]
    locals: tuple[tuple[int, str], ...]
    local_span: tuple[int, int]
    local_evidence: tuple[int, ...]
    local_bytes: int
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class _Value:
    expression: object
    start: int
    evidence: tuple[int, ...]


def numeric_bridge_body_expression(
    instructions: tuple[Operation, ...],
    facts: frozenset[Fact],
    entry: int,
    returned: int,
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
    """Resolve a numeric function body crossing a runtime bridge."""
    nodes = tuple(
        instruction
        for instruction in instructions
        if entry <= instruction.offset < returned
    )
    operations = translate_operations(nodes)
    result_stores = [
        (index, operation)
        for index, operation in enumerate(operations)
        if operation.kind in {"fstp_bp", "fstp64_bp", "fistp_bp", "fistp32_bp"}
        and operation.args == (0,)
    ]
    if len(result_stores) != 1:
        return None
    index, store = result_stores[0]
    if index < 2:
        return None
    bridge, load = operations[index - 2 : index]
    load_kinds = {
        "fild": "integer",
        "fild32": "long",
        "fld": "float",
        "fld64": "double",
    }
    result_kinds = {
        "fistp_bp": "integer",
        "fistp32_bp": "long",
        "fstp_bp": "float",
        "fstp64_bp": "double",
    }
    if not (
        bridge.kind == "movmem_ax"
        and len(bridge.args) == 1
        and load.kind in load_kinds
        and load.args == bridge.args
        and bridge.end == load.offset
        and load.end == store.offset
    ):
        return None
    ends = {instruction.offset: instruction.end for instruction in instructions}
    resolved = resolve_expression_before(bridge.offset, facts, ends)
    if resolved is None:
        return None
    parameters = {
        (value[2], value[3])
        for value in _tuples(resolved.value)
        if len(value) == 4
        and value[0] == "fn-param"
        and value[1] == entry
        and isinstance(value[2], int)
        and isinstance(value[3], str)
    }
    support = combine_evidence(
        resolved.evidence,
        (bridge.offset, load.offset, store.offset),
    )
    return (
        resolved.value,
        result_kinds[store.kind],
        (min(support), store.end),
        tuple(sorted(parameters)),
        support,
    )


def _tuples(value: object) -> Iterable[tuple[object, ...]]:
    if not isinstance(value, tuple):
        return
    yield value
    for item in value:
        yield from _tuples(item)


def numeric_block_body(
    instructions: tuple[Operation, ...], entry: int, returned: int
) -> NumericBlock | None:
    """Classify a numeric DEF FN block and its returned expression."""
    nodes = tuple(
        instruction
        for instruction in instructions
        if entry <= instruction.offset < returned
    )
    prefix = result_prefix(nodes)
    if prefix is None:
        return None
    initialization = local_initialization(nodes[prefix:])
    if initialization is None:
        return None
    init_nodes, local_start, local_bytes = initialization
    operations = translate_operations(nodes)
    first_parameter = 2 if prefix == 1 else 4
    kinds = bp_kinds(nodes, operations, minimum_offset=first_parameter)
    local_stop = local_start + local_bytes
    arrays = local_arrays(nodes, operations, local_start, local_bytes)
    compiler_temps = _compiler_local_temps(operations)
    local_kinds = {
        offset: found
        for offset, found in kinds.items()
        if local_start <= offset < local_stop
        and not any(array.base <= offset < array.end for array in arrays)
        and offset not in compiler_temps
    }
    parameter_kinds = {
        offset: found
        for offset, found in kinds.items()
        if first_parameter <= offset < local_start
    }
    if any(
        len(found) != 1 for found in (*local_kinds.values(), *parameter_kinds.values())
    ):
        return None
    locals_by_offset = {
        offset: next(iter(found)) for offset, found in local_kinds.items()
    }
    locals_by_offset.update({array.base: f"{array.kind}-array" for array in arrays})
    parameters_by_offset = {
        offset: next(iter(found)) for offset, found in parameter_kinds.items()
    }
    references = {
        **{
            offset: ("fn-param", entry, offset, kind)
            for offset, kind in parameters_by_offset.items()
        },
        **{
            offset: ("fn-local", entry, offset, kind)
            for offset, kind in locals_by_offset.items()
        },
    }
    results = _result_stores(operations, references)
    if not results:
        array_result = local_array_len_result(nodes, arrays, entry)
        if array_result is not None:
            expression, span, result_evidence = array_result
            results = (NumericResult(expression, "integer", span, result_evidence),)
    if not results or len({result.kind for result in results}) != 1:
        return None
    support = combine_evidence(
        tuple(node.offset for node in init_nodes),
        *(array.evidence for array in arrays),
        *(result.evidence for result in results),
    )
    return NumericBlock(
        results,
        tuple(sorted(parameters_by_offset.items())),
        tuple(sorted(locals_by_offset.items())),
        (init_nodes[0].offset, init_nodes[-1].end),
        tuple(node.offset for node in init_nodes),
        local_bytes,
        support,
    )


def numeric_body_facts(
    evidence: Evidence,
    facts: frozenset[Fact],
    *,
    entry: int,
    returned: int,
    parameters: tuple[tuple[int, str], ...],
    locals: tuple[tuple[int, str], ...],
    local_span: tuple[int, int] | None,
    local_evidence: tuple[int, ...],
) -> Iterable[Fact]:
    """Emit facts recovered from numeric DEF FN bodies."""
    local_kinds = dict(locals)
    local_values = {
        offset: (
            ("fn-local-array", entry, offset, kind.removesuffix("-array"))
            if kind.endswith("-array")
            else ("fn-local", entry, offset, kind)
        )
        for offset, kind in locals
    }
    references = {
        **{offset: ("fn-param", entry, offset, kind) for offset, kind in parameters},
        **local_values,
    }
    if local_values and local_span is not None:
        declared = tuple(
            local_values[offset]
            for offset in sorted(local_values)
            if not local_kinds[offset].endswith("-array")
        )
        yield Fact(
            "semantic.local",
            local_span,
            (declared,),
            local_evidence,
            "anchored",
        )
    nodes = tuple(
        instruction
        for instruction in evidence.instructions
        if entry <= instruction.offset < returned
    )
    operations = translate_operations(nodes)
    yield from _reference_facts(nodes, operations, references)
    yield from _assignment_facts(
        nodes,
        operations,
        facts,
        local_values,
        references,
    )
    yield from _local_input_facts(nodes, operations, facts, local_values)
    yield from _local_fp_for_facts(
        nodes,
        operations,
        facts,
        local_values,
        references,
    )
    yield from _increment_facts(nodes, operations, local_values, references)
    yield from _integer_local_condition_facts(
        operations,
        local_values,
        references,
    )
    yield from _materialized_bp_relation_facts(operations, references)


def _reference_facts(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    references: Mapping[int, object],
) -> Iterable[Fact]:
    for operation in operations:
        loaded = _direct_bp_value(operation, references)
        if loaded is not None:
            yield Fact(
                "expression.value",
                (operation.offset,),
                (loaded.expression,),
                loaded.evidence,
                "anchored",
            )
    for load, runtime in zip(nodes, nodes[1:]):
        if not (
            load.kind == "x86.mov_imm"
            and load.operands[:1] == ("si",)
            and len(load.operands) == 2
            and runtime.kind == "tb.runtime"
            and runtime.operands == (0x9E,)
            and load.end == runtime.offset
        ):
            continue
        reference = references.get(load.operands[1])
        if (
            not isinstance(reference, tuple)
            or len(reference) != 4
            or reference[3] != "string"
        ):
            continue
        yield Fact(
            "expression.string_operand",
            (load.offset, runtime.end),
            (reference,),
            (load.offset, runtime.offset),
            "anchored",
        )


def _assignment_facts(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    facts: frozenset[Fact],
    local_values: Mapping[int, object],
    references: Mapping[int, object],
) -> Iterable[Fact]:
    for index, operation in enumerate(operations):
        target = _local_assignment_target(operation, local_values)
        if target is None:
            continue
        source = _local_assignment_source(
            nodes,
            operations,
            index,
            references,
        )
        if source is None:
            continue
        resolved = resolve_expression(source.expression, facts)
        if resolved is None:
            continue
        end, commit_evidence = _statement_end(operation.end, nodes)
        yield Fact(
            "semantic.assign",
            (source.start, end),
            (target, resolved.value),
            combine_evidence(
                source.evidence,
                resolved.evidence,
                (operation.offset,),
                commit_evidence,
            ),
            "anchored",
        )


def _local_assignment_target(
    operation: CompilerOp, local_values: Mapping[int, object]
) -> object | None:
    if (
        operation.kind
        not in {
            "mov_bp_imm",
            "movm_ax_bp",
            "fistp_bp",
            "fistp32_bp",
            "fstp_bp",
            "fstp64_bp",
        }
        or not operation.args
    ):
        return None
    if not isinstance(operation.args[0], int):
        return None
    target = local_values.get(operation.args[0])
    if not isinstance(target, tuple) or len(target) != 4 or target[0] != "fn-local":
        return None
    return target


def _local_assignment_source(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    index: int,
    references: Mapping[int, object],
) -> _Value | None:
    operation = operations[index]
    if operation.kind == "mov_bp_imm" and len(operation.args) == 2:
        return _Value(
            ("const", operation.args[1]),
            operation.offset,
            (operation.offset,),
        )
    if operation.kind in {"fistp_bp", "fistp32_bp", "fstp_bp", "fstp64_bp"}:
        return _fp_expression_before(operations, index, references)
    source = _ax_value_before(operations, index, references)
    if source is None:
        source = _converted_integer_value_before(operations, index, references)
    if source is None:
        source = _len_plus_integer_before(nodes, operation.offset, references)
    return source


def _increment_facts(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    local_values: Mapping[int, object],
    references: Mapping[int, object],
) -> Iterable[Fact]:
    for index, operation in enumerate(operations):
        if (
            operation.kind != "addm_ax_bp"
            or not operation.args
            or not isinstance(operation.args[0], int)
            or operation.args[0] not in local_values
        ):
            continue
        source = _ax_value_before(operations, index, references)
        if source is None:
            continue
        local = local_values[operation.args[0]]
        end, commit_evidence = _statement_end(operation.end, nodes)
        yield Fact(
            "semantic.assign",
            (source.start, end),
            (local, ("binary", "+", local, source.expression)),
            combine_evidence(source.evidence, (operation.offset,), commit_evidence),
            "anchored",
        )


def _local_input_facts(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    facts: frozenset[Fact],
    local_values: Mapping[int, object],
) -> Iterable[Fact]:
    compiler = {operation.offset: operation for operation in operations}
    for index, header in enumerate(nodes):
        parsed = input_header(header)
        if parsed is None:
            continue
        prompt_address, flags, count = parsed
        if count != 1 or not flags & 0x4000:
            continue
        window = nodes[index + 1 : index + 7]
        if len(window) != 6:
            continue
        phase, convert_node, wait_node, load_node, store_node, commit = window
        converted = tuple(
            compiler.get(node.offset)
            for node in (convert_node, wait_node, load_node, store_node)
        )
        if any(operation is None for operation in converted):
            continue
        convert, wait, load, store = converted
        if not (
            phase.kind == "tb.statement"
            and phase.operands[:1] == ("READ_NUMBER",)
            and convert is not None
            and convert.kind == "fistp"
            and len(convert.args) == 1
            and wait is not None
            and wait.kind == "fwait"
            and load is not None
            and load.kind == "movaxmem"
            and load.args == convert.args
            and store is not None
            and store.kind == "movm_ax_bp"
            and len(store.args) == 1
            and commit.kind == "tb.runtime"
            and commit.operands == (0x87,)
            and all(left.end == right.offset for left, right in zip(window, window[1:]))
        ):
            continue
        if not isinstance(store.args[0], int):
            continue
        target = local_values.get(store.args[0])
        if (
            not isinstance(target, tuple)
            or len(target) != 4
            or target[0] != "fn-local"
            or target[3] != "integer"
        ):
            continue
        prompt = input_prompt(prompt_address, facts)
        if prompt is None:
            continue
        prompt_value, prompt_evidence = prompt
        yield Fact(
            "semantic.input",
            (header.offset, commit.end),
            (prompt_value, target, bool(flags & 0x40), bool(flags & 0x80)),
            combine_evidence(
                tuple(node.offset for node in window),
                (header.offset,),
                prompt_evidence,
            ),
            "anchored",
        )


def _integer_local_condition_facts(
    operations: tuple[CompilerOp, ...],
    local_values: Mapping[int, object],
    references: Mapping[int, object],
) -> Iterable[Fact]:
    skip_relations = {
        0x74: "<>",
        0x75: "=",
        0x7C: "<=",
        0x7D: ">",
        0x7E: "<",
        0x7F: ">=",
    }
    for index in range(1, len(operations) - 2):
        compare, branch, jump = operations[index : index + 3]
        if (
            compare.kind != "cmpax_bp"
            or len(compare.args) != 1
            or not isinstance(compare.args[0], int)
            or compare.args[0] not in local_values
            or branch.kind != "jcc"
            or len(branch.args) != 2
            or jump.kind != "jmp"
            or len(jump.args) != 1
            or compare.end != branch.offset
            or branch.end != jump.offset
            or branch.args[1] != jump.end
        ):
            continue
        if not isinstance(branch.args[0], int) or not isinstance(jump.args[0], int):
            continue
        relation = skip_relations.get(branch.args[0])
        source = _ax_value_before(operations, index, references)
        if relation is None or source is None:
            continue
        yield Fact(
            "semantic.if_goto",
            (source.start, jump.end),
            (
                relation,
                local_values[compare.args[0]],
                source.expression,
                jump.args[0],
                branch.args[1],
            ),
            combine_evidence(
                source.evidence,
                (compare.offset, branch.offset, jump.offset),
            ),
            "anchored",
        )


def _local_fp_for_facts(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    facts: frozenset[Fact],
    local_values: Mapping[int, object],
    references: Mapping[int, object],
) -> Iterable[Fact]:
    nodes_by_end = {node.end: node for node in nodes}
    for test_index, test in enumerate(operations):
        staged = _fp_for_staged_addresses(operations, test_index)
        if staged is None:
            continue
        template = match_fp_for_test(operations, test_index, staged)
        if template is None:
            continue
        header_target = test.offset
        if (
            test_index
            and operations[test_index - 1].kind == "fwait"
            and operations[test_index - 1].end == test.offset
        ):
            header_target = operations[test_index - 1].offset
        header = _local_fp_for_header(
            operations,
            test_index,
            header_target,
            template.limit,
            template.step,
            template.variable,
            template.wide,
            nodes_by_end,
            facts,
            local_values,
            references,
        )
        tail = _local_fp_for_tail(operations, test_index, template)
        if header is None or tail is None:
            continue
        jump, variable, initial, limit, step, header_evidence = header
        tail_start, tail_evidence = tail
        support = combine_evidence(
            header_evidence,
            tail_evidence,
            template.evidence,
        )
        yield Fact(
            "semantic.for",
            (limit.start, jump.end),
            (variable, initial.value, limit.value, step.value),
            support,
            "anchored",
        )
        yield Fact(
            "semantic.next",
            (tail_start, template.end),
            (variable,),
            support,
            "anchored",
        )


def _fp_for_staged_addresses(
    operations: tuple[CompilerOp, ...], index: int
) -> tuple[int, int, int] | None:
    if index + 4 >= len(operations):
        return None
    test = operations[index]
    limit = operations[index + 3]
    variable = operations[index + 4]
    if (
        test.kind != "testw_bp"
        or len(test.args) != 2
        or test.args[1] != 0x8000
        or limit.kind not in {"fld_bp", "fld64_bp"}
        or variable.kind not in {"fcomp", "fcomp_bp", "fcomp64"}
        or not all(
            operation.args and isinstance(operation.args[0], int)
            for operation in (test, limit, variable)
        )
    ):
        return None
    limit_address, step_address, variable_address = (
        limit.args[0],
        test.args[0],
        variable.args[0],
    )
    if not all(
        isinstance(address, int)
        for address in (limit_address, step_address, variable_address)
    ):
        return None
    assert isinstance(limit_address, int)
    assert isinstance(step_address, int)
    assert isinstance(variable_address, int)
    return limit_address, step_address - 2, variable_address


def _local_fp_for_header(
    operations: tuple[CompilerOp, ...],
    test_index: int,
    test_offset: int,
    limit_address: int,
    step_address: int,
    variable_address: int,
    wide: bool,
    nodes_by_end: dict[int, Operation],
    facts: frozenset[Fact],
    local_values: Mapping[int, object],
    references: Mapping[int, object],
) -> (
    tuple[
        CompilerOp,
        object,
        Resolved,
        Resolved,
        Resolved,
        tuple[int, ...],
    ]
    | None
):
    jump_indexes = [
        index
        for index, operation in enumerate(operations[:test_index])
        if operation.kind == "jmp" and operation.args == (test_offset,)
    ]
    if len(jump_indexes) != 1:
        return None
    jump_index = jump_indexes[0]
    jump = operations[jump_index]
    commit = nodes_by_end.get(jump.offset)
    if commit is None or commit.kind != "tb.runtime" or commit.operands != (0x87,):
        return None
    limit_bp = operations[test_index + 3].kind.endswith("_bp")
    variable_bp = operations[test_index + 4].kind.endswith("_bp")
    step_bp = operations[test_index].kind == "testw_bp"
    store_indexes = (
        _fp_store_before(operations, jump_index, limit_address, wide, limit_bp),
        _fp_store_before(operations, jump_index, step_address, wide, step_bp),
        _fp_store_before(operations, jump_index, variable_address, wide, variable_bp),
    )
    if any(index is None for index in store_indexes):
        return None
    limit_index, step_index, variable_index = store_indexes
    if not (
        isinstance(limit_index, int)
        and isinstance(step_index, int)
        and isinstance(variable_index, int)
        and limit_index < step_index < variable_index == jump_index - 1
    ):
        return None
    values = tuple(
        _resolved_fp_source(operations, index, references, facts)
        for index in (limit_index, step_index, variable_index)
    )
    if any(value is None for value in values):
        return None
    limit, step, initial = values
    if limit is None or step is None or initial is None:
        return None
    variable = local_values.get(variable_address)
    variable_support: tuple[int, ...] = ()
    if variable is None:
        resolved_variable = resolve_expression(
            ("memory", variable_address, "double" if wide else "float"),
            facts,
        )
        if resolved_variable is None:
            kind = "double" if wide else "float"
            variable = (
                "slot",
                f"V{variable_address:04X}",
                variable_address,
                kind,
            )
        else:
            variable = resolved_variable.value
            variable_support = resolved_variable.evidence
    support = combine_evidence(
        *(value.evidence for value in values if value is not None),
        tuple(operations[index].offset for index in store_indexes if index is not None),
        variable_support,
        (commit.offset, jump.offset),
    )
    return jump, variable, initial, limit, step, support


def _fp_store_before(
    operations: tuple[CompilerOp, ...],
    stop: int,
    address: int,
    wide: bool,
    bp_relative: bool,
) -> int | None:
    kind = ("fstp64" if wide else "fstp") + ("_bp" if bp_relative else "")
    matches = [
        index
        for index, operation in enumerate(operations[:stop])
        if operation.kind == kind and operation.args == (address,)
    ]
    return matches[-1] if matches else None


def _resolved_fp_source(
    operations: tuple[CompilerOp, ...],
    store_index: int,
    references: Mapping[int, object],
    facts: frozenset[Fact],
) -> Resolved | None:
    source = _fp_expression_before(operations, store_index, references)
    if source is None:
        return None
    resolved = resolve_expression(source.expression, facts)
    if resolved is None:
        return None
    return Resolved(
        resolved.value,
        combine_evidence(source.evidence, resolved.evidence),
        source.start,
    )


def _local_fp_for_tail(
    operations: tuple[CompilerOp, ...],
    test_index: int,
    template: FpForTemplate,
) -> tuple[int, tuple[int, ...]] | None:
    cursor = test_index
    sync_evidence: tuple[int, ...] = ()
    if cursor and operations[cursor - 1].kind == "fwait":
        cursor -= 1
        sync_evidence = (operations[cursor].offset,)
    if cursor < 3:
        return None
    load, fold, store = operations[cursor - 3 : cursor]
    load_kind = "fld64_bp" if template.wide else "fld_bp"
    variable_bp = operations[test_index + 4].kind.endswith("_bp")
    fold_kind = ("fold64" if template.wide else "fold") + ("_bp" if variable_bp else "")
    store_kind = ("fstp64" if template.wide else "fstp") + (
        "_bp" if variable_bp else ""
    )
    if not (
        load.kind == load_kind
        and load.args == (template.step,)
        and fold.kind == fold_kind
        and fold.args == ("+", template.variable)
        and store.kind == store_kind
        and store.args == (template.variable,)
        and load.end == fold.offset
        and fold.end == store.offset
        and store.end == operations[cursor].offset
    ):
        return None
    return load.offset, (load.offset, fold.offset, store.offset, *sync_evidence)


def _materialized_bp_relation_facts(
    operations: tuple[CompilerOp, ...], references: Mapping[int, object]
) -> Iterable[Fact]:
    relations = {
        0x72: ">",
        0x73: "<=",
        0x74: "=",
        0x75: "<>",
        0x76: ">=",
        0x77: "<",
        0x7C: ">",
        0x7D: "<=",
        0x7E: ">=",
        0x7F: "<",
    }
    for index in range(len(operations) - 4):
        load, compare, materialize, branch, increment = operations[index : index + 5]
        if not (
            load.kind == "movax"
            and len(load.args) == 1
            and compare.kind == "cmpax_bp"
            and len(compare.args) == 1
            and compare.args[0] in references
            and materialize.kind == "movax"
            and materialize.args == (0xFFFF,)
            and branch.kind == "jcc"
            and len(branch.args) == 2
            and increment.kind == "incax"
            and load.end == compare.offset
            and compare.end == materialize.offset
            and materialize.end == branch.offset
            and branch.end == increment.offset
            and branch.args[1] == increment.end
        ):
            continue
        if not isinstance(branch.args[0], int) or not isinstance(compare.args[0], int):
            continue
        relation = relations.get(branch.args[0])
        if relation is None:
            continue
        yield Fact(
            "expression.relation_value",
            (load.offset, increment.end),
            (
                relation,
                references[compare.args[0]],
                ("const", load.args[0]),
            ),
            tuple(
                operation.offset
                for operation in (load, compare, materialize, branch, increment)
            ),
            "anchored",
        )


def result_prefix(nodes: tuple[Operation, ...]) -> int | None:
    """Return the operation prefix ending at a numeric result store."""
    if not nodes or nodes[0].raw != "c7 46 00 00 00":
        return None
    return 2 if len(nodes) > 1 and nodes[1].raw == "c7 46 02 00 00" else 1


def local_initialization(
    nodes: tuple[Operation, ...],
) -> tuple[tuple[Operation, ...], int, int] | None:
    """Recover the local-frame initialization window and its size."""
    if len(nodes) < 12:
        return None
    window = nodes[:12]
    raws = tuple(bytes.fromhex(node.raw) for node in window)
    if not (
        raws[:4] == (b"\x51", b"\x57", b"\x8c\xd0", b"\x8e\xc0")
        and len(raws[4]) == 3
        and raws[4][0] == 0xB9
        and len(raws[5]) == 4
        and raws[5][:2] == b"\x8d\xbe"
        and raws[6:]
        == (
            b"\x31\xc0",
            b"\xfc",
            b"\xf3",
            b"\xab",
            b"\x5f",
            b"\x59",
        )
    ):
        return None
    local_words = struct.unpack_from("<H", raws[4], 1)[0]
    local_start = struct.unpack_from("<h", raws[5], 2)[0]
    if local_words <= 0 or local_start <= 2:
        return None
    return window, local_start, local_words * 2


def bp_kinds(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    *,
    minimum_offset: int = 3,
) -> dict[int, set[str]]:
    """Map BP-relative locals to their inferred scalar kinds."""
    kinds: dict[int, set[str]] = {}
    integer = {
        "mov_bp_imm",
        "movax_bp",
        "movm_ax_bp",
        "addax_bp",
        "imul_bp",
        "cmpax_bp",
        "cmpm_ax_bp",
        "addm_ax_bp",
        "testw_bp",
        "fild_bp",
        "fistp_bp",
    }
    direct = {
        "fild32_bp": "long",
        "fistp32_bp": "long",
        "fld_bp": "float",
        "fstp_bp": "float",
        "fcomp_bp": "float",
        "fold_bp": "float",
        "fld64_bp": "double",
        "fstp64_bp": "double",
        "fcomp64_bp": "double",
        "fold64_bp": "double",
    }
    for operation in operations:
        offset = _bp_offset(operation)
        if offset is None or offset < minimum_offset:
            continue
        kind = "integer" if operation.kind in integer else direct.get(operation.kind)
        if kind is not None:
            kinds.setdefault(offset, set()).add(kind)
    for left, right in zip(nodes, nodes[1:]):
        if (
            left.kind == "x86.mov_imm"
            and left.operands[:1] == ("si",)
            and len(left.operands) == 2
            and isinstance(left.operands[1], int)
            and left.operands[1] >= minimum_offset
            and right.kind == "tb.runtime"
            and right.operands in {(0x9E,), (0xA2,)}
            and left.end == right.offset
        ):
            kinds.setdefault(left.operands[1], set()).add("string")
    return kinds


def _bp_offset(operation: CompilerOp) -> int | None:
    if not operation.args:
        return None
    value = (
        operation.args[-1] if operation.kind.startswith("fold") else operation.args[0]
    )
    return value if isinstance(value, int) else None


def _result_stores(
    operations: tuple[CompilerOp, ...], references: Mapping[int, object]
) -> tuple[NumericResult, ...]:
    store_kinds = {
        "fstp_bp": "float",
        "fstp64_bp": "double",
        "fistp_bp": "integer",
        "fistp32_bp": "long",
        "movm_ax_bp": "integer",
    }
    results = []
    for index, store in enumerate(operations):
        kind = store_kinds.get(store.kind)
        if kind is None or store.args != (0,):
            continue
        value = _fp_value_before(operations, index, references)
        if value is None:
            continue
        results.append(
            NumericResult(
                value.expression,
                kind,
                (value.start, store.end),
                combine_evidence(value.evidence, (store.offset,)),
            )
        )
    return tuple(results)


def _fp_value_before(
    operations: tuple[CompilerOp, ...], index: int, references: Mapping[int, object]
) -> _Value | None:
    if index == 0:
        return None
    if index >= 3:
        bridge, load = operations[index - 2 : index]
        if (
            load.kind in {"fild", "fild32"}
            and len(load.args) == 1
            and bridge.kind == "movmem_ax"
            and bridge.args == load.args
            and bridge.end == load.offset
        ):
            source = _ax_value_before(operations, index - 2, references)
            if source is not None:
                return _Value(
                    source.expression,
                    source.start,
                    combine_evidence(
                        source.evidence,
                        (bridge.offset, load.offset),
                    ),
                )
    return _fp_expression_before(operations, index, references)


def _compiler_local_temps(operations: tuple[CompilerOp, ...]) -> frozenset[int]:
    statuses = {
        operation.args[0]
        for operation in operations
        if operation.kind == "testw_bp"
        and operation.args[1:] == (0x8000,)
        and isinstance(operation.args[0], int)
    }
    return frozenset(
        offset for status in statuses for offset in (status - 2, status, status + 2)
    )


def _direct_value(
    operation: CompilerOp, references: Mapping[int, object]
) -> _Value | None:
    if operation.kind in {"fld1", "fldz"}:
        return _Value(
            ("const", 1 if operation.kind == "fld1" else 0),
            operation.offset,
            (operation.offset,),
        )
    direct = {
        "fild_bp": "integer",
        "fild32_bp": "long",
        "fld_bp": "float",
        "fld64_bp": "double",
        "movax_bp": "integer",
    }
    if operation.kind in direct and len(operation.args) == 1:
        if not isinstance(operation.args[0], int):
            return None
        reference = references.get(operation.args[0])
        if reference is not None:
            return _Value(reference, operation.offset, (operation.offset,))
    memory = {"fild": "integer", "fild32": "long", "fld": "float", "fld64": "double"}
    kind = memory.get(operation.kind)
    if kind is not None and len(operation.args) == 1:
        return _Value(
            ("memory", operation.args[0], kind),
            operation.offset,
            (operation.offset,),
        )
    return None


def _direct_bp_value(
    operation: CompilerOp, references: Mapping[int, object]
) -> _Value | None:
    return _direct_value(operation, references)


def _ax_value_before(
    operations: tuple[CompilerOp, ...], index: int, references: Mapping[int, object]
) -> _Value | None:
    if index == 0:
        return None
    cursor = index - 1
    arithmetic = []
    while cursor >= 0 and operations[cursor].kind in {
        "movax",
        "movax_bp",
        "addax_bp",
        "imul_bp",
        "andax_m",
    }:
        arithmetic.append(operations[cursor])
        cursor -= 1
    arithmetic.reverse()
    if not arithmetic or arithmetic[-1].end != operations[index].offset:
        return None
    first = arithmetic[0]
    if first.kind == "movax" and len(first.args) == 1:
        expression: object = ("const", first.args[0])
    elif first.kind == "movax_bp" and len(first.args) == 1:
        if not isinstance(first.args[0], int):
            return None
        expression = references.get(first.args[0])
        if expression is None:
            return None
    else:
        return None
    for operation in arithmetic[1:]:
        if operation.kind in {"addax_bp", "imul_bp"} and len(operation.args) == 1:
            if not isinstance(operation.args[0], int):
                return None
            reference = references.get(operation.args[0])
            if reference is None:
                return None
            operator = "+" if operation.kind == "addax_bp" else "*"
            expression = ("binary", operator, reference, expression)
        elif operation.kind == "andax_m" and len(operation.args) == 1:
            expression = (
                "binary",
                "AND",
                ("memory", operation.args[0], "integer"),
                expression,
            )
        else:
            return None
    return _Value(
        expression,
        first.offset,
        tuple(operation.offset for operation in arithmetic),
    )


def _converted_integer_value_before(
    operations: tuple[CompilerOp, ...], index: int, references: Mapping[int, object]
) -> _Value | None:
    if index < 4:
        return None
    convert, wait, load = operations[index - 3 : index]
    store = operations[index]
    if not (
        convert.kind == "fistp"
        and len(convert.args) == 1
        and wait.kind == "fwait"
        and load.kind == "movaxmem"
        and load.args == convert.args
        and convert.end == wait.offset
        and wait.end == load.offset
        and load.end == store.offset
    ):
        return None
    source = _fp_expression_before(operations, index - 3, references)
    if source is None:
        return None
    return _Value(
        source.expression,
        source.start,
        combine_evidence(source.evidence, (convert.offset, wait.offset, load.offset)),
    )


def _fp_expression_before(
    operations: tuple[CompilerOp, ...], index: int, references: Mapping[int, object]
) -> _Value | None:
    if index == 0:
        return None
    cursor = index - 1
    folds = []
    while (
        cursor >= 0
        and operations[cursor].kind.startswith("fold")
        and operations[cursor].kind.endswith("_bp")
    ):
        folds.append(operations[cursor])
        cursor -= 1
    if cursor < 0:
        return None
    base = _direct_value(operations[cursor], references)
    if base is None:
        return None
    expression = base.expression
    support = list(base.evidence)
    for fold in reversed(folds):
        if len(fold.args) != 2:
            return None
        operator, offset = fold.args
        if not isinstance(offset, int):
            return None
        reference = references.get(offset)
        if reference is None:
            return None
        expression = ("binary", operator, reference, expression)
        support.append(fold.offset)
    return _Value(expression, base.start, tuple(support))


def _len_plus_integer_before(
    nodes: tuple[Operation, ...],
    store_offset: int,
    references: Mapping[int, object],
) -> _Value | None:
    position = next(
        (index for index, node in enumerate(nodes) if node.offset == store_offset),
        None,
    )
    if position is None or position < 6:
        return None
    number, string, read, stage, length, add = nodes[position - 6 : position]
    compiler = {
        operation.offset: operation for operation in translate_operations((number,))
    }
    number_operation = compiler.get(number.offset)
    if not (
        number_operation is not None
        and number_operation.kind == "movax_bp"
        and len(number_operation.args) == 1
        and string.kind == "x86.mov_imm"
        and string.operands[:1] == ("si",)
        and len(string.operands) == 2
        and read.kind == "tb.runtime"
        and read.operands == (0x9E,)
        and stage.raw in {"89 c3", "8b d8"}
        and length.kind == "tb.function"
        and length.operands == ("numeric", 0x22)
        and add.raw == "03 c3"
        and all(
            left.end == right.offset
            for left, right in zip(
                (number, string, read, stage, length),
                (string, read, stage, length, add),
            )
        )
    ):
        return None
    if not isinstance(number_operation.args[0], int) or not isinstance(
        string.operands[1], int
    ):
        return None
    integer = references.get(number_operation.args[0])
    string_value = references.get(string.operands[1])
    if (
        integer is None
        or not isinstance(string_value, tuple)
        or len(string_value) != 4
        or string_value[3] != "string"
    ):
        return None
    return _Value(
        (
            "binary",
            "+",
            ("call", "LEN", (string_value,)),
            integer,
        ),
        number.offset,
        tuple(node.offset for node in (number, string, read, stage, length, add)),
    )


def _statement_end(
    end: int, nodes: tuple[Operation, ...]
) -> tuple[int, tuple[int, ...]]:
    commit = next((node for node in nodes if node.offset == end), None)
    if (
        commit is not None
        and commit.kind == "tb.runtime"
        and commit.operands == (0x87,)
    ):
        return commit.end, (commit.offset,)
    return end, ()
