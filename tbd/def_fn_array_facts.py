from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence
from tbd.ir import Fact, Operation
from tbd.semantic import Resolved, combine_evidence, resolve_expression

_DESCRIPTOR_BYTES = 60
_ELEMENT_TYPES = {
    0x00: "integer",
    0x02: "long",
    0x04: "float",
    0x06: "double",
    0x0A: "string",
}
_ELEMENT_WIDTHS = {
    "integer": 2,
    "long": 4,
    "float": 4,
    "double": 8,
    "string": 4,
}


def _array_element_type(header: CompilerOp | None) -> str:
    if header is None or len(header.args) < 2 or not isinstance(header.args[1], int):
        return "float"
    return _ELEMENT_TYPES[header.args[1] & 0xFF]


@dataclass(frozen=True)
class LocalArray:
    """Descriptor for an array local to a DEF FN frame."""

    base: int
    kind: str
    evidence: tuple[int, ...]

    @property
    def end(self) -> int:
        """Return the byte offset immediately after the descriptor."""
        return self.base + _DESCRIPTOR_BYTES


def local_arrays(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    local_start: int,
    local_bytes: int,
) -> tuple[LocalArray, ...]:
    """Discover local array descriptors in a function body."""
    local_stop = local_start + local_bytes
    cleanup = {
        setup.operands[1]: (setup.offset, release.offset)
        for setup, release in zip(nodes, nodes[1:])
        if setup.kind == "x86.mov_imm"
        and setup.operands[:1] == ("si",)
        and len(setup.operands) == 2
        and isinstance(setup.operands[1], int)
        and release.kind == "tb.statement"
        and release.operands == ("LOCAL_ARRAY_FREE", 0x3A)
        and setup.end == release.offset
    }
    bases = tuple(sorted(cleanup))
    if not bases or any(
        base < local_start
        or base + _DESCRIPTOR_BYTES > local_stop
        or any(base < other < base + _DESCRIPTOR_BYTES for other in bases)
        for base in bases
    ):
        return ()
    headers = {
        operation.args[0] - 2: operation
        for operation in operations
        if operation.kind == "mov_bp_imm"
        and len(operation.args) == 2
        and isinstance(operation.args[0], int)
        and isinstance(operation.args[1], int)
        and operation.args[0] - 2 in cleanup
        and operation.args[1] >> 8 in {1, 2, 3}
        and operation.args[1] & 0xFF in _ELEMENT_TYPES
    }
    return tuple(
        LocalArray(
            base,
            (_array_element_type(headers.get(base))),
            combine_evidence(
                cleanup[base],
                () if base not in headers else (headers[base].offset,),
            ),
        )
        for base in bases
    )


def local_array_body_facts(
    evidence: Evidence,
    facts: frozenset[Fact],
    *,
    entry: int,
    returned: int,
    parameters: tuple[tuple[int, str], ...],
    locals: tuple[tuple[int, str], ...],
) -> Iterable[Fact]:
    """Recover facts for accesses to local array bodies."""
    arrays = {
        offset: ("fn-local-array", entry, offset, kind.removesuffix("-array"))
        for offset, kind in locals
        if kind.endswith("-array")
    }
    if not arrays:
        return
    references = {
        **{offset: ("fn-param", entry, offset, kind) for offset, kind in parameters},
        **{
            offset: ("fn-local", entry, offset, kind)
            for offset, kind in locals
            if not kind.endswith("-array")
        },
    }
    nodes = tuple(
        instruction
        for instruction in evidence.instructions
        if entry <= instruction.offset < returned
    )
    operations = translate_operations(nodes)
    yield from _local_dims(nodes, operations, arrays, references)
    yield from _local_erases(nodes, arrays)
    yield from _local_string_elements(nodes, operations, arrays, references, facts)


def local_array_len_result(
    nodes: tuple[Operation, ...], arrays: tuple[LocalArray, ...], entry: int
) -> tuple[object, tuple[int, int], tuple[int, ...]] | None:
    """Recover the result of a local-array length query."""
    by_base = {array.base: array for array in arrays if array.kind == "string"}
    matches = []
    for index in range(len(nodes) - 4):
        segment, offset, read, length, store = nodes[index : index + 5]
        base = _bp_segment_base(segment)
        array = by_base.get(base) if base is not None else None
        element = _array_element(array, offset, entry) if array is not None else None
        if not (
            element is not None
            and read.kind == "tb.runtime"
            and read.operands == (0x9D,)
            and length.kind == "tb.function"
            and length.operands == ("numeric", 0x22)
            and bytes.fromhex(store.raw) == b"\x89\x46\x00"
            and all(
                left.end == right.offset
                for left, right in zip(
                    (segment, offset, read, length),
                    (offset, read, length, store),
                )
            )
        ):
            continue
        matches.append(
            (
                ("call", "LEN", (element,)),
                (segment.offset, store.end),
                tuple(item.offset for item in (segment, offset, read, length, store)),
            )
        )
    return matches[0] if len(matches) == 1 else None


def _local_dims(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    arrays: Mapping[int, tuple[object, ...]],
    references: Mapping[int, tuple[object, ...]],
) -> Iterable[Fact]:
    operations_by_offset = {operation.offset: operation for operation in operations}
    opened: dict[int, tuple[int, int, tuple[int, ...]]] = {}
    for index, statement in enumerate(nodes):
        if statement.kind != "tb.statement" or statement.operands not in {
            ("DIM_BEGIN", 0x2C),
            ("DIM_END", 0x2E),
        }:
            continue
        scaffold = _descriptor_scaffold(nodes, index)
        if scaffold is None:
            continue
        start, base, scaffold_evidence = scaffold
        if base not in arrays:
            continue
        if statement.operands[0] == "DIM_BEGIN":
            opened[base] = (
                start,
                statement.end,
                combine_evidence(scaffold_evidence, (statement.offset,)),
            )
            continue
        opening = opened.pop(base, None)
        if opening is None:
            continue
        bound = _local_dim_bound(
            operations,
            operations_by_offset,
            opening[1],
            statement.offset,
            base,
            references,
        )
        if bound is None:
            continue
        value, bound_evidence = bound
        yield Fact(
            "semantic.dynamic_dim",
            (opening[0], statement.end),
            (arrays[base], (value,), (), False),
            combine_evidence(
                opening[2],
                scaffold_evidence,
                (statement.offset,),
                bound_evidence,
            ),
            "anchored",
        )


def _local_erases(
    nodes: tuple[Operation, ...], arrays: Mapping[int, tuple[object, ...]]
) -> Iterable[Fact]:
    for index, statement in enumerate(nodes):
        if statement.kind != "tb.statement" or statement.operands != ("ERASE", 0x36):
            continue
        scaffold = _descriptor_scaffold(nodes, index)
        if scaffold is None:
            continue
        start, base, support = scaffold
        array = arrays.get(base)
        if array is None:
            continue
        yield Fact(
            "semantic.statement",
            (start, statement.end),
            ("ERASE", 0x36, array),
            combine_evidence(support, (statement.offset,)),
            "anchored",
        )


def _local_string_elements(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    arrays: Mapping[int, tuple[object, ...]],
    references: Mapping[int, tuple[object, ...]],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    for segment, offset, runtime in zip(nodes, nodes[1:], nodes[2:]):
        base = _bp_segment_base(segment)
        array = arrays.get(base) if base is not None else None
        element = _array_element_value(array, offset)
        if element is None or not (
            runtime.kind == "tb.runtime"
            and runtime.operands in {(0x9D,), (0xA1,)}
            and segment.end == offset.offset
            and offset.end == runtime.offset
        ):
            continue
        if runtime.operands == (0x9D,):
            yield Fact(
                "expression.string_operand",
                (segment.offset, runtime.end),
                (element,),
                (segment.offset, offset.offset, runtime.offset),
                "anchored",
            )
            continue
        source = _string_expression_before(segment.offset, facts)
        if source is None:
            continue
        yield Fact(
            "semantic.assign",
            (source.start if source.start is not None else segment.offset, runtime.end),
            (element, source.value),
            combine_evidence(
                source.evidence,
                (segment.offset, offset.offset, runtime.offset),
            ),
            "anchored",
        )
    yield from _dynamic_local_string_elements(
        nodes,
        operations,
        arrays,
        references,
        facts,
    )


def _dynamic_local_string_elements(
    nodes: tuple[Operation, ...],
    operations: tuple[CompilerOp, ...],
    arrays: Mapping[int, tuple[object, ...]],
    references: Mapping[int, tuple[object, ...]],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    compiler = {operation.offset: operation for operation in operations}
    for index, segment in enumerate(nodes):
        base = _bp_segment_base(segment)
        array = arrays.get(base) if base is not None else None
        if array is None or index < 7 or index + 1 >= len(nodes):
            continue
        load_node, convert_node, wait_node, ax_node, si_node, shift1, shift2 = nodes[
            index - 7 : index
        ]
        runtime = nodes[index + 1]
        translated = tuple(
            compiler.get(node.offset)
            for node in (
                load_node,
                convert_node,
                wait_node,
                ax_node,
                si_node,
                shift1,
                shift2,
            )
        )
        if any(operation is None for operation in translated):
            continue
        load, convert, wait, ax, si, first_shift, second_shift = translated
        if not (
            load is not None
            and load.kind in {"fld", "fld_bp"}
            and len(load.args) == 1
            and convert is not None
            and convert.kind == "fistp"
            and len(convert.args) == 1
            and wait is not None
            and wait.kind == "fwait"
            and ax is not None
            and ax.kind == "movaxmem"
            and ax.args == convert.args
            and si is not None
            and si.kind == "movsiax"
            and first_shift is not None
            and first_shift.kind == "shlsi"
            and second_shift is not None
            and second_shift.kind == "shlsi"
            and runtime.kind == "tb.runtime"
            and runtime.operands == (0xA1,)
            and all(
                left.end == right.offset
                for left, right in zip(
                    (
                        load_node,
                        convert_node,
                        wait_node,
                        ax_node,
                        si_node,
                        shift1,
                        shift2,
                        segment,
                    ),
                    (
                        convert_node,
                        wait_node,
                        ax_node,
                        si_node,
                        shift1,
                        shift2,
                        segment,
                        runtime,
                    ),
                )
            )
        ):
            continue
        index_value = _dynamic_index_value(load, references, facts)
        source = _string_expression_before(load.offset, facts)
        if index_value is None or source is None:
            continue
        element = ("fn-local-array-element", *array[1:4], (index_value,))
        yield Fact(
            "semantic.assign",
            (source.start if source.start is not None else load.offset, runtime.end),
            (element, source.value),
            combine_evidence(
                source.evidence,
                tuple(node.offset for node in nodes[index - 7 : index + 2]),
            ),
            "anchored",
        )


def _dynamic_index_value(
    load: CompilerOp,
    references: Mapping[int, tuple[object, ...]],
    facts: frozenset[Fact],
) -> object | None:
    if load.kind == "fld_bp":
        if not isinstance(load.args[0], int):
            return None
        return references.get(load.args[0])
    resolved = resolve_expression(("memory", load.args[0], "float"), facts)
    if resolved is not None:
        return resolved.value
    address = load.args[0]
    return (
        ("slot", f"V{address:04X}", address, "float")
        if isinstance(address, int)
        else None
    )


def _string_expression_before(offset: int, facts: frozenset[Fact]) -> Resolved | None:
    matches = []
    for fact in facts:
        if not (
            fact.kind == "expression.string_operand"
            and len(fact.subject) == 2
            and fact.subject[1] == offset
            and len(fact.value) == 1
            and isinstance(fact.subject[0], int)
        ):
            continue
        resolved = resolve_expression(fact.value[0], facts)
        if resolved is not None:
            matches.append(
                (
                    resolved.value,
                    combine_evidence(fact.evidence, resolved.evidence),
                    fact.subject[0],
                )
            )
    if len(matches) != 1:
        return None
    value, evidence, start = matches[0]
    return Resolved(value, evidence, start)


def _descriptor_scaffold(
    nodes: tuple[Operation, ...], index: int
) -> tuple[int, int, tuple[int, ...]] | None:
    if index < 4:
        return None
    frame, add, push, segment = nodes[index - 4 : index]
    raw_add = bytes.fromhex(add.raw)
    if not (
        bytes.fromhex(frame.raw) == b"\x8b\xf5"
        and len(raw_add) == 3
        and raw_add[:2] == b"\x83\xc6"
        and bytes.fromhex(push.raw) == b"\x16"
        and bytes.fromhex(segment.raw) == b"\x07"
        and all(
            left.end == right.offset
            for left, right in zip(
                (frame, add, push, segment),
                (add, push, segment, nodes[index]),
            )
        )
    ):
        return None
    return (
        frame.offset,
        raw_add[2],
        (frame.offset, add.offset, push.offset, segment.offset),
    )


def _bp_segment_base(instruction: Operation) -> int | None:
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 3 and raw[:2] == b"\x8e\x46":
        return int.from_bytes(raw[2:], "little", signed=True)
    if len(raw) == 4 and raw[:2] == b"\x8e\x86":
        return int.from_bytes(raw[2:], "little", signed=True)
    return None


def _array_element(array: LocalArray, offset: Operation, entry: int) -> object | None:
    return _array_element_value(
        ("fn-local-array", entry, array.base, array.kind), offset
    )


def _array_element_value(array: object, offset: Operation) -> object | None:
    if not (
        isinstance(array, tuple)
        and len(array) == 4
        and array[0] == "fn-local-array"
        and isinstance(array[1], int)
        and isinstance(array[2], int)
        and isinstance(array[3], str)
        and offset.kind == "x86.mov_imm"
        and offset.operands[:1] == ("si",)
        and len(offset.operands) == 2
        and isinstance(offset.operands[1], int)
    ):
        return None
    width = _ELEMENT_WIDTHS.get(array[3])
    if width is None or offset.operands[1] % width:
        return None
    return (
        "fn-local-array-element",
        array[1],
        array[2],
        array[3],
        (("const", offset.operands[1] // width),),
    )


def _local_dim_bound(
    operations: tuple[CompilerOp, ...],
    operations_by_offset: dict[int, CompilerOp],
    start: int,
    end: int,
    base: int,
    references: Mapping[int, tuple[object, ...]],
) -> tuple[object, tuple[int, ...]] | None:
    candidates = tuple(
        (index, operation)
        for index, operation in enumerate(operations)
        if start <= operation.offset < end
        and operation.kind == "movm_ax_bp"
        and operation.args == (base + 10,)
    )
    if len(candidates) != 1:
        direct = tuple(
            operation
            for operation in operations
            if start <= operation.offset < end
            and operation.kind == "mov_bp_imm"
            and operation.args[0:1] == (base + 10,)
        )
        if len(direct) != 1 or not isinstance(direct[0].args[1], int):
            return None
        return (
            ("const", direct[0].args[1]),
            (direct[0].offset,),
        )
    index, store = candidates[0]
    value = _integer_value_before(operations, index, references)
    if value is None:
        return None
    expression, value_start, value_evidence = value
    lower = operations_by_offset.get(store.end)
    if not (
        lower is not None and lower.kind == "mov_bp_imm" and lower.args == (base + 8, 0)
    ):
        return None
    return (
        expression,
        combine_evidence(
            value_evidence,
            (store.offset, lower.offset),
            (value_start,),
        ),
    )


def _integer_value_before(
    operations: tuple[CompilerOp, ...],
    index: int,
    references: Mapping[int, tuple[object, ...]],
) -> tuple[object, int, tuple[int, ...]] | None:
    cursor = index - 1
    arithmetic = []
    while cursor >= 0 and operations[cursor].kind in {"movax", "movax_bp", "addax_bp"}:
        arithmetic.append(operations[cursor])
        cursor -= 1
    arithmetic.reverse()
    if not arithmetic or arithmetic[-1].end != operations[index].offset:
        return None
    first = arithmetic[0]
    if first.kind == "movax" and len(first.args) == 1:
        value: object = ("const", first.args[0])
    elif first.kind == "movax_bp" and len(first.args) == 1:
        if not isinstance(first.args[0], int):
            return None
        value = references.get(first.args[0])
        if value is None:
            return None
    else:
        return None
    for operation in arithmetic[1:]:
        if operation.kind != "addax_bp" or len(operation.args) != 1:
            return None
        if not isinstance(operation.args[0], int):
            return None
        reference = references.get(operation.args[0])
        if reference is None:
            return None
        value = ("binary", "+", reference, value)
    return value, first.offset, tuple(operation.offset for operation in arithmetic)
