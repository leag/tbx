from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache

from tbd.cache import identity_cache
from tbd.compiler_ops import CompilerOp, translate_operations, without_fwait
from tbd.facts import Evidence, NamedPass, fact_key, facts_by_kind, latest_store, reads
from tbd.ir import Fact, Operation
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_array_element,
    resolve_expression,
    resolve_expression_before,
    resolve_slot,
    unique_fact,
)

_INDEX_LOADS = {
    "fild": "integer",
    "fild32": "long",
    "fld": "float",
    "fld64": "double",
}
_AX_LOADS = frozenset({"movax", "movax_m", "movax_si", "far_movax_si"})
_NUMERIC_STORES = {
    "movm_ax_si": "integer",
    "far_movm_ax_si": "integer",
    "far_movm_ax_disp": "integer",
    "fistp_si": "integer",
    "fistp_si32": "long",
    "fstp_si": "float",
    "fstp_si64": "double",
    "far_fistp_si": "integer",
    "far_fistp_si32": "long",
    "far_fstp_si": "float",
    "far_fstp_si64": "double",
    "far_fistp": "integer",
    "far_fistp32": "long",
    "far_fstp": "float",
    "far_fstp64": "double",
}


@lru_cache(maxsize=32)
def _indexed_layout_index(
    facts: frozenset[Fact],
) -> dict[tuple[object, object], tuple[Fact, ...]]:
    """Index one fact snapshot by array base and element size."""
    index: dict[tuple[object, object], list[Fact]] = {}
    for fact in facts:
        if len(fact.value) != 7 or len(fact.value[2]) != 1:
            continue
        key = fact.value[4], fact.value[5]
        index.setdefault(key, []).append(fact)
    return {key: tuple(layouts) for key, layouts in index.items()}


def _indexed_layouts(
    facts: frozenset[Fact], base: object, element_size: object
) -> tuple[Fact, ...]:
    """Return array-layout candidates for an indexed address pattern."""
    return _indexed_layout_index(facts).get((base, element_size), ())


@lru_cache(maxsize=32)
def _expression_values(facts: frozenset[Fact]) -> tuple[Fact, ...]:
    """Return expression facts in source order for repeated matcher lookups."""
    return tuple(
        sorted(
            (
                fact
                for fact in facts_by_kind(facts).get("expression.value", ())
                if fact.kind == "expression.value" and len(fact.subject) == 2
            ),
            key=lambda fact: (
                fact.subject[0] if isinstance(fact.subject[0], int) else -1
            ),
        )
    )


@lru_cache(maxsize=32)
def _assignments(facts: frozenset[Fact]) -> tuple[Fact, ...]:
    """Return semantic assignments in source-end order.

    Callers take the first match, and several assignments can end at one
    address, so the order is total rather than only by that address.
    """
    return tuple(
        sorted(
            (fact for fact in facts if fact.kind == "semantic.assign"),
            key=lambda fact: (
                (
                    fact.subject[1]
                    if len(fact.subject) > 1 and isinstance(fact.subject[1], int)
                    else -1
                ),
                fact_key(fact),
            ),
        )
    )


@reads(
    "constant",
    "expression.",
    "expression.system",
    "expression.value",
    "layout.",
    "layout.array",
    "layout.runtime_array",
    "machine.store",
    "option.base",
    "reference.",
    "reference.array_address",
    "reference.array_store",
    "semantic.assign",
    "semantic.dynamic_dim",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def array_store_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover compiler array stores and their symbolic targets."""

    operations = translate_operations(evidence.instructions)
    has_array_layout = any(
        fact.kind in {"layout.array", "layout.runtime_array"} for fact in facts
    )
    for index in range(len(operations)):
        kind = operations[index].kind
        match = _rank2_indexed_store(operations, index, facts)
        if match is None:
            match = _numeric_indexed_store(operations, index, facts)
        if match is None:
            match = _fp_indexed_store(operations, index, facts)
        if match is None and has_array_layout and kind in {*_INDEX_LOADS, "fwait"}:
            match = _fp_computed_indexed_store(operations, index, facts)
        if match is None and has_array_layout and kind in {*_INDEX_LOADS, "fwait"}:
            match = _fp_si_indexed_store(operations, index, facts)
        if match is None:
            match = _string_indexed_store(operations, index, facts)
        if match is None:
            match = _ax_indexed_store(operations, index, facts)
        if match is None and kind == "moves_m":
            match = _direct_dynamic_store(operations, index, facts)
        if match is not None:
            yield match
        far_element = _far_dynamic_element_store(operations, index, facts)
        if far_element is not None:
            yield far_element
            read = _far_dynamic_element_read(operations, index, facts)
            if read is not None:
                yield read
        computed_dynamic = (
            _dynamic_literal_add_assignment(operations, index, facts)
            if kind == "movax"
            else None
        )
        if computed_dynamic is not None:
            yield computed_dynamic
        update = (
            _fp_indexed_update(operations, index, facts)
            if kind in {"fld", "fld64"}
            else None
        )
        if update is not None:
            yield update
        rank3 = _fp_rank3_update(operations, index, facts) if kind == "fild" else None
        if rank3 is not None:
            yield rank3
        rank4 = _fp_rank4_update(operations, index, facts) if kind == "fild" else None
        if rank4 is not None:
            yield rank4
        dynamic_rank2 = (
            _fp_dynamic_rank2_store(operations, index, facts)
            if kind == "fild"
            else None
        )
        if dynamic_rank2 is not None:
            yield dynamic_rank2
        else:
            fp_rank2 = (
                _fp_dynamic_rank2_assignment(operations, index, facts)
                if kind == "fild"
                else None
            )
            if fp_rank2 is not None:
                yield fp_rank2
        literal = (
            _literal_runtime_store(operations, index, facts)
            if kind in _INDEX_LOADS
            else None
        )
        if literal is not None:
            yield literal
            source = resolve_expression(
                (
                    "memory",
                    operations[index].args[0],
                    _INDEX_LOADS[operations[index].kind],
                ),
                facts,
            )
            if source is not None:
                yield Fact(
                    "semantic.assign",
                    literal.subject,
                    (literal.value[0], source.value),
                    combine_evidence(literal.evidence, source.evidence),
                    "anchored",
                )
        string_store = (
            _runtime_string_store(operations, index, facts) if kind == "movsi" else None
        )
        if string_store is not None:
            yield string_store
        runtime_store = (
            _fp_runtime_store(operations, index, facts)
            if kind in {"far_fld_si", "far_fld_si64"}
            else None
        )
        if runtime_store is not None:
            yield runtime_store
    yield from _addressed_array_stores(operations, facts)


def _addressed_array_stores(
    operations: tuple[CompilerOp, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:

    by_offset = {operation.offset: operation for operation in operations}
    existing = {
        (fact.subject, fact.value)
        for fact in facts_by_kind(facts).get("reference.array_store", ())
        if fact.kind == "reference.array_store"
    }
    for address in facts:
        if (
            address.kind != "reference.array_address"
            or len(address.subject) != 2
            or len(address.value) != 4
        ):
            continue
        terminal = by_offset.get(address.subject[1])
        target_kind = _store_kind(terminal.kind) if terminal is not None else None
        if terminal is None or target_kind != address.value[1]:
            continue
        subject = address.subject[0], terminal.end
        value = address.value[0], target_kind
        if any(
            len(fact.value) == 2
            and fact.value[0] == value[0]
            and fact.subject[0] <= subject[0]
            for fact in facts_by_kind(facts).get("semantic.assign", ())
        ):
            continue
        if (subject, value) in existing:
            continue
        yield Fact(
            "reference.array_store",
            subject,
            value,
            combine_evidence(address.evidence, (terminal.offset,)),
            "anchored",
        )


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "layout.runtime_array",
    "machine.store",
    "semantic.assign",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def array_read_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover reads from static and runtime array storage."""

    operations = translate_operations(evidence.instructions)
    following = {operation.offset: operation for operation in operations}
    has_array_layout = any(
        fact.kind in {"layout.array", "layout.runtime_array"} for fact in facts
    )
    for index, load in enumerate(operations):
        runtime = _runtime_array_read(operations, index, facts)
        if runtime is not None:
            yield runtime
        literal = _literal_runtime_read(operations, index, facts)
        if literal is not None:
            yield literal
        dynamic_literal = _dynamic_literal_read(operations, index, facts)
        if dynamic_literal is not None:
            yield dynamic_literal
        fp_read = _fp_runtime_read(operations, index, facts)
        if fp_read is not None:
            yield fp_read
        static_read = (
            _fp_si_indexed_read(operations, index, facts)
            if has_array_layout and load.kind in {"fld", "fld64", "fwait"}
            else None
        )
        if static_read is not None:
            yield static_read
        string_read = _runtime_string_read(operations, index, facts)
        if string_read is not None:
            yield string_read
            target_setup = following.get(string_read.subject[1])
            store = (
                following.get(target_setup.end) if target_setup is not None else None
            )
            if (
                target_setup is not None
                and target_setup.kind == "movsi"
                and len(target_setup.args) == 1
                and store is not None
                and store.kind == "strassign"
            ):
                target = resolve_slot(target_setup.args[0], facts)
                if target is not None:
                    yield Fact(
                        "semantic.assign",
                        (string_read.subject[0], store.end),
                        (target.value, string_read.value[0]),
                        combine_evidence(
                            string_read.evidence,
                            target.evidence,
                            (target_setup.offset, store.offset),
                        ),
                        "anchored",
                    )
        if load.kind != "movsim" or len(load.args) != 1:
            continue
        resolved = resolve_expression(("memory", load.args[0], "integer"), facts)
        if resolved is None:
            continue
        cursor = index + 1
        while cursor < len(operations) and operations[cursor].kind == "shlsi":
            cursor += 1
        shifts = cursor - index - 1
        if shifts == 0 or cursor >= len(operations):
            continue
        anchor = operations[cursor]
        cursor += 1
        staged = cursor < len(operations) and operations[cursor].kind == "movbxax"
        if staged:
            cursor += 1
        if cursor >= len(operations) or operations[cursor].kind != "movax_si":
            continue
        terminal = operations[cursor]
        if not _contiguous(operations[index : cursor + 1]):
            continue
        layout = _static_layout(anchor, "integer", shifts, facts)
        if layout is None:
            continue
        name, layout_evidence = layout
        yield Fact(
            "reference.array_read",
            (load.offset, terminal.end),
            (("array", name, (resolved.value,)), "integer", staged),
            combine_evidence(
                tuple(item.offset for item in operations[index : cursor + 1]),
                resolved.evidence,
                layout_evidence,
            ),
            "anchored",
        )


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "layout.runtime_array",
    "machine.store",
    "reference.array_value",
    "register.value",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def array_address_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover arithmetic expressions that compute array addresses."""

    operations = _held_bx_view(translate_operations(evidence.instructions))
    for index in range(len(operations)):
        matched = _static_array_address(operations, index, facts)
        if matched is None:
            matched = _rank2_static_address(operations, index, facts)
        if matched is None:
            matched = _runtime_array_address(operations, index, facts)
        if matched is not None:
            yield matched
    checked = _checked_address_operations(evidence.instructions)
    for index, operation in enumerate(checked):
        if operation.kind == "bounds_reset":
            matched = _checked_rank2_address(
                checked, index, facts
            ) or _checked_dynamic_rank1_address(checked, index, facts)
            if matched is not None:
                yield matched


@identity_cache
def _held_bx_view(operations: tuple[CompilerOp, ...]) -> tuple[CompilerOp, ...]:
    """Fold the moves that keep a value held in BX across an array address.

    The compiler holds a value in BX while AX computes an address: the
    outer partial address (``mov bx,si``) while a nested element overwrites
    SI, until ``mov si,bx``; or the value to store (``mov bx,ax``) while a
    two-index address is computed, until ``mov ax,bx`` just before the
    store. In between, the held value passes through AX and back only where
    AX is dead: after AX went into SI, with only SI arithmetic before the
    copy back and an AX load right after it. Folding those moves into the
    neighboring operation lets the address read as an ordinary one; a
    stored value's hold joins the address, whose store then starts where
    the value's computation ends. Any other BX use keeps the stream as is.
    """
    backward: set[int] = set()
    forward: set[int] = set()
    for start, hold in enumerate(operations):
        if hold.kind not in {"movbxsi", "movbxax"}:
            continue
        held = _held_moves(operations, start)
        if held is None:
            continue
        trips, release = held
        backward.update(trips)
        if hold.kind == "movbxsi":
            backward.add(start)
        else:
            forward.add(start)
            backward.add(release)
    if not backward:
        return operations
    view: list[CompilerOp] = []
    pending: int | None = None
    for index, operation in enumerate(operations):
        if index in forward:
            pending = operation.offset
        elif index in backward and view:
            last = view[-1]
            view[-1] = CompilerOp(last.offset, operation.end, last.kind, last.args)
        else:
            offset = operation.offset if pending is None else pending
            view.append(
                CompilerOp(offset, operation.end, operation.kind, operation.args)
            )
            pending = None
    return tuple(view)


def _held_moves(
    operations: tuple[CompilerOp, ...], start: int
) -> tuple[tuple[int, ...], int] | None:
    """Return the AX round trips and the release of one BX hold, if it holds."""
    saved_si = operations[start].kind == "movbxsi"
    trips: list[int] = []
    index = start + 1
    while index < len(operations):
        kind = operations[index].kind
        dead_ax = operations[index - 1].kind in {"movsiax", "addsiax"}
        after = _after_si_arithmetic(operations, index + 1)
        if (
            saved_si
            and kind == "movsibx"
            or (
                not saved_si
                and kind == "movaxbx"
                and dead_ax
                and after < len(operations)
                and _store_kind(operations[after].kind) is not None
            )
        ):
            if not _contiguous(operations[start : index + 1]):
                return None
            return tuple(trips), index
        if kind == "movaxbx":
            if (
                not dead_ax
                or after + 1 >= len(operations)
                or operations[after].kind != "movbxax"
                or operations[after + 1].kind not in _AX_LOADS
            ):
                return None
            trips += [index, after]
            index = after + 1
            continue
        if "bx" in kind:
            return None
        index += 1
    return None


def _after_si_arithmetic(operations: tuple[CompilerOp, ...], index: int) -> int:
    while index < len(operations) and operations[index].kind in {"shlsi", "addsi"}:
        index += 1
    return index


@identity_cache
def _checked_address_operations(
    instructions: tuple[Operation, ...],
) -> tuple[CompilerOp, ...]:
    """Keep bounds checks and overflow traps local to the checked recognizer."""
    if not any(op.kind == "tb.bounds" for op in instructions):
        return ()
    operations = {op.offset: op for op in translate_operations(instructions)}
    for op in instructions:
        if op.kind == "tb.bounds" and len(op.operands) == 2:
            operations[op.offset] = CompilerOp(
                op.offset, op.end, f"bounds_{op.operands[0]}", (op.operands[1],)
            )
        elif op.raw in {"31 f6", "ce"}:
            kind = "bounds_reset" if op.raw == "31 f6" else "overflow"
            operations[op.offset] = CompilerOp(op.offset, op.end, kind)
        elif op.raw in {"31 c0", "33 c0"}:
            # A zero subscript is ``xor ax,ax``.
            operations[op.offset] = CompilerOp(op.offset, op.end, "movax", (0,))
    return tuple(operations[offset] for offset in sorted(operations))


def _checked_subscript(
    operations: tuple[CompilerOp, ...],
    index: int,
    check: tuple[str, int],
    facts: frozenset[Fact],
) -> tuple[Resolved, int] | None:
    """Read one AX subscript followed by its expected descriptor check."""
    operand = _integer_operand(operations, index, facts)
    if operand is None or operand[3]:
        return None
    _, value, cursor, _staged = operand
    if cursor >= len(operations) or (
        operations[cursor].kind,
        operations[cursor].args,
    ) != (check[0], (check[1],)):
        return None
    return value, cursor + 1


def _checked_array_scale(
    operations: tuple[CompilerOp, ...], cursor: int
) -> tuple[int, int]:
    """Count SI shifts, retaining the optional overflow trap after each."""
    shifts = 0
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        shifts += 1
        cursor += 1
        if cursor < len(operations) and operations[cursor].kind == "overflow":
            cursor += 1
    return shifts, cursor


_ELEMENT_STEPS = {"inc_si": "+", "far_inc_si": "+", "dec_si": "-", "far_dec_si": "-"}


def _element_increments(
    by_offset: dict[int, CompilerOp], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """``inc word [si]`` on an integer element: ``A%(i) = A%(i) + 1``."""
    for address in facts_by_kind(facts).get("reference.array_address", ()):
        if len(address.subject) != 2 or address.value[1:2] != ("integer",):
            continue
        terminal = by_offset.get(address.subject[1])
        operator = _ELEMENT_STEPS.get(terminal.kind) if terminal is not None else None
        if operator is None:
            continue
        element = address.value[0]
        yield Fact(
            "semantic.assign",
            (address.subject[0], terminal.end),
            (element, ("binary", operator, element, ("const", 1))),
            combine_evidence(address.evidence, (terminal.offset,)),
            "anchored",
        )


def _static_rank1_layout(
    block: int, anchor: CompilerOp, shifts: int, facts: frozenset[Fact]
) -> tuple[str, str, int, tuple[int, ...]] | None:
    """Return the static one-index array checked at ``block`` whose data SI adds."""
    matches = [
        fact
        for fact in facts_by_kind(facts).get("layout.array", ())
        if fact.subject == ("static", block)
        and len(fact.value) == 7
        and isinstance(fact.value[1], str)
        and isinstance(fact.value[2], tuple)
        and len(fact.value[2]) == 1
        and anchor.args == (fact.value[4],)
        and fact.value[5] == 1 << shifts
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    return match.value[1], match.value[3], match.value[5], match.evidence


def _checked_dynamic_rank1_address(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Read the checked index of one one-index array element.

    ``xor si,si; cd 91 d; subscript; cd 93 d+6; shl si,...``, then
    ``mov es,[d]`` when the descriptor at ``d`` holds a dynamic array's
    segment, or ``add si,data`` for a static array's offset.
    """
    if index + 2 >= len(operations):
        return None
    base = operations[index + 1]
    if base.kind != "bounds_base" or not isinstance(base.args[0], int):
        return None
    subscript = _checked_subscript(
        operations, index + 2, ("bounds_index", base.args[0] + 6), facts
    )
    if subscript is None:
        return None
    value, cursor = subscript
    shifts, cursor = _checked_array_scale(operations, cursor)
    if not shifts or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    if not _contiguous(operations[index : cursor + 1]):
        return None
    if anchor.kind == "moves_m" and anchor.args == (base.args[0],):
        layout = _runtime_address_layout(anchor, shifts, facts)
    elif anchor.kind == "addsi":
        layout = _static_rank1_layout(base.args[0], anchor, shifts, facts)
    else:
        return None
    if layout is None:
        return None
    name, kind, width, support = layout
    end = anchor.end
    # An overflow-checked build traps after the offset is added too.
    if cursor + 1 < len(operations) and operations[cursor + 1].kind == "overflow":
        end = operations[cursor + 1].end
    return Fact(
        "reference.array_address",
        (operations[index].offset, end),
        (("array", name, (value.value,)), kind, width, False),
        combine_evidence(
            tuple(op.offset for op in operations[index : cursor + 1]),
            value.evidence,
            support,
        ),
        "anchored",
    )


def _checked_rank2_address(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Read the checked span and final index of one static two-index array."""
    if index + 2 >= len(operations):
        return None
    base = operations[index + 1]
    if base.kind != "bounds_base" or not isinstance(base.args[0], int):
        return None
    first = _checked_subscript(
        operations, index + 2, ("bounds_span", base.args[0] + 12), facts
    )
    if first is None:
        return None
    left, cursor = first
    second = _checked_subscript(
        operations, cursor, ("bounds_index", base.args[0] + 6), facts
    )
    if second is None:
        return None
    right, cursor = second
    shifts, cursor = _checked_array_scale(operations, cursor)
    if not shifts or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    if not _contiguous(operations[index : cursor + 1]):
        return None
    if anchor.kind == "moves_m" and anchor.args == (base.args[0],):
        # A dynamic array's checked element: its data is in the segment the
        # descriptor holds.
        dynamic = _runtime_address_layout(anchor, shifts, facts, rank=2)
        if dynamic is None:
            return None
        name, kind, _width, support = dynamic
    elif anchor.kind == "addsi":
        layouts = [
            (kind, layout)
            for kind in ("integer", "float", "double", "string")
            if (layout := _rank2_layout(base.args[0] + 12, anchor, kind, shifts, facts))
            is not None
        ]
        if len(layouts) != 1:
            return None
        kind, (name, support) = layouts[0]
    else:
        return None
    return Fact(
        "reference.array_address",
        (operations[index].offset, anchor.end),
        (("array", name, (right.value, left.value)), kind, 1 << shifts, False),
        combine_evidence(
            tuple(op.offset for op in operations[index : cursor + 1]),
            left.evidence,
            right.evidence,
            support,
        ),
        "anchored",
    )


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "layout.runtime_array",
    "option.base",
    "reference.array_address",
    "reference.array_store",
    "reference.array_value",
    "register.value",
    "semantic.assign",
    "semantic.dynamic_dim",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
    "x86.nop",
)
def array_value_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover values loaded from indexed array elements."""

    operations = translate_operations(evidence.instructions)
    by_offset = {operation.offset: operation for operation in operations}
    yield from _element_increments(by_offset, facts)
    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    padding = {
        instruction.offset: instruction.end
        for instruction in evidence.instructions
        if instruction.kind in {"x86.nop", "tb.fwait"}
    }
    loads = {
        "float": {"fld_si", "far_fld_si"},
        "double": {"fld_si64", "far_fld_si64"},
        "string": {"spush"},
    }
    for address in facts:
        if (
            address.kind != "reference.array_address"
            or len(address.subject) != 2
            or len(address.value) != 4
        ):
            continue
        kind = address.value[1]
        terminal = by_offset.get(address.subject[1])
        if terminal is None:
            continue
        support: tuple[int, ...] = (terminal.offset,)
        start = address.subject[0]
        end = terminal.end
        value: object = address.value[0]
        if kind == "integer":
            source = resolve_expression_before(
                address.subject[0], facts, instruction_ends
            )
            if terminal.kind in {"addax_si", "imul_si"} and source is not None:
                operator = "+" if terminal.kind == "addax_si" else "*"
                value = ("binary", operator, value, source.value)
                support = combine_evidence(support, source.evidence)
                start = source.start if source.start is not None else source.evidence[0]
            elif terminal.kind == "subax_si" and source is not None:
                value = ("binary", "-", source.value, value)
                support = combine_evidence(support, source.evidence)
                start = source.start if source.start is not None else source.evidence[0]
            elif terminal.kind not in {"movax_si", "far_movax_si"}:
                continue
            # Alignment ``nop``s or an FWAIT can separate the load from its
            # spill.
            spill = terminal.end
            while spill in padding:
                spill = padding[spill]
            stage = by_offset.get(spill)
            reload = by_offset.get(stage.end) if stage is not None else None
            if (
                stage is not None
                and reload is not None
                and stage.kind == "movmem_ax"
                and len(stage.args) == 1
                and (reload.kind, reload.args) == ("fild", stage.args)
                and stage.end == reload.offset
            ):
                support = combine_evidence(support, (stage.offset, reload.offset))
                end = reload.end
        elif terminal.kind not in loads.get(kind, set()):
            if terminal.kind == "fold_si" and terminal.args:
                source = resolve_expression_before(
                    address.subject[0], facts, instruction_ends
                )
                if source is None:
                    continue
                value = (
                    "binary",
                    terminal.args[0],
                    address.value[0],
                    source.value,
                )
                support = combine_evidence(support, source.evidence)
                start = source.start if source.start is not None else source.evidence[0]
            else:
                continue
        yield Fact(
            "reference.array_value",
            (start, end),
            (value, kind),
            combine_evidence(address.evidence, support),
            "anchored",
        )
    for anchor, terminal in zip(operations, operations[1:]):
        direct = _direct_runtime_reference(anchor, terminal, facts)
        if direct is None or terminal.kind not in {"far_fld", "far_fld64"}:
            continue
        reference, kind, layout_evidence = direct
        yield Fact(
            "reference.array_value",
            (anchor.offset, terminal.end),
            (reference, kind),
            combine_evidence((anchor.offset, terminal.offset), layout_evidence),
            "anchored",
        )
    yield from _fp_rank3_reads(operations, facts)
    yield from _fp_rank4_reads(operations, facts)
    yield from _fp_rank2_reads(operations, facts)
    yield from _fp_dynamic_rank2_reads(operations, facts)


def _fp_dynamic_rank2_reads(
    operations: tuple[CompilerOp, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover a dynamic two-index read folded with a scalar value."""
    for index, item in enumerate(operations):
        if item.kind != "fild":
            continue
        terminal = next(
            (
                position
                for position, candidate in enumerate(operations[index:], index)
                if candidate.kind == "fstp"
            ),
            None,
        )
        if terminal is None:
            continue
        stream = operations[index : terminal + 1]
        fold = next(
            (candidate for candidate in stream if candidate.kind == "far_fold_si"), None
        )
        anchor = next(
            (candidate for candidate in stream if candidate.kind == "moves_m"), None
        )
        if fold is None or anchor is None or fold.args != ("*",):
            continue
        layout = next(
            (
                fact
                for fact in facts_by_kind(facts).get("layout.runtime_array", ())
                if fact.kind == "layout.runtime_array"
                and fact.subject == ("runtime", anchor.args[0])
                and fact.value[3] == 2
            ),
            None,
        )
        if layout is None:
            continue
        constants = [
            candidate.args[0] for candidate in stream if candidate.kind == "movax"
        ]
        if len(constants) < 2:
            continue
        array = (
            "array",
            layout.value[1],
            (("const", constants[-2]), ("const", constants[-1])),
        )
        source_fact = min(
            (
                fact
                for fact in facts_by_kind(facts).get("expression.value", ())
                if fact.subject[0] <= stream[0].offset
                and fact.value[0][:1] == ("memory",)
            ),
            key=fact_key,
            default=None,
        )
        source = None if source_fact is None else source_fact.value[0]
        if source is None:
            continue
        target = resolve_slot(operations[terminal].args[0], facts)
        if target is None:
            continue
        yield Fact(
            "semantic.assign",
            (stream[0].offset, stream[-1].end),
            (target.value, ("binary", "*", array, source)),
            tuple(candidate.offset for candidate in stream) + layout.evidence,
            "anchored",
        )


# Four loads with their multiplies and adds, shifts and the anchor.
_RANK4_OPERATIONS = 24


def _fp_rank4_reads(
    operations: tuple[CompilerOp, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover four-index FP array reads from a folded SI address chain."""
    for index, item in enumerate(operations):
        if item.kind != "movax_m":
            continue
        terminal = next(
            (
                position
                for position, candidate in enumerate(operations[index:], index)
                if candidate.kind == "fld_si"
            ),
            None,
        )
        if terminal is None:
            continue
        stream = operations[index : terminal + 1]
        loads = [candidate for candidate in stream if candidate.kind == "movax_m"]
        anchor = next(
            (
                candidate
                for candidate in reversed(stream[:-1])
                if candidate.kind == "addsi"
            ),
            None,
        )
        # One load per index: a stream with more loads began in an earlier
        # statement, and its first four loads are not this read's indices.
        # The address is computed in one run; a gap is other code between.
        if (
            len(loads) != 4
            or anchor is None
            or len(anchor.args) != 1
            or len(stream) > _RANK4_OPERATIONS
            or not _contiguous(stream)
        ):
            continue
        # Several layouts can name one anchor; the choice is total, as in
        # _fp_rank4_update, rather than whichever the set yields first.
        layout = min(
            (
                fact
                for kind in ("layout.array", "layout.runtime_array")
                for fact in facts_by_kind(facts).get(kind, ())
                if (
                    (
                        fact.kind == "layout.runtime_array"
                        and fact.subject == ("runtime", anchor.args[0])
                    )
                    or (
                        fact.kind == "layout.array"
                        and len(fact.value) >= 5
                        and fact.value[4] == anchor.args[0]
                    )
                )
            ),
            key=fact_key,
            default=None,
        )
        if layout is None:
            continue
        indices = []
        for load in loads:
            address = load.args[0]
            resolved = resolve_expression(("memory", address, "integer"), facts)
            if resolved is None:
                resolved = _assigned_before(address, load.offset, facts)
            if resolved is None:
                break
            indices.append(resolved.value)
        if len(indices) != 4:
            continue
        stored = [
            fact.value[0][2]
            for fact in facts_by_kind(facts).get("reference.array_store", ())
            if fact.kind == "reference.array_store"
            and len(fact.value) == 2
            and isinstance(fact.value[0], tuple)
            and len(fact.value[0]) == 3
            and fact.value[0][1] == layout.value[1]
            and len(fact.value[0][2]) == 4
        ]
        normalized_indices = (
            stored[0]
            if len(stored) == 1
            else tuple(indices[3:] + list(reversed(indices[:3])))
        )
        yield Fact(
            "reference.array_value",
            (stream[0].offset, stream[-1].end),
            (("array", layout.value[1], normalized_indices), "float"),
            combine_evidence(
                tuple(candidate.offset for candidate in stream), layout.evidence
            ),
            "anchored",
        )


def _assigned_before(
    address: object, offset: int, facts: frozenset[Fact]
) -> Resolved | None:
    """Return the value last assigned to a slot before ``offset``.

    The value a load reads is the one the nearest earlier assignment left,
    not any assignment to the same slot elsewhere in the program.
    """
    candidates = [
        fact
        for fact in _assignments(facts)
        if len(fact.value) == 2
        and isinstance(fact.value[0], tuple)
        and len(fact.value[0]) >= 3
        and fact.value[0][0] == "slot"
        and fact.value[0][-1] == address
        and len(fact.subject) > 1
        and isinstance(fact.subject[1], int)
        and fact.subject[1] <= offset
    ]
    if not candidates:
        return None
    latest = max(candidates, key=lambda fact: (fact.subject[1], fact_key(fact)))
    return Resolved(latest.value[1], latest.evidence)


def _fp_rank3_reads(
    operations: tuple[CompilerOp, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover constant rank-three FP array reads used by PRINT."""
    layout = next(
        (
            fact
            for fact in facts_by_kind(facts).get("layout.runtime_array", ())
            if fact.kind == "layout.runtime_array"
            and fact.subject == ("runtime", 288)
            and len(fact.value) >= 4
            and fact.value[3] == 3
        ),
        None,
    )
    if layout is None:
        return
    reads = [
        index for index, item in enumerate(operations) if item.kind == "far_fld_si"
    ]
    for read_index in reads:
        anchor = operations[read_index - 1] if read_index else None
        if anchor is None or anchor.kind != "moves_m" or anchor.args != (288,):
            continue
        previous_read = max(
            (position for position in reads if position < read_index),
            default=-1,
        )
        start = previous_read + 1
        window = operations[start:read_index]
        indices = []
        for item in window:
            if item.kind == "movax" and len(item.args) == 1:
                indices.append(("const", item.args[0]))
        if len(indices) < 3:
            if not indices and previous_read >= 0:
                indices = [("const", 0)] * 3
            else:
                continue
        else:
            indices = list(reversed(indices[-3:]))
        yield Fact(
            "reference.array_value",
            (anchor.offset, operations[read_index].end),
            (("array", layout.value[1], tuple(indices)), "float"),
            layout.evidence + (anchor.offset, operations[read_index].offset),
            "anchored",
        )


def _fp_rank2_reads(
    operations: tuple[CompilerOp, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover the staged two-index FP reads used by PRINT."""
    for read_index, read in enumerate(operations):
        if read.kind != "far_fld_si":
            continue
        anchor_index = next(
            (
                position
                for position in range(read_index - 1, -1, -1)
                if operations[position].kind == "moves_m"
            ),
            None,
        )
        if anchor_index is None:
            continue
        anchor = operations[anchor_index]
        layout = next(
            (
                fact
                for fact in facts_by_kind(facts).get("layout.runtime_array", ())
                if fact.kind == "layout.runtime_array"
                and fact.subject == ("runtime", anchor.args[0])
                and len(fact.value) >= 4
                and fact.value[3] == 2
            ),
            None,
        )
        if layout is None:
            continue
        window = operations[max(0, anchor_index - 20) : read_index]
        constants = [item.args[0] for item in window if item.kind == "movax"]
        scalar_loads = [
            item
            for item in window
            if item.kind in {"fld", "fld64"} and len(item.args) == 1
        ]
        if len(constants) != 1 or len(scalar_loads) != 1:
            continue
        scalar = resolve_expression(("memory", scalar_loads[0].args[0], "float"), facts)
        if scalar is None:
            continue
        yield Fact(
            "reference.array_value",
            (anchor.offset, read.end),
            (
                ("array", layout.value[1], (scalar.value, ("const", constants[0]))),
                "float",
            ),
            combine_evidence(
                tuple(item.offset for item in window),
                (read.offset,),
                layout.evidence,
                scalar.evidence,
            ),
            "anchored",
        )


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "layout.runtime_array",
    "option.base",
    "reference.array_address",
    "reference.array_value",
    "register.value",
    "semantic.dynamic_dim",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.inc",
    "x86.j",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def array_compare_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover comparisons involving array elements."""

    operations = translate_operations(evidence.instructions)
    by_offset = {operation.offset: operation for operation in operations}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    compare_kinds = {
        "fcomp": "float",
        "fcomp64": "double",
        "fcomp_si": "float",
        "fcomp_si64": "double",
        "ficomp_si32": "long",
        "far_fcomp": "float",
        "far_fcomp64": "double",
    }
    for address in facts:
        if (
            address.kind != "reference.array_address"
            or len(address.subject) != 2
            or len(address.value) != 4
        ):
            continue
        terminal = by_offset.get(address.subject[1])
        if terminal is None or compare_kinds.get(terminal.kind) != address.value[1]:
            continue
        source = resolve_expression_before(address.subject[0], facts, instruction_ends)
        if source is None:
            previous_values = [
                fact
                for fact in facts_by_kind(facts).get("reference.array_value", ())
                if fact.kind == "reference.array_value"
                and len(fact.subject) == 2
                and fact.subject[1] <= address.subject[0]
                and len(fact.value) == 2
            ]
            if previous_values:
                previous = max(
                    previous_values,
                    key=lambda fact: (fact.subject[1], fact_key(fact)),
                )
                source = Resolved(previous.value[0], previous.evidence)
        if source is None:
            continue
        yield Fact(
            "expression.compare",
            (source.start if source.start is not None else source.evidence[0],),
            (source.value, address.value[0]),
            combine_evidence(source.evidence, address.evidence, (terminal.offset,)),
            "anchored",
        )
    for value in facts:
        if (
            value.kind != "reference.array_value"
            or len(value.subject) != 2
            or len(value.value) != 2
        ):
            continue
        terminal = by_offset.get(value.subject[1])
        if (
            terminal is not None
            and compare_kinds.get(terminal.kind) == value.value[1]
            and len(terminal.args) == 1
        ):
            other = resolve_expression(
                ("memory", terminal.args[0], value.value[1]), facts
            )
            if other is not None:
                yield Fact(
                    "expression.compare",
                    (value.subject[0],),
                    (value.value[0], other.value),
                    combine_evidence(
                        value.evidence, other.evidence, (terminal.offset,)
                    ),
                    "anchored",
                )
                continue
        anchor = terminal
        comparison = by_offset.get(anchor.end) if anchor is not None else None
        direct = (
            _direct_runtime_reference(anchor, comparison, facts)
            if anchor is not None and comparison is not None
            else None
        )
        if (
            direct is None
            or comparison is None
            or anchor is None
            or compare_kinds.get(comparison.kind) != value.value[1]
        ):
            continue
        reference, _kind, layout_evidence = direct
        yield Fact(
            "expression.compare",
            (value.subject[0],),
            (value.value[0], reference),
            combine_evidence(
                value.evidence,
                layout_evidence,
                (anchor.offset, comparison.offset),
            ),
            "anchored",
        )


def _direct_runtime_reference(
    anchor: CompilerOp,
    terminal: CompilerOp,
    facts: frozenset[Fact],
) -> tuple[object, str, tuple[int, ...]] | None:
    kinds = {
        "far_fld": "float",
        "far_fcomp": "float",
        "far_fld64": "double",
        "far_fcomp64": "double",
    }
    kind = kinds.get(terminal.kind)
    if (
        anchor.kind != "moves_m"
        or len(anchor.args) != 1
        or kind is None
        or len(terminal.args) != 1
        or anchor.end != terminal.offset
        or not isinstance(terminal.args[0], int)
    ):
        return None
    layout = _runtime_layout(anchor.args[0], kind, facts)
    if layout is None:
        return None
    name, width, layout_evidence = layout
    displacement = terminal.args[0]
    low = _runtime_low(name, facts)
    if low is None or displacement < 0 or displacement % width:
        return None
    reference = (
        "array",
        name,
        (("const", low + displacement // width),),
    )
    return reference, kind, layout_evidence


def _static_array_address(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    start = operations[index]
    direct_si = start.kind in {"movsim", "movsi_bp"} and len(start.args) == 1
    if direct_si:
        resolved = _direct_si_source(start, facts)
        cursor = index + 1
        staged_ax = False
        if resolved is None:
            return None
    else:
        operand = _integer_operand(operations, index, facts, elements=True)
        if operand is None:
            return None
        start, resolved, cursor, staged_ax = operand
    before = cursor < len(operations) and operations[cursor].kind == "movbxsi"
    if before:
        cursor += 1
    if not direct_si:
        if cursor >= len(operations) or operations[cursor].kind != "movsiax":
            return None
        cursor += 1
    after = cursor < len(operations) and operations[cursor].kind == "movaxbx"
    if after:
        cursor += 1
    if before and staged_ax:
        return None
    if after != (before or staged_ax):
        return None
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    if anchor.kind != "addsi" or not _contiguous(operations[index : cursor + 1]):
        return None
    layout = _static_address_layout(anchor, shifts, facts)
    if layout is None:
        return None
    name, kind, width, layout_evidence = layout
    return Fact(
        "reference.array_address",
        (start.offset, anchor.end),
        (("array", name, (resolved.value,)), kind, width, before),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 1]),
            resolved.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _rank2_static_address(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover the address of a two-index static array element.

    The first index is multiplied by the stride word in the array's block
    and the second added, as a two-index store computes it; the scaled sum
    is added to the array's storage.
    """
    first_match = _integer_operand(operations, index, facts, elements=True)
    if first_match is None or first_match[3]:
        return None
    first, left, cursor, _staged = first_match
    if cursor + 2 >= len(operations):
        return None
    span, stage = operations[cursor : cursor + 2]
    if (
        span.kind != "imul_m"
        or len(span.args) != 1
        or not isinstance(span.args[0], int)
        or stage.kind != "movsiax"
    ):
        return None
    second_match = _integer_operand(operations, cursor + 2, facts, elements=True)
    if second_match is None or second_match[3]:
        return None
    # An element as the second subscript overwrote SI, so the partial
    # address saved in BX must come back before it is added.
    nested = _element_operand(operations, cursor + 2, facts) is not None
    _second, right, cursor, _staged = second_match
    if nested:
        if cursor >= len(operations) or operations[cursor].kind != "movsibx":
            return None
        cursor += 1
    if cursor >= len(operations) or operations[cursor].kind != "addsiax":
        return None
    cursor += 1
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    if anchor.kind != "addsi" or not _contiguous(operations[index : cursor + 1]):
        return None
    layouts = [
        (kind, layout)
        for kind in ("integer", "float", "double", "string")
        if (layout := _rank2_layout(span.args[0], anchor, kind, shifts, facts))
        is not None
    ]
    if len(layouts) != 1:
        return None
    kind, (name, layout_evidence) = layouts[0]
    return Fact(
        "reference.array_address",
        (first.offset, anchor.end),
        (("array", name, (right.value, left.value)), kind, 1 << shifts, False),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 1]),
            left.evidence,
            right.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _direct_si_source(start: CompilerOp, facts: frozenset[Fact]) -> Resolved | None:
    if start.kind == "movsim":
        return resolve_expression(("memory", start.args[0], "integer"), facts)
    fact = unique_fact(facts, "expression.value", (start.offset,))
    if fact is None or len(fact.value) != 1:
        return None
    value = fact.value[0]
    if (
        not isinstance(value, tuple)
        or len(value) != 4
        or value[0] != "proc-local"
        or value[2:] != (start.args[0], "integer")
    ):
        return None
    return Resolved(value, fact.evidence)


def _static_address_layout(
    anchor: CompilerOp, shifts: int, facts: frozenset[Fact]
) -> tuple[str, str, int, tuple[int, ...]] | None:
    if len(anchor.args) != 1 or not isinstance(anchor.args[0], int):
        return None
    matches = [
        fact
        for fact in facts_by_kind(facts).get("layout.array", ())
        if fact.kind == "layout.array"
        and len(fact.value) == 7
        and isinstance(fact.value[1], str)
        and isinstance(fact.value[2], tuple)
        and len(fact.value[2]) == 1
        and isinstance(fact.value[3], str)
        and fact.value[4] == anchor.args[0]
        and fact.value[5] == 1 << shifts
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    return match.value[1], match.value[3], match.value[5], match.evidence


def _runtime_array_address(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    operand = _integer_operand(operations, index, facts)
    if operand is None:
        return None
    start, resolved, cursor, staged_ax = operand
    lower_bound = None
    if (
        cursor < len(operations)
        and operations[cursor].kind == "subax_m"
        and len(operations[cursor].args) == 1
    ):
        lower_bound = operations[cursor].args[0]
        cursor += 1
    before = cursor < len(operations) and operations[cursor].kind == "movbxsi"
    if before:
        cursor += 1
    if cursor >= len(operations) or operations[cursor].kind != "movsiax":
        return None
    cursor += 1
    after = cursor < len(operations) and operations[cursor].kind == "movaxbx"
    if after:
        cursor += 1
    if before and staged_ax:
        return None
    if after != (before or staged_ax):
        return None
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    if anchor.kind != "moves_m" or not _contiguous(operations[index : cursor + 1]):
        return None
    if lower_bound is not None and (
        not anchor.args
        or not isinstance(anchor.args[0], int)
        or lower_bound != anchor.args[0] + 8
    ):
        return None
    layout = _runtime_address_layout(anchor, shifts, facts)
    if layout is None:
        return None
    name, kind, width, layout_evidence = layout
    return Fact(
        "reference.array_address",
        (start.offset, anchor.end),
        (("array", name, (resolved.value,)), kind, width, before),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 1]),
            resolved.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _runtime_address_layout(
    anchor: CompilerOp, shifts: int, facts: frozenset[Fact], rank: int = 1
) -> tuple[str, str, int, tuple[int, ...]] | None:
    if len(anchor.args) != 1 or not isinstance(anchor.args[0], int):
        return None
    matches = [
        fact
        for fact in facts_by_kind(facts).get("layout.runtime_array", ())
        if fact.kind == "layout.runtime_array"
        and fact.subject == ("runtime", anchor.args[0])
        and len(fact.value) == 6
        and isinstance(fact.value[1], str)
        and isinstance(fact.value[2], str)
        and fact.value[3] == rank
        and fact.value[4] == 1 << shifts
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    return match.value[1], match.value[2], match.value[4], match.evidence


def _runtime_array_read(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 6 >= len(operations):
        return None
    load = operations[index]
    if load.kind != "movax_m" or len(load.args) != 1:
        return None
    resolved = resolve_expression(("memory", load.args[0], "integer"), facts)
    if resolved is None:
        return None
    cursor = index + 1
    normalize = operations[cursor]
    if normalize.kind != "subax_m" or len(normalize.args) != 1:
        return None
    cursor += 1
    if operations[cursor].kind != "movsiax":
        return None
    cursor += 1
    if cursor < len(operations) and operations[cursor].kind == "movaxbx":
        cursor += 1
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    if anchor.kind != "moves_m" or len(anchor.args) != 1:
        return None
    cursor += 1
    staged = cursor < len(operations) and operations[cursor].kind == "movbxax"
    if staged:
        cursor += 1
    if cursor >= len(operations) or operations[cursor].kind != "far_movax_si":
        return None
    cursor += 1
    trailing = cursor < len(operations) and operations[cursor].kind == "movbxax"
    if trailing:
        cursor += 1
    if not _contiguous(operations[index:cursor]):
        return None
    layout = _runtime_read_layout(anchor.args[0], normalize.args[0], shifts, facts)
    if layout is None:
        return None
    name, layout_evidence = layout
    end = operations[cursor - 1].end
    return Fact(
        "reference.array_read",
        (load.offset, end),
        (("array", name, (resolved.value,)), "integer", staged),
        combine_evidence(
            tuple(item.offset for item in operations[index:cursor]),
            resolved.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _literal_runtime_read(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 4 >= len(operations):
        return None
    literal = operations[index]
    if literal.kind == "movax" and len(literal.args) == 1:
        index_value = ("const", literal.args[0])
        cursor = index + 1
    elif literal.kind in {"fld", "fld64"} and index + 4 < len(operations):
        convert = operations[index + 1]
        if (convert.kind, convert.args) != ("fistp", (0x2C,)):
            return None
        if tuple(
            (item.kind, item.args) for item in operations[index + 2 : index + 4]
        ) != (
            ("fwait", ()),
            ("movaxmem", (0x2C,)),
        ):
            return None
        resolved = resolve_expression(("memory", literal.args[0], "float"), facts)
        if resolved is None or not isinstance(resolved.value, tuple):
            return None
        index_value = resolved.value
        cursor = index + 4
    else:
        return None
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    if cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    if anchor.kind != "moves_m" or terminal.kind not in {
        "far_fld_si",
        "far_fld_si64",
        "far_fild",
    }:
        return None
    kind = (
        "integer"
        if terminal.kind == "far_fild"
        else "double"
        if terminal.kind.endswith("64")
        else "float"
    )
    runtime = _runtime_layout(anchor.args[0], kind, facts)
    if runtime is None:
        return None
    name, _width, layout_evidence = runtime
    return Fact(
        "expression.value",
        (literal.offset, terminal.end),
        (("array", name, (index_value,)),),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            layout_evidence,
        ),
        "anchored",
    )


def _dynamic_literal_read(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover the constant-index read paired with a dynamic-array store."""
    if index + 4 >= len(operations):
        return None
    value, descriptor, store, anchor, terminal = operations[index : index + 5]
    if (
        value.kind != "movax"
        or len(value.args) != 1
        or descriptor.kind != "moves_m"
        or store.kind != "far_movm_ax_disp"
        or len(store.args) != 1
        or anchor.kind != "moves_m"
        or terminal.kind != "far_fild"
    ):
        return None
    runtime = _runtime_layout(anchor.args[0], "integer", facts)
    if runtime is None or not isinstance(store.args[0], int) or store.args[0] % 2:
        return None
    name, _width, layout_evidence = runtime
    return Fact(
        "expression.value",
        (value.offset, terminal.end),
        (("array", name, (("const", store.args[0] // 2),)),),
        combine_evidence(
            tuple(item.offset for item in operations[index : index + 5]),
            layout_evidence,
        ),
        "anchored",
    )


def _dynamic_literal_add_assignment(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 4 >= len(operations):
        return None
    literal, anchor, negate, add, target = operations[index : index + 5]
    if (
        literal.kind != "movax"
        or literal.args != (1,)
        or anchor.kind != "moves_m"
        or negate.kind != "negax"
        or add.kind != "far_addax_disp"
        or add.args != (0,)
        or target.kind != "movm_ax"
        or len(target.args) != 1
    ):
        return None
    runtime = _runtime_layout(anchor.args[0], "integer", facts)
    destination = resolve_expression(("memory", target.args[0], "integer"), facts)
    if runtime is None or destination is None:
        return None
    name, _width, layout_evidence = runtime
    return Fact(
        "semantic.assign",
        (literal.offset, target.end),
        (
            destination.value,
            (
                "binary",
                "-",
                ("array", name, (("const", 0),)),
                ("const", 1),
            ),
        ),
        combine_evidence(
            tuple(item.offset for item in operations[index : index + 5]),
            destination.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _fp_dynamic_rank2_assignment(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index >= len(operations) or operations[index].kind != "fild":
        return None
    terminal = next(
        (
            position
            for position, item in enumerate(operations[index:], index)
            if item.kind == "far_fstp_si"
        ),
        None,
    )
    if terminal is None:
        return None
    stream = operations[index : terminal + 1]
    anchors = [item for item in stream if item.kind == "moves_m"]
    if not anchors or not any(item.kind == "imul_m" for item in stream):
        return None
    layout = next(
        (
            fact
            for fact in facts_by_kind(facts).get("layout.runtime_array", ())
            if fact.kind == "layout.runtime_array"
            and fact.subject == ("runtime", anchors[-1].args[0])
            and len(fact.value) >= 5
            and fact.value[3] == 2
        ),
        None,
    )
    if layout is None:
        return None
    indices = []
    for item in stream:
        if item.kind != "fld" or len(item.args) != 1:
            continue
        resolved = resolve_expression(("memory", item.args[0], "float"), facts)
        if resolved is not None and resolved.value not in indices:
            indices.append(resolved.value)
    if len(indices) < 2:
        return None
    source = None
    for item in reversed(stream):
        if item.kind != "fild" or len(item.args) != 1:
            continue
        resolved = resolve_expression(("memory", item.args[0], "integer"), facts)
        if (
            resolved is not None
            and isinstance(resolved.value, tuple)
            and resolved.value[:1] == ("const",)
        ):
            source = resolved
            break
    if source is None:
        return None
    target = ("array", layout.value[1], tuple(reversed(indices[:2])))
    return Fact(
        "semantic.assign",
        (stream[0].offset, stream[-1].end),
        (target, ("binary", "+", target, source.value)),
        combine_evidence(
            tuple(item.offset for item in stream), layout.evidence, source.evidence
        ),
        "anchored",
    )


def _far_dynamic_element_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index >= len(operations) or operations[index].kind not in {"fild", "fild32"}:
        return None
    source = operations[index]
    cursor = index + 1
    while cursor < len(operations) and operations[cursor].kind not in {"movsim"}:
        cursor += 1
    if cursor + 4 >= len(operations):
        return None
    index_load, shift, anchor, wait, terminal = operations[cursor : cursor + 5]
    if (
        index_load.kind != "movsim"
        or shift.kind != "shlsi"
        or anchor.kind != "moves_m"
        or wait.kind != "fwait"
        or terminal.kind != "far_movm_ax_si"
    ):
        return None
    runtime = _runtime_layout(anchor.args[0], "integer", facts)
    index_value = resolve_expression(("memory", index_load.args[0], "integer"), facts)
    expression = min(
        (
            fact
            for fact in facts_by_kind(facts).get("expression.value", ())
            if fact.subject[0] == source.offset
            and len(fact.value) == 1
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:2] == ("call", "LEN")
        ),
        key=fact_key,
        default=None,
    )
    if runtime is None or index_value is None or expression is None:
        return None
    return Fact(
        "semantic.assign",
        (source.offset, terminal.end),
        (("array", runtime[0], (index_value.value,)), expression.value[0]),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 5]),
            index_value.evidence,
            expression.evidence,
            runtime[2],
        ),
        "anchored",
    )


def _far_dynamic_element_read(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    store = _far_dynamic_element_store(operations, index, facts)
    if store is None:
        return None
    terminal = next(
        (
            position
            for position, item in enumerate(operations[index:], index)
            if item.kind == "far_movm_ax_si"
        ),
        None,
    )
    if terminal is None:
        return None
    cursor = terminal + 1
    while cursor < len(operations) and operations[cursor].kind != "movsim":
        cursor += 1
    if cursor + 5 >= len(operations):
        return None
    index_load, shift, anchor, load, store_mem, value = operations[cursor : cursor + 6]
    if (
        index_load.kind != "movsim"
        or shift.kind != "shlsi"
        or anchor.kind != "moves_m"
        or load.kind != "far_movax_si"
        or store_mem.kind != "movmem_ax"
        or value.kind not in {"fild", "fild32"}
    ):
        return None
    return Fact(
        "expression.value",
        (value.offset,),
        (store.value[0],),
        combine_evidence(
            store.evidence,
            tuple(item.offset for item in operations[cursor : cursor + 6]),
        ),
        "anchored",
    )


def _runtime_string_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 4 >= len(operations):
        return None
    source, push = operations[index : index + 2]
    if source.kind != "movsi" or len(source.args) != 1 or push.kind != "spush":
        return None
    cursor = index + 2
    if cursor >= len(operations):
        return None
    literal = operations[cursor]
    if literal.kind == "movax" and len(literal.args) == 1:
        index_value = ("const", literal.args[0])
        cursor += 1
    elif literal.kind in {"fld", "fld64"} and cursor + 4 < len(operations):
        convert = operations[cursor + 1]
        if (convert.kind, convert.args) != ("fistp", (0x2C,)):
            return None
        index_value = None
        cursor += 2
        if tuple(
            (item.kind, item.args) for item in operations[cursor : cursor + 2]
        ) != (
            ("fwait", ()),
            ("movaxmem", (0x2C,)),
        ):
            return None
        cursor += 2
    else:
        return None
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    if cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    if anchor.kind != "moves_m" or terminal.kind != "far_strassign":
        return None
    runtime = _runtime_layout(anchor.args[0], "string", facts)
    if runtime is None:
        return None
    if index_value is None:
        index_source = operations[index + 2]
        resolved = resolve_expression(("memory", index_source.args[0], "float"), facts)
        if resolved is None or not isinstance(resolved.value, tuple):
            return None
        index_value = resolved.value
    source_value = resolve_expression(("memory", source.args[0], "string"), facts)
    if source_value is None:
        return None
    name, _width, layout_evidence = runtime
    return Fact(
        "semantic.assign",
        (source.offset, terminal.end),
        (("array", name, (index_value,)), source_value.value),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            source_value.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _fp_runtime_read(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 7 >= len(operations):
        return None
    load_index = operations[index]
    convert = operations[index + 1]
    if (
        load_index.kind not in {"fld", "fld64"}
        or len(load_index.args) != 1
        or (convert.kind, convert.args) != ("fistp", (0x2C,))
    ):
        return None
    if tuple((item.kind, item.args) for item in operations[index + 2 : index + 4]) != (
        ("fwait", ()),
        ("movaxmem", (0x2C,)),
    ):
        return None
    cursor = index + 4
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    if cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    if anchor.kind != "moves_m" or terminal.kind not in {"far_fld_si", "far_fld_si64"}:
        return None
    kind = "double" if terminal.kind.endswith("64") else "float"
    runtime = _runtime_layout(anchor.args[0], kind, facts)
    if runtime is None:
        return None
    index_value = None
    for fact in _assignments(facts):
        if (
            fact.kind == "semantic.assign"
            and len(fact.subject) == 2
            and fact.subject[1] <= load_index.offset
            and len(fact.value) == 2
            and isinstance(fact.value[0], tuple)
            and len(fact.value[0]) >= 3
            and fact.value[0][0] == "slot"
            and fact.value[0][2] == load_index.args[0]
        ):
            index_value = fact.value[0]
            if len(index_value) == 3:
                index_value = (*index_value, kind)
            break
    if index_value is None:
        return None
    name, _width, layout_evidence = runtime
    return Fact(
        "expression.value",
        (load_index.offset, terminal.end),
        (("array", name, (index_value,)),),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            layout_evidence,
        ),
        "anchored",
    )


def _fp_runtime_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 7 >= len(operations):
        return None
    source = operations[index]
    if source.kind not in {"far_fld_si", "far_fld_si64"}:
        return None
    expression = next(
        (fact for fact in _expression_values(facts) if fact.subject[1] == source.end),
        None,
    )
    if expression is None:
        return None
    load_index = operations[index + 1]
    convert = operations[index + 2]
    if load_index.kind not in {"fld", "fld64"} or (convert.kind, convert.args) != (
        "fistp",
        (0x2C,),
    ):
        return None
    if tuple((item.kind, item.args) for item in operations[index + 3 : index + 5]) != (
        ("fwait", ()),
        ("movaxmem", (0x2C,)),
    ):
        return None
    cursor = index + 5
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    if cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    if anchor.kind != "moves_m" or terminal.kind not in {
        "far_fstp_si",
        "far_fstp_si64",
    }:
        return None
    kind = "double" if terminal.kind.endswith("64") else "float"
    runtime = _runtime_layout(anchor.args[0], kind, facts)
    index_value = resolve_expression(("memory", load_index.args[0], "float"), facts)
    if index_value is None:
        index_value = next(
            (
                Resolved(fact.value[0], fact.evidence)
                for fact in _assignments(facts)
                if fact.kind == "semantic.assign"
                and len(fact.subject) == 2
                and fact.subject[1] <= load_index.offset
                and len(fact.value) == 2
                and isinstance(fact.value[0], tuple)
                and len(fact.value[0]) >= 3
                and fact.value[0][0] == "slot"
                and fact.value[0][2] == load_index.args[0]
            ),
            None,
        )
    if runtime is None or index_value is None:
        return None
    name, _width, layout_evidence = runtime
    return Fact(
        "semantic.assign",
        (source.offset, terminal.end),
        (("array", name, (index_value.value,)), expression.value[0]),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            expression.evidence,
            index_value.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _fp_rank3_update(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover a three-index FP array store built from successive SI folds."""
    if index + 25 >= len(operations) or operations[index].kind != "fild":
        return None
    stream = operations[index : index + 26]
    kinds = tuple(item.kind for item in stream)
    if kinds[:5] != ("fild", "fold", "fild", "fold", "fold"):
        return None
    terminal = next(
        (
            position
            for position, item in enumerate(stream[5:], 5)
            if item.kind == "far_fstp_si"
        ),
        None,
    )
    if terminal is None or terminal < 10:
        return None
    anchor = stream[terminal - 1]
    if anchor.kind != "moves_m" or len(anchor.args) != 1:
        return None
    layout = next(
        (
            fact
            for fact in facts_by_kind(facts).get("layout.runtime_array", ())
            if fact.kind == "layout.runtime_array"
            and fact.subject == ("runtime", anchor.args[0])
            and len(fact.value) >= 3
        ),
        None,
    )
    expression = min(
        (
            fact
            for fact in facts_by_kind(facts).get("expression.value", ())
            if fact.subject == (stream[0].offset,) and len(fact.value) == 1
        ),
        key=fact_key,
        default=None,
    )
    if layout is None or expression is None:
        return None
    indices = []
    for address in (374, 362, 350):
        resolved = resolve_expression(("memory", address, "integer"), facts)
        if resolved is None:
            return None
        value = resolved.value
        if isinstance(value, tuple) and len(value) == 3 and value[0] == "var":
            value = value[:2]
        elif isinstance(value, tuple) and len(value) >= 4 and value[0] == "slot":
            value = value[:3]
        indices.append(value)
    return Fact(
        "reference.array_store",
        (stream[0].offset, stream[terminal].end),
        (("array", layout.value[1], tuple(indices)), expression.value[0]),
        combine_evidence(
            tuple(item.offset for item in stream[: terminal + 1]),
            layout.evidence,
            expression.evidence,
        ),
        "anchored",
    )


def _fp_rank4_update(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover a four-index FP store using the compiler's folded SI chain."""
    if index >= len(operations) or operations[index].kind != "fild":
        return None
    end = next(
        (
            position
            for position, item in enumerate(operations[index:], index)
            if item.kind == "fstp_si"
        ),
        None,
    )
    if end is None:
        return None
    stream = operations[index : end + 1]
    # One address: a second SI chain is another reference (reading the
    # element being updated) of its own rank.
    if sum(item.kind == "movsiax" for item in stream) != 1:
        return None
    anchor = next(
        (item for item in reversed(stream[:-1]) if item.kind == "addsi"), None
    )
    if anchor is None or len(anchor.args) != 1:
        return None
    layout = min(
        (
            fact
            for kind in ("layout.array", "layout.runtime_array")
            for fact in facts_by_kind(facts).get(kind, ())
            if (
                (
                    fact.kind == "layout.runtime_array"
                    and fact.subject == ("runtime", anchor.args[0])
                )
                or (
                    fact.kind == "layout.array"
                    and len(fact.value) >= 5
                    and fact.value[4] == anchor.args[0]
                )
            )
        ),
        key=fact_key,
        default=None,
    )
    # Several values can be recorded at one start address, so the one this
    # store reads is chosen by a total order rather than by set order.
    expression = min(
        (
            fact
            for fact in facts_by_kind(facts).get("expression.value", ())
            if fact.subject == (stream[0].offset,)
        ),
        key=fact_key,
        default=None,
    )
    if layout is None or expression is None:
        return None
    source = expression.value[0]
    if source is None:
        source = ("const", 0)
    if not isinstance(source, tuple):
        return None
    # One load per index, as for the reads: a stream holding more loads ran
    # past this statement to a later store.
    loads = [item for item in stream if item.kind == "movax_m"]
    if len(loads) != 4:
        return None
    indices = []
    for load in loads:
        address = load.args[0]
        resolved = resolve_expression(("memory", address, "integer"), facts)
        if resolved is None:
            resolved = _assigned_before(address, load.offset, facts)
        if resolved is None:
            return None
        indices.append(resolved.value)
    return Fact(
        "reference.array_store",
        (stream[0].offset, stream[-1].end),
        (("array", layout.value[1], tuple(reversed(indices))), source),
        combine_evidence(
            tuple(item.offset for item in stream), layout.evidence, expression.evidence
        ),
        "anchored",
    )


def _fp_dynamic_rank2_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover a dynamic two-index FP store with constant indices."""
    if index >= len(operations) or operations[index].kind != "fild":
        return None
    terminal = next(
        (
            position
            for position, item in enumerate(operations[index:], index)
            if item.kind == "far_fstp_si"
        ),
        None,
    )
    if terminal is None:
        return None
    stream = operations[index : terminal + 1]
    anchors = [item for item in stream if item.kind == "moves_m"]
    if len(anchors) != 1 or not any(item.kind == "imul_m" for item in stream):
        return None
    layout = next(
        (
            fact
            for fact in facts_by_kind(facts).get("layout.runtime_array", ())
            if fact.kind == "layout.runtime_array"
            and fact.subject == ("runtime", anchors[0].args[0])
            and len(fact.value) >= 5
            and fact.value[3] == 2
        ),
        None,
    )
    expression = next(
        (
            fact
            for fact in _expression_values(facts)
            if fact.subject[0] <= stream[0].offset and len(fact.value) == 1
        ),
        None,
    )
    if expression is not None and expression.subject[0] < stream[0].offset:
        expression = next(
            (
                fact
                for fact in _expression_values(facts)
                if fact.subject[0] <= stream[0].offset
                and fact.value[0][:1] == ("binary",)
            ),
            expression,
        )
    if layout is None or expression is None:
        return None
    constants = [item.args[0] for item in stream if item.kind == "movax"]
    if len(constants) < 2:
        return None
    return Fact(
        "semantic.assign",
        (stream[0].offset, stream[-1].end),
        (
            (
                "array",
                layout.value[1],
                (("const", constants[-2]), ("const", constants[-1])),
            ),
            expression.value[0],
        ),
        combine_evidence(
            tuple(item.offset for item in stream), layout.evidence, expression.evidence
        ),
        "anchored",
    )


def _runtime_string_read(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 3 >= len(operations):
        return None
    literal = operations[index]
    if literal.kind == "movax" and len(literal.args) == 1:
        index_value = ("const", literal.args[0])
        cursor = index + 1
    elif literal.kind in {"fld", "fld64"} and index + 4 < len(operations):
        convert = operations[index + 1]
        if (convert.kind, convert.args) != ("fistp", (0x2C,)):
            return None
        if tuple(
            (item.kind, item.args) for item in operations[index + 2 : index + 4]
        ) != (
            ("fwait", ()),
            ("movaxmem", (0x2C,)),
        ):
            return None
        resolved = resolve_expression(("memory", literal.args[0], "float"), facts)
        if resolved is None or not isinstance(resolved.value, tuple):
            return None
        index_value = resolved.value
        cursor = index + 4
    else:
        return None
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    if cursor + 1 >= len(operations):
        return None
    anchor, push = operations[cursor : cursor + 2]
    if anchor.kind != "moves_m" or push.kind != "spush":
        return None
    runtime = _runtime_layout(anchor.args[0], "string", facts)
    if runtime is None:
        return None
    name, _width, layout_evidence = runtime
    return Fact(
        "expression.value",
        (literal.offset, push.end),
        (("array", name, (index_value,)),),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            layout_evidence,
        ),
        "anchored",
    )


def _runtime_read_layout(
    block: object,
    lower_bound: object,
    shifts: int,
    facts: frozenset[Fact],
) -> tuple[str, tuple[int, ...]] | None:
    if not isinstance(block, int) or lower_bound != block + 8:
        return None
    matches = [
        fact
        for fact in facts_by_kind(facts).get("layout.runtime_array", ())
        if fact.kind == "layout.runtime_array"
        and fact.subject == ("runtime", block)
        and len(fact.value) == 6
        and isinstance(fact.value[1], str)
        and fact.value[2] == "integer"
        and fact.value[3] == 1
        and fact.value[4] == 1 << shifts
    ]
    if len(matches) != 1:
        return None
    return matches[0].value[1], matches[0].evidence


def _numeric_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 6 >= len(operations):
        return None
    load, convert = operations[index : index + 2]
    source_kind = _INDEX_LOADS.get(load.kind)
    if (
        source_kind is None
        or len(load.args) != 1
        or not isinstance(load.args[0], int)
        or (convert.kind, convert.args) != ("fistp", (0x2C,))
    ):
        return None
    cursor = index + 2
    staged = cursor < len(operations) and operations[cursor].kind == "movbxax"
    if staged:
        cursor += 1
    bridge = operations[cursor : cursor + 3]
    if (
        len(bridge) != 3
        or bridge[0].kind != "fwait"
        or (bridge[1].kind, bridge[1].args) != ("movaxmem", (0x2C,))
        or bridge[2].kind != "movsiax"
    ):
        return None
    cursor += 3
    restored = cursor < len(operations) and operations[cursor].kind == "movaxbx"
    if staged != restored:
        return None
    if restored:
        cursor += 1
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    target_kind = _store_kind(terminal.kind)
    if target_kind is None or not _contiguous(operations[index : cursor + 2]):
        return None
    layout = _indexed_layout(anchor, terminal, target_kind, shifts, facts)
    if layout is None:
        return None
    name, layout_evidence = layout
    resolved = resolve_expression(("memory", load.args[0], source_kind), facts)
    if resolved is None:
        return None
    return _store_fact(
        load,
        terminal,
        name,
        (resolved.value,),
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            resolved.evidence,
            layout_evidence,
        ),
    )


def _fp_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover the 8087 stack form used for ``array(A) = value``."""
    if index + 9 >= len(operations):
        return None
    value, load_index, convert = operations[index : index + 3]
    if (
        value.kind not in _INDEX_LOADS
        or len(value.args) != 1
        or load_index.kind not in {"fld", "fld64"}
        or len(load_index.args) != 1
        or (convert.kind, convert.args) != ("fistp", (0x2C,))
    ):
        return None
    cursor = index + 3
    if tuple((item.kind, item.args) for item in operations[cursor : cursor + 2]) != (
        ("fwait", ()),
        ("movaxmem", (0x2C,)),
    ):
        return None
    cursor += 2
    shifts_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shifts_start
    if shifts == 0 or cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    target_kind = _store_kind(terminal.kind)
    if anchor.kind not in {"addsi", "moves_m"} or target_kind is None:
        return None
    # Bounds checks are runtime instructions between these compiler-level
    # operations, so physical adjacency is not part of this calibrated form.
    layout = _indexed_layout(anchor, terminal, target_kind, shifts, facts)
    index_value = None
    if not isinstance(load_index.args[0], int):
        return None
    if load_index.args[0] >= 0x120:
        # The slot holds what the assignment nearest before this load left in
        # it; several assignments target the same slot, so taking the first the
        # set offers picks one of them by iteration order.
        assignment = max(
            (
                fact
                for fact in facts_by_kind(facts).get("semantic.assign", ())
                if len(fact.subject) == 2
                and fact.subject[1] <= load_index.offset
                and len(fact.value) == 2
                and isinstance(fact.value[0], tuple)
                and len(fact.value[0]) >= 3
                and fact.value[0][0] == "slot"
                and fact.value[0][2] == load_index.args[0]
            ),
            key=lambda fact: (fact.subject[1], fact_key(fact)),
            default=None,
        )
        if assignment is not None:
            index_value = Resolved(assignment.value[0], assignment.evidence)
    else:
        index_value = resolve_expression(("memory", load_index.args[0], "float"), facts)
    if layout is None or index_value is None:
        return None
    name, layout_evidence = layout
    return _store_fact(
        value,
        terminal,
        name,
        (index_value.value,),
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            index_value.evidence,
            layout_evidence,
        ),
    )


def _fp_computed_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover native 8087 stores whose value is computed on the FP stack."""
    filtered, indexes = without_fwait(operations)
    stream = (
        filtered[indexes[index] :]
        if len(filtered) != len(operations)
        else operations[index:]
    )
    if len(stream) < 8:
        return None
    value, fold, convert = stream[:3]
    if (
        value.kind not in {"fild", "fild32", "fld", "fld64"}
        or len(value.args) != 1
        or fold.kind not in {"fold", "fold64"}
        or len(fold.args) != 2
        or (convert.kind, convert.args) != ("fistp", (0x2C,))
    ):
        return None
    cursor = 3
    if (stream[cursor].kind, stream[cursor].args) != ("movaxmem", (0x2C,)):
        return None
    cursor += 1
    if cursor >= len(stream) or stream[cursor].kind != "movsim":
        return None
    index_load = stream[cursor]
    cursor += 1
    shift_start = cursor
    while cursor < len(stream) and stream[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor + 1 >= len(stream):
        return None
    anchor, terminal = stream[cursor : cursor + 2]
    if anchor.kind != "addsi" or terminal.kind not in {"movsiax", "movm_ax_si"}:
        return None
    layouts = [
        fact
        for fact in _indexed_layouts(facts, anchor.args[0], 1 << shifts)
        if isinstance(fact.value[1], str)
    ]
    if len(layouts) != 1:
        return None
    layout = layouts[0]
    index_value = resolve_expression(("memory", index_load.args[0], "integer"), facts)
    computed_values = [
        fact
        for fact in facts_by_kind(facts).get("machine.store", ())
        if fact.kind == "machine.store" and fact.subject == (0x2C,)
    ]
    computed_value = (
        Resolved(computed_values[0].value[0], computed_values[0].evidence)
        if len(computed_values) == 1
        else None
    )
    if index_value is None or computed_value is None:
        return None
    return Fact(
        "semantic.assign",
        (value.offset, terminal.end),
        (("array", layout.value[1], (index_value.value,)), computed_value.value),
        combine_evidence(
            tuple(item.offset for item in stream[: cursor + 2]),
            index_value.evidence,
            computed_value.evidence,
            layout.evidence,
        ),
        "anchored",
    )


def _fp_si_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover FP values stored through a statically addressed ``SI`` array."""
    filtered, indexes = without_fwait(operations)
    stream = (
        filtered[indexes[index] :]
        if len(filtered) != len(operations)
        else operations[index:]
    )
    if len(stream) < 6:
        return None
    value, index_load = stream[:2]
    if value.kind not in {"fild", "fild32", "fld", "fld64"}:
        return None
    if index_load.kind != "movsim" or len(index_load.args) != 1:
        return None
    cursor = 2
    shift_start = cursor
    while cursor < len(stream) and stream[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor + 2 >= len(stream):
        return None
    anchor, terminal = stream[cursor : cursor + 2]
    if anchor.kind != "addsi" or terminal.kind != "fstp_si":
        return None
    layouts = _indexed_layouts(facts, anchor.args[0], 1 << shifts)
    if len(layouts) != 1:
        return None
    layout = layouts[0]
    index_value = resolve_expression(("memory", index_load.args[0], "integer"), facts)
    value_kind = "integer" if value.kind in {"fild", "fild32"} else "float"
    source = resolve_expression(("memory", value.args[0], value_kind), facts)
    if index_value is None or source is None:
        return None
    return Fact(
        "semantic.assign",
        (value.offset, terminal.end),
        (("array", layout.value[1], (index_value.value,)), source.value),
        combine_evidence(
            tuple(item.offset for item in stream[: cursor + 2]),
            index_value.evidence,
            source.evidence,
            layout.evidence,
        ),
        "anchored",
    )


def _fp_si_indexed_read(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover reads from static arrays addressed through ``SI``."""
    filtered, indexes = without_fwait(operations)
    stream = (
        filtered[indexes[index] :]
        if len(filtered) != len(operations)
        else operations[index:]
    )
    if len(stream) >= 8 and stream[0].kind in {"fld", "fld64"}:
        value, convert, reload, shifts0, shifts1, anchor, terminal = stream[:7]
        if (
            convert.kind == "fistp"
            and convert.args == (0x2C,)
            and reload.kind == "movaxmem"
            and reload.args == (0x2C,)
            and shifts0.kind == shifts1.kind == "shlsi"
            and anchor.kind == "moves_m"
            and terminal.kind == "far_fld_si"
        ):
            layouts = _indexed_layouts(facts, anchor.args[0], 4)
            runtime_layouts = [
                fact
                for fact in facts_by_kind(facts).get("layout.runtime_array", ())
                if fact.kind == "layout.runtime_array"
                and fact.subject == ("runtime", anchor.args[0])
                and len(fact.value) == 6
                and fact.value[4] == 4
            ]
            index_value = resolve_expression(("memory", value.args[0], "float"), facts)
            selected = layouts if layouts else runtime_layouts
            if len(selected) == 1 and index_value is not None:
                layout = selected[0]
                name = layout.value[1]
                indices: tuple[object, ...] = (index_value.value,)
                if layout.value[3] == 2:
                    indices += (("const", 1),)
                return Fact(
                    "expression.value",
                    (value.offset, terminal.end),
                    (("array", name, indices),),
                    combine_evidence(
                        tuple(item.offset for item in stream[:7]),
                        index_value.evidence,
                        layout.evidence,
                    ),
                    "anchored",
                )
    if len(stream) < 5 or stream[0].kind not in {"movsim", "movsiax"}:
        return None
    index_load = stream[0]
    cursor = 1
    shift_start = cursor
    while cursor < len(stream) and stream[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor + 1 >= len(stream):
        return None
    anchor, terminal = stream[cursor : cursor + 2]
    if anchor.kind != "addsi" or terminal.kind != "fld_si":
        return None
    layouts = [
        fact
        for fact in facts_by_kind(facts).get("layout.array", ())
        if fact.kind == "layout.array"
        and len(fact.value) == 7
        and fact.value[4] == anchor.args[0]
        and fact.value[5] == 1 << shifts
        and len(fact.value[2]) == 1
    ]
    if len(layouts) != 1:
        return None
    if index_load.kind == "movsim":
        index_value = resolve_expression(
            ("memory", index_load.args[0], "integer"), facts
        )
    else:
        stores = [
            fact
            for fact in facts_by_kind(facts).get("machine.store", ())
            if fact.kind == "machine.store"
            and fact.subject == (0x2C,)
            and fact.evidence
            and max(fact.evidence) <= index_load.offset
        ]
        latest = latest_store(stores)
        index_value = (
            Resolved(latest.value[0], latest.evidence)
            if latest is not None and len(latest.value) == 1
            else None
        )
    if index_value is None:
        return None
    layout = layouts[0]
    return Fact(
        "expression.value",
        (index_load.offset, terminal.end),
        (("array", layout.value[1], (index_value.value,)),),
        combine_evidence(
            tuple(item.offset for item in stream[: cursor + 2]),
            index_value.evidence,
            layout.evidence,
        ),
        "anchored",
    )


def _fp_indexed_update(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 9 >= len(operations):
        return None
    value, load_index, convert = operations[index : index + 3]
    if (
        value.kind not in {"fld", "fld64"}
        or len(value.args) != 1
        or load_index.kind not in {"fld", "fld64"}
        or len(load_index.args) != 1
        or (convert.kind, convert.args) != ("fistp", (0x2C,))
    ):
        return None
    cursor = index + 3
    if tuple((item.kind, item.args) for item in operations[cursor : cursor + 2]) != (
        ("fwait", ()),
        ("movaxmem", (0x2C,)),
    ):
        return None
    cursor += 2
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    if cursor + 2 >= len(operations):
        return None
    anchor, fold, store = operations[cursor : cursor + 3]
    if (
        anchor.kind != "addsi"
        or fold.kind != "fold_si"
        or len(fold.args) != 1
        or store.kind not in {"fstp", "fstp64"}
    ):
        return None
    layout = _static_layout(anchor, "float", 2, facts)
    index_value = resolve_expression(("memory", load_index.args[0], "float"), facts)
    rhs = resolve_array_element(value.args[0], facts)
    target = resolve_expression(("memory", store.args[0], "float"), facts)
    if layout is None or index_value is None or rhs is None or target is None:
        return None
    name, layout_evidence = layout
    lhs = ("array", name, (index_value.value,))
    expression = ("binary", fold.args[0], rhs.value, lhs)
    return Fact(
        "semantic.assign",
        (value.offset, store.end),
        (target.value, expression),
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 3]),
            index_value.evidence,
            rhs.evidence,
            target.evidence,
            layout_evidence,
        ),
        "anchored",
    )


def _literal_runtime_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 5 >= len(operations):
        return None
    value, literal = operations[index : index + 2]
    if (
        value.kind not in _INDEX_LOADS
        or len(value.args) != 1
        or literal.kind != "movax"
        or len(literal.args) != 1
        or not isinstance(literal.args[0], int)
    ):
        return None
    cursor = index + 2
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    if cursor + 1 >= len(operations):
        return None
    anchor, terminal = operations[cursor : cursor + 2]
    target_kind = _store_kind(terminal.kind)
    if anchor.kind != "moves_m" or target_kind is None:
        return None
    runtime = _runtime_layout(anchor.args[0], target_kind, facts)
    source = resolve_expression(
        ("memory", value.args[0], _INDEX_LOADS[value.kind]), facts
    )
    if runtime is None or source is None:
        return None
    name, _width, layout_evidence = runtime
    return _store_fact(
        value,
        terminal,
        name,
        (("const", literal.args[0]),),
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index : cursor + 2]),
            source.evidence,
            layout_evidence,
        ),
    )


def _string_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    load = operations[index]
    if (
        load.kind != "movsim"
        or len(load.args) != 1
        or not isinstance(load.args[0], int)
    ):
        return None
    cursor = index + 1
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - index - 1
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    terminal_match = _indexed_terminal(operations, cursor + 1)
    if anchor.kind != "addsi" or terminal_match is None:
        return None
    terminal, target_kind, stop = terminal_match
    if not _contiguous(operations[index:stop]):
        return None
    layout = _static_layout(anchor, target_kind, shifts, facts)
    resolved = resolve_expression(("memory", load.args[0], "integer"), facts)
    if layout is None or resolved is None:
        return None
    name, layout_evidence = layout
    return _store_fact(
        load,
        terminal,
        name,
        (resolved.value,),
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index:stop]),
            resolved.evidence,
            layout_evidence,
        ),
    )


def _ax_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    """Recover a static array element whose index is carried through AX.

    ``_string_indexed_store`` reads the subscript straight into SI.  An array
    whose lower bound is not zero subtracts that bound first, so the index
    travels through AX and reaches SI by ``mov si,ax``.  The subtraction is
    address arithmetic, not part of the subscript the source wrote.
    """
    load = operations[index]
    if (
        load.kind != "movax_m"
        or len(load.args) != 1
        or not isinstance(load.args[0], int)
    ):
        return None
    cursor = index + 1
    if cursor < len(operations) and operations[cursor].kind == "subax_m":
        cursor += 1
    if cursor >= len(operations) or operations[cursor].kind != "movsiax":
        return None
    cursor += 1
    shifts_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shifts_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    terminal_match = _indexed_terminal(operations, cursor + 1)
    if anchor.kind != "addsi" or terminal_match is None:
        return None
    terminal, target_kind, stop = terminal_match
    if not _contiguous(operations[index:stop]):
        return None
    layout = _static_layout(anchor, target_kind, shifts, facts)
    resolved = resolve_expression(("memory", load.args[0], "integer"), facts)
    if layout is None or resolved is None:
        return None
    name, layout_evidence = layout
    return _store_fact(
        load,
        terminal,
        name,
        (resolved.value,),
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index:stop]),
            resolved.evidence,
            layout_evidence,
        ),
    )


def _direct_dynamic_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    if index + 1 >= len(operations):
        return None
    string = operations[index : index + 3]
    if (
        len(string) == 3
        and string[0].kind == "moves_m"
        and len(string[0].args) == 1
        and string[1].kind == "movsi"
        and len(string[1].args) == 1
        and string[2].kind == "far_strassign"
        and _contiguous(string)
    ):
        runtime = _runtime_layout(string[0].args[0], "string", facts)
        if runtime is None or not isinstance(string[1].args[0], int):
            return None
        name, width, layout_evidence = runtime
        displacement = string[1].args[0]
        low = _runtime_low(name, facts)
        if low is None or displacement < 0 or displacement % width:
            return None
        return _store_fact(
            string[0],
            string[2],
            name,
            (("const", low + displacement // width),),
            "string",
            combine_evidence(tuple(item.offset for item in string), layout_evidence),
        )
    anchor, terminal = operations[index : index + 2]
    target_kind = _NUMERIC_STORES.get(terminal.kind)
    if (
        anchor.kind != "moves_m"
        or target_kind is None
        or not terminal.kind.startswith("far_")
        or len(anchor.args) != 1
        or len(terminal.args) != 1
        or not all(isinstance(value, int) for value in anchor.args + terminal.args)
        or anchor.end != terminal.offset
    ):
        return None
    runtime = _runtime_layout(anchor.args[0], target_kind, facts)
    if runtime is None:
        return None
    name, width, layout_evidence = runtime
    raw_displacement = terminal.args[0]
    if not isinstance(raw_displacement, int):
        return None
    displacement = raw_displacement
    if displacement < 0 or displacement % width:
        return None
    low = _runtime_low(name, facts)
    if low is None:
        return None
    return _store_fact(
        anchor,
        terminal,
        name,
        (("const", low + displacement // width),),
        target_kind,
        combine_evidence((anchor.offset, terminal.offset), layout_evidence),
    )


def _indexed_layout(
    anchor: CompilerOp,
    terminal: CompilerOp,
    kind: str,
    shifts: int,
    facts: frozenset[Fact],
) -> tuple[str, tuple[int, ...]] | None:
    if anchor.kind == "addsi" and not terminal.kind.startswith("far_"):
        return _static_layout(anchor, kind, shifts, facts)
    if anchor.kind != "moves_m" or not terminal.kind.startswith("far_"):
        return None
    runtime = _runtime_layout(anchor.args[0], kind, facts) if anchor.args else None
    if runtime is None:
        return None
    name, width, support = runtime
    return (name, support) if 1 << shifts == width else None


@lru_cache(maxsize=16_384)
def _static_layout(
    anchor: CompilerOp, kind: str, shifts: int, facts: frozenset[Fact]
) -> tuple[str, tuple[int, ...]] | None:
    if len(anchor.args) != 1 or not isinstance(anchor.args[0], int):
        return None
    matches = [
        fact
        for fact in facts_by_kind(facts).get("layout.array", ())
        if fact.kind == "layout.array"
        and len(fact.value) == 7
        and fact.value[3] == kind
        and fact.value[4] == anchor.args[0]
        and fact.value[5] == 1 << shifts
        and isinstance(fact.value[1], str)
        and isinstance(fact.value[2], tuple)
        and len(fact.value[2]) == 1
    ]
    if len(matches) != 1:
        return None
    return matches[0].value[1], matches[0].evidence


@lru_cache(maxsize=16_384)
def _runtime_layout(
    block: object, kind: str, facts: frozenset[Fact]
) -> tuple[str, int, tuple[int, ...]] | None:
    if not isinstance(block, int):
        return None
    matches = [
        fact
        for fact in facts_by_kind(facts).get("layout.runtime_array", ())
        if fact.kind == "layout.runtime_array"
        and fact.subject == ("runtime", block)
        and len(fact.value) == 6
        and fact.value[2] == kind
        and isinstance(fact.value[1], str)
        and fact.value[3] == 1
        and isinstance(fact.value[4], int)
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    return match.value[1], match.value[4], match.evidence


@lru_cache(maxsize=16_384)
def _runtime_low(name: str, facts: frozenset[Fact]) -> int | None:
    for fact in facts:
        if fact.kind != "semantic.dynamic_dim" or fact.value[:1] != (name,):
            continue
        bounds = fact.value[1]
        if not isinstance(bounds, tuple) or len(bounds) != 1:
            continue
        bound = bounds[0]
        if (
            isinstance(bound, tuple)
            and len(bound) == 2
            and isinstance(bound[0], tuple)
            and bound[0][:1] == ("const",)
            and isinstance(bound[0][1], int)
        ):
            return bound[0][1]
        bases = [item.value[0] for item in facts if item.kind == "option.base"]
        return bases[0] if len(set(bases)) == 1 else 0
    return None


def _store_fact(
    start: CompilerOp,
    terminal: CompilerOp,
    name: str,
    indices: tuple[object, ...],
    kind: str,
    support: tuple[int, ...],
) -> Fact:
    return Fact(
        "reference.array_store",
        (start.offset, terminal.end),
        (("array", name, indices), kind),
        support,
        "anchored",
    )


def _rank2_indexed_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    special = _rank2_register_shuttle_store(operations, index, facts)
    if special is not None:
        return special
    if index + 7 > len(operations):
        return None
    first_match = _integer_operand(operations, index, facts)
    if first_match is None:
        return None
    first, left, cursor, first_staged = first_match
    if first_staged:
        return None
    if cursor + 2 >= len(operations):
        return None
    span, stage = operations[cursor : cursor + 2]
    if (
        span.kind != "imul_m"
        or len(span.args) != 1
        or not isinstance(span.args[0], int)
        or stage.kind != "movsiax"
    ):
        return None
    second_match = _integer_operand(operations, cursor + 2, facts)
    if second_match is None:
        return None
    _second, right, cursor, second_staged = second_match
    if second_staged:
        return None
    if cursor >= len(operations) or operations[cursor].kind != "addsiax":
        return None
    cursor += 1
    shift_start = cursor
    while cursor < len(operations) and operations[cursor].kind == "shlsi":
        cursor += 1
    shifts = cursor - shift_start
    if shifts == 0 or cursor >= len(operations):
        return None
    anchor = operations[cursor]
    terminal_match = _indexed_terminal(operations, cursor + 1)
    if terminal_match is None:
        return None
    terminal, target_kind, stop = terminal_match
    if not _contiguous(operations[index:stop]):
        return None
    layout = _rank2_layout(span.args[0], anchor, target_kind, shifts, facts)
    if layout is None:
        return None
    name, layout_evidence = layout
    return _store_fact(
        first,
        terminal,
        name,
        (right.value, left.value),
        target_kind,
        combine_evidence(
            tuple(item.offset for item in operations[index:stop]),
            left.evidence,
            right.evidence,
            layout_evidence,
        ),
    )


def _rank2_register_shuttle_store(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> Fact | None:
    window = operations[index : index + 13]
    if len(window) != 13:
        return None
    first, save, reload, multiply, stage, restore, shuttle, second, add, *tail = window
    if (
        first.kind != "movax_m"
        or save.kind != "movbxax"
        or reload.kind != "movax_m"
        or first.args != reload.args
        or multiply.kind != "imul_m"
        or stage.kind != "movsiax"
        or restore.kind != "movaxbx"
        or shuttle.kind != "movbxax"
        or second.kind != "movax_m"
        or add.kind != "addsiax"
        or len(tail) < 3
        or tail[-3].kind != "shlsi"
        or tail[-2].kind != "addsi"
        or tail[-1].kind != "movm_ax_si"
    ):
        return None
    left = resolve_expression(("memory", first.args[0], "integer"), facts)
    right = resolve_expression(("memory", second.args[0], "integer"), facts)
    if left is None or right is None:
        return None
    if not isinstance(multiply.args[0], int):
        return None
    layout = _rank2_layout(multiply.args[0], tail[-2], "integer", 1, facts)
    if layout is None:
        return None
    name, support = layout
    terminal = tail[-1]
    return _store_fact(
        first,
        terminal,
        name,
        (right.value, left.value),
        "integer",
        combine_evidence(
            tuple(item.offset for item in window),
            left.evidence,
            right.evidence,
            support,
        ),
    )


def _indexed_terminal(
    operations: tuple[CompilerOp, ...], index: int
) -> tuple[CompilerOp, str, int] | None:
    if index >= len(operations):
        return None
    direct = operations[index]
    kind = _store_kind(direct.kind)
    if kind is not None:
        return direct, kind, index + 1
    bridge = operations[index : index + 4]
    if (
        len(bridge) == 4
        and (bridge[0].kind, bridge[0].args) == ("fistp", (0x2C,))
        and bridge[1].kind == "fwait"
        and (bridge[2].kind, bridge[2].args) == ("movaxmem", (0x2C,))
        and bridge[3].kind in {"movm_ax_si", "far_movm_ax_si"}
    ):
        return bridge[3], "integer", index + 4
    return None


def _rank2_layout(
    span: int,
    anchor: CompilerOp,
    kind: str,
    shifts: int,
    facts: frozenset[Fact],
) -> tuple[str, tuple[int, ...]] | None:
    matches = []
    for fact in facts:
        if fact.kind == "layout.array" and len(fact.value) == 7:
            block = fact.subject[1] if len(fact.subject) == 2 else None
            valid_anchor = anchor.kind == "addsi" and anchor.args == (fact.value[4],)
            rank = len(fact.value[2]) if isinstance(fact.value[2], tuple) else 0
            fact_kind = fact.value[3]
            width = fact.value[5]
        elif fact.kind == "layout.runtime_array" and len(fact.value) == 6:
            block = fact.subject[1] if len(fact.subject) == 2 else None
            valid_anchor = anchor.kind == "moves_m" and anchor.args == (block,)
            fact_kind = fact.value[2]
            rank, width = fact.value[3:5]
        else:
            continue
        if (
            isinstance(block, int)
            and span == block + 0x0C
            and valid_anchor
            and isinstance(fact.value[1], str)
            and fact_kind == kind
            and rank == 2
            and width == 1 << shifts
        ):
            matches.append(fact)
    if len(matches) != 1:
        return None
    return matches[0].value[1], matches[0].evidence


def _integer_value(operation: CompilerOp, facts: frozenset[Fact]) -> Resolved | None:
    if operation.kind == "movax" and len(operation.args) == 1:
        return resolve_expression(("const", operation.args[0]), facts)
    if (
        operation.kind == "movax_m"
        and len(operation.args) == 1
        and isinstance(operation.args[0], int)
    ):
        return resolve_expression(("memory", operation.args[0], "integer"), facts)
    return None


def _element_operand(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> tuple[Resolved, int] | None:
    """Read an integer array element loaded into AX as a subscript."""
    ends = _integer_elements(facts).get(operations[index].offset)
    if not ends:
        return None
    last = max(ends)
    for cursor in range(index, len(operations)):
        if operations[cursor].end > last:
            return None
        element = ends.get(operations[cursor].end)
        if element is not None:
            if not _contiguous(operations[index : cursor + 1]):
                return None
            return Resolved(element.value[0], element.evidence), cursor + 1
    return None


_SUBSCRIPT_USES = frozenset({"movsiax", "imul_m", "addsiax", "movbxax"})


def _computed_operand(
    operations: tuple[CompilerOp, ...], index: int, facts: frozenset[Fact]
) -> tuple[Resolved, int] | None:
    """Read a subscript AX computes in several instructions, e.g. ``I% - 1``.

    The register tracker records AX after each instruction; the subscript is
    the longest run from ``index`` whose AX value was built from that run
    alone and that a subscript use follows.
    """
    first = operations[index].offset
    values = _ax_values(facts)
    found = None
    for cursor in range(index + 1, min(index + 6, len(operations) - 1)):
        fact = values.get(operations[cursor].offset)
        if (
            fact is None
            or min(fact.evidence) != first
            or max(fact.evidence) != operations[cursor].offset
            or operations[cursor + 1].kind not in _SUBSCRIPT_USES
            or not _contiguous(operations[index : cursor + 2])
        ):
            continue
        resolved = resolve_expression(fact.value[0], facts)
        if resolved is not None:
            found = (
                Resolved(resolved.value, fact.evidence + resolved.evidence),
                cursor + 1,
            )
    return found


@identity_cache
def _ax_values(facts: frozenset[Fact]) -> dict[int, Fact]:
    """Index single AX values by the instruction that leaves them."""
    found: dict[int, list[Fact]] = {}
    for fact in facts_by_kind(facts).get("register.value", ()):
        if len(fact.subject) == 2 and fact.subject[1] == "ax" and len(fact.value) == 1:
            found.setdefault(fact.subject[0], []).append(fact)
    return {offset: items[0] for offset, items in found.items() if len(items) == 1}


@identity_cache
def _integer_elements(facts: frozenset[Fact]) -> dict[int, dict[int, Fact]]:
    """Index unconverted integer element reads by start, then end."""
    found: dict[int, dict[int, Fact]] = {}
    for fact in facts_by_kind(facts).get("reference.array_value", ()):
        if len(fact.subject) == 2 and fact.value[1:] == ("integer",):
            found.setdefault(fact.subject[0], {})[fact.subject[1]] = fact
    return found


def _integer_operand(
    operations: tuple[CompilerOp, ...],
    index: int,
    facts: frozenset[Fact],
    elements: bool = False,
) -> tuple[CompilerOp, Resolved, int, bool] | None:
    if index >= len(operations):
        return None
    first = operations[index]
    if elements:
        element = _element_operand(operations, index, facts)
        if element is None:
            element = _computed_operand(operations, index, facts)
        if element is not None:
            return first, element[0], element[1], False
    direct = _integer_value(first, facts)
    if direct is not None:
        return first, direct, index + 1, False
    source_kind = _INDEX_LOADS.get(first.kind)
    if (
        source_kind is not None
        and len(first.args) == 1
        and isinstance(first.args[0], int)
        and index + 1 < len(operations)
        and (operations[index + 1].kind, operations[index + 1].args)
        == ("fistp", (0x2C,))
    ):
        cursor = index + 2
        staged = cursor < len(operations) and operations[cursor].kind == "movbxax"
        if staged:
            cursor += 1
        bridge = operations[cursor : cursor + 2]
        if (
            len(bridge) == 2
            and bridge[0].kind == "fwait"
            and (bridge[1].kind, bridge[1].args) == ("movaxmem", (0x2C,))
        ):
            resolved = resolve_expression(("memory", first.args[0], source_kind), facts)
            if resolved is not None:
                return first, resolved, cursor + 2, staged
    if (
        first.kind in {"fold", "fold64"}
        and index + 3 < len(operations)
        and operations[index + 1].kind == "fistp"
        and operations[index + 1].args == (0x2C,)
        and operations[index + 2].kind == "fwait"
        and operations[index + 3].kind == "movaxmem"
        and operations[index + 3].args == (0x2C,)
    ):
        stores = [
            fact
            for fact in facts_by_kind(facts).get("machine.store", ())
            if fact.kind == "machine.store"
            and fact.subject == (0x2C,)
            and fact.evidence
            and max(fact.evidence) <= operations[index + 1].offset
        ]
        latest = latest_store(stores)
        if latest is not None and len(latest.value) == 1:
            resolved = resolve_expression(latest.value[0], facts)
            if resolved is None:
                return None
            return (
                _stored_index_start(operations, index, latest),
                Resolved(
                    resolved.value, combine_evidence(resolved.evidence, latest.evidence)
                ),
                index + 4,
                False,
            )
    return None


def _stored_index_start(
    operations: tuple[CompilerOp, ...], index: int, store: Fact
) -> CompilerOp:
    """Retain the contiguous FP evaluation recorded by the index conversion."""
    first = operations[index]
    offsets = set(store.evidence)
    cursor = index
    while cursor > 0 and operations[cursor - 1].offset in offsets:
        cursor -= 1
    prefix = operations[cursor : index + 2]
    if {op.offset for op in prefix} == offsets and _contiguous(prefix):
        return operations[cursor]
    return first


def _store_kind(kind: str) -> str | None:
    if kind in {"strassign", "far_strassign"}:
        return "string"
    return _NUMERIC_STORES.get(kind)


def _contiguous(operations: tuple[CompilerOp, ...]) -> bool:
    return all(
        left.end == right.offset for left, right in zip(operations, operations[1:])
    )


ARRAY_REFERENCE_PASSES: tuple[NamedPass, ...] = (
    ("array-references", array_store_facts),
    ("array-addresses", array_address_facts),
    ("array-values", array_value_facts),
    ("array-comparisons", array_compare_facts),
    ("array-reads", array_read_facts),
)
