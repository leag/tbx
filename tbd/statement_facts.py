from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass, fact_key, facts_by_kind, indexed_facts, reads
from tbd.ir import Fact, Operation
from tbd.matchers import fp_ax_bridge, string_push_scaffold
from tbd.profile import EC_SOURCE_STATEMENTS
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_expression,
    resolve_expression_before,
)
from tbd.slots import slot_name
from tbd.string_statement_facts import SINGLE_STRING_STATEMENT_NAMES

_DEDICATED_STATEMENT_NAMES = SINGLE_STRING_STATEMENT_NAMES | frozenset(
    {
        "COLOR",
        "CIRCLE",
        "ERASE",
        "ERASE_STATIC",
        "FILES",
        "GET_GFX",
        "INPUT",
        "LINE_STMT",
        "ON_GOSUB",
        "ON_GOTO",
        "ON_TRAP",
        "OPEN",
        "PAINT",
        "PSET",
        "PUT_GFX",
        "RUN",
        "SCREEN",
        "TRAP_CTL",
        "VIEW",
        "WINDOW",
    }
)
_DEDICATED_NUMERIC_STATEMENT_SUBS = frozenset(
    {0x0A, 0x0C, 0x3C, 0x86, 0x88, 0xA2, 0xB0, 0xB6, 0xD0}
)


@reads(
    "constant",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "flow.branch",
    "flow.goto",
    "layout.array",
    "layout.runtime_array",
    "machine.store",
    "memory.read",
    "memory.write",
    "option.base",
    "reference.array_value",
    "register.value",
    "semantic.dim",
    "semantic.dynamic_dim",
    "semantic.local_dim",
    "semantic.on_gosub",
    "semantic.on_goto",
    "semantic.statement",
    "semantic.sub_def",
    "signature",
    "slot",
    "tb.defseg_reset",
    "tb.defseg_set",
    "tb.fp",
    "tb.fwait",
    "tb.proc_enter",
    "tb.run",
    "tb.runtime",
    "tb.statement",
    "x86.jmp",
    "x86.jmp_far",
    "x86.mov",
    "x86.mov_acc_mem",
    "x86.mov_imm",
    "x86.op_8e",
    "x86.op_d1",
)
def statement_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover source statements from runtime and compiler signatures."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for signature in facts:
        statement = _simple_statement(signature, instructions)
        if statement is not None:
            yield statement
    yield from _numeric_statement_facts(instructions, facts)
    yield from _palette_using_facts(instructions, facts)
    yield from _pset_facts(instructions, facts)
    yield from _line_facts(instructions, facts)
    yield from _view_facts(instructions, facts)
    yield from _window_facts(instructions, facts)
    yield from _circle_facts(instructions, facts)
    yield from _paint_facts(instructions, facts)
    yield from _gfx_transfer_facts(instructions, facts)
    yield from _erase_facts(instructions, facts)
    yield from _erase_pre_goto_facts(facts)
    yield from _width_facts(instructions, facts)
    yield from _binary_transfer_facts(instructions, facts)
    yield from _random_record_facts(instructions, facts)
    yield from _string_transfer_facts(instructions, facts)
    yield from _defseg_facts(instructions, facts)
    yield from _close_facts(instructions, facts)
    yield from _trap_ctl_facts(instructions)
    yield from _on_trap_facts(instructions, facts)
    yield from _on_dispatch_facts(instructions, facts)
    yield from _file_run_facts(instructions, facts)
    yield from _resume_facts(instructions, facts)
    yield from _static_dim_facts(evidence, facts)
    yield from _option_base_facts(evidence, facts)
    yield from _delay_facts(instructions, facts)


def _palette_using_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover the array element consumed by the PALETTE USING runtime call."""
    statements = tuple(
        instruction
        for instruction in instructions.values()
        if instruction.kind == "tb.statement"
        and instruction.operands == ("PALETTE_USING", 0x8A)
    )
    arrays = indexed_facts(
        (
            fact
            for fact in facts
            if fact.kind == "layout.runtime_array"
            and fact.subject[:1] == ("runtime",)
            and len(fact.value) >= 4
            and fact.value[2] == "integer"
            and fact.value[3] == 1
        ),
        lambda fact: fact.subject[1],
        lambda fact: fact.value,
    )
    static_arrays = indexed_facts(
        (
            fact
            for fact in facts
            if fact.kind == "layout.array"
            and len(fact.value) >= 7
            and fact.value[3] == "integer"
        ),
        lambda fact: fact.value[4],
        lambda fact: fact.value,
    )
    for statement in statements:
        index_expression = _palette_index_expression(instructions, statement)
        pointer = next(
            (
                instruction
                for instruction in instructions.values()
                if instruction.end <= statement.offset
                and instruction.kind == "x86.op_8e"
                and instruction.raw == "8e 06 20 01"
            ),
            None,
        )
        if pointer is None:
            setup = next(
                (
                    instruction
                    for instruction in instructions.values()
                    if instruction.kind == "x86.mov_imm"
                    and instruction.operands[:1] == ("si",)
                    and instruction.end <= statement.offset
                ),
                None,
            )
            if setup is None:
                continue
            array = static_arrays.get(setup.operands[1])
            if array is None:
                continue
            yield Fact(
                "semantic.statement",
                (setup.offset, statement.end),
                ("PALETTE_USING", 0x8A, ("array", array[1], (index_expression,))),
                (setup.offset, statement.offset),
                "anchored",
            )
            continue
        array = arrays.get(288)
        if array is None:
            continue
        yield Fact(
            "semantic.statement",
            (pointer.offset, statement.end),
            ("PALETTE_USING", 0x8A, ("array", array[1], (index_expression,))),
            (pointer.offset, statement.offset),
            "anchored",
        )


def _palette_index_expression(
    instructions: dict[int, Operation], statement: Operation
) -> object:
    ordered = tuple(instructions.values())
    index = ordered.index(statement)
    if index >= 2:
        load, shift, pointer = ordered[index - 3 : index]
        raw = bytes.fromhex(load.raw)
        if (
            load.kind == "x86.mov"
            and raw[:2] == b"\x8b\x36"
            and shift.kind == "x86.op_d1"
            and bytes.fromhex(shift.raw) == b"\xd1\xe6"
            and pointer.kind == "x86.op_8e"
            and pointer.raw == "8e 06 20 01"
        ):
            address = struct.unpack_from("<H", raw, 2)[0]
            return ("slot", slot_name(address), address)
    return ("const", 0)


def _option_base_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    if not evidence.instructions:
        return
    votes = [
        fact for fact in facts if fact.kind == "option.base" and fact.value == (1,)
    ]
    if not votes:
        return
    yield Fact(
        "semantic.option_base",
        (evidence.instructions[0].offset, -1),
        (1,),
        combine_evidence(*(fact.evidence for fact in votes)),
        "anchored",
    )


def _static_dim_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    if not evidence.instructions:
        return
    has_runtime_dim = any(
        instruction.kind == "tb.statement"
        and instruction.operands[:1] == ("DIM_BEGIN",)
        for instruction in evidence.instructions
    )
    if has_runtime_dim and not any(fact.kind == "option.base" for fact in facts):
        return
    has_procedure = any(
        instruction.kind == "tb.proc_enter" for instruction in evidence.instructions
    )
    procedures = tuple(fact for fact in facts if fact.kind == "semantic.sub_def")
    if has_procedure and not procedures:
        return
    code_start = evidence.instructions[0].offset
    arrays = sorted(
        (fact for fact in facts if fact.kind == "layout.array"),
        key=lambda fact: (fact.value[0], fact_key(fact)),
    )
    option_values = {
        fact.value[0]
        for fact in facts
        if fact.kind == "option.base"
        and len(fact.value) == 1
        and fact.value[0] in {0, 1}
    }
    option_base = next(iter(option_values)) if len(option_values) == 1 else 0
    for array in arrays:
        order, name, bounds, _kind, _base, _size, _count = array.value
        source_bounds = tuple(
            high if low == option_base else (low, high) for low, high in bounds
        )
        owner = _static_array_owner(array, procedures, facts)
        fact_kind = "semantic.local_dim" if owner is not None else "semantic.dim"
        subject = (
            (owner.value[0] + 1, order) if owner is not None else (code_start, order)
        )
        yield Fact(
            fact_kind,
            subject,
            (name, source_bounds, (), False),
            combine_evidence(array.evidence, (code_start,)),
            "anchored",
        )


def _static_array_owner(
    array: Fact,
    procedures: tuple[Fact, ...],
    facts: frozenset[Fact],
) -> Fact | None:
    _order, _name, _bounds, _kind, base, width, count = array.value
    if not all(isinstance(value, int) for value in (base, width, count)):
        return None
    sources = {
        source
        for fact in facts
        if fact.kind in {"memory.read", "memory.write"}
        and fact.subject
        and isinstance(fact.subject[0], int)
        and base <= fact.subject[0] < base + width * count
        for source in fact.evidence
    }
    if not sources:
        return None
    owners = {
        procedure
        for source in sources
        for procedure in procedures
        if procedure.subject[0] <= source < procedure.subject[1]
    }
    outside = any(
        not any(
            procedure.subject[0] <= source < procedure.subject[1]
            for procedure in procedures
        )
        for source in sources
    )
    return next(iter(owners)) if len(owners) == 1 and not outside else None


def _simple_statement(
    signature: Fact, instructions: dict[int, Operation]
) -> Fact | None:
    if signature.kind != "signature" or not signature.subject:
        return None
    kind, operands = signature.value
    instruction = instructions.get(signature.subject[0])
    if kind != "tb.statement" or instruction is None:
        return None
    if len(operands) < 2 or not isinstance(operands[1], int):
        return None
    if operands[1] in {0x16, 0x18, 0x26}:
        return None
    source = EC_SOURCE_STATEMENTS.get(operands[1])
    if source is None:
        return None
    name, fixed_operands = source
    if (
        name in _DEDICATED_STATEMENT_NAMES
        or operands[1] in _DEDICATED_NUMERIC_STATEMENT_SUBS
    ):
        return None
    return Fact(
        "semantic.statement",
        (instruction.offset, instruction.end),
        (name, operands[1], *fixed_operands, *operands[2:]),
        signature.evidence,
        "signature",
    )


def _numeric_statement_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    unary = {
        0x0A: "CALL_ABSOLUTE",
        0x0C: "CALL_INTERRUPT",
        0x3C: "ERROR_STMT",
        0xB0: "RANDOMIZE",
    }
    binary = {
        0xA2: "POKE",
        0xB6: "REG_SET",
        0xD0: "SOUND",
    }
    for statement in instructions.values():
        if statement.kind != "tb.statement" or len(statement.operands) < 2:
            continue
        sub = statement.operands[1]
        if sub in unary:
            value = _ax_expression_before(
                statement.offset, by_end, instruction_ends, facts
            )
            if value is not None:
                yield _numeric_statement_fact(statement, unary[sub], sub, (value,))
            continue
        if sub in binary:
            right = _ax_expression_before(
                statement.offset, by_end, instruction_ends, facts
            )
            left = (
                _ax_expression_before(right.start, by_end, instruction_ends, facts)
                if right is not None and right.start is not None
                else None
            )
            if left is not None and right is not None:
                yield _numeric_statement_fact(
                    statement, binary[sub], sub, (left, right)
                )
            continue
        if sub == 0x86:
            yield Fact(
                "semantic.statement",
                (statement.offset, statement.end),
                ("PALETTE", sub),
                (statement.offset,),
                "signature",
            )
            continue
        if sub == 0x88:
            color = _ax_expression_before(
                statement.offset, by_end, instruction_ends, facts
            )
            bridge = (
                by_end.get(color.start)
                if color is not None and color.start is not None
                else None
            )
            attribute = (
                _ax_expression_before(bridge.offset, by_end, instruction_ends, facts)
                if bridge is not None and _moves_ax_to_bx(bridge)
                else None
            )
            if attribute is not None and color is not None and bridge is not None:
                yield _numeric_statement_fact(
                    statement,
                    "PALETTE",
                    sub,
                    (attribute, color),
                    extra=(bridge.offset,),
                )


def _numeric_statement_fact(
    statement: Operation,
    name: str,
    sub: int,
    values: tuple[Resolved, ...],
    *,
    extra: tuple[int, ...] = (),
) -> Fact:
    starts = [value.start for value in values if value.start is not None]
    start = min(starts) if starts else statement.offset
    return Fact(
        "semantic.statement",
        (start, statement.end),
        (name, sub, *(value.value for value in values)),
        combine_evidence(
            *(value.evidence for value in values), extra, (statement.offset,)
        ),
        "anchored",
    )


def _pset_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 3
            or statement.operands[0] != "PSET"
            or not isinstance(statement.operands[1], int)
            or not isinstance(statement.operands[2], int)
        ):
            continue
        sub, flags = statement.operands[1:]
        cursor = statement.offset
        color = None
        color_support: tuple[int, ...] = ()
        if flags & 0x04:
            store = by_end.get(cursor)
            candidates = [
                fact
                for fact in stores
                if fact.subject == (0x88,)
                and fact.evidence
                and fact.evidence[-1] == (store.offset if store else None)
                and len(fact.value) == 1
            ]
            if store is None or len(candidates) != 1:
                continue
            source = resolve_expression(candidates[0].value[0], facts)
            if source is None:
                continue
            color = source.value
            color_support = combine_evidence(candidates[0].evidence, source.evidence)
            cursor = store.offset
        y = resolve_expression_before(cursor, facts, instruction_ends)
        x = (
            resolve_expression_before(y.start, facts, instruction_ends)
            if y is not None and y.start is not None
            else None
        )
        if x is None or y is None:
            continue
        # The opcode is always PSET; bit 0 selects PRESET mode on the
        # statement, which is represented separately by the flag operand.
        action = "PSET"
        yield Fact(
            "semantic.statement",
            (x.start if x.start is not None else x.evidence[0], statement.end),
            (action, sub, bool(flags & 0x08), x.value, y.value, color),
            combine_evidence(
                x.evidence,
                y.evidence,
                color_support,
                (statement.offset,),
            ),
            "anchored",
        )


def _line_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 3
            or statement.operands[0] != "LINE_STMT"
            or not isinstance(statement.operands[1], int)
            or not isinstance(statement.operands[2], int)
        ):
            continue
        sub, flags = statement.operands[1:]
        cursor = statement.offset
        style = None
        style_support: tuple[int, ...] = ()
        if flags & 0x01:
            store = by_end.get(cursor)
            resolved = _stored_expression_at(0xAC, store, stores, facts)
            if store is None or resolved is None:
                continue
            style, style_support = resolved.value, resolved.evidence
            cursor = store.offset
        color = None
        color_support: tuple[int, ...] = ()
        if flags & 0x08:
            store = by_end.get(cursor)
            resolved = _stored_expression_at(0xA0, store, stores, facts)
            if store is None or resolved is None:
                continue
            color, color_support = resolved.value, resolved.evidence
            cursor = store.offset
        y2 = resolve_expression_before(cursor, facts, instruction_ends)
        x2 = (
            resolve_expression_before(y2.start, facts, instruction_ends)
            if y2 is not None and y2.start is not None
            else None
        )
        if x2 is None or y2 is None or x2.start is None:
            continue
        # The first point, when given, is stored to its cells just before
        # the second is computed: x1 to [88h] last, y1 to [94h] before it.
        x1 = y1 = None
        if flags & 0x40:
            x1_store = by_end.get(x2.start)
            x1 = _stored_expression_at(0x88, x1_store, stores, facts)
            y1_store = by_end.get(x1_store.offset) if x1_store is not None else None
            y1 = _stored_expression_at(0x94, y1_store, stores, facts)
            if x1 is None or y1 is None:
                continue
        box = "BF" if flags & 0x02 else ("B" if flags & 0x04 else None)
        points = (x1, y1) if x1 is not None and y1 is not None else ()
        starts = tuple(
            value.start for value in (*points, x2, y2) if value.start is not None
        )
        if not starts or _crosses_a_statement(min(starts), statement, instructions):
            continue
        yield Fact(
            "semantic.statement",
            (min(starts), statement.end),
            (
                "LINE_STMT",
                sub,
                bool(flags & 0x20),
                None if x1 is None else x1.value,
                None if y1 is None else y1.value,
                bool(flags & 0x10),
                x2.value,
                y2.value,
                color,
                box,
                style,
            ),
            combine_evidence(
                *(value.evidence for value in points),
                x2.evidence,
                y2.evidence,
                color_support,
                style_support,
                (statement.offset,),
            ),
            "anchored",
        )


def _stored_expression_at(
    address: int,
    instruction: Operation | None,
    stores: tuple[Fact, ...],
    facts: frozenset[Fact],
) -> Resolved | None:
    if instruction is None:
        return None
    candidates = [
        fact
        for fact in stores
        if fact.subject == (address,)
        and fact.evidence
        and fact.evidence[-1] == instruction.offset
        and len(fact.value) == 1
    ]
    if len(candidates) != 1:
        return None
    source = resolve_expression(candidates[0].value[0], facts)
    if source is None:
        return None
    evidence = combine_evidence(candidates[0].evidence, source.evidence)
    # The value's own code is the store's evidence; the slot it reads adds
    # every reference to that slot in the program, which says nothing about
    # where this statement starts.
    return Resolved(source.value, evidence, min(candidates[0].evidence))


def _latest_stored_expression_before(
    address: int,
    offset: int,
    stores: tuple[Fact, ...],
    facts: frozenset[Fact],
) -> Resolved | None:
    candidates = [
        fact
        for fact in stores
        if fact.subject == (address,)
        and fact.evidence
        and fact.evidence[-1] < offset
        and len(fact.value) == 1
    ]
    if not candidates:
        return None
    latest = max(fact.evidence[-1] for fact in candidates)
    matches = [fact for fact in candidates if fact.evidence[-1] == latest]
    if len(matches) != 1:
        return None
    source = resolve_expression(matches[0].value[0], facts)
    if source is None:
        return None
    evidence = combine_evidence(matches[0].evidence, source.evidence)
    # As in _stored_expression_at, the store's own evidence is its code.
    return Resolved(source.value, evidence, min(matches[0].evidence))


def _view_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 3
            or statement.operands[0] != "VIEW"
            or not isinstance(statement.operands[1], int)
            or not isinstance(statement.operands[2], int)
        ):
            continue
        sub, flags = statement.operands[1:]
        if not flags & 0x04:
            yield Fact(
                "semantic.statement",
                (statement.offset, statement.end),
                ("VIEW", sub, bool(flags & 0x08), None, None, None, None, None, None),
                (statement.offset,),
                "anchored",
            )
            continue
        values = [
            _latest_stored_expression_before(address, statement.offset, stores, facts)
            for address in (0x88, 0x94, 0xA0, 0xAC)
        ]
        if values[0] is None:
            values[0] = _zero_ax_store_before(
                0x88, statement.offset, stores, instructions
            )
        if any(value is None for value in values):
            continue
        resolved_values = tuple(value for value in values if value is not None)
        fill = (
            _latest_stored_expression_before(0xB8, statement.offset, stores, facts)
            if flags & 0x02
            else None
        )
        border = (
            _latest_stored_expression_before(0xC4, statement.offset, stores, facts)
            if flags & 0x01
            else None
        )
        if (flags & 0x02 and fill is None) or (flags & 0x01 and border is None):
            continue
        support_values = (
            *resolved_values,
            *((fill,) if fill else ()),
            *((border,) if border else ()),
        )
        starts = tuple(
            value.start for value in support_values if value.start is not None
        )
        if not starts or _crosses_a_statement(min(starts), statement, instructions):
            continue
        yield Fact(
            "semantic.statement",
            (min(starts), statement.end),
            (
                "VIEW",
                sub,
                bool(flags & 0x08),
                *(value.value for value in resolved_values),
                None if fill is None else fill.value,
                None if border is None else border.value,
            ),
            combine_evidence(
                *(value.evidence for value in support_values),
                (statement.offset,),
            ),
            "anchored",
        )


def _zero_ax_store_before(
    address: int,
    offset: int,
    stores: tuple[Fact, ...],
    instructions: dict[int, Operation],
) -> Resolved | None:
    candidates = [
        fact
        for fact in stores
        if fact.subject == (address,)
        and fact.value == (("register", "ax"),)
        and fact.evidence
        and fact.evidence[-1] < offset
    ]
    if not candidates:
        return None
    store = max(candidates, key=lambda fact: (fact.evidence[-1], fact_key(fact)))
    for instruction in sorted(
        (
            instruction
            for instruction in instructions.values()
            if store.evidence[-1] - 16 <= instruction.offset < store.evidence[-1]
        ),
        key=lambda instruction: instruction.offset,
        reverse=True,
    ):
        if bytes.fromhex(instruction.raw) == b"\x31\xc0":
            return Resolved(
                ("const", 0),
                combine_evidence(store.evidence, (instruction.offset,)),
                instruction.offset,
            )
    return None


def _crosses_a_statement(
    start: int, statement: Operation, instructions: dict[int, Operation]
) -> bool:
    """Report operands taken from before another statement.

    A statement's operands are set up by the instructions that precede it, so
    the span reaching back for them cannot step over a different statement.
    Without this a coordinate last written far earlier is read as this
    statement's, and the resulting span swallows everything between.
    """
    return any(
        start < offset < statement.offset and other.kind == "tb.statement"
        for offset, other in instructions.items()
    )


def _window_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 3
            or statement.operands[0] != "WINDOW"
            or not isinstance(statement.operands[1], int)
            or not isinstance(statement.operands[2], int)
        ):
            continue
        sub, flags = statement.operands[1:]
        values = tuple(
            _latest_stored_expression_before(address, statement.offset, stores, facts)
            for address in (0x88, 0x94, 0xA0, 0xAC)
        )
        if any(value is None for value in values):
            continue
        resolved = tuple(value for value in values if value is not None)
        starts = tuple(value.start for value in resolved if value.start is not None)
        if not starts or _crosses_a_statement(min(starts), statement, instructions):
            continue
        yield Fact(
            "semantic.statement",
            (min(starts), statement.end),
            ("WINDOW", sub, bool(flags & 0x02), *(value.value for value in resolved)),
            combine_evidence(
                *(value.evidence for value in resolved),
                (statement.offset,),
            ),
            "anchored",
        )


def _circle_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 3
            or statement.operands[0] != "CIRCLE"
            or not isinstance(statement.operands[1], int)
            or not isinstance(statement.operands[2], int)
        ):
            continue
        sub, flags = statement.operands[1:]
        cursor = statement.offset
        optional: list[tuple[int, Resolved | None]] = []
        failed = False
        for bit, address in ((0x01, 0xAC), (0x04, 0xA0), (0x02, 0x94), (0x08, 0x88)):
            if not flags & bit:
                optional.append((bit, None))
                continue
            store = by_end.get(cursor)
            value = _stored_expression_at(address, store, stores, facts)
            if store is None or value is None:
                failed = True
                break
            optional.append((bit, value))
            cursor = value.start if value.start is not None else store.offset
        if failed:
            continue
        radius = resolve_expression_before(cursor, facts, instruction_ends)
        y = (
            resolve_expression_before(radius.start, facts, instruction_ends)
            if radius is not None and radius.start is not None
            else None
        )
        x = (
            resolve_expression_before(y.start, facts, instruction_ends)
            if y is not None and y.start is not None
            else None
        )
        if x is None or y is None or radius is None:
            continue
        option_values = {bit: value for bit, value in optional}
        rendered_options: list[object] = []
        for bit in (0x08, 0x02, 0x04, 0x01):
            option_value = option_values[bit]
            rendered_options.append(
                None if option_value is None else option_value.value
            )
        support_values = (
            x,
            y,
            radius,
            *(value for _bit, value in optional if value is not None),
        )
        starts = tuple(
            value.start for value in support_values if value.start is not None
        )
        yield Fact(
            "semantic.statement",
            (min(starts), statement.end),
            (
                "CIRCLE",
                sub,
                bool(flags & 0x10),
                x.value,
                y.value,
                radius.value,
                *rendered_options,
            ),
            combine_evidence(
                *(value.evidence for value in support_values),
                (statement.offset,),
            ),
            "anchored",
        )


def _paint_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    strings = tuple(fact for fact in facts if fact.kind == "expression.string_operand")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 3
            or statement.operands[0] not in {"PAINT", "PAINT_TILE"}
            or not isinstance(statement.operands[1], int)
            or not isinstance(statement.operands[2], int)
        ):
            continue
        sub, flags = statement.operands[1:]
        cursor = statement.offset
        border = None
        if flags & 0x01:
            store = by_end.get(cursor)
            border = _stored_expression_at(0x94, store, stores, facts)
            if store is None or border is None:
                continue
            cursor = border.start if border.start is not None else store.offset
        fill = None
        if statement.operands[0] == "PAINT_TILE":
            candidates = [
                fact
                for fact in strings
                if len(fact.subject) == 2
                and fact.subject[1] == cursor
                and isinstance(fact.subject[0], int)
                and len(fact.value) == 1
            ]
            if len(candidates) != 1:
                continue
            source = candidates[0]
            fill = Resolved(source.value[0], source.evidence, source.subject[0])
            cursor = source.subject[0]
        elif flags & 0x02:
            store = by_end.get(cursor)
            fill = _stored_expression_at(0x88, store, stores, facts)
            if store is None or fill is None:
                continue
            cursor = fill.start if fill.start is not None else store.offset
        y = resolve_expression_before(cursor, facts, instruction_ends)
        x = (
            resolve_expression_before(y.start, facts, instruction_ends)
            if y is not None and y.start is not None
            else None
        )
        if x is None or y is None:
            continue
        values = (x, y, *((fill,) if fill else ()), *((border,) if border else ()))
        starts = tuple(value.start for value in values if value.start is not None)
        yield Fact(
            "semantic.statement",
            (min(starts), statement.end),
            (
                "PAINT",
                sub,
                x.value,
                y.value,
                None if fill is None else fill.value,
                None if border is None else border.value,
            ),
            combine_evidence(
                *(value.evidence for value in values),
                (statement.offset,),
            ),
            "anchored",
        )


def _gfx_transfer_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    layouts = _array_descriptor_layouts(facts)
    ordered = tuple(sorted(instructions.values(), key=lambda item: item.offset))
    positions = {instruction.offset: index for index, instruction in enumerate(ordered)}
    for statement in ordered:
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 3
            or statement.operands[0] not in {"GET_GFX", "PUT_GFX"}
            or not isinstance(statement.operands[1], int)
            or not isinstance(statement.operands[2], int)
        ):
            continue
        array = _gfx_array_before(statement, ordered, positions, layouts)
        if array is None:
            continue
        name, cursor, array_support = array
        count = 4 if statement.operands[0] == "GET_GFX" else 2
        values: list[Resolved] = []
        for _ in range(count):
            value = resolve_expression_before(cursor, facts, instruction_ends)
            if value is None or value.start is None:
                break
            values.append(value)
            cursor = value.start
        if len(values) != count:
            continue
        values.reverse()
        sub, action = statement.operands[1:]
        operands: tuple[object, ...]
        if statement.operands[0] == "GET_GFX":
            operands = ("GET_GFX", sub, *(value.value for value in values), name)
        else:
            operands = (
                "PUT_GFX",
                sub,
                *(value.value for value in values),
                name,
                action,
            )
        starts = tuple(value.start for value in values if value.start is not None)
        yield Fact(
            "semantic.statement",
            (min(starts), statement.end),
            operands,
            combine_evidence(
                *(value.evidence for value in values),
                array_support,
                (statement.offset,),
            ),
            "anchored",
        )


def _gfx_array_before(
    statement: Operation,
    instructions: tuple[Operation, ...],
    positions: dict[int, int],
    layouts: dict[int, Fact],
) -> tuple[str, int, tuple[int, ...]] | None:
    position = positions[statement.offset] - 1
    support: list[int] = []
    while position >= 0 and len(support) < 3:
        instruction = instructions[position]
        if instruction.end != (statement.offset if not support else support[-1]):
            return None
        if (
            instruction.kind == "x86.mov_imm"
            and instruction.operands[:1] == ("si",)
            and len(instruction.operands) == 2
            and isinstance(instruction.operands[1], int)
        ):
            layout = layouts.get(instruction.operands[1])
            if layout is None:
                return None
            return (
                layout.value[1],
                instruction.offset,
                combine_evidence(
                    (instruction.offset,), tuple(reversed(support)), layout.evidence
                ),
            )
        raw = bytes.fromhex(instruction.raw)
        if not (
            raw == b"\x8e\xc2"
            or (
                instruction.kind == "x86.mov_imm"
                and instruction.operands[:1] == ("dx",)
            )
        ):
            return None
        support.append(instruction.offset)
        position -= 1
    return None


def _erase_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    layouts = _array_descriptor_layouts(facts)
    ordered = tuple(sorted(instructions.values(), key=lambda item: item.offset))
    positions = {instruction.offset: index for index, instruction in enumerate(ordered)}
    for statement in ordered:
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 2
            or statement.operands[0] not in {"ERASE", "ERASE_STATIC"}
            or not isinstance(statement.operands[1], int)
        ):
            continue
        array = _gfx_array_before(statement, ordered, positions, layouts)
        if array is None:
            yield Fact(
                "semantic.statement",
                (statement.offset, statement.end),
                ("ERASE", statement.operands[1]),
                (statement.offset,),
                "signature",
            )
            continue
        name, start, support = array
        yield Fact(
            "semantic.statement",
            (start, statement.end),
            ("ERASE", statement.operands[1], name),
            combine_evidence(support, (statement.offset,)),
            "anchored",
        )


def _array_descriptor_layouts(facts: frozenset[Fact]) -> dict[int, Fact]:
    return indexed_facts(
        (
            fact
            for fact in facts
            if fact.kind in {"layout.array", "layout.runtime_array"}
            and len(fact.subject) == 2
            and fact.subject[0] in {"static", "runtime"}
            and isinstance(fact.subject[1], int)
            and len(fact.value) >= 2
            and isinstance(fact.value[1], str)
        ),
        lambda fact: fact.subject[1],
    )


def _erase_pre_goto_facts(facts: frozenset[Fact]) -> Iterable[Fact]:
    erasures = tuple(
        fact
        for fact in facts
        if fact.kind == "semantic.statement"
        and len(fact.subject) == 2
        and len(fact.value) == 3
        and fact.value[0] == "ERASE"
        and isinstance(fact.value[2], str)
    )
    dimensions = tuple(
        fact
        for fact in facts
        if fact.kind == "semantic.dynamic_dim"
        and len(fact.subject) == 2
        and fact.value
        and isinstance(fact.value[0], str)
    )
    gotos = tuple(
        fact
        for fact in facts
        if fact.kind == "flow.goto"
        and len(fact.subject) == 2
        and len(fact.value) == 1
        and all(isinstance(value, int) for value in (*fact.subject, *fact.value))
    )
    for erase in erasures:
        dimensions_for_array = [
            dimension
            for dimension in dimensions
            if dimension.value[0] == erase.value[2]
            and erase.subject[1] < dimension.subject[0]
        ]
        for dimension in dimensions_for_array:
            enter = [
                goto
                for goto in gotos
                if goto.subject[1] == erase.subject[0]
                and goto.value == (dimension.subject[0],)
            ]
            skip = [
                goto
                for goto in gotos
                if goto.subject[0] == erase.subject[1]
                and goto.subject[1] == dimension.subject[0]
            ]
            repeat = [
                goto
                for goto in gotos
                if dimension.subject[1] <= goto.subject[0] <= dimension.subject[1] + 4
                and goto.value == (erase.subject[0],)
            ]
            if len(enter) != 1 or len(skip) != 1 or len(repeat) != 1:
                continue
            if skip[0].value[0] != repeat[0].subject[1]:
                continue
            support = combine_evidence(
                erase.evidence,
                dimension.evidence,
                enter[0].evidence,
                skip[0].evidence,
                repeat[0].evidence,
            )
            for goto in (enter[0], skip[0], repeat[0]):
                yield Fact(
                    "semantic.goto",
                    goto.subject,
                    goto.value,
                    support,
                    "anchored",
                )


def _width_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    strings = tuple(fact for fact in facts if fact.kind == "expression.string_operand")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 2
            or statement.operands[0] not in {"WIDTH", "WIDTH_DEVICE", "WIDTH_FILE"}
            or not isinstance(statement.operands[1], int)
        ):
            continue
        width = _ax_expression_before(statement.offset, by_end, instruction_ends, facts)
        if width is None or width.start is None:
            continue
        target = None
        target_support: tuple[int, ...] = ()
        start = width.start
        if statement.operands[0] == "WIDTH_DEVICE":
            matches = [
                fact
                for fact in strings
                if len(fact.subject) == 2
                and fact.subject[1] == width.start
                and isinstance(fact.subject[0], int)
                and len(fact.value) == 1
            ]
            if len(matches) != 1:
                continue
            target = matches[0].value[0]
            target_support = matches[0].evidence
            start = matches[0].subject[0]
        elif statement.operands[0] == "WIDTH_FILE":
            store = by_end.get(width.start)
            file_number = _stored_expression_at(0x60, store, stores, facts)
            if file_number is None:
                continue
            target = ("file", file_number.value)
            target_support = file_number.evidence
            start = (
                file_number.start
                if file_number.start is not None
                else file_number.evidence[0]
            )
        yield Fact(
            "semantic.statement",
            (start, statement.end),
            ("WIDTH", statement.operands[1], target, width.value),
            combine_evidence(
                width.evidence,
                target_support,
                (statement.offset,),
            ),
            "anchored",
        )


def _binary_transfer_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    strings = tuple(fact for fact in facts if fact.kind == "expression.string_operand")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 2
            or statement.operands[0] not in {"BLOAD", "BLOAD_DEFAULT", "BSAVE"}
            or not isinstance(statement.operands[1], int)
        ):
            continue
        count = (
            2
            if statement.operands[0] == "BSAVE"
            else (0 if statement.operands[0] == "BLOAD_DEFAULT" else 1)
        )
        cursor = statement.offset
        values: list[Resolved] = []
        for _ in range(count):
            value = resolve_expression_before(cursor, facts, instruction_ends)
            if value is None or value.start is None:
                break
            values.append(value)
            cursor = value.start
        if len(values) != count:
            continue
        values.reverse()
        filenames = [
            fact
            for fact in strings
            if len(fact.subject) == 2
            and fact.subject[1] == cursor
            and isinstance(fact.subject[0], int)
            and len(fact.value) == 1
        ]
        if len(filenames) != 1:
            continue
        filename = filenames[0]
        name = "BSAVE" if statement.operands[0] == "BSAVE" else "BLOAD"
        offset = values[0].value if values else None
        length = values[1].value if len(values) == 2 else None
        yield Fact(
            "semantic.statement",
            (filename.subject[0], statement.end),
            (
                name,
                statement.operands[1],
                filename.value[0],
                offset,
                length,
            ),
            combine_evidence(
                filename.evidence,
                *(value.evidence for value in values),
                (statement.offset,),
            ),
            "anchored",
        )


def _random_record_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 2
            or statement.operands[0] not in {"GET", "PUT", "SEEK"}
            or not isinstance(statement.operands[1], int)
        ):
            continue
        name = statement.operands[0]
        position = None
        if name != "GET" or statement.operands[1] != 0x46:
            position = _ax_expression_before(
                statement.offset, by_end, instruction_ends, facts
            )
            if position is None:
                position = _val_before(statement.offset, by_end, facts)
        if name == "SEEK" and (position is None or position.start is None):
            continue
        store_end = (
            position.start
            if position is not None and position.start is not None
            else statement.offset
        )
        store = by_end.get(store_end)
        file_number = _stored_expression_at(0x60, store, stores, facts)
        if file_number is None:
            continue
        starts = tuple(
            start
            for start in (
                file_number.start,
                None if position is None else position.start,
            )
            if start is not None
        )
        yield Fact(
            "semantic.statement",
            (min(starts), statement.end),
            (
                name,
                statement.operands[1],
                file_number.value,
                None if position is None else position.value,
            ),
            combine_evidence(
                file_number.evidence,
                () if position is None else position.evidence,
                (statement.offset,),
            ),
            "anchored",
        )


def _string_transfer_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    by_offset = {
        instruction.offset: instruction for instruction in instructions.values()
    }
    instruction_ends = {
        instruction.offset: instruction.end for instruction in instructions.values()
    }
    stores = tuple(fact for fact in facts if fact.kind == "machine.store")
    strings = tuple(fact for fact in facts if fact.kind == "expression.string_operand")
    for statement in instructions.values():
        if (
            statement.kind != "tb.statement"
            or len(statement.operands) != 2
            or statement.operands[0] not in {"PUT_STRING", "GET_STRING", "IOCTL"}
            or not isinstance(statement.operands[1], int)
        ):
            continue
        if statement.operands[0] != "GET_STRING":
            operands = [
                fact
                for fact in strings
                if len(fact.subject) == 2
                and fact.subject[1] == statement.offset
                and isinstance(fact.subject[0], int)
                and len(fact.value) == 1
            ]
            if len(operands) != 1:
                continue
            value = operands[0]
            file_store = by_end.get(value.subject[0])
            file_number = _stored_expression_at(0x60, file_store, stores, facts)
            if file_number is None:
                continue
            start = (
                file_number.start
                if file_number.start is not None
                else file_number.evidence[0]
            )
            yield Fact(
                "semantic.statement",
                (start, statement.end),
                (
                    statement.operands[0],
                    statement.operands[1],
                    file_number.value,
                    value.value[0],
                ),
                combine_evidence(
                    file_number.evidence,
                    value.evidence,
                    (statement.offset,),
                ),
                "anchored",
            )
            continue
        length = _ax_expression_before(
            statement.offset, by_end, instruction_ends, facts
        )
        if length is None or length.start is None:
            continue
        file_store = by_end.get(length.start)
        file_number = _stored_expression_at(0x60, file_store, stores, facts)
        setup = by_offset.get(statement.end)
        target_store = by_offset.get(setup.end) if setup is not None else None
        if (
            file_number is None
            or setup is None
            or setup.kind != "x86.mov_imm"
            or setup.operands[:1] != ("si",)
            or len(setup.operands) != 2
            or not isinstance(setup.operands[1], int)
            or target_store is None
            or _runtime_vector(target_store) != 0xA0
        ):
            continue
        target = resolve_expression(("memory", setup.operands[1], "string"), facts)
        if target is None:
            continue
        start = (
            file_number.start
            if file_number.start is not None
            else file_number.evidence[0]
        )
        yield Fact(
            "semantic.statement",
            (start, target_store.end),
            (
                "GET_STRING",
                statement.operands[1],
                file_number.value,
                length.value,
                target.value,
            ),
            combine_evidence(
                file_number.evidence,
                length.evidence,
                (statement.offset, setup.offset, target_store.offset),
                target.evidence,
            ),
            "anchored",
        )


def _runtime_vector(instruction: Operation | None) -> int | None:
    if instruction is None or instruction.kind != "tb.runtime":
        return None
    value = instruction.operands[0] if instruction.operands else None
    return value if isinstance(value, int) else None


def _val_before(
    offset: int, by_end: dict[int, Operation], facts: frozenset[Fact]
) -> Resolved | None:
    """Return the ``VAL`` whose call ends at ``offset``, on the FP stack."""
    call = by_end.get(offset)
    if call is None or call.kind != "tb.runtime" or call.operands != (0xAC,):
        return None
    values = [
        fact
        for fact in facts_by_kind(facts).get("expression.value", ())
        if len(fact.value) == 1
        and isinstance(fact.value[0], tuple)
        and fact.value[0][:2] == ("call", "VAL")
        and call.offset in fact.evidence
        and isinstance(fact.subject[0], int)
    ]
    if len({fact.value for fact in values}) != 1:
        return None
    value = min(values, key=fact_key)
    return Resolved(value.value[0], value.evidence, value.subject[0])


def _ax_expression_before(
    offset: int,
    by_end: dict[int, Operation],
    instruction_ends: dict[int, int],
    facts: frozenset[Fact],
) -> Resolved | None:
    resolved = resolve_expression_before(offset, facts, instruction_ends)
    if resolved is not None:
        return resolved
    load = by_end.get(offset)
    bridge = fp_ax_bridge(load, by_end)
    if bridge is not None:
        expression, evidence = bridge
        value = resolve_expression(expression, facts)
        if value is not None:
            return Resolved(
                value.value, combine_evidence(evidence, value.evidence), evidence[0]
            )
    address = _direct_ax_memory_address(load)
    if load is None or address is None:
        return None
    value = resolve_expression(("memory", address, "integer"), facts)
    if value is None:
        return None
    return Resolved(
        value.value,
        combine_evidence((load.offset,), value.evidence),
        load.offset,
    )


def _direct_ax_memory_address(instruction: Operation | None) -> int | None:
    if instruction is None or instruction.kind != "x86.mov":
        return None
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 3 and raw[0] == 0xA1:
        return struct.unpack_from("<H", raw, 1)[0]
    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
        return struct.unpack_from("<H", raw, 2)[0]
    return None


def _moves_ax_to_bx(instruction: Operation | None) -> bool:
    return instruction is not None and bytes.fromhex(instruction.raw) == b"\x89\xc3"


def _close_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    for close in instructions.values():
        if close.kind != "tb.statement" or len(close.operands) < 2:
            continue
        sub = close.operands[1]
        if sub == 0x16:
            yield Fact(
                "semantic.close",
                (close.offset, close.end),
                (None,),
                (close.offset,),
                "signature",
            )
            continue
        if sub != 0x18:
            continue
        load = by_end.get(close.offset)
        value = _immediate_ax(load)
        evidence: tuple[int, ...] = (
            (load.offset, close.offset) if load is not None else ()
        )
        if value is None:
            bridged = fp_ax_bridge(load, by_end)
            if bridged is None:
                continue
            expression, evidence = bridged
            resolved = resolve_expression(expression, facts)
            if resolved is None:
                continue
            value = resolved.value
            support = combine_evidence(evidence, resolved.evidence)
            confidence = "anchored"
        else:
            support = evidence
            confidence = "signature"
        if not evidence:
            continue
        yield Fact(
            "semantic.close",
            (evidence[0], close.end),
            (value,),
            combine_evidence(support, (close.offset,)),
            confidence,
        )


def _trap_ctl_facts(instructions: dict[int, Operation]) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    for instruction in instructions.values():
        if instruction.kind != "tb.statement" or len(instruction.operands) < 2:
            continue
        source = EC_SOURCE_STATEMENTS.get(instruction.operands[1])
        if source is None or source[0] != "TRAP_CTL" or len(source[1]) != 2:
            continue
        event, mode = source[1]
        number: object = None
        start = instruction.offset
        support: tuple[int, ...] = (instruction.offset,)
        if event in {"COM", "KEY"}:
            load = by_end.get(instruction.offset)
            immediate = _immediate_ax(load)
            if load is None or not isinstance(immediate, int):
                continue
            number = ("const", immediate)
            start = load.offset
            support = (load.offset, instruction.offset)
        yield Fact(
            "semantic.trap_ctl",
            (start, instruction.end),
            (event, number, mode),
            support,
            "signature",
        )


def _on_trap_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    values = tuple(fact for fact in facts if fact.kind == "expression.value")
    for instruction in instructions.values():
        if instruction.kind != "tb.statement" or len(instruction.operands) != 3:
            continue
        source = EC_SOURCE_STATEMENTS.get(instruction.operands[1])
        if source is None or source[0] != "ON_TRAP" or len(source[1]) != 1:
            continue
        event = source[1][0]
        target = instruction.operands[2]
        # The handler has to be somewhere we decoded.  A displacement that
        # reaches outside the image is not a destination, and naming it would
        # put an address in the export that the program never branches to.
        if not isinstance(target, int) or target not in instructions:
            continue
        number: object = None
        start = instruction.offset
        support: tuple[int, ...] = (instruction.offset,)
        if event in {"COM", "KEY", "PLAY"}:
            load = by_end.get(instruction.offset)
            immediate = _immediate_ax(load)
            if load is None or not isinstance(immediate, int):
                continue
            number = ("const", immediate)
            start = load.offset
            support = (load.offset, instruction.offset)
        elif event == "TIMER":
            candidates = [
                value
                for value in values
                if value.evidence
                and (last := instructions.get(value.evidence[-1])) is not None
                and last.end == instruction.offset
            ]
            if len(candidates) != 1:
                continue
            resolved = resolve_expression(candidates[0].value[0], facts)
            if resolved is None:
                continue
            number = resolved.value
            start = candidates[0].evidence[0]
            support = combine_evidence(
                candidates[0].evidence,
                resolved.evidence,
                (instruction.offset,),
            )
        elif event != "PEN":
            continue
        yield Fact(
            "semantic.on_trap",
            (start, instruction.end),
            (event, number, target),
            support,
            "signature",
        )


def _immediate_ax(instruction: Operation | None) -> object | None:
    if (
        instruction is not None
        and instruction.kind == "x86.mov_imm"
        and len(instruction.operands) == 2
        and instruction.operands[0] == "ax"
    ):
        return instruction.operands[1]
    return None


def _on_dispatch_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    # Every destination has to be somewhere we decoded.  A table laid out
    # differently than this reader expects yields addresses outside the image,
    # and naming those would put branches in the export that do not exist.
    kinds = {
        "ON_GOTO": (0x74, "semantic.on_goto"),
        "ON_GOSUB": (0x72, "semantic.on_gosub"),
    }
    for instruction in instructions.values():
        if (
            instruction.kind != "tb.statement"
            or len(instruction.operands) < 3
            or instruction.operands[0] not in kinds
            or instruction.operands[1] != kinds[instruction.operands[0]][0]
            or not all(
                isinstance(target, int) and target in instructions
                for target in instruction.operands[2:]
            )
        ):
            continue
        load = by_end.get(instruction.offset)
        bridge = fp_ax_bridge(load, by_end)
        load_raw = bytes.fromhex(load.raw) if load is not None else b""
        if bridge is None and len(load_raw) == 4 and load_raw[:2] == b"\x8b\x06":
            # An integer selector is loaded straight into AX from its variable.
            assert load is not None
            address = int.from_bytes(load_raw[2:], "little")
            bridge = ("memory", address, "integer"), (load.offset,)
        if bridge is None:
            continue
        expression, bridge_evidence = bridge
        resolved = resolve_expression(expression, facts)
        if resolved is None:
            continue
        yield Fact(
            kinds[instruction.operands[0]][1],
            (bridge_evidence[0], instruction.end),
            (resolved.value, *instruction.operands[2:]),
            combine_evidence(
                bridge_evidence,
                resolved.evidence,
                (instruction.offset,),
            ),
            "anchored",
        )


def _file_run_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions.values()}
    for instruction in instructions.values():
        if instruction.kind != "tb.statement" or instruction.operands[:2] != (
            "RUN",
            0xC4,
        ):
            continue
        scaffold = string_push_scaffold(instruction, by_end)
        if scaffold is None:
            continue
        setup, runtime = scaffold
        resolved = resolve_expression(("memory", setup.operands[1], "string"), facts)
        if resolved is None:
            continue
        yield Fact(
            "semantic.run",
            (setup.offset, instruction.end),
            (resolved.value,),
            combine_evidence(
                (setup.offset, runtime.offset, instruction.offset),
                resolved.evidence,
            ),
            "anchored",
        )


def _defseg_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    values = tuple(fact for fact in facts if fact.kind == "expression.value")
    for instruction in instructions.values():
        if instruction.kind == "tb.defseg_reset":
            yield Fact(
                "semantic.defseg",
                (instruction.offset, instruction.end),
                (),
                (instruction.offset,),
                "signature",
            )
            continue
        if instruction.kind == "tb.defseg_set" and instruction.operands:
            yield Fact(
                "semantic.defseg",
                (instruction.offset, instruction.end),
                (("const", instruction.operands[0]),),
                (instruction.offset,),
                "signature",
            )
            continue
        if not (
            instruction.kind == "tb.statement"
            and instruction.operands[:2] == ("DEF_SEG", 0x26)
        ):
            continue
        candidates = [
            value
            for value in values
            if value.evidence
            and (last := instructions.get(value.evidence[-1])) is not None
            and last.end == instruction.offset
        ]
        if len(candidates) != 1:
            continue
        resolved = resolve_expression(candidates[0].value[0], facts)
        if resolved is None:
            continue
        yield Fact(
            "semantic.defseg",
            (candidates[0].evidence[0], instruction.end),
            (resolved.value,),
            combine_evidence(
                candidates[0].evidence,
                (instruction.offset,),
                resolved.evidence,
            ),
            "signature",
        )


def _resume_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    signatures = indexed_facts(
        (fact for fact in facts if fact.kind == "signature" and fact.subject),
        lambda fact: fact.subject[0],
    )
    for begin in signatures.values():
        if begin.value != ("tb.statement", ("RESUME_BEGIN", 0xBC)):
            continue
        begin_instruction = instructions.get(begin.subject[0])
        if begin_instruction is None:
            continue
        tail = instructions.get(begin_instruction.end)
        if tail is None:
            continue
        value = _resume_value(tail)
        if value is None:
            continue
        tail_signature = signatures.get(tail.offset)
        if tail.kind == "tb.statement" and tail_signature is None:
            continue
        yield Fact(
            "semantic.resume",
            (begin_instruction.offset, tail.end),
            value,
            combine_evidence(begin.evidence, (tail.offset,)),
            "signature",
        )


def _resume_value(tail: Operation) -> tuple[object, ...] | None:
    if tail.kind == "tb.statement" and tail.operands[:2] == ("RESUME_BARE", 0xBE):
        return ()
    if tail.kind == "tb.statement" and tail.operands[:2] == ("RESUME_NEXT", 0xC0):
        return ("NEXT",)
    if tail.kind in {"x86.jmp", "x86.jmp_far", "tb.run"} and tail.operands:
        target = tail.operands[0]
        return (target,) if isinstance(target, int) else None
    return None


def _delay_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    signatures = indexed_facts(
        (fact for fact in facts if fact.kind == "signature" and fact.subject),
        lambda fact: fact.subject[0],
    )
    branches = indexed_facts(
        (
            fact
            for fact in facts
            if fact.kind == "flow.branch" and len(fact.subject) == 2
        ),
        lambda fact: fact.subject[0],
    )
    for value in facts:
        delay = _delay(value, instructions, signatures, branches, facts)
        if delay is not None:
            yield delay


def _delay(
    value: Fact,
    instructions: dict[int, Operation],
    signatures: dict[int, Fact],
    branches: dict[int, Fact],
    facts: frozenset[Fact],
) -> Fact | None:
    if value.kind != "expression.value" or not value.evidence:
        return None
    last = instructions.get(value.evidence[-1])
    begin = signatures.get(last.end) if last else None
    begin_instruction = _statement_instruction(begin, "DELAY_INIT", instructions)
    # A trap hook (int3) can sit before the poll, and the loop jumps back
    # to that hook.
    poll = (
        signatures.get(_after_hooks(begin_instruction.end, instructions))
        if begin_instruction
        else None
    )
    poll_instruction = _statement_instruction(poll, "DELAY_POLL", instructions)
    commit = signatures.get(poll_instruction.end) if poll_instruction else None
    commit_instruction = _runtime_instruction(commit, 0x87, instructions)
    branch = branches.get(commit_instruction.end) if commit_instruction else None
    if (
        branch is None
        or begin is None
        or poll is None
        or commit is None
        or poll_instruction is None
        or branch.value[0] != "<>"
        or not isinstance(branch.value[1], int)
        or _after_hooks(branch.value[1], instructions) != poll_instruction.offset
    ):
        return None
    resolved = resolve_expression(value.value[0], facts)
    if resolved is None:
        return None
    support = combine_evidence(
        value.evidence,
        begin.evidence,
        poll.evidence,
        commit.evidence,
        branch.evidence,
        resolved.evidence,
    )
    return Fact(
        "semantic.delay",
        (
            value.subject[0]
            if isinstance(value.subject[0], int)
            else value.evidence[0],
            branch.subject[1],
        ),
        (resolved.value,),
        support,
        "anchored",
    )


def _after_hooks(offset: int, instructions: dict[int, Operation]) -> int:
    """Skip the trap-hook ``int3`` instructions at ``offset``."""
    while (hook := instructions.get(offset)) is not None and hook.kind == "x86.int3":
        offset = hook.end
    return offset


def _statement_instruction(
    fact: Fact | None, name: str, instructions: dict[int, Operation]
) -> Operation | None:
    if fact is None or fact.value != ("tb.statement", (name, _delay_sub(name))):
        return None
    return instructions.get(fact.subject[0])


def _runtime_instruction(
    fact: Fact | None, vector: int, instructions: dict[int, Operation]
) -> Operation | None:
    if fact is None or fact.value != ("tb.runtime", (vector,)):
        return None
    return instructions.get(fact.subject[0])


def _delay_sub(name: str) -> int:
    return 0x28 if name == "DELAY_INIT" else 0x2A


STATEMENT_FACT_PASSES: tuple[NamedPass, ...] = (("statements", statement_facts),)
