"""Turbo Basic runtime-chain facts over immutable instructions."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.matchers import fp_ax_bridge
from tbd.semantic import Resolved, combine_evidence, resolve_expression, resolve_slot

_NUMERIC_ITEMS = {0xBB: "console", 0xBD: "file", 0xBC: "printer"}
_STRING_ITEMS = {0xBE: "console", 0xC0: "file", 0xBF: "printer"}
_FLUSHES = {0xB8: "console", 0xBA: "file", 0xB9: "printer"}
_SEPARATORS = {0xC1: "console", 0xC3: "file", 0xC2: "printer"}
_CONTROL_ITEMS = {
    0xC7: ("TAB", "console"),
    0xC9: ("TAB", "file"),
    0xC8: ("TAB", "printer"),
    0xC4: ("SPC", "console"),
    0xC6: ("SPC", "file"),
    0xC5: ("SPC", "printer"),
}
_UNRESOLVED_CONTROLS = {vector: mode for vector, (_name, mode) in _CONTROL_ITEMS.items()}


@dataclass(frozen=True)
class _Item:
    start: int
    end: int
    mode: str
    value: object
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class _Chain:
    start: int
    items: tuple[_Item, ...]
    evidence: tuple[int, ...]


def runtime_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve complete runtime statements without consuming instructions."""

    expressions = _expression_index(facts, evidence.instructions)
    using_clauses = _print_using_clauses(
        evidence.instructions, expressions, facts
    )
    nested_using = _nested_using_subjects(
        evidence.instructions, using_clauses
    )
    items = _print_items(
        evidence.instructions,
        expressions,
        facts,
        tuple(
            clause for clause in using_clauses if clause.subject in nested_using
        ),
    )
    by_end = {item.end: item for item in items}
    instructions_by_end = {
        instruction.end: instruction for instruction in evidence.instructions
    }
    separators = {
        instruction.end: instruction
        for instruction in evidence.instructions
        if _runtime_vector(instruction) in _SEPARATORS
    }
    for instruction in evidence.instructions:
        mode = _FLUSHES.get(_runtime_vector(instruction))
        if mode is None:
            continue
        chain = _item_chain(by_end, separators, instruction.offset, mode)
        if not chain or _has_preceding_item(instructions_by_end, chain.start, mode):
            continue
        statement_mode: object = mode
        start = chain.start
        file_evidence: tuple[int, ...] = ()
        if mode == "file":
            file_result = _write_file_number(
                facts, instructions_by_end, chain.start
            )
            if file_result is None:
                continue
            statement_mode, start, file_evidence = file_result
        values = tuple(item.value for item in chain.items)
        support = combine_evidence(
            *(item.evidence for item in chain.items),
            chain.evidence,
            file_evidence,
            (instruction.offset,),
        )
        yield Fact(
            "semantic.lprint" if mode == "printer" else "semantic.print",
            (start, instruction.end),
            (statement_mode, values, True),
            support,
            "anchored",
        )
    yield from using_clauses
    yield from _standalone_print_using_facts(
        evidence.instructions, items, using_clauses, nested_using, facts
    )
    yield from _blank_lprint_facts(evidence.instructions)
    yield from _blank_file_print_facts(evidence.instructions, facts)
    yield from _write_facts(evidence.instructions, facts)
    yield from _fixed_string_facts(evidence.instructions, facts)
    yield from _field_facts(evidence.instructions, facts)
    yield from _mid_assign_facts(evidence.instructions, facts)


def _blank_lprint_facts(instructions: tuple[Operation, ...]) -> Iterable[Fact]:
    for previous, current in zip(instructions, instructions[1:]):
        if (
            previous.end == current.offset
            and _runtime_vector(previous) == 0xB9
            and _runtime_vector(current) == 0xB9
        ):
            yield Fact(
                "semantic.lprint",
                (current.offset, current.end),
                ("printer", (), True),
                (previous.offset, current.offset),
                "signature",
            )


def _blank_file_print_facts(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {instruction.end: instruction for instruction in instructions}
    for flush in instructions:
        if _runtime_vector(flush) != 0xBA:
            continue
        file_result = _write_file_number(facts, by_end, flush.offset)
        if file_result is None:
            continue
        file_number, start, file_evidence = file_result
        yield Fact(
            "semantic.print",
            (start, flush.end),
            (file_number, (), True),
            combine_evidence(file_evidence, (flush.offset,)),
            "anchored",
        )


def _field_facts(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_end = {item.end: item for item in instructions}
    for index, begin in enumerate(instructions):
        if _phase_name(begin) != "FIELD_BEGIN":
            continue
        items = []
        cursor = index + 1
        while cursor + 5 <= len(instructions):
            item = _field_item(instructions[cursor : cursor + 5])
            if item is None:
                break
            width, address, support = item
            items.append((width, address, support))
            yield Fact(
                "memory.write",
                (address,),
                ("string",),
                support,
                "signature",
            )
            cursor += 5
        if not items:
            continue
        file_result = _write_file_number(facts, by_end, begin.offset)
        if file_result is None:
            continue
        file_number, start, file_evidence = file_result
        fields = []
        field_evidence = []
        for width, address, support in items:
            target = resolve_slot(address, facts)
            if target is None:
                break
            fields.append((("const", width), target.value + ("string",)))
            field_evidence.extend((support, target.evidence))
        else:
            end = instructions[cursor - 1].end
            support = combine_evidence(
                (begin.offset,), file_evidence, *field_evidence
            )
            yield Fact(
                "semantic.field",
                (start, end),
                (file_number, tuple(fields)),
                support,
                "anchored",
            )


def _field_item(
    window: tuple[Operation, ...],
) -> tuple[object, object, tuple[int, ...]] | None:
    if len(window) != 5 or not _contiguous(window):
        return None
    width, target, segment_load, segment_set, phase = window
    if (
        width.kind != "x86.mov_imm"
        or width.operands[:1] != ("ax",)
        or len(width.operands) != 2
        or target.kind != "x86.mov_imm"
        or target.operands[:1] != ("si",)
        or len(target.operands) != 2
        or segment_load.kind != "x86.mov_imm"
        or segment_load.operands != ("dx", 0x98)
        or bytes.fromhex(segment_set.raw) != b"\x8e\xc2"
        or _phase_name(phase) != "FIELD_ITEM"
    ):
        return None
    return (
        width.operands[1],
        target.operands[1],
        tuple(item.offset for item in window),
    )


def _fixed_string_facts(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    modes = {0xA4: "semantic.lset", 0xA5: "semantic.rset"}
    for index in range(len(instructions) - 5):
        window = instructions[index : index + 6]
        source_setup, source_read, target_setup, segment_load, segment_set, terminal = window
        kind = modes.get(_runtime_vector(terminal))
        if (
            kind is None
            or not _contiguous(window)
            or not _is_string_setup(source_setup, source_read)
            or target_setup.kind != "x86.mov_imm"
            or target_setup.operands[:1] != ("si",)
            or len(target_setup.operands) != 2
            or segment_load.kind != "x86.mov_imm"
            or segment_load.operands != ("dx", 0x96)
            or bytes.fromhex(segment_set.raw) != b"\x8e\xc2"
        ):
            continue
        source = resolve_expression(
            ("memory", source_setup.operands[1], "string"), facts
        )
        target = resolve_slot(target_setup.operands[1], facts)
        if source is None or target is None:
            continue
        support = combine_evidence(
            tuple(item.offset for item in window), source.evidence, target.evidence
        )
        yield Fact(
            kind,
            (source_setup.offset, terminal.end),
            (target.value + ("string",), source.value),
            support,
            "anchored",
        )


def _mid_assign_facts(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover scalar MID$ assignment from either complete runtime ABI."""

    shapes = ((7, False), (9, True))
    for index in range(len(instructions)):
        for size, has_length in shapes:
            window = instructions[index : index + size]
            matched = _mid_assign_template(window, has_length)
            if matched is None:
                continue
            target_address, start_value, source_address, length_value = matched
            instruction_support = tuple(item.offset for item in window)
            yield Fact(
                "memory.write",
                (target_address,),
                ("string",),
                instruction_support,
                "signature",
            )
            target = resolve_slot(target_address, facts)
            start = resolve_expression(start_value, facts)
            source = resolve_expression(
                ("memory", source_address, "string"), facts
            )
            length = (
                resolve_expression(length_value, facts)
                if length_value is not None
                else None
            )
            if (
                target is None
                or start is None
                or source is None
                or (has_length and length is None)
            ):
                continue
            support = combine_evidence(
                instruction_support,
                target.evidence,
                start.evidence,
                source.evidence,
                () if length is None else length.evidence,
            )
            yield Fact(
                "semantic.mid_assign",
                (window[0].offset, window[-1].end),
                (
                    target.value + ("string",),
                    start.value,
                    source.value,
                    None if length is None else length.value,
                ),
                support,
                "anchored",
            )
    yield from _array_mid_assign_facts(instructions, facts)


def _array_mid_assign_facts(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    by_offset = {instruction.offset: instruction for instruction in instructions}
    by_end = {instruction.end: instruction for instruction in instructions}
    targets = [
        fact
        for fact in facts
        if fact.kind == "reference.array_address"
        and len(fact.subject) == 2
        and fact.value[1:] == ("string", 4, False)
    ]
    for target in targets:
        source_read = by_end.get(target.subject[0])
        source_setup = by_end.get(source_read.offset) if source_read else None
        length_load = by_end.get(source_setup.offset) if source_setup else None
        stage = by_end.get(length_load.offset) if length_load else None
        start_load = by_end.get(stage.offset) if stage else None
        segment_load = by_offset.get(target.subject[1])
        segment_set = by_offset.get(segment_load.end) if segment_load else None
        terminal = by_offset.get(segment_set.end) if segment_set else None
        if (
            source_setup is None
            or source_read is None
            or not _is_string_setup(source_setup, source_read)
            or start_load is None
            or stage is None
            or length_load is None
            or bytes.fromhex(stage.raw) != b"\x89\xc3"
            or segment_load is None
            or segment_load.kind != "x86.mov_imm"
            or segment_load.operands[:1] != ("dx",)
            or len(segment_load.operands) != 2
            or segment_set is None
            or bytes.fromhex(segment_set.raw) != b"\x8e\xc2"
            or terminal is None
            or _runtime_vector(terminal) != 0xAF
        ):
            continue
        start = _ax_expression(start_load)
        length = _ax_expression(length_load)
        source = resolve_expression(
            ("memory", source_setup.operands[1], "string"), facts
        )
        start_value = resolve_expression(start, facts) if start is not None else None
        length_value = (
            resolve_expression(length, facts) if length is not None else None
        )
        if source is None or start_value is None or length_value is None:
            continue
        yield Fact(
            "semantic.mid_assign",
            (start_load.offset, terminal.end),
            (
                target.value[0],
                start_value.value,
                source.value,
                length_value.value,
            ),
            combine_evidence(
                target.evidence,
                source.evidence,
                start_value.evidence,
                length_value.evidence,
                (
                    start_load.offset,
                    stage.offset,
                    length_load.offset,
                    source_setup.offset,
                    source_read.offset,
                    segment_load.offset,
                    segment_set.offset,
                    terminal.offset,
                ),
            ),
            "anchored",
        )


def _mid_assign_template(
    window: tuple[Operation, ...], has_length: bool
) -> tuple[int, object, int, object | None] | None:
    expected_size = 9 if has_length else 7
    if len(window) != expected_size or not _contiguous(window):
        return None
    if has_length:
        start_load, stage, length_load, *tail = window
        if bytes.fromhex(stage.raw) != b"\x89\xc3":
            return None
        length_value = _ax_expression(length_load)
        terminal_vector = 0xAF
    else:
        start_load, *tail = window
        length_value = None
        terminal_vector = 0xAE
    start_value = _ax_expression(start_load)
    source_setup, source_read, target_setup, segment_load, segment_set, terminal = tail
    if (
        start_value is None
        or (has_length and length_value is None)
        or not _is_string_setup(source_setup, source_read)
        or target_setup.kind != "x86.mov_imm"
        or len(target_setup.operands) != 2
        or target_setup.operands[0] != "si"
        or not isinstance(target_setup.operands[1], int)
        or not _is_es_setup(segment_load, segment_set)
        or _runtime_vector(terminal) != terminal_vector
    ):
        return None
    return (
        target_setup.operands[1],
        start_value,
        source_setup.operands[1],
        length_value,
    )


def _ax_expression(instruction: Operation) -> object | None:
    if (
        instruction.kind == "x86.mov_imm"
        and len(instruction.operands) == 2
        and instruction.operands[0] == "ax"
    ):
        return "const", instruction.operands[1]
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
        return "memory", struct.unpack_from("<H", raw, 2)[0], "integer"
    return None


def _is_es_setup(load: Operation, write: Operation) -> bool:
    # The relocated DGROUP segment value varies with link layout; the register
    # convention and adjacent ES write are the stable compiler signature.
    return (
        load.kind == "x86.mov_imm"
        and len(load.operands) == 2
        and load.operands[0] == "dx"
        and isinstance(load.operands[1], int)
        and bytes.fromhex(write.raw) == b"\x8e\xc2"
    )


def _write_facts(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    expressions = _expression_index(facts, instructions)
    items = _write_items(instructions, expressions, facts)
    by_end = {item.end: item for item in items}
    by_end_instruction = {item.end: item for item in instructions}
    separators = {
        item.end: item
        for item in instructions
        if _phase_name(item) in {"WRITE_SEPARATOR", "WRITE_FILE_SEPARATOR"}
    }
    for flush in instructions:
        mode = {0xB8: "console", 0xBA: "file"}.get(_runtime_vector(flush))
        if mode is None:
            continue
        chain = _item_chain(by_end, separators, flush.offset, mode)
        if not chain or _has_preceding_item(by_end_instruction, chain.start, mode):
            continue
        file_number = None
        start = chain.start
        file_evidence: tuple[int, ...] = ()
        if mode == "file":
            resolved = _write_file_number(facts, by_end_instruction, start)
            if resolved is None:
                continue
            file_number, start, file_evidence = resolved
        support = combine_evidence(
            *(item.evidence for item in chain.items),
            chain.evidence,
            file_evidence,
            (flush.offset,),
        )
        yield Fact(
            "semantic.write",
            (start, flush.end),
            (file_number, tuple(item.value for item in chain.items)),
            support,
            "anchored",
        )


def _write_items(
    instructions: tuple[Operation, ...],
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> tuple[_Item, ...]:
    result = []
    modes = {"WRITE_ITEM": "console", "WRITE_FILE_NUMBER": "file"}
    for index, instruction in enumerate(instructions):
        mode = modes.get(_phase_name(instruction))
        expression = expressions.get(instruction.offset)
        if mode is not None and expression is not None:
            resolved = resolve_expression(expression.value[0], facts)
            if resolved is not None:
                support = combine_evidence(
                    expression.evidence, resolved.evidence, (instruction.offset,)
                )
                result.append(
                    _Item(
                        expression.evidence[0],
                        instruction.end,
                        mode,
                        resolved.value,
                        support,
                    )
                )
        window = instructions[index : index + 3]
        if item := _write_string_item(window, facts):
            result.append(item)
    return tuple(result)


def _write_string_item(
    window: tuple[Operation, ...], facts: frozenset[Fact]
) -> _Item | None:
    if len(window) != 3:
        return None
    setup, read, phase = window
    if not _is_string_setup(setup, read) or _phase_name(phase) != "WRITE_FILE_STRING":
        return None
    resolved = resolve_expression(("memory", setup.operands[1], "string"), facts)
    if resolved is None:
        return None
    support = combine_evidence(
        (setup.offset, read.offset, phase.offset), resolved.evidence
    )
    return _Item(setup.offset, phase.end, "file", resolved.value, support)


def _write_file_number(
    facts: frozenset[Fact],
    instructions_by_end: dict[int, Operation],
    start: int,
) -> tuple[object, int, tuple[int, ...]] | None:
    store = instructions_by_end.get(start)
    if store is None:
        return None
    effects = [
        fact
        for fact in facts
        if fact.kind == "machine.store"
        and fact.subject == (0x60,)
        and fact.evidence
        and fact.evidence[-1] == store.offset
        and len(fact.value) == 1
    ]
    if len(effects) != 1:
        return None
    resolved = resolve_expression(effects[0].value[0], facts)
    if resolved is None:
        return None
    file_number = resolved.value
    if isinstance(file_number, tuple) and file_number[:1] == ("const",):
        file_number = file_number[1]
    return file_number, effects[0].evidence[0], combine_evidence(
        effects[0].evidence, resolved.evidence
    )


def _phase_name(instruction: Operation) -> str | None:
    if instruction.kind != "tb.statement" or not instruction.operands:
        return None
    name = instruction.operands[0]
    return name if isinstance(name, str) else None


def _expression_index(
    facts: frozenset[Fact], instructions: tuple[Operation, ...]
) -> dict[int, Fact]:
    ends = {instruction.offset: instruction.end for instruction in instructions}
    candidates: dict[int, list[Fact]] = {}
    for fact in facts:
        if fact.kind == "reference.array_value" and len(fact.subject) == 2:
            end = fact.subject[1]
        elif fact.kind == "expression.value" and fact.evidence:
            end = ends.get(fact.evidence[-1])
        else:
            continue
        if end is not None:
            candidates.setdefault(end, []).append(fact)
    result = {}
    for end, matches in candidates.items():
        references = [
            fact for fact in matches if fact.kind == "reference.array_value"
        ]
        if len(references) == 1:
            result[end] = references[0]
        elif not references and len(matches) == 1:
            result[end] = matches[0]
    return result


def _print_items(
    instructions: tuple[Operation, ...],
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
    using_clauses: tuple[Fact, ...] = (),
) -> tuple[_Item, ...]:
    result = []
    by_end = {instruction.end: instruction for instruction in instructions}
    for index, instruction in enumerate(instructions):
        if item := _numeric_item(instruction, expressions, facts):
            result.append(item)
        if item := _string_item(instructions[index : index + 3], facts):
            result.append(item)
        if item := _control_item(instructions[index : index + 2]):
            result.append(item)
        if item := _bridged_control(instruction, by_end, facts):
            result.append(item)
    for clause in using_clauses:
        mode, fmt, values = clause.value
        result.append(
            _Item(
                clause.subject[0],
                clause.subject[1],
                mode,
                ("print_using", mode, fmt, values, False),
                clause.evidence,
            )
        )
    return tuple(result)


def _print_using_clauses(
    instructions: tuple[Operation, ...],
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> tuple[Fact, ...]:
    """Translate complete CA/(CB|CC,item)+ compiler chains."""

    result = []
    for index in range(2, len(instructions)):
        begin = instructions[index]
        if _runtime_vector(begin) != 0xCA:
            continue
        setup, read = instructions[index - 2 : index]
        if not _is_string_setup(setup, read) or read.end != begin.offset:
            continue
        fmt = resolve_expression(("memory", setup.operands[1], "string"), facts)
        if fmt is None:
            continue
        cursor = index + 1
        values = []
        support = [fmt.evidence, (setup.offset, read.offset, begin.offset)]
        mode = None
        while cursor < len(instructions):
            emitted = _using_value(
                instructions, cursor, expressions, facts
            )
            if emitted is None:
                control = _control_item(instructions[cursor : cursor + 2])
                if (
                    control is None
                    or mode is None
                    or control.mode != mode
                    or not _using_emit_follows(instructions, cursor + 2)
                ):
                    break
                values.append(control.value)
                support.append(control.evidence)
                cursor += 2
                continue
            value, leg_mode, stop, item_evidence = emitted
            if mode is not None and leg_mode != mode:
                break
            mode = leg_mode
            values.append(value)
            support.append(item_evidence)
            cursor = stop
        if not values or mode is None:
            continue
        result.append(
            Fact(
                "reference.print_using",
                (setup.offset, instructions[cursor - 1].end),
                (mode, fmt.value, tuple(values)),
                combine_evidence(*support),
                "anchored",
            )
        )
    return tuple(result)


def _using_emit_follows(
    instructions: tuple[Operation, ...], index: int
) -> bool:
    for instruction in instructions[index : index + 12]:
        vector = _runtime_vector(instruction)
        if vector in {0xCB, 0xCC}:
            return True
        if vector in {0x87, 0xB8, 0xB9, 0xBA, 0xCA}:
            return False
    return False


def _nested_using_subjects(
    instructions: tuple[Operation, ...], clauses: tuple[Fact, ...]
) -> frozenset[tuple[object, ...]]:
    nested: set[tuple[object, ...]] = set()
    ordered = sorted(clauses, key=lambda clause: clause.subject)
    for left, right in zip(ordered, ordered[1:]):
        between = (
            instruction
            for instruction in instructions
            if left.subject[1] <= instruction.offset < right.subject[0]
        )
        if not any(
            _runtime_vector(instruction) in {0x87, 0xB8, 0xB9, 0xBA}
            for instruction in between
        ):
            nested.update((left.subject, right.subject))
    return frozenset(nested)


def _using_value(
    instructions: tuple[Operation, ...],
    index: int,
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> tuple[object, str, int, tuple[int, ...]] | None:
    emit_index = index
    expression = expressions.get(instructions[index].offset)
    if _runtime_vector(instructions[index]) != 0xCB:
        for candidate in range(index + 1, min(index + 12, len(instructions))):
            operation = instructions[candidate]
            matched = expressions.get(operation.offset)
            if (
                _runtime_vector(operation) == 0xCB
                and matched is not None
                and matched.evidence[:1] == (instructions[index].offset,)
                and _contiguous(instructions[index : candidate + 1])
            ):
                emit_index = candidate
                expression = matched
                break
    emit = instructions[emit_index]
    if _runtime_vector(emit) == 0xCB and emit_index + 1 < len(instructions):
        leg = instructions[emit_index + 1]
        mode = _STRING_ITEMS.get(_runtime_vector(leg))
        expression = expression or expressions.get(emit.offset)
        resolved = (
            resolve_expression(expression.value[0], facts)
            if expression is not None
            else None
        )
        if mode is None or resolved is None or emit.end != leg.offset:
            return None
        return (
            resolved.value,
            mode,
            emit_index + 2,
            combine_evidence(
                expression.evidence,
                resolved.evidence,
                (emit.offset, leg.offset),
            ),
        )
    window = instructions[index : index + 4]
    if len(window) != 4:
        return None
    setup, read, emit, leg = window
    mode = _STRING_ITEMS.get(_runtime_vector(leg))
    if (
        not _is_string_setup(setup, read)
        or _runtime_vector(emit) != 0xCC
        or mode is None
        or not _contiguous(window)
    ):
        return None
    resolved = resolve_expression(("memory", setup.operands[1], "string"), facts)
    if resolved is None:
        return None
    return (
        resolved.value,
        mode,
        index + 4,
        combine_evidence(
            resolved.evidence,
            tuple(item.offset for item in window),
        ),
    )


def _standalone_print_using_facts(
    instructions: tuple[Operation, ...],
    items: tuple[_Item, ...],
    clauses: tuple[Fact, ...],
    nested: frozenset[tuple[object, ...]],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    by_offset = {instruction.offset: instruction for instruction in instructions}
    by_end = {item.end: item for item in items}
    instruction_by_end = {
        instruction.end: instruction for instruction in instructions
    }
    separators = {
        instruction.end: instruction
        for instruction in instructions
        if _runtime_vector(instruction) in _SEPARATORS
    }
    for clause in clauses:
        if clause.subject in nested:
            continue
        following = by_offset.get(clause.subject[1])
        vector = _runtime_vector(following) if following is not None else None
        mode, fmt, values = clause.value
        expected_flush = {"console": 0xB8, "file": 0xBA, "printer": 0xB9}.get(
            mode
        )
        committed = vector == 0x87 and mode == "printer"
        flushed = vector == expected_flush
        if following is None or (not committed and not flushed):
            continue
        statement_mode: object = mode
        start = clause.subject[0]
        file_evidence: tuple[int, ...] = ()
        if mode == "file":
            file_result = _write_file_number(facts, instruction_by_end, start)
            if file_result is None:
                continue
            statement_mode, start, file_evidence = file_result
        yield Fact(
            "semantic.print_using",
            (start, following.end),
            (statement_mode, fmt, values, flushed),
            combine_evidence(
                clause.evidence, file_evidence, (following.offset,)
            ),
            "anchored",
        )
        preceding = _item_chain(by_end, separators, clause.subject[0], mode)
        if not preceding or _has_preceding_item(
            instruction_by_end, preceding.start, mode
        ):
            continue
        yield Fact(
            "semantic.lprint" if mode == "printer" else "semantic.print",
            (preceding.start, clause.subject[0]),
            (mode, tuple(item.value for item in preceding.items), False),
            combine_evidence(
                *(item.evidence for item in preceding.items),
                preceding.evidence,
                clause.evidence,
            ),
            "anchored",
        )


def _numeric_item(
    runtime: Operation,
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> _Item | None:
    mode = _NUMERIC_ITEMS.get(_runtime_vector(runtime))
    expression = expressions.get(runtime.offset)
    if (
        mode is None
        and expression is not None
        and expression.kind == "reference.array_value"
        and expression.value[1] == "string"
    ):
        mode = _STRING_ITEMS.get(_runtime_vector(runtime))
    if mode is None or expression is None:
        return None
    resolved = (
        Resolved(expression.value[0], expression.evidence)
        if expression.kind == "reference.array_value"
        else resolve_expression(expression.value[0], facts)
    )
    if resolved is None:
        return None
    support = combine_evidence(expression.evidence, resolved.evidence, (runtime.offset,))
    start = (
        expression.subject[0]
        if expression.kind == "reference.array_value"
        else expression.evidence[0]
    )
    return _Item(start, runtime.end, mode, resolved.value, support)


def _string_item(
    window: tuple[Operation, ...], facts: frozenset[Fact]
) -> _Item | None:
    if len(window) != 3:
        return None
    setup, read, runtime = window
    mode = _STRING_ITEMS.get(_runtime_vector(runtime))
    if not _is_string_setup(setup, read) or mode is None:
        return None
    resolved = resolve_expression(
        ("memory", setup.operands[1], "string"), facts
    )
    if resolved is None:
        return None
    support = combine_evidence(
        (setup.offset, read.offset, runtime.offset), resolved.evidence
    )
    return _Item(setup.offset, runtime.end, mode, resolved.value, support)


def _control_item(pair: tuple[Operation, ...]) -> _Item | None:
    if len(pair) != 2:
        return None
    load, runtime = pair
    control = _CONTROL_ITEMS.get(_runtime_vector(runtime))
    if (
        control is None
        or load.kind != "x86.mov_imm"
        or load.operands[:1] != ("ax",)
        or len(load.operands) != 2
        or load.end != runtime.offset
    ):
        return None
    name, mode = control
    value = "call", name, (("const", load.operands[1]),)
    return _Item(
        load.offset,
        runtime.end,
        mode,
        value,
        (load.offset, runtime.offset),
    )


def _bridged_control(
    runtime: Operation,
    by_end: dict[int, Operation],
    facts: frozenset[Fact],
) -> _Item | None:
    control = _CONTROL_ITEMS.get(_runtime_vector(runtime))
    reload = by_end.get(runtime.offset)
    bridge = fp_ax_bridge(reload, by_end)
    if control is None or bridge is None:
        return None
    expression, evidence = bridge
    resolved = resolve_expression(expression, facts)
    if resolved is None:
        return None
    name, mode = control
    value = "call", name, (resolved.value,)
    support = combine_evidence(
        evidence,
        (runtime.offset,),
        resolved.evidence,
    )
    return _Item(evidence[0], runtime.end, mode, value, support)


def _contiguous(instructions: tuple[Operation, ...]) -> bool:
    return all(
        left.end == right.offset
        for left, right in zip(instructions, instructions[1:])
    )


def _item_chain(
    by_end: dict[int, _Item],
    separators: dict[int, Operation],
    end: int,
    mode: str,
) -> _Chain | None:
    reverse = []
    support = []
    cursor = end
    start = end
    while True:
        item = by_end.get(cursor)
        if item is not None and item.mode == mode:
            reverse.append(item)
            cursor = start = item.start
            continue
        separator = separators.get(cursor)
        if (
            separator is not None
            and _separator_mode(separator) == mode
        ):
            support.append(separator.offset)
            cursor = start = separator.offset
            continue
        break
    if not reverse:
        return None
    return _Chain(start, tuple(reversed(reverse)), tuple(support))


def _separator_mode(instruction: Operation) -> str | None:
    runtime_mode = _SEPARATORS.get(_runtime_vector(instruction))
    if runtime_mode is not None:
        return runtime_mode
    return {
        "WRITE_SEPARATOR": "console",
        "WRITE_FILE_SEPARATOR": "file",
    }.get(_phase_name(instruction))


def _has_preceding_item(
    instructions_by_end: dict[int, Operation], start: int, mode: str
) -> bool:
    previous = instructions_by_end.get(start)
    vector = _runtime_vector(previous) if previous is not None else None
    preceding_mode = _NUMERIC_ITEMS.get(
        vector, _STRING_ITEMS.get(vector, _UNRESOLVED_CONTROLS.get(vector))
    )
    if preceding_mode is None and previous is not None:
        preceding_mode = {
            "WRITE_ITEM": "console",
            "WRITE_FILE_NUMBER": "file",
            "WRITE_FILE_STRING": "file",
        }.get(_phase_name(previous))
    return preceding_mode == mode


def _is_string_setup(setup: Operation, read: Operation) -> bool:
    return (
        setup.kind == "x86.mov_imm"
        and len(setup.operands) == 2
        and setup.operands[0] == "si"
        and isinstance(setup.operands[1], int)
        and _runtime_vector(read) == 0x9C
        and setup.end == read.offset
    )


def _runtime_vector(instruction: Operation) -> int | None:
    if instruction.kind != "tb.runtime" or not instruction.operands:
        return None
    vector = instruction.operands[0]
    return vector if isinstance(vector, int) else None


RUNTIME_FACT_PASSES: tuple[NamedPass, ...] = (("runtime", runtime_facts),)
