from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from tbd.facts import Evidence, NamedPass, fact_key, facts_by_kind, reads
from tbd.ir import Fact, Operation
from tbd.matchers import fp_ax_bridge
from tbd.operation_helpers import contiguous as _contiguous
from tbd.operation_helpers import runtime_vector as _runtime_vector
from tbd.operation_helpers import statement_name as _phase_name
from tbd.semantic import (
    Resolved,
    combine_evidence,
    function_parameter_at,
    resolve_expression,
    resolve_expression_before,
    resolve_slot,
    unique_fact,
)

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
_UNRESOLVED_CONTROLS = {
    vector: mode for vector, (_name, mode) in _CONTROL_ITEMS.items()
}


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


@reads(
    "constant",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "layout.array",
    "machine.store",
    "printer",
    "reference.array_address",
    "reference.array_store",
    "reference.array_value",
    "region.if_",
    "register.value",
    "semantic.",
    "semantic.def_fn",
    "semantic.lset",
    "semantic.rset",
    "signature",
    "slot",
    "tb.fp",
    "tb.function",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.add",
    "x86.j",
    "x86.mov",
    "x86.mov_acc_mem",
    "x86.mov_imm",
    "x86.op_83",
    "x86.ret",
    "x86.retf",
    "x86.xor",
)
def runtime_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover runtime I/O, PRINT, and field-operation facts."""
    for call in evidence.instructions:
        if call.kind != "tb.function" or call.operands != ("numeric", 0x1C):
            continue
        operands = sorted(
            (
                fact
                for fact in facts
                if fact.kind == "expression.string_operand"
                and len(fact.subject) == 2
                and fact.subject[1] <= call.offset
                and len(fact.value) == 1
            ),
            key=lambda fact: (fact.subject[0], fact_key(fact)),
        )
        if len(operands) >= 2:
            left, right = operands[-2:]
            # Both strings are pushed right before the call, in order.
            if (
                left.value[0][0] != "string"
                and left.subject[1] == right.subject[0]
                and right.subject[1] == call.offset
            ):
                yield Fact(
                    "expression.value",
                    (left.subject[0], call.end),
                    (("call", "INSTR", (left.value[0], right.value[0])),),
                    combine_evidence(left.evidence, right.evidence, (call.offset,)),
                    "anchored",
                )

    expressions = _expression_index(facts, evidence.instructions)
    using_clauses = _print_using_clauses(evidence.instructions, expressions, facts)
    nested_using = _nested_using_subjects(evidence.instructions, using_clauses)
    items = _print_items(
        evidence.instructions,
        expressions,
        facts,
        tuple(clause for clause in using_clauses if clause.subject in nested_using),
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
    targets = _jump_targets(evidence.instructions)
    for instruction in evidence.instructions:
        vector = _runtime_vector(instruction)
        mode = _FLUSHES.get(vector) if vector is not None else None
        if mode is None:
            continue
        previous = instructions_by_end.get(instruction.offset)
        # A flush after a jump, or one a jump lands on, is a PRINT of its own;
        # the items before it were left pending by a PRINT ending in ``;``.
        after_jump = previous is not None and previous.kind.startswith("x86.j")
        if (
            mode == "console"
            and previous is not None
            and (after_jump or instruction.offset in targets)
        ):
            # Only an item ending right there was left pending by its PRINT.
            last = previous.offset if after_jump else instruction.offset
            preceding = [
                item for item in items if item.mode == mode and item.end == last
            ]
            if preceding:
                item = max(preceding, key=lambda candidate: candidate.end)
                yield Fact(
                    "semantic.print",
                    (item.start, item.end),
                    (mode, (item.value,), False),
                    combine_evidence(item.evidence, (item.end,)),
                    "anchored",
                )
            yield Fact(
                "semantic.print",
                (instruction.offset, instruction.end),
                (mode, (), True),
                (previous.offset, instruction.offset),
                "signature",
            )
            continue
        chain = _item_chain(
            by_end,
            separators,
            instruction.offset,
            mode,
            preserve_separators=True,
        )
        if not chain or (
            _has_preceding_item(instructions_by_end, chain.start, mode)
            and not (
                chain.items
                and isinstance(chain.items[0].value, tuple)
                and chain.items[0].value[:1] == ("array",)
            )
        ):
            continue
        statement_mode: object = mode
        start = chain.start
        file_evidence: tuple[int, ...] = ()
        if mode == "file":
            file_result = _write_file_number(facts, instructions_by_end, chain.start)
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
    for end in evidence.instructions:
        if end.kind != "tb.statement" or end.operands[:1] != ("END",):
            continue
        pending = tuple(
            item for item in items if item.mode == "console" and item.end <= end.offset
        )
        if len(pending) < 2:
            continue
        pending = pending[-2:]
        # Only items that run straight into END are still pending.  Anything
        # separated from it by a flush or by other statements was printed by
        # its own statement, and pairing the last two would invent a PRINT.
        if pending[-1].end != end.offset or pending[0].end != pending[1].start:
            continue
        yield Fact(
            "semantic.print",
            (pending[0].start, pending[-1].end),
            ("console", tuple(item.value for item in pending), False),
            combine_evidence(*(item.evidence for item in pending)),
            "anchored",
        )
    yield from using_clauses
    yield from _standalone_print_using_facts(
        evidence.instructions, items, using_clauses, nested_using, facts
    )
    yield from _committed_print_facts(evidence.instructions, items, facts)
    yield from _unterminated_print_facts(evidence.instructions, items, facts)
    yield from _blank_lprint_facts(evidence.instructions)
    yield from _blank_console_print_facts(evidence.instructions)
    yield from _blank_file_print_facts(evidence.instructions, facts)
    yield from _write_facts(evidence.instructions, facts)
    yield from _fixed_string_facts(evidence.instructions, facts)
    yield from _field_facts(evidence.instructions, facts)
    yield from _mid_assign_facts(evidence.instructions, facts)


def _committed_print_facts(
    instructions: tuple[Operation, ...],
    items: tuple[_Item, ...],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    """Recover PRINT chains that a trailing semicolon ends without a newline.

    A trailing ``;`` leaves the cursor in place, so the compiler commits the
    statement instead of emitting the mode's newline flush.  The commit must
    directly follow the chain's final print item; a commit anywhere else ends
    some other statement and must not claim the preceding items.
    """
    by_end = {item.end: item for item in items}
    instructions_by_end = {item.end: item for item in instructions}
    separators = {
        instruction.end: instruction
        for instruction in instructions
        if _runtime_vector(instruction) in _SEPARATORS
    }
    for instruction in instructions:
        if _runtime_vector(instruction) != 0x87:
            continue
        final = by_end.get(instruction.offset)
        if final is None or _is_using_item(final):
            continue
        mode = final.mode
        chain = _item_chain(
            by_end,
            separators,
            instruction.offset,
            mode,
            preserve_separators=True,
        )
        if not chain or _has_preceding_item(instructions_by_end, chain.start, mode):
            continue
        statement_mode: object = mode
        start = chain.start
        file_evidence: tuple[int, ...] = ()
        if mode == "file":
            file_result = _write_file_number(facts, instructions_by_end, chain.start)
            if file_result is None:
                continue
            statement_mode, start, file_evidence = file_result
        yield Fact(
            "semantic.lprint" if mode == "printer" else "semantic.print",
            (start, instruction.end),
            (statement_mode, tuple(item.value for item in chain.items), False),
            combine_evidence(
                *(item.evidence for item in chain.items),
                chain.evidence,
                file_evidence,
                (instruction.offset,),
            ),
            "anchored",
        )


def _unterminated_print_facts(
    instructions: tuple[Operation, ...],
    items: tuple[_Item, ...],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    """Recover a PRINT chain the compiler left without a flush or a commit.

    A trailing semicolon needs no newline, and when the following statement
    begins with its own setup the compiler emits no commit either.  The chain
    is only complete where another recovered statement starts, which is the
    evidence that nothing further was appended to it.  A flush or commit there
    belongs to the rules that handle them.
    """
    by_end = {item.end: item for item in items}
    by_offset = {instruction.offset: instruction for instruction in instructions}
    instructions_by_end = {item.end: item for item in instructions}
    separators = {
        instruction.end: instruction
        for instruction in instructions
        if _runtime_vector(instruction) in _SEPARATORS
    }
    continuations = {*_SEPARATORS, *_FLUSHES, *_NUMERIC_ITEMS, *_STRING_ITEMS}
    continuations.update(_CONTROL_ITEMS)
    continuations.add(0x87)
    # A statement, a block IF or code a jump lands on starts after the items.
    statement_starts = {
        fact.subject[0]
        for fact in facts
        if fact.kind.startswith(("semantic.", "region.if_"))
        and len(fact.subject) == 2
        and isinstance(fact.subject[0], int)
    } | _jump_targets(instructions)
    # An item starting where this one ends continues the chain even when its
    # first instruction is its own operand's code rather than a runtime call.
    item_starts = {(item.start, item.mode) for item in items}
    for item in items:
        if item.mode != "console" or _is_using_item(item):
            continue
        following = by_offset.get(item.end)
        if (
            following is None
            or _runtime_vector(following) in continuations
            or (item.end, item.mode) in item_starts
        ):
            continue
        if item.end not in statement_starts:
            continue
        chain = _item_chain(
            by_end,
            separators,
            item.end,
            item.mode,
            preserve_separators=True,
        )
        if not chain or _has_preceding_item(
            instructions_by_end, chain.start, item.mode
        ):
            continue
        yield Fact(
            "semantic.print",
            (chain.start, item.end),
            (item.mode, tuple(entry.value for entry in chain.items), False),
            combine_evidence(
                *(entry.evidence for entry in chain.items),
                chain.evidence,
                (item.end,),
            ),
            "anchored",
        )


def _is_using_item(item: _Item) -> bool:
    """Report whether an item is a PRINT USING clause with its own recovery."""
    return isinstance(item.value, tuple) and item.value[:1] == ("print_using",)


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


def _blank_console_print_facts(
    instructions: tuple[Operation, ...],
) -> Iterable[Fact]:
    """Recover a bare PRINT with no items of its own.

    A console flush carries no operand, so it is a bare PRINT whenever nothing
    could have pushed an item into it: directly after a loop's terminating
    conditional jump, after a return, after another console flush, after a
    statement commit, each of which consumed every preceding item itself, or
    after the event-trap poll stamped before a statement.
    """
    for previous, current in zip(instructions, instructions[1:]):
        if (
            _runtime_vector(current) == 0xB8
            and previous.end == current.offset
            and (
                previous.kind.startswith("x86.j")
                # An event-trap poll stamps the start of a statement.
                or previous.kind
                in {"x86.ret", "x86.retf", "tb.checked_return", "x86.int3"}
                or _runtime_vector(previous) in {0xB8, 0x87}
            )
        ):
            yield Fact(
                "semantic.print",
                (current.offset, current.end),
                ("console", (), True),
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
        field_evidence: list[tuple[int, ...]] = []
        for width, address, support in items:
            target = resolve_slot(address, facts)
            if target is None:
                break
            if not isinstance(target.value, tuple):
                break
            fields.append((("const", width), target.value + ("string",)))
            field_evidence.extend((support, target.evidence))
        else:
            end = instructions[cursor - 1].end
            support = combine_evidence((begin.offset,), file_evidence, *field_evidence)
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
        # The buffer's segment descriptor differs by program.
        or segment_load.operands[:1] != ("dx",)
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
        source_setup, source_read, target_setup, segment_load, segment_set, terminal = (
            window
        )
        vector = _runtime_vector(terminal)
        kind = modes.get(vector) if vector is not None else None
        if (
            kind is None
            or not _contiguous(window)
            or not _is_string_setup(source_setup, source_read)
            or target_setup.kind != "x86.mov_imm"
            or target_setup.operands[:1] != ("si",)
            or len(target_setup.operands) != 2
            or segment_load.kind != "x86.mov_imm"
            # DX names the field buffer's segment descriptor, which differs by
            # program; its value does not change what LSET or RSET stores.
            or segment_load.operands[:1] != ("dx",)
            or bytes.fromhex(segment_set.raw) != b"\x8e\xc2"
        ):
            continue
        source = resolve_expression(
            ("memory", source_setup.operands[1], "string"), facts
        )
        target = resolve_slot(target_setup.operands[1], facts)
        if source is None or target is None:
            continue
        if not isinstance(target.value, tuple):
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

    yield from _frame_mid_assign_facts(instructions, facts)
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
            if target is None:
                parameter = function_parameter_at(
                    facts, window[0].offset, target_address, "string"
                )
                if parameter is not None:
                    target = Resolved(parameter, ())
            if isinstance(start_value, tuple) and start_value[:1] == ("bp",):
                parameter = function_parameter_at(
                    facts, window[0].offset, start_value[1], "integer"
                )
                start_value = parameter if parameter is not None else start_value
            if isinstance(length_value, tuple) and length_value[:1] == ("bp",):
                parameter = function_parameter_at(
                    facts, window[0].offset, length_value[1], "integer"
                )
                length_value = parameter if parameter is not None else length_value
            start = resolve_expression(start_value, facts)
            source = resolve_expression(("memory", source_address, "string"), facts)
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
            if not isinstance(target.value, tuple):
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


def _frame_mid_assign_facts(
    instructions: tuple[Operation, ...], facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Decode the by-reference MID$ form used inside string DEF FN bodies."""
    for index, terminal in enumerate(instructions):
        if _runtime_vector(terminal) != 0xAF or index < 9:
            continue
        window = instructions[index - 9 : index + 1]
        if len(window) != 10:
            continue
        start_load, _bridge, length_load, source_setup, source_read = window[:5]
        target_setup, target_read = window[5:7]
        if (
            bytes.fromhex(start_load.raw)[:2] != b"\x8b\x46"
            or length_load.kind != "x86.mov_imm"
            or length_load.operands != ("ax", 1)
            or source_setup.kind != "x86.mov_imm"
            or source_setup.operands[:1] != ("si",)
            or not isinstance(source_setup.operands[1], int)
            or _runtime_vector(source_read) != 0x9C
            or target_setup.kind != "x86.mov"
            or target_read.kind != "x86.op_83"
        ):
            continue
        owner = next(
            (
                fact
                for fact in facts
                if fact.kind == "semantic.def_fn"
                and fact.subject[0] < start_load.offset < fact.subject[1]
            ),
            None,
        )
        if owner is None:
            continue
        entry = owner.value[0]
        target_raw = bytes.fromhex(target_read.raw)
        # ``mov si,bp; add si,d`` addresses the string at [bp+d].
        target = (
            _function_frame_slot(facts, entry, target_raw[2], "string")
            if target_setup.raw == "8b f5" and target_raw[:2] == b"\x83\xc6"
            else None
        )
        start = _function_frame_slot(
            facts, entry, bytes.fromhex(start_load.raw)[2], "integer"
        )
        source = resolve_expression(
            ("memory", source_setup.operands[1], "string"), facts
        )
        if source is None:
            operand = next(
                (
                    fact
                    for fact in facts
                    if fact.kind == "expression.string_operand"
                    and fact.subject[0] == source_setup.offset
                    and len(fact.value) == 1
                ),
                None,
            )
            if operand is not None:
                source = Resolved(operand.value[0], operand.evidence)
        if target is None or start is None or source is None:
            continue
        yield Fact(
            "semantic.mid_assign",
            (start_load.offset, terminal.end),
            (target, start, source.value, ("const", 1)),
            combine_evidence(tuple(item.offset for item in window), source.evidence),
            "anchored",
        )


def _function_frame_slot(
    facts: frozenset[Fact], entry: int, displacement: int, kind: str
) -> tuple[object, ...] | None:
    """Return the DEF FN parameter or local at ``[bp+displacement]``."""
    found = set()
    for fact in facts:
        if fact.kind == "semantic.def_fn" and len(fact.value) == 5:
            slots = fact.value[2]
        elif fact.kind == "semantic.local" and len(fact.value) == 1:
            slots = fact.value[0]
        else:
            continue
        for slot in slots if isinstance(slots, tuple) else ():
            if slot in {
                ("fn-param", entry, displacement, kind),
                ("fn-local", entry, displacement, kind),
            }:
                found.add(slot)
    return next(iter(found)) if len(found) == 1 else None


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
        length_value = resolve_expression(length, facts) if length is not None else None
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
    if len(raw) == 4 and raw[:2] == b"\x8b\x46":
        return "bp", raw[2]
    return None


def _is_es_setup(load: Operation, write: Operation) -> bool:

    return (
        load.kind == "x86.mov_imm"
        and len(load.operands) == 2
        and load.operands[0] == "dx"
        and isinstance(load.operands[1], int)
        and bytes.fromhex(write.raw) == b"\x8e\xc2"
    )


def _jump_targets(instructions: tuple[Operation, ...]) -> set[object]:
    return {
        item.operands[0]
        for item in instructions
        if item.kind.startswith("x86.j") and len(item.operands) == 1
    }


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
    # Code a jump lands on begins a statement, so a flush there ends no item
    # before it: ``IF c THEN PRINT x;`` jumps over the item to the next PRINT.
    targets = _jump_targets(instructions)
    for flush in instructions:
        vector = _runtime_vector(flush)
        mode = (
            {0xB8: "console", 0xBA: "file"}.get(vector) if vector is not None else None
        )
        if mode is None or flush.offset in targets:
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
        values = tuple(item.value for item in chain.items)
        if mode == "console" and any(_is_string_value(value) for value in values):
            yield Fact(
                "semantic.print",
                (chain.items[0].start, flush.end),
                (mode, values, True),
                support,
                "anchored",
            )
        else:
            yield Fact(
                "semantic.write",
                (start, flush.end),
                (file_number, values),
                support,
                "anchored",
            )


def _write_items(
    instructions: tuple[Operation, ...],
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> tuple[_Item, ...]:
    result: list[_Item] = []
    modes: dict[object, str] = {
        "WRITE_ITEM": "console",
        "WRITE_FILE_NUMBER": "file",
    }
    for key, value in _STRING_ITEMS.items():
        modes[key] = value
    for index, instruction in enumerate(instructions):
        mode = modes.get(_phase_name(instruction))
        if mode is None:
            vector = _runtime_vector(instruction)
            mode = _STRING_ITEMS.get(vector) if vector is not None else None
        expression = expressions.get(instruction.offset)
        if mode is not None and expression is not None:
            resolved = resolve_expression(expression.value[0], facts)
            if resolved is not None:
                support = combine_evidence(
                    expression.evidence, resolved.evidence, (instruction.offset,)
                )
                result.append(
                    _Item(
                        _own_start(expression),
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


def _is_string_value(value: object) -> bool:
    if not isinstance(value, tuple) or not value:
        return False
    if value[0] == "string":
        return True
    if value[0] == "call" and len(value) > 1:
        return isinstance(value[1], str) and value[1].endswith("$")
    return (
        value[0] == "array"
        and len(value) > 1
        and isinstance(value[1], str)
        and value[1].endswith("$")
    )


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
        for fact in facts_by_kind(facts).get("machine.store", ())
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
    return (
        file_number,
        effects[0].evidence[0],
        combine_evidence(effects[0].evidence, resolved.evidence),
    )


_VALUE_SPAN = 256
"""The farthest a value that records only its start may end from it."""


def _own_end(fact: Fact, ends: dict[int, int]) -> int | None:
    """Return where a value that records only its start ends, if it is known.

    Its evidence also names instructions elsewhere -- every reference to a
    slot it reads, for one -- so the last evidence address can lie in another
    statement, even another part of the program.  When that address is
    farther from the start than any one expression's code runs, the end is
    unknown and the value is not indexed by it.
    """
    start = fact.subject[0] if fact.subject else None
    end = next(
        (ends[offset] for offset in reversed(fact.evidence) if offset in ends),
        None,
    )
    if end is None or (isinstance(start, int) and end - start > _VALUE_SPAN):
        return None
    return end


def _outermost_call(calls: list[Fact]) -> Fact | None:
    """Return the call value that contains every other ending at the same place.

    Values that disagree otherwise are rival readings of one item, and the
    reading chosen among them would change from round to round.
    """
    if not calls:
        return None
    values = {fact.value[0] for fact in calls}
    outer = [
        fact
        for fact in calls
        if all(
            value == fact.value[0] or repr(value) in repr(fact.value[0])
            for value in values
        )
    ]
    if not outer:
        return None
    return min(outer, key=lambda fact: (fact.subject[0], fact_key(fact)))


def _expression_index(
    facts: frozenset[Fact], instructions: tuple[Operation, ...]
) -> dict[int, Fact]:
    ends = {instruction.offset: instruction.end for instruction in instructions}
    candidates: dict[int, list[Fact]] = {}
    for fact in facts:
        if fact.kind == "reference.array_value" and len(fact.subject) == 2:
            end = fact.subject[1]
        elif fact.kind == "expression.value" and fact.evidence:
            end = (
                fact.subject[1]
                if len(fact.subject) == 2 and isinstance(fact.subject[1], int)
                else _own_end(fact, ends)
            )
        else:
            continue
        if end is not None:
            candidates.setdefault(end, []).append(fact)
    result = {}
    store_indices = {
        fact.value[0][2]
        for fact in facts
        if fact.kind == "reference.array_store"
        and len(fact.value) == 2
        and isinstance(fact.value[0], tuple)
        and len(fact.value[0]) == 3
        and isinstance(fact.value[0][2], tuple)
    }
    for end, matches in candidates.items():
        references = [fact for fact in matches if fact.kind == "reference.array_value"]
        matching_stores = [
            fact
            for fact in references
            if isinstance(fact.value[0], tuple)
            and len(fact.value[0]) == 3
            and fact.value[0][2] in store_indices
        ]
        if len(matching_stores) == 1:
            result[end] = matching_stores[0]
        elif len(references) == 1:
            result[end] = references[0]
        else:
            calls = [
                fact
                for fact in matches
                if fact.kind == "expression.value"
                and len(fact.value) == 1
                and isinstance(fact.value[0], tuple)
                and fact.value[0][:1] == ("call",)
            ]
            chosen = _outermost_call(calls)
            if chosen is not None:
                result[end] = chosen
            elif not calls and not references and len(matches) == 1:
                result[end] = matches[0]
    offsets = {
        instruction.offset: index for index, instruction in enumerate(instructions)
    }
    for fact in facts:
        if (
            fact.kind != "expression.value"
            or len(fact.subject) != 1
            or not fact.value
            or not isinstance(fact.value[0], tuple)
            or fact.value[0][:1] != ("array",)
        ):
            continue
        position = offsets.get(fact.subject[0])
        if position is None:
            continue
        for instruction in instructions[position : position + 8]:
            if _runtime_vector(instruction) in _NUMERIC_ITEMS | _STRING_ITEMS:
                result[instruction.offset] = fact
                break
    for fact in facts:
        if fact.kind != "reference.array_value" or len(fact.subject) != 2:
            continue
        index = offsets.get(fact.subject[1])
        if index is None:
            continue
        for instruction in instructions[index : index + 4]:
            if _runtime_vector(instruction) in _NUMERIC_ITEMS | _STRING_ITEMS:
                result.setdefault(instruction.offset, fact)
                break
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
        if item := _chr_item(instructions[index : index + 3], facts, by_end):
            result.append(item)
        if item := _control_item(instructions[index : index + 2]):
            result.append(item)
        if item := _bridged_control(instruction, by_end, facts):
            result.append(item)
    existing_ends = {item.end for item in result}
    # A string operand on the string stack (a function result, a
    # concatenation, an element) printed by a string item call is that item;
    # of operands nested inside one another, the outermost is.
    operands: dict[int, Fact] = {}
    for fact in facts_by_kind(facts).get("expression.string_operand", ()):
        if len(fact.subject) != 2 or len(fact.value) != 1:
            continue
        known = operands.get(fact.subject[1])
        if known is None or (fact.subject[0], fact_key(fact)) < (
            known.subject[0],
            fact_key(known),
        ):
            operands[fact.subject[1]] = fact
    for instruction in instructions:
        vector = _runtime_vector(instruction)
        mode = _STRING_ITEMS.get(vector) if vector is not None else None
        operand = operands.get(instruction.offset)
        if mode is None or operand is None or instruction.end in existing_ends:
            continue
        result.append(
            _Item(
                operand.subject[0],
                instruction.end,
                mode,
                operand.value[0],
                combine_evidence(operand.evidence, (instruction.offset,)),
            )
        )
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


def _chr_item(
    window: tuple[Operation, ...],
    facts: frozenset[Fact] = frozenset(),
    by_end: dict[int, Operation] | None = None,
) -> _Item | None:
    """Recognize ``CHR$(n)`` printed as an item, n a constant or a variable."""
    if len(window) != 3:
        return None
    setup, function, runtime = window
    vector = _runtime_vector(runtime)
    if (
        function.kind != "tb.runtime"
        or function.operands != (0xB3,)
        or vector not in _STRING_ITEMS
    ):
        return None
    argument = None
    support: tuple[int, ...] = ()
    if (
        setup.kind == "x86.mov_imm"
        and setup.operands[:1] == ("ax",)
        and len(setup.operands) == 2
    ):
        argument = ("const", setup.operands[1])
    elif setup.raw.startswith("8b 06 ") and len(setup.raw.split()) == 4:
        raw = bytes.fromhex(setup.raw)
        resolved = resolve_expression(
            ("memory", int.from_bytes(raw[2:], "little"), "integer"), facts
        )
        if resolved is not None:
            argument, support = resolved.value, resolved.evidence
    start = setup.offset
    if argument is None and by_end is not None and setup.raw.startswith("03 06 "):
        # ``CHR$(65 + k)``: ``mov ax,k; add ax,[65]``, the pool's constant.
        load = by_end.get(setup.offset)
        tracked = [
            fact
            for fact in facts_by_kind(facts).get("register.value", ())
            if fact.subject == (setup.offset, "ax") and len(fact.value) == 1
        ]
        address = int.from_bytes(bytes.fromhex(setup.raw)[2:4], "little")
        if load is not None and load.raw == "31 c0" and not tracked:
            # The tracker does not follow the zeroing idiom; AX holds 0.
            zero = ("binary", "+", ("const", 0), ("memory", address, "integer"))
            tracked = [
                Fact(
                    "register.value",
                    (setup.offset, "ax"),
                    (zero,),
                    (load.offset, setup.offset),
                    "structural",
                )
            ]
        if (
            load is not None
            and (
                (load.kind == "x86.mov_imm" and load.operands[:1] == ("ax",))
                or load.raw == "31 c0"
            )
            and len(tracked) == 1
        ):
            resolved = resolve_expression(tracked[0].value[0], facts)
            if resolved is not None:
                argument = resolved.value
                support = combine_evidence(tracked[0].evidence, resolved.evidence)
                start = load.offset
    if argument is None and by_end is not None:
        converted = _converted_ax(setup, by_end, facts)
        if converted is not None:
            argument, support, start = converted
    if argument is None:
        return None
    return _Item(
        start,
        runtime.end,
        _STRING_ITEMS[vector],
        ("call", "CHR$", (argument,)),
        combine_evidence((setup.offset, function.offset, runtime.offset), support),
    )


def _converted_ax(
    reload: Operation, by_end: dict[int, Operation], facts: frozenset[Fact]
) -> tuple[object, tuple[int, ...], int] | None:
    """Read a real converted to AX: ``...; fistp [2Ch]; fwait; mov ax,[2Ch]``.

    The value is whatever expression ends at the FISTP, e.g. an element read.
    """
    if reload.raw != "a1 2c 00":
        return None
    store = by_end.get(reload.offset)
    wait = None
    if store is not None and store.kind == "tb.fwait":
        wait, store = store, by_end.get(store.offset)
    if store is None or store.raw != "cd 3b 1e 2c 00":
        return None
    ends = {item.offset: item.end for item in by_end.values()}
    value = resolve_expression_before(store.offset, facts, ends)
    if value is None or not isinstance(value.start, int):
        return None
    support = (store.offset, reload.offset, *(() if wait is None else (wait.offset,)))
    return value.value, combine_evidence(value.evidence, support), value.start


def _print_using_clauses(
    instructions: tuple[Operation, ...],
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> tuple[Fact, ...]:

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
            emitted = _using_value(instructions, cursor, expressions, facts)
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


def _using_emit_follows(instructions: tuple[Operation, ...], index: int) -> bool:
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
    ordered = sorted(clauses, key=lambda clause: (clause.subject, fact_key(clause)))
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
        leg_vector = _runtime_vector(leg)
        mode = _STRING_ITEMS.get(leg_vector) if leg_vector is not None else None
        expression = expression or expressions.get(emit.offset)
        resolved = (
            resolve_expression(expression.value[0], facts)
            if expression is not None
            else None
        )
        if (
            mode is None
            or resolved is None
            or expression is None
            or emit.end != leg.offset
        ):
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
    leg_vector = _runtime_vector(leg)
    mode = _STRING_ITEMS.get(leg_vector) if leg_vector is not None else None
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
    instruction_by_end = {instruction.end: instruction for instruction in instructions}
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
        expected_flush = {"console": 0xB8, "file": 0xBA, "printer": 0xB9}.get(mode)
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
            combine_evidence(clause.evidence, file_evidence, (following.offset,)),
            "anchored",
        )
        preceding = _item_chain(
            by_end,
            separators,
            clause.subject[0],
            mode,
            preserve_separators=True,
        )
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


def _string_function_call(expression: Fact, facts: frozenset[Fact]) -> bool:
    """Whether a runtime call in this expression returns a string.

    The dispatch records its result type, so a call printed through a string
    item vector is only accepted when its own signature says it produced a
    string.
    """
    for offset in expression.evidence:
        signature = unique_fact(facts, "signature", (offset,))
        if (
            signature is not None
            and len(signature.value) == 2
            and signature.value[0] == "tb.function"
            and isinstance(signature.value[1], tuple)
            and signature.value[1][:1] == ("string",)
        ):
            return True
    return False


def _numeric_item(
    runtime: Operation,
    expressions: dict[int, Fact],
    facts: frozenset[Fact],
) -> _Item | None:
    runtime_vector = _runtime_vector(runtime)
    mode = _NUMERIC_ITEMS.get(runtime_vector) if runtime_vector is not None else None
    expression = expressions.get(runtime.offset)
    if (
        mode is None
        and expression is not None
        and expression.kind == "reference.array_value"
        and expression.value[1] == "string"
    ):
        mode = _STRING_ITEMS.get(runtime_vector) if runtime_vector is not None else None
    if (
        mode is None
        and expression is not None
        and expression.kind == "expression.value"
        and expression.value
        and isinstance(expression.value[0], tuple)
        and len(expression.value[0]) == 4
        and expression.value[0][0] in {"proc-param", "proc-local"}
        and expression.value[0][3] == "string"
    ):
        mode = _STRING_ITEMS.get(runtime_vector) if runtime_vector is not None else None
    if (
        mode is None
        and expression is not None
        and expression.kind == "expression.value"
        and expression.value
        and isinstance(expression.value[0], tuple)
        and len(expression.value[0]) == 4
        and expression.value[0][0] == "fn-call"
        and expression.value[0][3] == "string"
    ):
        mode = _STRING_ITEMS.get(runtime_vector) if runtime_vector is not None else None
    if (
        mode is None
        and expression is not None
        and expression.kind == "expression.value"
        and expression.value
        and isinstance(expression.value[0], tuple)
        and expression.value[0][:1] == ("call",)
        and _string_function_call(expression, facts)
    ):
        mode = _STRING_ITEMS.get(runtime_vector) if runtime_vector is not None else None
    if mode is None or expression is None:
        return None
    resolved = (
        Resolved(expression.value[0], expression.evidence)
        if expression.kind == "reference.array_value"
        else resolve_expression(expression.value[0], facts)
    )
    if (
        resolved is None
        and expression.kind == "expression.value"
        and len(expression.value) == 1
        and isinstance(expression.value[0], tuple)
        and expression.value[0][:1] == ("call",)
    ):
        resolved = Resolved(expression.value[0], expression.evidence)
    if resolved is None:
        return None
    support = combine_evidence(
        expression.evidence, resolved.evidence, (runtime.offset,)
    )
    return _Item(_own_start(expression), runtime.end, mode, resolved.value, support)


def _own_start(expression: Fact) -> int:
    """Where a value's own code starts: its subject, not its evidence.

    The evidence of a value names every reference to the slots it reads.
    """
    start = expression.subject[0] if expression.subject else None
    return start if isinstance(start, int) else expression.evidence[0]


def _string_item(window: tuple[Operation, ...], facts: frozenset[Fact]) -> _Item | None:
    if len(window) != 3:
        return None
    setup, read, runtime = window
    vector = _runtime_vector(runtime)
    mode = _STRING_ITEMS.get(vector) if vector is not None else None
    if not _is_string_setup(setup, read) or mode is None:
        return None
    resolved = resolve_expression(("memory", setup.operands[1], "string"), facts)
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
    vector = _runtime_vector(runtime)
    control = _CONTROL_ITEMS.get(vector) if vector is not None else None
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
    vector = _runtime_vector(runtime)
    control = _CONTROL_ITEMS.get(vector) if vector is not None else None
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


def _item_chain(
    by_end: dict[int, _Item],
    separators: dict[int, Operation],
    end: int,
    mode: str,
    *,
    preserve_separators: bool = False,
) -> _Chain | None:
    """Collect adjacent print items and their explicit separators."""
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
        if separator is not None and _separator_mode(separator) == mode:
            if preserve_separators:
                reverse.append(
                    _Item(
                        separator.offset,
                        separator.end,
                        mode,
                        ("print-separator", ","),
                        (separator.offset,),
                    )
                )
            support.append(separator.offset)
            cursor = start = separator.offset
            continue
        break
    if not reverse:
        return None
    return _Chain(start, tuple(reversed(reverse)), tuple(support))


def _separator_mode(instruction: Operation) -> str | None:
    vector = _runtime_vector(instruction)
    runtime_mode = _SEPARATORS.get(vector) if vector is not None else None
    if runtime_mode is not None:
        return runtime_mode
    phase = _phase_name(instruction)
    return (
        {
            "WRITE_SEPARATOR": "console",
            "WRITE_FILE_SEPARATOR": "file",
        }.get(phase)
        if phase is not None
        else None
    )


def _has_preceding_item(
    instructions_by_end: dict[int, Operation], start: int, mode: str
) -> bool:
    previous = instructions_by_end.get(start)
    vector = _runtime_vector(previous) if previous is not None else None
    preceding_mode = (
        _NUMERIC_ITEMS.get(
            vector, _STRING_ITEMS.get(vector, _UNRESOLVED_CONTROLS.get(vector))
        )
        if vector is not None
        else None
    )
    if preceding_mode is None and previous is not None:
        phase = _phase_name(previous)
        preceding_mode = (
            {
                "WRITE_ITEM": "console",
                "WRITE_FILE_NUMBER": "file",
                "WRITE_FILE_STRING": "file",
            }.get(phase)
            if phase is not None
            else None
        )
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


RUNTIME_FACT_PASSES: tuple[NamedPass, ...] = (("runtime", runtime_facts),)
