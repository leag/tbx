"""Source statement facts over signatures and semantic evidence."""

from __future__ import annotations

import struct
from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.profile import EC_SOURCE_STATEMENTS, FP_TRANSFER_TYPES
from tbd.semantic import combine_evidence, resolve_expression


def statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Expose complete source statements without consuming their evidence."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for signature in facts:
        statement = _simple_statement(signature, instructions)
        if statement is not None:
            yield statement
    yield from _defseg_facts(instructions, facts)
    yield from _close_facts(instructions, facts)
    yield from _trap_ctl_facts(instructions)
    yield from _on_trap_facts(instructions, facts)
    yield from _resume_facts(instructions, facts)
    yield from _static_dim_facts(evidence, facts)
    yield from _delay_facts(instructions, facts)


def _static_dim_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    if not evidence.instructions:
        return
    code_start = evidence.instructions[0].offset
    arrays = sorted(
        (fact for fact in facts if fact.kind == "layout.array"),
        key=lambda fact: fact.value[0],
    )
    for array in arrays:
        order, name, bounds, _kind, _base, _size, _count = array.value
        source_bounds = tuple(
            high if low == 0 else (low, high) for low, high in bounds
        )
        yield Fact(
            "semantic.dim",
            (code_start, order),
            (name, source_bounds, (), False),
            combine_evidence(array.evidence, (code_start,)),
            "anchored",
        )


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
    if name in {"ON_TRAP", "TRAP_CTL"}:
        return None
    return Fact(
        "semantic.statement",
        (instruction.offset, instruction.end),
        (name, operands[1], *fixed_operands, *operands[2:]),
        signature.evidence,
        "signature",
    )


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
        evidence = (load.offset, close.offset) if load is not None else ()
        if value is None:
            bridged = _close_bridge(load, by_end)
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
        number = None
        start = instruction.offset
        support = (instruction.offset,)
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
        if not isinstance(target, int):
            continue
        number = None
        start = instruction.offset
        support = (instruction.offset,)
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


def _close_bridge(
    reload: Operation | None, by_end: dict[int, Operation]
) -> tuple[object, tuple[int, ...]] | None:
    if reload is None:
        return None
    reload_raw = bytes.fromhex(reload.raw)
    if reload.kind != "tb.fp" or len(reload_raw) != 5 or reload_raw[:3] != b"\xcd\x3d\xa1":
        return None
    scratch = struct.unpack_from("<H", reload_raw, 3)[0]
    store = by_end.get(reload.offset)
    source = by_end.get(store.offset) if store is not None else None
    if store is None or source is None:
        return None
    store_raw = bytes.fromhex(store.raw)
    source_raw = bytes.fromhex(source.raw)
    if (
        len(store_raw) != 5
        or store_raw[:3] != b"\xcd\x3b\x1e"
        or struct.unpack_from("<H", store_raw, 3)[0] != scratch
        or source.kind != "tb.fp"
        or len(source_raw) != 5
        or source_raw[0] != 0xCD
        or source_raw[2] != 0x06
        or source_raw[1] not in FP_TRANSFER_TYPES
    ):
        return None
    address = struct.unpack_from("<H", source_raw, 3)[0]
    expression = "memory", address, FP_TRANSFER_TYPES[source_raw[1]]
    return expression, (source.offset, store.offset, reload.offset)


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
    signatures = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind == "signature" and fact.subject
    }
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
    if tail.kind == "tb.statement" and tail.operands[:2] == (
        "RESUME_BARE", 0xBE
    ):
        return ()
    if tail.kind == "tb.statement" and tail.operands[:2] == (
        "RESUME_NEXT", 0xC0
    ):
        return ("NEXT",)
    if tail.kind in {"x86.jmp", "x86.jmp_far", "tb.run"} and tail.operands:
        target = tail.operands[0]
        return (target,) if isinstance(target, int) else None
    return None


def _delay_facts(
    instructions: dict[int, Operation], facts: frozenset[Fact]
) -> Iterable[Fact]:
    signatures = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind == "signature" and fact.subject
    }
    branches = {
        fact.subject[0]: fact
        for fact in facts
        if fact.kind == "flow.branch" and len(fact.subject) == 2
    }
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
    poll = signatures.get(begin_instruction.end) if begin_instruction else None
    poll_instruction = _statement_instruction(poll, "DELAY_POLL", instructions)
    commit = signatures.get(poll_instruction.end) if poll_instruction else None
    commit_instruction = _runtime_instruction(commit, 0x87, instructions)
    branch = branches.get(commit_instruction.end) if commit_instruction else None
    if branch is None or branch.value != ("<>", poll_instruction.offset):
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
        (value.evidence[0], branch.subject[1]),
        (resolved.value,),
        support,
        "anchored",
    )


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


STATEMENT_FACT_PASSES: tuple[NamedPass, ...] = (
    ("statements", statement_facts),
)
