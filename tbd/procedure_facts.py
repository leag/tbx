from __future__ import annotations

import struct
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import cast

from tbd.compiler_ops import CompilerOp, translate_operations
from tbd.facts import Evidence, NamedPass, fact_key, facts_by_kind, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import contiguous as _contiguous
from tbd.operation_helpers import runtime_call as _runtime
from tbd.semantic import (
    Resolved,
    combine_evidence,
    frame_slots,
    has_frame_word,
    resolve_array_element,
    resolve_expression,
    resolve_expression_before,
    resolve_slot,
    resolve_string,
)
from tbd.slots import is_slot, slot_name

_CALLS = {"x86.call", "x86.call_far"}
_JUMPS = {"x86.jmp", "x86.jmp_far"}


@dataclass(frozen=True)
class _Procedure:
    declaration: int
    entry: int
    end: int
    frame_pop: int
    evidence: tuple[int, ...]
    inline_body: tuple[int, int] | None = None


@dataclass(frozen=True)
class InlineProcedure:
    """Compiler-generated inline procedure region."""

    declaration: int
    entry: int
    body_end: int
    end: int
    evidence: tuple[int, ...]


@dataclass(frozen=True)
class _CallFrame:
    start: int
    arguments: tuple[object, ...]
    kinds: tuple[object, ...]
    evidence: tuple[int, ...]
    local_bytes: int = 0


@reads(
    "constant",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "flow.call",
    "layout.array",
    "reference.array_address",
    "reference.array_value",
    "reference.proc_array_address",
    "register.value",
    "semantic.call",
    "semantic.local",
    "semantic.sub_def",
    "signature",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.fwait",
    "tb.proc_enter",
    "tb.proc_return",
    "tb.runtime",
    "tb.statement",
    "x86.call",
    "x86.call_far",
    "x86.inc",
    "x86.into",
    "x86.j",
    "x86.je",
    "x86.jg",
    "x86.jge",
    "x86.jl",
    "x86.jle",
    "x86.jmp",
    "x86.jmp_far",
    "x86.jne",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def procedure_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover SUB, FUNCTION, CALL, and procedure parameter facts."""
    procedures = _procedures(evidence)
    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    instruction_indexes = {
        instruction.offset: index
        for index, instruction in enumerate(evidence.instructions)
    }
    flows = tuple(
        flow
        for flow in facts
        if flow.kind == "flow.call" and len(flow.subject) == 2 and flow.value
    )
    resolved_calls: dict[Fact, _CallFrame] = {}
    for procedure in procedures.values():
        if procedure.inline_body is not None:
            body_start, body_end = procedure.inline_body
            yield Fact(
                "semantic.inline",
                (body_start, body_end),
                (evidence.image[body_start:body_end].hex(),),
                procedure.evidence,
                "signature",
            )
        procedure_flows = tuple(
            flow for flow in flows if flow.value[0] == procedure.entry
        )
        frames = tuple(
            _call_frame(
                flow,
                procedure,
                evidence.instructions,
                instruction_indexes,
                facts,
            )
            for flow in procedure_flows
        )
        resolved_flow_frames = tuple(
            (flow, frame)
            for flow, frame in zip(procedure_flows, frames)
            if frame is not None
        )
        resolved = tuple(frame for _flow, frame in resolved_flow_frames)
        parameter_list = _parameters(procedure.frame_pop)
        recursive_unresolved = all(
            frame is not None
            or procedure.declaration <= flow.subject[0] < procedure.end
            for flow, frame in zip(procedure_flows, frames)
        )
        # A SUB has one signature, so call sites that cannot be walked fail on
        # an argument shape rather than on a different signature.  Each walk
        # consumes exactly the frame the procedure pops, so several sites
        # agreeing independently pin the layout even when others are unread.
        corroborated = len(resolved) > 1
        # One walk is enough when it accounts for the whole frame: the bytes it
        # read and the locals it names add up to what the procedure pops, so
        # there is nothing left for an unread site to disagree about.
        complete = any(
            _frame_bytes(frame.kinds) + frame.local_bytes == procedure.frame_pop
            for frame in resolved
        )
        if resolved and (
            len(resolved) == len(frames)
            or recursive_unresolved
            or corroborated
            or complete
        ):
            layouts = {(frame.kinds, frame.local_bytes) for frame in resolved}
            if len(layouts) == 1:
                kinds, _local_bytes = next(iter(layouts))
                # An $INLINE SUB is declared without parameters whatever
                # its callers push.
                if procedure.inline_body is None:
                    parameter_list = _resolved_parameters(procedure.entry, kinds)
                resolved_calls.update(resolved_flow_frames)
        body_support: tuple[int, ...] = ()
        if parameter_list == _parameters(procedure.frame_pop):
            body_layout = _body_parameter_layout(
                procedure,
                evidence.instructions,
                _forwarded_kinds(procedure.entry, facts),
            )
            if body_layout is not None:
                kinds, body_support = body_layout
                parameter_list = _resolved_parameters(procedure.entry, kinds)
        frame_resolved = parameter_list != _parameters(procedure.frame_pop)
        support = combine_evidence(
            procedure.evidence,
            body_support,
            *((frame.evidence for frame in resolved) if frame_resolved else ()),
        )
        yield Fact(
            "semantic.sub_def",
            (procedure.declaration, procedure.end),
            (procedure.entry, parameter_list),
            support,
            "anchored" if frame_resolved else "signature",
        )
        if parameter_list and parameter_list[0] != "unresolved-frame":
            yield from _parameter_body_facts(
                procedure, parameter_list, evidence.instructions, facts
            )
            yield from _array_parameter_body_facts(
                procedure, parameter_list, evidence.instructions, facts
            )
        # The local block is part of the same layout the callers agree on, so
        # it is believed on the same terms as the parameters above.  Naming it
        # is what lets a frame slot above the parameters resolve at all.
        if (
            resolved
            and (len(resolved) == len(frames) or corroborated)
            and parameter_list[:1] != ("unresolved-frame",)
            and len({frame.local_bytes for frame in resolved}) == 1
            and resolved[0].local_bytes > 0
        ):
            yield from _local_body_facts(
                procedure,
                parameter_list,
                resolved[0].local_bytes,
                evidence.instructions,
                facts,
            )
        elif body_support and parameter_list[:1] != ("unresolved-frame",):
            # A frame typed from the body splits at the block the entry
            # clears, which is exactly the locals.
            local_bytes = procedure.frame_pop - 4 * len(parameter_list)
            if local_bytes > 0:
                yield from _local_body_facts(
                    procedure,
                    parameter_list,
                    local_bytes,
                    evidence.instructions,
                    facts,
                )
        yield from _exit_sub_facts(procedure, evidence.instructions)
    for flow in flows:
        called_procedure = procedures.get(flow.value[0])
        instruction = instructions.get(flow.subject[0])
        if (
            called_procedure is None
            or instruction is None
            or instruction.kind not in _CALLS
        ):
            continue
        frame = resolved_calls.get(flow)
        arguments = (
            frame.arguments
            if frame is not None
            else _arguments(called_procedure.frame_pop)
        )
        start = frame.start if frame is not None else flow.subject[0]
        yield Fact(
            "semantic.call",
            (start, flow.subject[1]),
            (called_procedure.entry, arguments),
            combine_evidence(
                flow.evidence,
                called_procedure.evidence,
                () if frame is None else frame.evidence,
            ),
            "anchored" if frame is not None else "signature",
        )


def _overflow_trap(instructions: tuple[Operation, ...], cursor: int, start: int) -> int:
    """Return 1 when an overflow trap sits directly before ``cursor``."""
    if cursor < 2:
        return 0
    trap = instructions[cursor - 1]
    return 1 if trap.kind == "x86.into" and trap.end == start else 0


def _call_frame(
    flow: Fact,
    procedure: _Procedure,
    instructions: tuple[Operation, ...],
    indexes: dict[int, int],
    facts: frozenset[Fact],
) -> _CallFrame | None:
    frame_bytes = procedure.frame_pop
    released = _call_stack_release(flow.subject[1], instructions, indexes)
    if frame_bytes == 0 and procedure.inline_body is not None and released:
        # $INLINE code returns with a plain RETF, and the caller releases
        # the arguments it pushed.
        frame_bytes, released = released, 0
    if frame_bytes == 0:
        return _CallFrame(flow.subject[0], (), (), flow.evidence)
    cursor = indexes.get(flow.subject[0])
    if cursor is None:
        return None
    reversed_arguments = []
    reversed_kinds = []
    support = list(flow.evidence)
    start = flow.subject[0]
    remaining = frame_bytes
    local_bytes = 0
    if cursor >= 2 and _runtime(instructions[cursor - 1], 0x81):
        marker = instructions[cursor - 1]
        support.append(marker.offset)
        cursor -= 1
        start = marker.offset
    while remaining:
        if cursor > 0:
            # An overflow-checked build traps between the frame setup and the
            # arguments it precedes, so the allocation can sit one further back.
            trap = _overflow_trap(instructions, cursor, start)
            allocation = instructions[cursor - 1 - trap]
            allocated = _stack_allocation(allocation)
            if allocated is not None:
                if allocated != remaining + released:
                    return None
                local_bytes = remaining
                support.append(allocation.offset)
                if trap:
                    support.append(instructions[cursor - 1].offset)
                start = allocation.offset
                cursor -= 1 + trap
                remaining = 0
                break
        descriptor = _array_descriptor_call_argument(
            flow.subject[0], instructions, cursor, facts
        )
        if descriptor is not None and remaining >= 60:
            argument, kind, argument_start, argument_evidence, consumed = descriptor
            reversed_arguments.append(argument)
            reversed_kinds.append(kind)
            support.extend(argument_evidence)
            start = argument_start
            cursor -= consumed
            remaining -= 60
            continue
        if remaining < 4:
            return None
        if cursor < 2:
            return None
        # The last argument pushed is the parameter at [bp+6].
        displacement = 6 + frame_bytes - remaining
        direct = _direct_call_argument(
            procedure, instructions, cursor, facts, displacement
        )
        callee_kind = _resolved_parameter_kinds(procedure.entry, facts).get(
            displacement
        )
        local = _local_call_argument(
            procedure, flow.subject[0], instructions, cursor, facts, callee_kind
        )
        forwarded = _forwarded_call_argument(
            flow.subject[0], instructions, cursor, facts, callee_kind
        )
        temporary_string = _temporary_string_call_argument(instructions, cursor, facts)
        parameter_array_element = _array_parameter_element_call_argument(
            flow.subject[0], instructions, cursor, facts
        )
        array_element = _array_element_call_argument(instructions, cursor, facts)
        direct_array_element = _direct_array_element_call_argument(
            procedure, instructions, cursor, facts
        )
        integer_temporary = _integer_temporary_call_argument(
            instructions, cursor, facts
        )
        numeric_temporary = _numeric_temporary_call_argument(
            instructions, cursor, facts
        )
        match = (
            direct
            or local
            or forwarded
            or temporary_string
            or parameter_array_element
            or array_element
            or direct_array_element
            or integer_temporary
            or numeric_temporary
        )
        if match is None:
            # The scratch pointer is also cleared before a call that no marker
            # precedes.  An argument matcher that expects the clear consumes it
            # itself, so it is only skipped here once nothing else matched.
            clear = instructions[cursor - 1]
            if _runtime_pointer_clear(clear) and clear.end == start:
                support.append(clear.offset)
                start = clear.offset
                cursor -= 1
                continue
            return None
        argument, kind, argument_start, argument_evidence, consumed = match
        reversed_arguments.append(argument.value)
        reversed_kinds.append(kind)
        support.extend(argument_evidence)
        support.extend(argument.evidence)
        start = argument_start
        cursor -= consumed
        remaining -= 4
    if cursor > 0:
        allocation = instructions[cursor - 1]
        allocated = _stack_allocation(allocation)
        if allocated is not None and released:
            if allocated != released:
                return None
            support.append(allocation.offset)
            start = allocation.offset
    return _CallFrame(
        start,
        tuple(reversed(reversed_arguments)),
        tuple(reversed(reversed_kinds)),
        combine_evidence(tuple(support)),
        local_bytes,
    )


def _array_descriptor_call_argument(
    call_offset: int,
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
) -> tuple[object, object, int, tuple[int, ...], int] | None:
    end = cursor
    if end > 0 and _runtime_pointer_clear(instructions[end - 1]):
        end -= 1
    if end >= 2:
        load, copy = instructions[end - 2 : end]
        if (
            load.kind == "x86.mov_imm"
            and load.operands[:1] == ("si",)
            and len(load.operands) == 2
            and isinstance(load.operands[1], int)
            and _runtime(copy, 0xD4)
            and load.end == copy.offset
        ):
            layouts = [
                fact
                for fact in facts
                if fact.kind == "layout.array"
                and len(fact.subject) == 2
                and fact.subject[1] == load.operands[1]
                and len(fact.value) == 7
                and isinstance(fact.value[1], str)
                and isinstance(fact.value[2], tuple)
                and isinstance(fact.value[3], str)
            ]
            if len(layouts) == 1:
                layout = layouts[0]
                marker = ("array", layout.value[3], len(layout.value[2]))
                support = combine_evidence((load.offset, copy.offset), layout.evidence)
                return (
                    ("array", layout.value[1], ()),
                    marker,
                    load.offset,
                    support,
                    cursor - (end - 2),
                )
    if end < 7:
        return None
    set_ax, set_ds, load_bp, add_displacement, copy, restore_dx, restore_ds = (
        instructions[end - 7 : end]
    )
    add_raw = bytes.fromhex(add_displacement.raw)
    displacement = (
        add_raw[2] if len(add_raw) == 3 and add_raw[:2] == b"\x83\xc6" else None
    )
    if (
        bytes.fromhex(set_ax.raw) != b"\x8c\xd0"
        or bytes.fromhex(set_ds.raw) != b"\x8e\xd8"
        or bytes.fromhex(load_bp.raw) != b"\x8b\xf5"
        or displacement is None
        or not _runtime(copy, 0xD4)
        or restore_dx.kind != "x86.mov_imm"
        or restore_dx.operands[:1] != ("dx",)
        or bytes.fromhex(restore_ds.raw) != b"\x8e\xda"
        or not _contiguous(
            (set_ax, set_ds, load_bp, add_displacement, copy, restore_dx, restore_ds)
        )
    ):
        return None
    candidates = set()
    for fact in facts:
        if (
            fact.kind != "semantic.sub_def"
            or len(fact.subject) != 2
            or not all(isinstance(value, int) for value in fact.subject)
            or not fact.subject[0] <= call_offset < fact.subject[1]
            or len(fact.value) != 2
            or not isinstance(fact.value[1], tuple)
        ):
            continue
        for parameter in fact.value[1]:
            if (
                isinstance(parameter, tuple)
                and len(parameter) == 5
                and parameter[0] == "proc-array-param"
                and parameter[2] == displacement
                and isinstance(parameter[3], str)
                and isinstance(parameter[4], int)
            ):
                candidates.add(parameter)
    if len(candidates) != 1:
        return None
    parameter = next(iter(candidates))
    support = tuple(
        instruction.offset for instruction in instructions[end - 7 : cursor]
    )
    return (
        parameter,
        ("array", parameter[3], parameter[4]),
        set_ax.offset,
        support,
        cursor - (end - 7),
    )


def _direct_call_argument(
    procedure: _Procedure,
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
    displacement: int,
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    if cursor < 3:
        return None
    push_segment, load_address, push_offset = instructions[cursor - 3 : cursor]
    if (
        bytes.fromhex(push_segment.raw) != b"\x1e"
        or load_address.kind != "x86.mov_imm"
        or load_address.operands[:1] != ("ax",)
        or len(load_address.operands) != 2
        or not isinstance(load_address.operands[1], int)
        or bytes.fromhex(push_offset.raw) != b"\x50"
    ):
        return None
    address = load_address.operands[1]
    argument = resolve_slot(address, facts)
    kind = _slot_kind(address, facts)
    if argument is None or kind is None:
        kind = _single_parameter_kind(procedure, instructions) or _signature_kind(
            procedure.entry, displacement, facts
        )
        argument = resolve_array_element(address, facts) or (
            resolve_expression(("memory", address, kind), facts)
            if kind is not None
            else None
        )
        # A variable only ever passed by reference has no typed access to
        # name its slot; an integer can take the high half of a cell.
        half = kind == "integer" and is_slot(address - 2)
        if argument is None and kind is not None and (is_slot(address) or half):
            name = f"{slot_name(address - 2)}H" if half else slot_name(address)
            argument = Resolved(
                ("slot", name, address, kind),
                (load_address.offset,),
            )
    if argument is None or kind is None:
        return None
    if (
        isinstance(argument.value, tuple)
        and len(argument.value) >= 3
        and argument.value[0] == "slot"
    ):
        argument = Resolved(
            argument.value[:3] + (kind,),
            argument.evidence,
            argument.start,
        )
    return (
        argument,
        kind,
        push_segment.offset,
        (push_segment.offset, load_address.offset, push_offset.offset),
        3,
    )


def _signature_kind(
    entry: int, displacement: int, facts: frozenset[Fact]
) -> str | None:
    """Return the one kind the resolved signatures give a parameter."""
    kinds = {
        parameter[3]
        for fact in facts
        if fact.kind == "semantic.sub_def"
        and fact.value[0] == entry
        and isinstance(fact.value[1], tuple)
        for parameter in fact.value[1]
        if isinstance(parameter, tuple)
        and parameter[:1] == ("proc-param",)
        and parameter[2] == displacement
    }
    return next(iter(kinds)) if len(kinds) == 1 else None


def _local_call_argument(
    procedure: _Procedure,
    call_offset: int,
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
    callee_kind: str | None = None,
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    """Read a local of the calling procedure passed by reference.

    An untyped local takes the kind the callee's signature gives this
    argument, or the one kind all the callee's parameters have.
    """
    if cursor < 4:
        return None
    push_offset = instructions[cursor - 1]
    # Adding the frame base is arithmetic, so an overflow-checked build traps
    # between it and the push that hands the address over.
    trap = _overflow_trap(instructions, cursor - 1, push_offset.offset)
    if cursor < 4 + trap:
        return None
    push_segment, load_displacement, add_base = instructions[
        cursor - 4 - trap : cursor - 1 - trap
    ]
    if (
        bytes.fromhex(push_segment.raw) != b"\x16"
        or load_displacement.kind != "x86.mov_imm"
        or load_displacement.operands[:1] != ("ax",)
        or len(load_displacement.operands) != 2
        or not isinstance(load_displacement.operands[1], int)
        or bytes.fromhex(add_base.raw) != b"\x03\xc5"
        or bytes.fromhex(push_offset.raw) != b"\x50"
        or not _contiguous(instructions[cursor - 4 - trap : cursor])
    ):
        return None
    displacement = load_displacement.operands[1]
    candidates = set()
    for fact in facts:
        if fact.kind != "semantic.local" or len(fact.value) != 1:
            continue
        for local in fact.value[0]:
            if (
                isinstance(local, tuple)
                and len(local) == 4
                and local[0] == "proc-local"
                and isinstance(local[1], int)
                and local[2] == displacement
                and isinstance(local[3], str)
                and _procedure_contains(local[1], call_offset, facts)
            ):
                candidates.add(local)
    if not candidates:
        kind = callee_kind or _single_parameter_kind_for_call(procedure, instructions)
        owners = _containing_procedure_entries(call_offset, facts)
        if kind is None or len(owners) != 1:
            return None
        local = ("proc-local", next(iter(owners)), displacement, kind)
    elif len(candidates) == 1:
        local = next(iter(candidates))
    else:
        return None
    evidence = tuple(
        operation.offset for operation in instructions[cursor - 4 - trap : cursor]
    )
    return (
        Resolved(local, evidence),
        local[3],
        push_segment.offset,
        evidence,
        4 + trap,
    )


def _procedure_contains(entry: int, offset: int, facts: frozenset[Fact]) -> bool:
    return entry in _containing_procedure_entries(offset, facts)


def _containing_procedure_entries(offset: int, facts: frozenset[Fact]) -> set[int]:
    return {
        fact.value[0]
        for fact in facts
        if fact.kind == "semantic.sub_def"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
        and fact.subject[0] <= offset < fact.subject[1]
        and len(fact.value) == 2
        and isinstance(fact.value[0], int)
    }


def _single_parameter_kind_for_call(
    procedure: _Procedure, instructions: tuple[Operation, ...]
) -> str | None:
    kind = _single_parameter_kind(procedure, instructions)
    if kind is not None:
        return kind
    body = tuple(
        instruction
        for instruction in instructions
        if procedure.entry < instruction.offset < procedure.end
    )
    if _parameter_bytes(procedure, body) != 4:
        return None
    is_string = any(
        _les_si_bp_displacement(instruction) == 6
        and terminal.kind == "tb.runtime"
        and terminal.operands in {(0x9D,), (0xA1,)}
        for instruction, terminal in zip(body, body[1:])
    )
    return "string" if is_string else None


def _body_parameter_layout(
    procedure: _Procedure,
    instructions: tuple[Operation, ...],
    forwarded: Mapping[int, str] | None = None,
) -> tuple[tuple[object, ...], tuple[int, ...]] | None:
    """Use an explicitly typed dereference to identify a complete scalar frame."""
    if procedure.inline_body is not None:
        return None
    body = tuple(
        op for op in instructions if procedure.entry <= op.offset < procedure.end
    )
    if not body or not _contiguous(body):
        return None
    kinds = _body_parameter_kinds(procedure, body, forwarded)
    if kinds is None:
        return None
    return kinds, tuple(op.offset for op in body)


def _parameter_bytes(procedure: _Procedure, body: tuple[Operation, ...]) -> int | None:
    """Return how many frame bytes hold parameters rather than locals.

    A procedure with locals clears them on entry, and the cleared block names
    both where the locals start and how many bytes they occupy.  The split is
    only believed when the two regions together account for the frame the
    procedure pops.
    """
    if len(body) < 12:
        return procedure.frame_pop
    raws = tuple(bytes.fromhex(instruction.raw) for instruction in body[:12])
    if (
        raws[0] != b"\x51"
        or raws[1] != b"\x57"
        or raws[2] != b"\x8c\xd0"
        or raws[3] != b"\x8e\xc0"
        or len(raws[4]) != 3
        or raws[4][0] != 0xB9
        or len(raws[5]) != 4
        or raws[5][:2] != b"\x8d\xbe"
        or raws[6:] != (b"\x31\xc0", b"\xfc", b"\xf3", b"\xab", b"\x5f", b"\x59")
        or not _contiguous(body[:12])
    ):
        return procedure.frame_pop
    local_bytes = 2 * struct.unpack_from("<H", raws[4], 1)[0]
    local_start = struct.unpack_from("<h", raws[5], 2)[0]
    parameter_bytes = local_start - 6
    if (
        parameter_bytes < 0
        or parameter_bytes % 4
        or parameter_bytes + local_bytes != procedure.frame_pop
    ):
        return None
    return parameter_bytes


def _single_parameter_kind(
    procedure: _Procedure, instructions: tuple[Operation, ...]
) -> str | None:
    kinds = _body_parameter_kinds(procedure, instructions)
    return kinds[0] if kinds is not None and len(kinds) == 1 else None


def _body_parameter_kinds(
    procedure: _Procedure,
    instructions: tuple[Operation, ...],
    forwarded: Mapping[int, str] | None = None,
) -> tuple[str, ...] | None:
    """Type every parameter of a procedure from how its body uses it.

    The parameters fill the frame below the locals; each is a far pointer
    the body dereferences in a way that names its type. The kinds are in
    CALL order, the first argument deepest in the frame, and are known only
    when every parameter has exactly one.
    """
    body = tuple(
        instruction
        for instruction in instructions
        if procedure.entry < instruction.offset < procedure.end
    )
    parameter_bytes = _parameter_bytes(procedure, body)
    if not parameter_bytes:
        return None
    count = parameter_bytes // 4
    # A parameter the body only passes on takes the kind its call gives it.
    kinds = tuple(
        _parameter_kind_at(body, displacement) or (forwarded or {}).get(displacement)
        for displacement in (
            6 + 4 * (count - 1 - position) for position in range(count)
        )
    )
    if any(kind is None for kind in kinds):
        return None
    return cast(tuple[str, ...], kinds)


def _parameter_kind_at(body: tuple[Operation, ...], displacement: int) -> str | None:
    """Return the one kind the body's uses give the parameter at [bp+n]."""
    compiler_operations = {
        operation.offset: operation for operation in translate_operations(body)
    }
    operation_kinds = {
        operation_kind: kind
        for actions in _PARAMETER_OPERATIONS.values()
        for kind, operation_kind in actions.items()
    }
    kinds = set()
    for instruction, terminal in zip(body, body[1:]):
        if _les_si_bp_displacement(instruction) != displacement:
            continue
        raw = bytes.fromhex(terminal.raw)
        operation = compiler_operations.get(terminal.offset)
        kind = operation_kinds.get(operation.kind) if operation is not None else None
        kind = _pointer_access_kind(raw) or kind
        if terminal.kind == "tb.runtime" and terminal.operands in {(0x9D,), (0xA1,)}:
            kind = "string"
        if kind is not None:
            kinds.add(kind)
    return next(iter(kinds)) if len(kinds) == 1 else None


# Word operations whose memory operand is ``es:[si]`` (ModRM mod 0, r/m 4):
# the ALU group, MOV, and the F7/FF groups (IMUL, INC, DEC and the rest).
_WORD_OPCODES = {0x01, 0x03, 0x09, 0x0B, 0x21, 0x23, 0x29, 0x2B, 0x31, 0x33}
_WORD_OPCODES |= {0x39, 0x3B, 0x89, 0x8B, 0xC7, 0xF7, 0xFF}
# The type an x87 escape's memory operand has, by the registers of the ModRM
# that address one (arithmetic uses all eight; loads and stores 0, 2, 3).
_X87_OPERANDS = {
    0xD8: ("float", range(8)),
    0xD9: ("float", (0, 2, 3)),
    0xDA: ("long", range(8)),
    0xDB: ("long", (0, 2, 3)),
    0xDC: ("double", range(8)),
    0xDD: ("double", (0, 2, 3)),
    0xDE: ("integer", range(8)),
    0xDF: ("integer", (0, 2, 3)),
}


def _pointer_access_kind(raw: bytes) -> str | None:
    """Return the type an instruction accesses through the pointer in ES:SI.

    A word operation is an integer's. A far FP operation (``cd 3c esc
    modrm``) names its operand's type with its x87 escape.
    """
    if len(raw) >= 3 and raw[0] == 0x26 and raw[2] & 0xC7 == 0x04:
        return "integer" if raw[1] in _WORD_OPCODES else None
    if len(raw) >= 4 and raw[:2] == b"\xcd\x3c" and raw[3] & 0xC7 == 0x04:
        kind, registers = _X87_OPERANDS.get(raw[2], (None, ()))
        return kind if (raw[3] >> 3) & 7 in registers else None
    return None


def _forwarded_call_argument(
    call_offset: int,
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
    callee_kind: str | None = None,
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    """Read a parameter of the calling procedure passed on as it came.

    ``push [bp+d+2]; push [bp+d]`` pushes the far pointer the caller was
    given. When the caller's frame is not resolved yet, the parameter takes
    the kind the callee's signature gives this argument, which is how the
    caller's own frame gets typed for a parameter it only passes on.
    """
    push_segment, push_offset = instructions[cursor - 2 : cursor]
    segment_displacement = _push_bp_displacement(push_segment)
    offset_displacement = _push_bp_displacement(push_offset)
    if (
        segment_displacement is None
        or offset_displacement is None
        or segment_displacement != offset_displacement + 2
    ):
        return None
    candidates = []
    for fact in facts:
        if (
            fact.kind != "semantic.sub_def"
            or len(fact.subject) != 2
            or not all(isinstance(value, int) for value in fact.subject)
            or not fact.subject[0] <= call_offset < fact.subject[1]
            or len(fact.value) != 2
            or not isinstance(fact.value[1], tuple)
        ):
            continue
        for parameter in fact.value[1]:
            if (
                isinstance(parameter, tuple)
                and len(parameter) == 4
                and parameter[0] == "proc-param"
                and parameter[2] == offset_displacement
                and isinstance(parameter[3], str)
            ):
                candidates.append(parameter)
    if not candidates and callee_kind is not None:
        callers = {
            fact.value[0]
            for fact in facts_by_kind(facts).get("semantic.sub_def", ())
            if len(fact.subject) == 2
            and all(isinstance(value, int) for value in fact.subject)
            and fact.subject[0] <= call_offset < fact.subject[1]
            and fact.value[1][:1] == ("unresolved-frame",)
        }
        if len(callers) == 1:
            candidates = [
                ("proc-param", next(iter(callers)), offset_displacement, callee_kind)
            ]
    if len(set(candidates)) != 1:
        return None
    parameter = candidates[0]
    evidence = (push_segment.offset, push_offset.offset)
    return (
        Resolved(parameter, evidence),
        parameter[3],
        push_segment.offset,
        evidence,
        2,
    )


def _resolved_parameter_kinds(entry: int, facts: frozenset[Fact]) -> dict[int, str]:
    """Return the kind of each parameter of a procedure with a known signature."""
    kinds: dict[int, set[str]] = {}
    for fact in facts_by_kind(facts).get("semantic.sub_def", ()):
        if len(fact.value) != 2 or fact.value[0] != entry:
            continue
        for parameter in fact.value[1] if isinstance(fact.value[1], tuple) else ():
            if (
                isinstance(parameter, tuple)
                and len(parameter) == 4
                and parameter[0] == "proc-param"
                and isinstance(parameter[2], int)
                and isinstance(parameter[3], str)
            ):
                kinds.setdefault(parameter[2], set()).add(parameter[3])
    return {d: next(iter(found)) for d, found in kinds.items() if len(found) == 1}


def _forwarded_kinds(entry: int, facts: frozenset[Fact]) -> dict[int, str]:
    """Return the kind each call in a procedure passes one of its parameters as."""
    kinds: dict[int, set[str]] = {}
    for fact in facts_by_kind(facts).get("semantic.call", ()):
        arguments = fact.value[1] if len(fact.value) == 2 else ()
        for argument in arguments if isinstance(arguments, tuple) else ():
            if (
                isinstance(argument, tuple)
                and len(argument) == 4
                and argument[:2] == ("proc-param", entry)
                and isinstance(argument[2], int)
                and isinstance(argument[3], str)
            ):
                kinds.setdefault(argument[2], set()).add(argument[3])
    return {d: next(iter(found)) for d, found in kinds.items() if len(found) == 1}


def _temporary_string_call_argument(
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    end = cursor
    if end > 0 and _runtime_pointer_clear(instructions[end - 1]):
        end -= 1
    if end >= 5:
        (
            load_displacement,
            address_temporary,
            assign_temporary,
            push_segment,
            push_offset,
        ) = instructions[end - 5 : end]
        sources = [
            fact
            for fact in facts
            if fact.kind == "expression.string_operand"
            and len(fact.subject) == 2
            and isinstance(fact.subject[0], int)
            and fact.subject[1] == load_displacement.offset
            and len(fact.value) == 1
        ]
        indexes = {
            instruction.offset: index for index, instruction in enumerate(instructions)
        }
        if (
            len(sources) == 1
            and sources[0].subject[0] in indexes
            and load_displacement.kind == "x86.mov_imm"
            and load_displacement.operands[:1] == ("si",)
            and len(load_displacement.operands) == 2
            and isinstance(load_displacement.operands[1], int)
            and bytes.fromhex(address_temporary.raw) == b"\x01\xe6"
            and _runtime(assign_temporary, 0xA3)
            and bytes.fromhex(push_segment.raw) == b"\x16"
            and bytes.fromhex(push_offset.raw) == b"\x56"
        ):
            source = sources[0]
            start = indexes[source.subject[0]]
            coverage_start = start
            if start > 0 and _stack_allocation(instructions[start - 1]) is not None:
                coverage_start -= 1
            window = instructions[coverage_start:cursor]
            if _contiguous(window):
                evidence = combine_evidence(
                    source.evidence,
                    tuple(instruction.offset for instruction in window),
                )
                return (
                    Resolved(source.value[0], evidence, source.subject[0]),
                    "string",
                    window[0].offset,
                    evidence,
                    cursor - start,
                )
    if cursor < 9:
        return None
    window = instructions[cursor - 9 : cursor]
    (
        allocation,
        load_string,
        push_string,
        load_displacement,
        address_temporary,
        assign_temporary,
        push_segment,
        push_offset,
        clear_runtime_pointer,
    ) = window
    clear_raw = bytes.fromhex(clear_runtime_pointer.raw)
    if (
        _stack_allocation(allocation) != 4
        or load_string.kind != "x86.mov_imm"
        or load_string.operands[:1] != ("si",)
        or len(load_string.operands) != 2
        or not isinstance(load_string.operands[1], int)
        or push_string.kind != "tb.runtime"
        or push_string.operands != (0x9C,)
        or load_displacement.kind != "x86.mov_imm"
        or load_displacement.operands != ("si", 0)
        or bytes.fromhex(address_temporary.raw) != b"\x01\xe6"
        or assign_temporary.kind != "tb.runtime"
        or assign_temporary.operands != (0xA3,)
        or bytes.fromhex(push_segment.raw) != b"\x16"
        or bytes.fromhex(push_offset.raw) != b"\x56"
        or len(clear_raw) != 6
        or clear_raw[:2] != b"\xc7\x06"
        or clear_raw[4:] != b"\x00\x00"
        or not _contiguous(window)
    ):
        return None
    string = resolve_string(load_string.operands[1], facts)
    if string is None:
        return None
    support = combine_evidence(
        tuple(instruction.offset for instruction in window),
        string.evidence,
    )
    return string, "string", allocation.offset, support, len(window)


def _array_element_call_argument(
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    if cursor < 4:
        return None
    load_segment, set_segment, push_segment, push_offset = instructions[
        cursor - 4 : cursor
    ]
    if (
        load_segment.kind != "x86.mov_imm"
        or load_segment.operands[:1] != ("dx",)
        or len(load_segment.operands) != 2
        or bytes.fromhex(set_segment.raw) != b"\x8e\xc2"
        or bytes.fromhex(push_segment.raw) != b"\x06"
        or bytes.fromhex(push_offset.raw) != b"\x56"
        or not _contiguous((load_segment, set_segment, push_segment, push_offset))
    ):
        return None
    addresses = [
        fact
        for fact in facts
        if fact.kind == "reference.array_address"
        and len(fact.subject) == 2
        and fact.subject[1] == load_segment.offset
        and len(fact.value) == 4
        and fact.value[1] in {"integer", "long", "float", "double", "string"}
        and isinstance(fact.subject[0], int)
    ]
    if len(addresses) != 1:
        return None
    address = addresses[0]
    support = combine_evidence(
        address.evidence,
        (
            load_segment.offset,
            set_segment.offset,
            push_segment.offset,
            push_offset.offset,
        ),
    )
    return (
        Resolved(address.value[0], address.evidence, address.subject[0]),
        address.value[1],
        address.subject[0],
        support,
        4,
    )


def _array_parameter_element_call_argument(
    call_offset: int,
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    end = cursor
    if end > 0 and _runtime_pointer_clear(instructions[end - 1]):
        end -= 1
    if (
        end >= 2
        and bytes.fromhex(instructions[end - 2].raw) == b"\x06"
        and bytes.fromhex(instructions[end - 1].raw) == b"\x56"
    ):
        push_segment, push_offset = instructions[end - 2 : end]
        references = [
            fact
            for fact in facts
            if fact.kind == "reference.proc_array_address"
            and len(fact.subject) == 2
            and fact.subject[1] == push_segment.offset
            and len(fact.value) == 2
            and isinstance(fact.subject[0], int)
            and isinstance(fact.value[1], str)
        ]
        indexes = {
            instruction.offset: index for index, instruction in enumerate(instructions)
        }
        if len(references) == 1 and references[0].subject[0] in indexes:
            reference = references[0]
            start = indexes[reference.subject[0]]
            window = instructions[start:cursor]
            if _contiguous(window):
                evidence = combine_evidence(
                    reference.evidence,
                    (push_segment.offset, push_offset.offset),
                )
                return (
                    Resolved(reference.value[0], evidence, reference.subject[0]),
                    reference.value[1],
                    reference.subject[0],
                    evidence,
                    len(window),
                )
    if cursor < 9 or not _runtime_pointer_clear(instructions[cursor - 1]):
        return None
    window = instructions[cursor - 9 : cursor]
    (
        load_index,
        subtract_bound,
        set_offset,
        scale_low,
        scale_high,
        set_segment,
        push_segment,
        push_offset,
        _clear,
    ) = window
    load_operations = translate_operations((load_index,))
    load_operation = load_operations[0] if load_operations else None
    subtract_raw = bytes.fromhex(subtract_bound.raw)
    segment_raw = bytes.fromhex(set_segment.raw)
    if (
        load_operation is None
        or load_operation.kind != "movax_m"
        or len(load_operation.args) != 1
        or not isinstance(load_operation.args[0], int)
        or len(subtract_raw) != 3
        or subtract_raw[:2] != b"\x2b\x46"
        or bytes.fromhex(set_offset.raw) != b"\x89\xc6"
        or bytes.fromhex(scale_low.raw) != b"\xd1\xe6"
        or bytes.fromhex(scale_high.raw) != b"\xd1\xe6"
        or len(segment_raw) != 3
        or segment_raw[:2] != b"\x8e\x46"
        or bytes.fromhex(push_segment.raw) != b"\x06"
        or bytes.fromhex(push_offset.raw) != b"\x56"
        or not _contiguous(window)
    ):
        return None
    descriptor_displacement = segment_raw[2]
    if subtract_raw[2] != descriptor_displacement + 8:
        return None
    index = resolve_expression(("memory", load_operation.args[0], "integer"), facts)
    if index is None:
        return None
    candidates = set()
    for fact in facts:
        if (
            fact.kind != "semantic.sub_def"
            or len(fact.subject) != 2
            or not all(isinstance(value, int) for value in fact.subject)
            or not fact.subject[0] <= call_offset < fact.subject[1]
            or len(fact.value) != 2
            or not isinstance(fact.value[1], tuple)
        ):
            continue
        for parameter in fact.value[1]:
            if (
                isinstance(parameter, tuple)
                and len(parameter) == 5
                and parameter[0] == "proc-array-param"
                and parameter[2] == descriptor_displacement
            ):
                candidates.add(parameter)
    if len(candidates) != 1:
        return None
    parameter = next(iter(candidates))
    argument = (
        "proc-array-element",
        parameter[1],
        parameter[2],
        parameter[3],
        parameter[4],
        (index.value,),
    )
    evidence = combine_evidence(
        tuple(instruction.offset for instruction in window), index.evidence
    )
    return (
        Resolved(argument, evidence, load_index.offset),
        parameter[3],
        load_index.offset,
        evidence,
        len(window),
    )


def _direct_array_element_call_argument(
    procedure: _Procedure,
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    if cursor < 5:
        return None
    load_offset, load_segment, set_segment, push_segment, push_offset = instructions[
        cursor - 5 : cursor
    ]
    if (
        load_offset.kind != "x86.mov_imm"
        or load_offset.operands[:1] != ("si",)
        or len(load_offset.operands) != 2
        or not isinstance(load_offset.operands[1], int)
        or load_segment.kind != "x86.mov_imm"
        or load_segment.operands[:1] != ("dx",)
        or bytes.fromhex(set_segment.raw) != b"\x8e\xc2"
        or bytes.fromhex(push_segment.raw) != b"\x06"
        or bytes.fromhex(push_offset.raw) != b"\x56"
        or not _contiguous(
            (load_offset, load_segment, set_segment, push_segment, push_offset)
        )
    ):
        return None
    argument = resolve_array_element(load_offset.operands[1], facts)
    kind = _single_parameter_kind(procedure, instructions)
    if argument is None or kind is None:
        return None
    support = combine_evidence(
        argument.evidence,
        tuple(instruction.offset for instruction in instructions[cursor - 5 : cursor]),
    )
    return argument, kind, load_offset.offset, support, 5


def _numeric_temporary_call_argument(
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    if cursor < 4:
        return None
    end = cursor
    if end >= 2 and _runtime(instructions[end - 1], 0x87):
        clear_raw = bytes.fromhex(instructions[end - 2].raw)
        if (
            len(clear_raw) != 6
            or clear_raw[:2] != b"\xc7\x06"
            or clear_raw[4:] != b"\x00\x00"
        ):
            return None
        end -= 2
    if end < 4:
        return None
    push_segment, push_offset = instructions[end - 2 : end]
    store = instructions[end - 3]
    stores = {
        "far_fistp_si": "integer",
        "far_fistp_si32": "long",
        "far_fstp_si": "float",
        "far_fstp_si64": "double",
    }
    translated_store = translate_operations((store,))
    kind = stores.get(translated_store[0].kind) if translated_store else None
    if (
        kind is None
        or bytes.fromhex(push_segment.raw) != b"\x16"
        or bytes.fromhex(push_offset.raw) != b"\x56"
    ):
        return None
    address_start = end - 4
    if bytes.fromhex(instructions[address_start].raw) != b"\x89\xe6" and (
        address_start > 0
        and instructions[address_start - 1].kind == "x86.mov_imm"
        and instructions[address_start - 1].operands[:1] == ("si",)
        and len(instructions[address_start - 1].operands) == 2
        and isinstance(instructions[address_start - 1].operands[1], int)
        and bytes.fromhex(instructions[address_start].raw) == b"\x01\xe6"
    ):
        address_start -= 1
    elif bytes.fromhex(instructions[address_start].raw) != b"\x89\xe6":
        return None
    source_match = _numeric_source_before(
        instructions[address_start].offset, instructions, address_start, facts
    )
    if source_match is None:
        return None
    source, start = source_match
    coverage_start = start
    if start > 0 and _stack_allocation(instructions[start - 1]) is not None:
        coverage_start -= 1
    window = instructions[coverage_start:cursor]
    if not _contiguous(window):
        return None
    support = combine_evidence(
        source.evidence,
        tuple(instruction.offset for instruction in window),
    )
    return source, kind, window[0].offset, support, cursor - start


def _integer_temporary_call_argument(
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
) -> tuple[Resolved, str, int, tuple[int, ...], int] | None:
    if cursor < 5:
        return None
    end = cursor
    if _runtime_pointer_clear(instructions[end - 1]):
        end -= 1
    if end < 5:
        return None
    push_segment, push_offset = instructions[end - 2 : end]
    store = instructions[end - 3]
    address_start = end - 4
    if bytes.fromhex(instructions[address_start].raw) != b"\x89\xe6" and (
        address_start > 0
        and instructions[address_start - 1].kind == "x86.mov_imm"
        and instructions[address_start - 1].operands[:1] == ("si",)
        and len(instructions[address_start - 1].operands) == 2
        and isinstance(instructions[address_start - 1].operands[1], int)
        and bytes.fromhex(instructions[address_start].raw) == b"\x01\xe6"
    ):
        address_start -= 1
    elif bytes.fromhex(instructions[address_start].raw) != b"\x89\xe6":
        return None
    if address_start == 0:
        return None
    load = instructions[address_start - 1]
    source = None
    start = address_start - 1
    if (
        load.kind == "x86.mov_imm"
        and load.operands[:1] == ("ax",)
        and len(load.operands) == 2
        and isinstance(load.operands[1], int)
    ):
        source = Resolved(("const", load.operands[1]), (load.offset,), load.offset)
    elif bytes.fromhex(load.raw) == b"\x31\xc0":
        # The compiler loads a zero argument with ``xor ax,ax`` rather than a
        # move, which the constant above does not cover.
        source = Resolved(("const", 0), (load.offset,), load.offset)
    else:
        source = resolve_expression_before(
            instructions[address_start].offset,
            facts,
            {instruction.offset: instruction.end for instruction in instructions},
        )
        indexes = {
            instruction.offset: index for index, instruction in enumerate(instructions)
        }
        if source is not None and source.start in indexes:
            start = indexes[source.start]
        else:
            source = None
    if source is None:
        return None
    coverage_start = start
    if start > 0 and _stack_allocation(instructions[start - 1]) is not None:
        coverage_start -= 1
    window = instructions[coverage_start:cursor]
    if (
        bytes.fromhex(store.raw) != b"\x36\x89\x04"
        or bytes.fromhex(push_segment.raw) != b"\x16"
        or bytes.fromhex(push_offset.raw) != b"\x56"
        or not _contiguous(window)
    ):
        return None
    evidence = combine_evidence(
        source.evidence,
        tuple(instruction.offset for instruction in window),
    )
    return (
        Resolved(source.value, evidence, source.start),
        "integer",
        window[0].offset,
        evidence,
        cursor - start,
    )


def _runtime_pointer_clear(instruction: Operation) -> bool:
    raw = bytes.fromhex(instruction.raw)
    return len(raw) == 6 and raw[:2] == b"\xc7\x06" and raw[4:] == b"\x00\x00"


def _numeric_source_before(
    offset: int,
    instructions: tuple[Operation, ...],
    cursor: int,
    facts: frozenset[Fact],
) -> tuple[Resolved, int] | None:
    if cursor == 0:
        return None
    translated = translate_operations((instructions[cursor - 1],))
    direct = translated[0] if translated else None
    source = _direct_numeric_source(direct, facts)
    if source is not None:
        return source, cursor - 1
    indexes = {
        instruction.offset: index for index, instruction in enumerate(instructions)
    }
    candidates = []
    for fact in facts:
        if (
            fact.kind != "expression.value"
            or len(fact.subject) != 1
            or not isinstance(fact.subject[0], int)
            or len(fact.value) != 1
            or instructions[cursor - 1].offset not in fact.evidence
        ):
            continue
        start = indexes.get(fact.subject[0])
        if start is None or not start < cursor:
            continue
        source_instructions = instructions[start:cursor]
        if source_instructions[-1].end == offset and _contiguous(source_instructions):
            resolved = resolve_expression(fact.value[0], facts)
            if resolved is None:
                continue
            candidates.append(
                (
                    Resolved(
                        resolved.value,
                        combine_evidence(fact.evidence, resolved.evidence),
                        fact.subject[0],
                    ),
                    start,
                )
            )
    return candidates[0] if len(candidates) == 1 else None


def _slot_kind(address: int, facts: frozenset[Fact]) -> str | None:
    candidates = [
        fact
        for fact in facts
        if fact.kind == "slot"
        and fact.subject == (address,)
        and len(fact.value) >= 2
        and isinstance(fact.value[1], tuple)
        and len(fact.value[1]) == 1
        and fact.value[1][0] in {"integer", "long", "float", "double", "string"}
    ]
    return candidates[0].value[1][0] if len(candidates) == 1 else None


def _exit_sub_facts(
    procedure: _Procedure, instructions: tuple[Operation, ...]
) -> Iterable[Fact]:
    # A SUB with no frame ends in a bare ``retf`` rather than the framed
    # return; a jump to either leaves the SUB.
    returns = [
        instruction
        for instruction in instructions
        if instruction.kind in {"tb.proc_return", "x86.retf"}
        and procedure.entry < instruction.offset
        and instruction.end == procedure.end
    ]
    if len(returns) != 1:
        return
    target = returns[0].offset
    # The compiler stamps event-trap polls (int3) before the return, and a
    # jump to one of them leaves the SUB just the same.
    targets = {target}
    by_end = {instruction.end: instruction for instruction in instructions}
    hook = by_end.get(target)
    while hook is not None and hook.kind == "x86.int3":
        targets.add(hook.offset)
        hook = by_end.get(hook.offset)
    # Before it returns, the SUB releases its string locals
    # (``les si,[bp+d]``, then the runtime's release); a jump to the first
    # release is the same exit.
    release = by_end.get(min(targets))
    while (
        release is not None
        and _runtime(release, 0xD3)
        and (pointer := by_end.get(release.offset)) is not None
        and bytes.fromhex(pointer.raw)[:2] in {b"\xc4\x76", b"\xc4\xb6"}
    ):
        targets.add(pointer.offset)
        release = by_end.get(pointer.offset)
    for instruction in instructions:
        if (
            procedure.entry < instruction.offset < target
            and instruction.kind in _JUMPS
            and len(instruction.operands) == 1
            and instruction.operands[0] in targets
        ):
            yield Fact(
                "semantic.exit_sub",
                (instruction.offset, instruction.end),
                (),
                (instruction.offset, instruction.operands[0]),
                "anchored",
            )


def _frame_bytes(kinds: tuple[object, ...]) -> int:
    """Return the frame space the parameters of this layout occupy."""

    return sum(60 if _array_parameter_kind(kind) else 4 for kind in kinds)


def _resolved_parameters(entry: int, kinds: tuple[object, ...]) -> tuple[object, ...]:
    sizes = tuple(60 if _array_parameter_kind(kind) else 4 for kind in kinds)
    parameters: list[object] = []
    for index, kind in enumerate(kinds):
        displacement = 6 + sum(sizes[index + 1 :])
        if _array_parameter_kind(kind):
            array_kind = cast(tuple[object, object, object], kind)
            parameters.append(
                ("proc-array-param", entry, displacement, array_kind[1], array_kind[2])
            )
        else:
            parameters.append(("proc-param", entry, displacement, kind))
    return tuple(parameters)


def _array_parameter_kind(kind: object) -> bool:
    return (
        isinstance(kind, tuple)
        and len(kind) == 3
        and kind[0] == "array"
        and isinstance(kind[1], str)
        and isinstance(kind[2], int)
    )


def _parameter_body_facts(
    procedure: _Procedure,
    parameters: tuple[object, ...],
    instructions: tuple[Operation, ...],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    by_displacement = {
        parameter[2]: parameter
        for parameter in parameters
        if isinstance(parameter, tuple)
        and len(parameter) == 4
        and parameter[0] == "proc-param"
        and isinstance(parameter[2], int)
    }
    body = tuple(
        instruction
        for instruction in instructions
        if procedure.entry < instruction.offset < procedure.end
    )
    compiler_operations = {
        operation.offset: operation for operation in translate_operations(body)
    }
    for index, instruction in enumerate(body):
        displacement = _les_si_bp_displacement(instruction)
        if displacement is None:
            continue
        parameter = by_displacement.get(displacement)
        if parameter is None or index + 1 >= len(body):
            continue
        terminal = body[index + 1]
        raw = bytes.fromhex(terminal.raw)
        terminal_operation = compiler_operations.get(terminal.offset)
        if parameter[3] == "integer" and len(raw) == 5 and raw[:3] == b"\x26\xc7\x04":
            # ``mov word es:[si],n``: a constant stored through the pointer.
            yield Fact(
                "semantic.assign",
                (instruction.offset, terminal.end),
                (parameter, ("const", int.from_bytes(raw[3:], "little", signed=True))),
                (instruction.offset, terminal.offset),
                "anchored",
            )
        if raw in {b"\x26\xff\x04", b"\x26\xff\x0c"}:
            name = "INCR" if raw[-1] == 0x04 else "DECR"
            yield Fact(
                "semantic.statement",
                (instruction.offset, terminal.end),
                (name, -1, parameter),
                (instruction.offset, terminal.offset),
                "anchored",
            )
        if (
            raw == b"\x26\x8b\x04"
            or _parameter_operation_matches(terminal_operation, parameter[3], "load")
            or (
                parameter[3] == "string"
                and terminal.kind == "tb.runtime"
                and terminal.operands == (0x9D,)
            )
        ):
            yield Fact(
                "expression.value",
                (instruction.offset,),
                (parameter,),
                (instruction.offset, terminal.offset),
                "anchored",
            )
        if (
            parameter[3] == "integer"
            and index > 0
            and index + 3 < len(body)
            and raw == b"\x26\x3b\x04"
        ):
            load = body[index - 1]
            branch = body[index + 2]
            jump = body[index + 3]
            relations = {
                "x86.je": "=",
                "x86.jne": "<>",
                "x86.jl": ">",
                "x86.jle": ">=",
                "x86.jg": "<",
                "x86.jge": "<=",
            }
            relation = relations.get(branch.kind)
            if (
                load.kind == "x86.mov_imm"
                and load.operands[:1] == ("ax",)
                and len(load.operands) == 2
                and isinstance(load.operands[1], int)
                and relation is not None
                and len(branch.operands) == 1
                and isinstance(branch.operands[0], int)
                and jump.kind in _JUMPS
                and len(jump.operands) == 1
                and isinstance(jump.operands[0], int)
                and branch.operands[0] == jump.end
                and jump.operands[0] > branch.operands[0]
                and _contiguous((load, instruction, terminal, branch, jump))
            ):
                yield Fact(
                    "semantic.if_inline",
                    (load.offset, jump.operands[0]),
                    (
                        (relation, parameter, ("const", load.operands[1])),
                        branch.operands[0],
                        jump.operands[0],
                        None,
                    ),
                    (
                        load.offset,
                        instruction.offset,
                        terminal.offset,
                        branch.offset,
                        jump.offset,
                    ),
                    "anchored",
                )
        if index > 0 and _parameter_operation_matches(
            terminal_operation, parameter[3], "store"
        ):
            source = None
            for previous in reversed(body[max(0, index - 3) : index]):
                candidate = compiler_operations.get(previous.offset)
                source = _direct_numeric_source(candidate, facts)
                if source is None and candidate is not None:
                    source = _scratch_numeric_source(
                        candidate, compiler_operations, facts
                    )
                if source is None and candidate is not None:
                    source = _parameter_load_source(candidate, previous.offset, facts)
                if source is not None:
                    break
            commit = body[index + 2] if index + 2 < len(body) else None
            if source is not None and _runtime(commit, 0x87):
                assert commit is not None
                yield Fact(
                    "semantic.assign",
                    (source.start, commit.end),
                    (parameter, source.value),
                    combine_evidence(
                        source.evidence,
                        (instruction.offset, terminal.offset, commit.offset),
                    ),
                    "anchored",
                )
        if (
            parameter[3] == "string"
            and terminal_operation is not None
            and terminal_operation.kind == "far_strassign"
        ):
            sources = [
                fact
                for fact in facts
                if fact.kind == "expression.string_operand"
                and len(fact.subject) == 2
                and fact.subject[1] == instruction.offset
                and len(fact.value) == 1
            ]
            if len(sources) == 1:
                string_source = sources[0]
                yield Fact(
                    "semantic.assign",
                    (string_source.subject[0], terminal_operation.end),
                    (parameter, string_source.value[0]),
                    combine_evidence(
                        string_source.evidence,
                        (instruction.offset, terminal_operation.offset),
                    ),
                    "anchored",
                )
        if index > 0 and _parameter_operation_matches(
            terminal_operation, parameter[3], "compare"
        ):
            source = _direct_numeric_source(
                compiler_operations.get(body[index - 1].offset), facts
            )
            if source is not None:
                yield Fact(
                    "expression.compare",
                    (source.start,),
                    (source.value, parameter),
                    combine_evidence(
                        source.evidence,
                        (instruction.offset, terminal.offset),
                    ),
                    "anchored",
                )
        if index > 0 and raw in {b"\x26\x01\x04", b"\x26\x29\x04"}:
            value = body[index - 1]
            if (
                value.kind == "x86.mov_imm"
                and value.operands[:1] == ("ax",)
                and len(value.operands) == 2
            ):
                yield Fact(
                    "semantic.assign",
                    (value.offset, terminal.end),
                    (
                        parameter,
                        (
                            "binary",
                            "+" if raw == b"\x26\x01\x04" else "-",
                            parameter,
                            ("const", value.operands[1]),
                        ),
                    ),
                    (value.offset, instruction.offset, terminal.offset),
                    "anchored",
                )


def _array_parameter_body_facts(
    procedure: _Procedure,
    parameters: tuple[object, ...],
    instructions: tuple[Operation, ...],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    arrays = {
        parameter[2]: parameter
        for parameter in parameters
        if isinstance(parameter, tuple)
        and len(parameter) == 5
        and parameter[0] == "proc-array-param"
        and isinstance(parameter[2], int)
        and isinstance(parameter[3], str)
        and isinstance(parameter[4], int)
    }
    if not arrays:
        return
    body = tuple(
        instruction
        for instruction in instructions
        if procedure.entry < instruction.offset < procedure.end
    )
    by_offset = {instruction.offset: instruction for instruction in body}
    ends = {instruction.offset: instruction.end for instruction in instructions}
    for index in range(len(body) - 4):
        subtract, set_offset, scale_low, scale_high, set_segment = body[
            index : index + 5
        ]
        bound_displacement = _bp_operand_displacement(
            bytes.fromhex(subtract.raw), b"\x2b\x46", b"\x2b\x86"
        )
        descriptor_displacement = _bp_operand_displacement(
            bytes.fromhex(set_segment.raw), b"\x8e\x46", b"\x8e\x86"
        )
        if descriptor_displacement is None or bound_displacement is None:
            continue
        parameter = arrays.get(descriptor_displacement)
        if (
            parameter is None
            or bound_displacement != descriptor_displacement + 8
            or bytes.fromhex(set_offset.raw) != b"\x89\xc6"
            or bytes.fromhex(scale_low.raw) != b"\xd1\xe6"
            or bytes.fromhex(scale_high.raw) != b"\xd1\xe6"
            or not _contiguous(
                (subtract, set_offset, scale_low, scale_high, set_segment)
            )
        ):
            continue
        source = resolve_expression_before(subtract.offset, facts, ends)
        if source is None:
            continue
        start = source.start if source.start is not None else source.evidence[0]
        if not isinstance(start, int):
            continue
        element = (
            "proc-array-element",
            parameter[1],
            parameter[2],
            parameter[3],
            parameter[4],
            (source.value,),
        )
        support = combine_evidence(
            source.evidence,
            tuple(
                instruction.offset
                for instruction in (
                    subtract,
                    set_offset,
                    scale_low,
                    scale_high,
                    set_segment,
                )
            ),
        )
        yield Fact(
            "reference.proc_array_address",
            (start, set_segment.end),
            (element, parameter[3]),
            support,
            "anchored",
        )
        consume = by_offset.get(set_segment.end)
        if parameter[3] == "string" and _runtime(consume, 0x9D):
            assert consume is not None
            yield Fact(
                "expression.string_operand",
                (start, consume.end),
                (element,),
                combine_evidence(support, (consume.offset,)),
                "anchored",
            )


def _bp_operand_displacement(
    raw: bytes, short_prefix: bytes, long_prefix: bytes
) -> int | None:
    if len(raw) == 3 and raw[:2] == short_prefix:
        return struct.unpack_from("<b", raw, 2)[0]
    if len(raw) == 4 and raw[:2] == long_prefix:
        return struct.unpack_from("<h", raw, 2)[0]
    return None


def _local_body_facts(
    procedure: _Procedure,
    parameters: tuple[object, ...],
    local_bytes: int,
    instructions: tuple[Operation, ...],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    body = tuple(
        instruction
        for instruction in instructions
        if procedure.entry < instruction.offset < procedure.end
    )
    local_start = 6 + 4 * len(parameters)
    initialization = _numeric_local_initialization(body, local_bytes, local_start)
    if initialization is None:
        return
    compiler_operations = translate_operations(body)
    kinds: dict[int, set[str]] = {}
    operation_kinds = {
        "mov_bp_imm": "integer",
        "movax_bp": "integer",
        "movsi_bp": "integer",
        "movm_ax_bp": "integer",
        "fild_bp": "integer",
        "fild32_bp": "long",
        "fld_bp": "float",
        "fld64_bp": "double",
        "fistp_bp": "integer",
        "fistp32_bp": "long",
        "fstp_bp": "float",
        "fstp64_bp": "double",
        "ficomp32_bp": "long",
        "fcomp_bp": "float",
        "fcomp64_bp": "double",
    }
    for operation in compiler_operations:
        kind = operation_kinds.get(operation.kind)
        if kind is not None and operation.args and isinstance(operation.args[0], int):
            kinds.setdefault(operation.args[0], set()).add(kind)
    for instruction in body:
        update = _bp_increment(instruction)
        if update is not None:
            kinds.setdefault(update[0], set()).add("integer")
    accesses = _local_string_accesses(body)
    for _setup, _runtime_call, displacement, _action in accesses:
        kinds.setdefault(displacement, set()).add("string")
    # The SUB releases each string local before it returns.
    for pointer, release in zip(body, body[1:]):
        displacement = _les_si_bp_displacement(pointer)
        if displacement is not None and _runtime(release, 0xD3):
            kinds.setdefault(displacement, set()).add("string")
    for fact in facts:
        if (
            fact.kind != "semantic.call"
            or len(fact.value) != 2
            or not isinstance(fact.value[1], tuple)
        ):
            continue
        for argument in fact.value[1]:
            if (
                isinstance(argument, tuple)
                and len(argument) == 4
                and argument[0] == "proc-local"
                and argument[1] == procedure.entry
                and isinstance(argument[2], int)
                and isinstance(argument[3], str)
            ):
                kinds.setdefault(argument[2], set()).add(argument[3])
    locals_by_displacement = {
        displacement: ("proc-local", procedure.entry, displacement, next(iter(found)))
        for displacement, found in kinds.items()
        if len(found) == 1 and local_start <= displacement < local_start + local_bytes
    }
    if not locals_by_displacement:
        return
    ordered = tuple(
        locals_by_displacement[key] for key in sorted(locals_by_displacement)
    )
    yield Fact(
        "semantic.local",
        (initialization[0].offset, initialization[-1].end),
        (ordered,),
        tuple(instruction.offset for instruction in initialization),
        "anchored",
    )
    by_offset = {operation.offset: operation for operation in compiler_operations}
    yield from _integer_local_copies(compiler_operations, locals_by_displacement, facts)
    yield from _string_local_facts(accesses, locals_by_displacement, facts)
    for instruction in body:
        local_operation = by_offset.get(instruction.offset)
        if local_operation is not None and local_operation.kind == "mov_bp_imm":
            displacement, value = local_operation.args
            if not isinstance(displacement, int):
                continue
            local = locals_by_displacement.get(displacement)
            if local is not None:
                yield Fact(
                    "semantic.assign",
                    (instruction.offset, instruction.end),
                    (local, ("const", value)),
                    (instruction.offset,),
                    "anchored",
                )
        update = _bp_increment(instruction)
        if update is not None:
            displacement, name = update
            local = locals_by_displacement.get(displacement)
            if local is not None:
                yield Fact(
                    "semantic.statement",
                    (instruction.offset, instruction.end),
                    (name, -1, local),
                    (instruction.offset,),
                    "anchored",
                )
        load_kinds = {
            "movax_bp": "integer",
            "movsi_bp": "integer",
            "fild_bp": "integer",
            "fild32_bp": "long",
            "fld_bp": "float",
            "fld64_bp": "double",
        }
        load_kind = (
            load_kinds.get(local_operation.kind)
            if local_operation is not None
            else None
        )
        if (
            load_kind is not None
            and local_operation is not None
            and local_operation.args
        ):
            if not isinstance(local_operation.args[0], int):
                continue
            local = locals_by_displacement.get(local_operation.args[0])
            if local is not None and local[3] == load_kind:
                yield Fact(
                    "expression.value",
                    (instruction.offset,),
                    (local,),
                    (instruction.offset,),
                    "anchored",
                )
    instructions_by_offset = {instruction.offset: instruction for instruction in body}
    store_kinds = {
        "fistp_bp": "integer",
        "fistp32_bp": "long",
        "fstp_bp": "float",
        "fstp64_bp": "double",
    }
    for index, store in enumerate(compiler_operations):
        store_kind = store_kinds.get(store.kind)
        if store_kind is None or not store.args or index == 0:
            continue
        if not isinstance(store.args[0], int):
            continue
        local = locals_by_displacement.get(store.args[0])
        commit = instructions_by_offset.get(store.end)
        if local is None or local[3] != store_kind or not _runtime(commit, 0x87):
            continue
        source_operation = compiler_operations[index - 1]
        source = (
            _direct_numeric_source(source_operation, facts)
            if source_operation.end == store.offset
            else None
        )
        if source is None and index >= 2:
            preload = compiler_operations[index - 2]
            fold = compiler_operations[index - 1]
            if (
                preload.kind == "fld1"
                and preload.end == fold.offset
                and fold.end == store.offset
                and fold.kind in {"fold_bp", "fold64_bp"}
                and len(fold.args) == 2
                and fold.args[1] == local[2]
            ):
                source = Resolved(
                    ("binary", fold.args[0], local, ("const", 1)),
                    (preload.offset, fold.offset),
                    preload.offset,
                )
        if source is not None:
            if commit is None:
                continue
            yield Fact(
                "semantic.assign",
                (source.start, commit.end),
                (local, source.value),
                combine_evidence(source.evidence, (store.offset, commit.offset)),
                "anchored",
            )
    yield from _integer_local_stores(
        compiler_operations, body, locals_by_displacement, facts
    )
    compare_kinds = {
        "ficomp32_bp": "long",
        "fcomp_bp": "float",
        "fcomp64_bp": "double",
    }
    for index, compare in enumerate(compiler_operations):
        compare_kind = compare_kinds.get(compare.kind)
        if compare_kind is None or not compare.args or index == 0:
            continue
        if not isinstance(compare.args[0], int):
            continue
        local = locals_by_displacement.get(compare.args[0])
        source_operation = compiler_operations[index - 1]
        if (
            local is None
            or local[3] != compare_kind
            or source_operation.end != compare.offset
        ):
            continue
        source = _direct_numeric_source(source_operation, facts)
        if source is None and source_operation.kind == "fld1":
            source = Resolved(
                ("const", 1),
                (source_operation.offset,),
                source_operation.offset,
            )
        if source is not None:
            yield Fact(
                "expression.compare",
                (source.start,),
                (source.value, local),
                combine_evidence(source.evidence, (compare.offset,)),
                "anchored",
            )
    for index, local_update in enumerate(compiler_operations):
        operator = {"addm_ax_bp": "+", "subm_ax_bp": "-"}.get(local_update.kind)
        if operator is None or not local_update.args or index == 0:
            continue
        previous_operation = compiler_operations[index - 1]
        if not isinstance(local_update.args[0], int):
            continue
        local = locals_by_displacement.get(local_update.args[0])
        if (
            local is None
            or local[3] != "integer"
            or previous_operation.kind != "movax"
            or len(previous_operation.args) != 1
            or previous_operation.end != local_update.offset
        ):
            continue
        yield Fact(
            "semantic.assign",
            (previous_operation.offset, local_update.end),
            (
                local,
                ("binary", operator, local, ("const", previous_operation.args[0])),
            ),
            (previous_operation.offset, local_update.offset),
            "anchored",
        )
    yield from _mixed_integer_local_assignments(
        body,
        compiler_operations,
        parameters,
        locals_by_displacement,
    )


def _local_string_accesses(
    body: tuple[Operation, ...],
) -> tuple[tuple[Operation, Operation, int, str], ...]:
    """Find each ``mov si,d`` naming the string local at ``[bp+d]``.

    A procedure's string local is pushed with ``mov si,d; cd 9e`` and
    assigned with ``mov si,d; cd a2``, where a DGROUP string uses 0x9C and
    0xA0 with its slot's address.
    """
    found = []
    for setup, runtime in zip(body, body[1:]):
        action = {(0x9E,): "read", (0xA2,): "write"}.get(runtime.operands)
        if (
            action is not None
            and runtime.kind == "tb.runtime"
            and setup.end == runtime.offset
            and setup.kind == "x86.mov_imm"
            and setup.operands[:1] == ("si",)
            and isinstance(setup.operands[1], int)
        ):
            found.append((setup, runtime, setup.operands[1], action))
    return tuple(found)


def _string_local_facts(
    accesses: tuple[tuple[Operation, Operation, int, str], ...],
    locals_by_displacement: Mapping[int, tuple[object, ...]],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    """Read a pushed string local as an operand and a stored one as assigned.

    The value stored is the string operand that ends at the ``mov si``.
    """
    operands = tuple(
        fact
        for fact in facts_by_kind(facts).get("expression.string_operand", ())
        if len(fact.subject) == 2 and len(fact.value) == 1
    )
    for setup, runtime, displacement, action in accesses:
        local = locals_by_displacement.get(displacement)
        if local is None or local[3] != "string":
            continue
        if action == "read":
            yield Fact(
                "expression.string_operand",
                (setup.offset, runtime.end),
                (local,),
                (setup.offset, runtime.offset),
                "anchored",
            )
            continue
        sources = [fact for fact in operands if fact.subject[1] == setup.offset]
        start = min((fact.subject[0] for fact in sources), default=None)
        widest = [fact for fact in sources if fact.subject[0] == start]
        if len(widest) != 1:
            continue
        yield Fact(
            "semantic.assign",
            (widest[0].subject[0], runtime.end),
            (local, widest[0].value[0]),
            combine_evidence(widest[0].evidence, (setup.offset, runtime.offset)),
            "anchored",
        )


def _integer_local_stores(
    operations: tuple[CompilerOp, ...],
    body: tuple[Operation, ...],
    locals_by_displacement: Mapping[int, object],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    """Assign an integer local the value AX holds when it is stored.

    ``AV% = LEN(A$)``: LEN leaves its value in AX, then ``mov [bp+12h],ax``.
    """
    ending_at = {instruction.end: instruction.offset for instruction in body}
    values = facts_by_kind(facts).get("expression.value", ())
    for store in operations:
        if store.kind != "movm_ax_bp" or not store.args:
            continue
        local = locals_by_displacement.get(store.args[0])
        if not isinstance(local, tuple) or local[3] != "integer":
            continue
        last = ending_at.get(store.offset)
        sources = {
            fact.value[0]: fact
            for fact in values
            if last is not None
            and last in fact.evidence
            and fact.subject[1:] in {(), (store.offset,)}
            and len(fact.value) == 1
            and fact.subject[0] <= last
        }
        # The value that ends at the store is the widest one starting first.
        if not sources:
            continue
        start = min(fact.subject[0] for fact in sources.values())
        widest = [fact for fact in sources.values() if fact.subject[0] == start]
        if len(widest) != 1:
            continue
        source = widest[0]
        yield Fact(
            "semantic.assign",
            (source.subject[0], store.end),
            (local, source.value[0]),
            combine_evidence(source.evidence, (store.offset,)),
            "anchored",
        )


def _integer_local_copies(
    operations: tuple[CompilerOp, ...],
    locals_by_displacement: Mapping[int, tuple[object, ...]],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    """Preserve a typed DGROUP integer copied directly into a known local."""
    for load, store in zip(operations, operations[1:]):
        if (
            load.kind != "movax_m"
            or store.kind != "movm_ax_bp"
            or load.end != store.offset
            or len(load.args) != 1
            or len(store.args) != 1
            or not isinstance(load.args[0], int)
            or not isinstance(store.args[0], int)
        ):
            continue
        local = locals_by_displacement.get(store.args[0])
        if local is None or local[3] != "integer":
            continue
        source = resolve_expression(("memory", load.args[0], "integer"), facts)
        if source is not None:
            yield Fact(
                "semantic.assign",
                (load.offset, store.end),
                (local, source.value),
                combine_evidence((load.offset, store.offset), source.evidence),
                "anchored",
            )


def _mixed_integer_local_assignments(
    body: tuple[Operation, ...],
    compiler_operations: tuple[CompilerOp, ...],
    parameters: tuple[object, ...],
    locals_by_displacement: Mapping[int, tuple[object, ...]],
) -> Iterable[Fact]:
    parameters_by_displacement = {
        parameter[2]: parameter
        for parameter in parameters
        if isinstance(parameter, tuple)
        and len(parameter) == 4
        and parameter[0] == "proc-param"
        and parameter[3] == "integer"
    }
    instruction_indexes = {
        instruction.offset: index for index, instruction in enumerate(body)
    }
    for store in compiler_operations:
        if store.kind != "movm_ax_bp" or not store.args:
            continue
        if not isinstance(store.args[0], int):
            continue
        target = locals_by_displacement.get(store.args[0])
        index = instruction_indexes.get(store.offset)
        if target is None or target[3] != "integer" or index is None:
            continue
        if index >= 3:
            load, address, add = body[index - 3 : index]
            parameter = parameters_by_displacement.get(_les_si_bp_displacement(address))
            if (
                load.kind == "x86.mov_imm"
                and load.operands[:1] == ("ax",)
                and len(load.operands) == 2
                and parameter is not None
                and bytes.fromhex(add.raw) == b"\x26\x03\x04"
                and load.end == address.offset
                and address.end == add.offset
                and add.end == store.offset
            ):
                yield Fact(
                    "semantic.assign",
                    (load.offset, store.end),
                    (
                        target,
                        ("binary", "+", parameter, ("const", load.operands[1])),
                    ),
                    (load.offset, address.offset, add.offset, store.offset),
                    "anchored",
                )
                continue
        operation_index = next(
            (
                candidate
                for candidate, operation in enumerate(compiler_operations)
                if operation.offset == store.offset
            ),
            None,
        )
        if operation_index is None or operation_index < 2:
            continue
        load_operation, multiply_operation = compiler_operations[
            operation_index - 2 : operation_index
        ]
        source = (
            locals_by_displacement.get(multiply_operation.args[0])
            if (
                multiply_operation.kind == "imul_bp"
                and multiply_operation.args
                and isinstance(multiply_operation.args[0], int)
            )
            else None
        )
        if (
            load_operation.kind == "movax"
            and len(load_operation.args) == 1
            and isinstance(load_operation.args[0], int)
            and source is not None
            and source[3] == "integer"
            and load_operation.end == multiply_operation.offset
            and multiply_operation.end == store.offset
        ):
            yield Fact(
                "semantic.assign",
                (load_operation.offset, store.end),
                (
                    target,
                    ("binary", "*", source, ("const", load_operation.args[0])),
                ),
                (load_operation.offset, multiply_operation.offset, store.offset),
                "anchored",
            )


def _numeric_local_initialization(
    body: tuple[Operation, ...], local_bytes: int, local_start: int
) -> tuple[Operation, ...] | None:
    if len(body) < 12 or local_bytes <= 0 or local_bytes % 2:
        return None
    window = body[:12]
    raws = tuple(bytes.fromhex(instruction.raw) for instruction in window)
    if (
        raws[0] != b"\x51"
        or raws[1] != b"\x57"
        or raws[2] != b"\x8c\xd0"
        or raws[3] != b"\x8e\xc0"
        or not (len(raws[4]) == 3 and raws[4][0] == 0xB9)
        or struct.unpack_from("<H", raws[4], 1)[0] != local_bytes // 2
        or len(raws[5]) != 4
        or raws[5][:2] != b"\x8d\xbe"
        or struct.unpack_from("<h", raws[5], 2)[0] != local_start
        or raws[6:]
        != (
            b"\x31\xc0",
            b"\xfc",
            b"\xf3",
            b"\xab",
            b"\x5f",
            b"\x59",
        )
    ):
        return None
    return window


def _bp_increment(instruction: Operation) -> tuple[int, str] | None:
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 3 and raw[:2] in {b"\xff\x46", b"\xff\x4e"}:
        return (
            struct.unpack_from("<b", raw, 2)[0],
            "INCR" if raw[1] == 0x46 else "DECR",
        )
    if len(raw) == 4 and raw[:2] in {b"\xff\x86", b"\xff\x8e"}:
        return (
            struct.unpack_from("<h", raw, 2)[0],
            "INCR" if raw[1] == 0x86 else "DECR",
        )
    return None


_PARAMETER_OPERATIONS = {
    "load": {
        "integer": "far_fild_si",
        "long": "far_fild_si32",
        "float": "far_fld_si",
        "double": "far_fld_si64",
    },
    "store": {
        "integer": "far_fistp_si",
        "long": "far_fistp_si32",
        "float": "far_fstp_si",
        "double": "far_fstp_si64",
    },
    "compare": {
        "long": "far_ficomp_si32",
        "float": "far_fcomp_si",
        "double": "far_fcomp_si64",
    },
}

_DIRECT_NUMERIC_LOADS = {
    "fild": "integer",
    "fild32": "long",
    "fld": "float",
    "fld64": "double",
}


def _parameter_operation_matches(
    operation: CompilerOp | None, kind: object, action: str
) -> bool:
    return (
        operation is not None
        and isinstance(kind, str)
        and operation.kind == _PARAMETER_OPERATIONS[action].get(kind)
    )


def _direct_numeric_source(
    operation: CompilerOp | None, facts: frozenset[Fact]
) -> Resolved | None:
    if operation is not None and operation.kind in {"fldz", "fld1"}:
        return Resolved(
            ("const", 0 if operation.kind == "fldz" else 1),
            (operation.offset,),
            operation.offset,
        )
    kind = _DIRECT_NUMERIC_LOADS.get(operation.kind) if operation is not None else None
    if (
        operation is None
        or kind is None
        or len(operation.args) != 1
        or not isinstance(operation.args[0], int)
    ):
        return None
    resolved = resolve_expression(("memory", operation.args[0], kind), facts)
    if resolved is None:
        return None
    return Resolved(
        resolved.value,
        combine_evidence((operation.offset,), resolved.evidence),
        operation.offset,
    )


def _scratch_numeric_source(
    operation: CompilerOp,
    operations: dict[int, CompilerOp],
    facts: frozenset[Fact],
) -> Resolved | None:
    """Recover constants materialized through the compiler's scratch word."""
    if operation.kind != "fild" or len(operation.args) != 1:
        return None
    prior = sorted(
        (item for item in operations.values() if item.end <= operation.offset),
        key=lambda item: item.offset,
    )
    if len(prior) < 3:
        return None
    mov, negate, store = prior[-3:]
    if (
        mov.kind != "movax"
        or len(mov.args) != 1
        or negate.kind != "negax"
        or store.kind != "movmem_ax"
        or store.args != operation.args
    ):
        return None
    if not isinstance(mov.args[0], int):
        return None
    return Resolved(
        ("const", -mov.args[0]),
        (mov.offset, negate.offset, store.offset, operation.offset),
        operation.offset,
    )


def _parameter_load_source(
    operation: CompilerOp,
    before: int,
    facts: frozenset[Fact],
) -> Resolved | None:
    if operation.kind not in {"far_fld_si", "far_fld_si64"}:
        return None
    candidates = [
        fact
        for fact in facts
        if fact.kind == "expression.value"
        and len(fact.subject) == 1
        and fact.subject[0] < before
        and len(fact.value) == 1
        and isinstance(fact.value[0], tuple)
        and fact.value[0][:1] == ("proc-param",)
    ]
    if not candidates:
        return None
    source = max(candidates, key=lambda fact: (fact.subject[0], fact_key(fact)))
    return Resolved(source.value[0], source.evidence, source.subject[0])


def _les_si_bp_displacement(instruction: Operation) -> int | None:
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 3 and raw[:2] == b"\xc4\x76":
        return struct.unpack_from("<b", raw, 2)[0]
    if len(raw) == 4 and raw[:2] == b"\xc4\xb6":
        return struct.unpack_from("<h", raw, 2)[0]
    return None


def _push_bp_displacement(instruction: Operation) -> int | None:
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 3 and raw[:2] == b"\xff\x76":
        return struct.unpack_from("<b", raw, 2)[0]
    if len(raw) == 4 and raw[:2] == b"\xff\xb6":
        return struct.unpack_from("<h", raw, 2)[0]
    return None


def _stack_allocation(instruction: Operation) -> int | None:
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 3 and raw[:2] == b"\x83\xec":
        return raw[2]
    if len(raw) == 4 and raw[:2] == b"\x81\xec":
        return struct.unpack_from("<H", raw, 2)[0]
    return None


def _stack_release(instruction: Operation) -> int | None:
    raw = bytes.fromhex(instruction.raw)
    if len(raw) == 3 and raw[:2] == b"\x83\xc4":
        return raw[2]
    if len(raw) == 4 and raw[:2] == b"\x81\xc4":
        return struct.unpack_from("<H", raw, 2)[0]
    return None


def _call_stack_release(
    call_end: int,
    instructions: tuple[Operation, ...],
    indexes: dict[int, int],
) -> int:
    index = indexes.get(call_end)
    if index is None:
        return 0
    for instruction in instructions[index : index + 8]:
        released = _stack_release(instruction)
        if released is not None:
            return released
        raw = bytes.fromhex(instruction.raw)
        if (
            raw == b"\x8b\xdc"
            or (len(raw) == 4 and raw[:3] == b"\x36\xc4\x77")
            or _runtime(instruction, 0xD3)
        ):
            continue
        break
    return 0


def _procedures(evidence: Evidence) -> dict[int, _Procedure]:
    instructions = evidence.instructions
    entries = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.kind == "tb.proc_enter"
    ]
    result = {}
    for position, index in enumerate(entries):
        limit = (
            entries[position + 1] if position + 1 < len(entries) else len(instructions)
        )
        returns = [
            instruction
            for instruction in instructions[index + 1 : limit]
            if instruction.kind == "tb.proc_return"
        ]
        # The compiler brackets a procedure with a jump over it, so a return
        # past that jump's destination belongs to whatever the compiler placed
        # after the body -- an inline procedure, say -- and not to this one.
        bracket_end = _bracket_destination(instructions, index)
        if len(returns) > 1 and bracket_end is not None:
            bracketed = [
                instruction for instruction in returns if instruction.end <= bracket_end
            ]
            if len(bracketed) == 1:
                returns = bracketed
        if len(returns) != 1:
            continue
        entry = instructions[index]
        returned = returns[0]
        frame_pop = returned.operands[0] if returned.operands else None
        if not isinstance(frame_pop, int):
            continue
        bracket = _declaration_bracket(instructions, index, returned.end)
        declaration = bracket.offset if bracket is not None else entry.offset
        support = combine_evidence(
            (entry.offset, returned.offset),
            () if bracket is None else (bracket.offset,),
        )
        result[entry.offset] = _Procedure(
            declaration, entry.offset, returned.end, frame_pop, support
        )
    for inline in inline_procedure_regions(evidence):
        # A SUB without parameters has no frame either, but its body commits
        # compiled statements; only a body that commits none is $INLINE code.
        compiled = any(
            instruction.kind == "tb.runtime"
            and instruction.operands == (0x87,)
            and inline.entry <= instruction.offset < inline.body_end
            for instruction in instructions
        )
        result[inline.entry] = _Procedure(
            inline.declaration,
            inline.entry,
            inline.end,
            0,
            inline.evidence,
            None if compiled else (inline.entry, inline.body_end),
        )
    return result


def inline_procedure_regions(evidence: Evidence) -> tuple[InlineProcedure, ...]:
    """Find compiler-generated inline procedure regions."""
    instructions = evidence.instructions
    brackets = {
        instruction.end: instruction
        for instruction in instructions
        if instruction.kind in _JUMPS and instruction.operands
    }
    calls: dict[int, list[Operation]] = {}
    for instruction in instructions:
        if (
            instruction.kind == "x86.call_far"
            and instruction.operands
            and isinstance(instruction.operands[0], int)
        ):
            calls.setdefault(instruction.operands[0], []).append(instruction)
    result = []
    for entry, entry_calls in calls.items():
        bracket = brackets.get(entry)
        main = bracket.operands[0] if bracket and bracket.operands else None
        if not (
            bracket is not None
            and isinstance(main, int)
            and entry <= main - 1 < len(evidence.image)
            and evidence.image[main - 1] == 0xCB
        ):
            continue
        framed_entry = any(
            instruction.offset == entry and instruction.kind == "tb.proc_enter"
            for instruction in instructions
        )
        framed_return = any(
            instruction.kind == "tb.proc_return"
            and entry < instruction.offset
            and instruction.end == main
            for instruction in instructions
        )
        if (
            framed_entry
            and framed_return
            and not _has_inline_port_io(evidence.image, entry, main - 1)
            and not _machine_code_body(instructions, entry, main)
        ):
            continue
        support = combine_evidence(
            (bracket.offset, main - 1),
            tuple(call.offset for call in entry_calls),
        )
        result.append(InlineProcedure(bracket.offset, entry, main - 1, main, support))
    found = {item.entry for item in result}
    # A declaration-skipped routine with no caller in the decoded code is
    # still $INLINE machine code when nothing in it is compiled BASIC.
    for entry, bracket in brackets.items():
        main = bracket.operands[0]
        if (
            entry in found
            or not isinstance(main, int)
            or not entry < main - 1 < len(evidence.image)
            or evidence.image[main - 1] != 0xCB
            or not _machine_code_body(instructions, entry, main)
        ):
            continue
        support = (bracket.offset, main - 1)
        result.append(InlineProcedure(bracket.offset, entry, main - 1, main, support))
    return tuple(sorted(result, key=lambda item: item.entry))


_MACHINE_ONLY = frozenset(
    {
        "opaque.byte",
        "x86.in_al_dx",
        "x86.out",
        "x86.lods",
        "x86.stos",
        "x86.movs",
        "x86.cli",
        "x86.sti",
        "x86.cld",
        "x86.std",
        "x86.loop",
    }
)


def _machine_code_body(
    instructions: tuple[Operation, ...], entry: int, end: int
) -> bool:
    """Whether a framed routine holds no compiled Turbo Basic code.

    A compiled SUB or FN saves SP in the runtime's frame word
    (``mov [0066h],sp``) and calls the runtime; hand-written machine code
    has neither, only plain x86 between its frame entry and far return,
    and some instruction the compiler never emits for BASIC.
    """
    body = [item for item in instructions if entry <= item.offset < end]
    return (
        bool(body)
        and body[0].kind == "tb.proc_enter"
        and body[-1].end == end
        and body[-1].raw.split()[-1:] == ["cb"]
        and all(
            item.kind.startswith(("x86.", "opaque."))
            or item.kind in {"tb.proc_enter", "tb.proc_return"}
            for item in body
        )
        and not any(item.raw == "89 26 66 00" for item in body)
        # A far call is how a compiled SUB calls another.
        and not any(item.kind == "x86.call_far" for item in body)
        # The compiler appends ``int3; retf`` to $INLINE code; a hook
        # anywhere else is a compiled statement boundary.
        and not any(item.kind == "x86.int3" for item in body[:-2])
        # Plain moves and adds are also what a small compiled SUB is made of;
        # port I/O, string instructions, interrupt flags or LOOP are not, and
        # a compiled SUB pops the arguments it reads, where a plain RETF
        # after reading [bp+6] and up leaves them to the caller.
        and (
            any(item.kind in _MACHINE_ONLY for item in body)
            or any(_reads_arguments(item) for item in body)
        )
    )


# Opcodes followed by a ModRM byte, among those that address memory.
_MODRM_OPCODES = {0x01, 0x03, 0x29, 0x2B, 0x39, 0x3B, 0x88, 0x89, 0x8A, 0x8B}
_MODRM_OPCODES |= {0x80, 0x81, 0x83, 0x8D, 0xC4, 0xC5, 0xC6, 0xC7, 0xF7, 0xFF}


def _reads_arguments(instruction: Operation) -> bool:
    """Whether an instruction addresses ``[bp+d]`` with ``d >= 6``, an argument."""
    raw = bytes.fromhex(instruction.raw)
    for prefix in (0, 1):
        if len(raw) < prefix + 3 or (prefix and raw[0] not in {0x26, 0x2E, 0x36, 0x3E}):
            continue
        if raw[prefix] not in _MODRM_OPCODES:
            continue
        modrm = raw[prefix + 1]
        if modrm & 7 == 6 and modrm >> 6 == 1 and raw[prefix + 2] < 0x80:
            return raw[prefix + 2] >= 6
    return False


def _has_inline_port_io(image: bytes, start: int, end: int) -> bool:

    return any(
        image[offset] == 0xB0 and image[offset + 2] == 0xE6
        for offset in range(start, max(start, end - 3))
    )


def _bracket_destination(
    instructions: tuple[Operation, ...], entry_index: int
) -> int | None:
    """Return where the jump bracketing a procedure lands, if there is one."""
    if entry_index == 0:
        return None
    candidate = instructions[entry_index - 1]
    target = candidate.operands[0] if candidate.operands else None
    if (
        candidate.kind in _JUMPS
        and candidate.end == instructions[entry_index].offset
        and isinstance(target, int)
        and target > instructions[entry_index].offset
    ):
        return target
    return None


def _declaration_bracket(
    instructions: tuple[Operation, ...], entry_index: int, body_end: int
) -> Operation | None:
    if entry_index == 0:
        return None
    candidate = instructions[entry_index - 1]
    target = candidate.operands[0] if candidate.operands else None
    if (
        candidate.kind in _JUMPS
        and candidate.end == instructions[entry_index].offset
        and isinstance(target, int)
        and target >= body_end
    ):
        return candidate
    return None


def _parameters(frame_pop: int) -> tuple[object, ...]:
    if frame_pop == 0:
        return ()
    return ("unresolved-frame", frame_pop)


def _arguments(frame_pop: int) -> tuple[object, ...]:
    if frame_pop == 0:
        return ()
    return ("unresolved-call-arguments", frame_pop)


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "register.value",
    "semantic.local",
    "semantic.sub_def",
    "slot",
)
def frame_value_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Span each value the symbolic tracker computed from frame words.

    The value runs from the first instruction computing it to the end of
    the one leaving it in AX. A word read alone is already the procedure
    pass's value.
    """
    if not frame_slots(facts):
        return
    ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    for fact in facts_by_kind(facts).get("register.value", ()):
        if (
            fact.subject[1:] != ("ax",)
            or not fact.evidence
            or not has_frame_word(fact.value[0])
            or fact.value[0][:1] in {("frame",), ("frame-param",)}
        ):
            continue
        end = ends.get(fact.subject[0])
        expression = fact.value[0]
        # An FP value rounded into an integer temporary is what storing it
        # in an integer variable does anyway.
        if expression[:2] == ("conversion", "integer"):
            expression = expression[2]
        resolved = resolve_expression(expression, facts)
        if resolved is None or end is None:
            continue
        yield Fact(
            "expression.value",
            (min(fact.evidence), end),
            (resolved.value,),
            fact.evidence,
            "anchored",
        )


PROCEDURE_FACT_PASSES: tuple[NamedPass, ...] = (
    ("procedures", procedure_facts),
    ("frame-values", frame_value_facts),
)
