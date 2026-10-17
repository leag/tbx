from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections.abc import Iterable

from tbd.block_if_facts import (
    block_body_goto_facts,
    block_if_region_facts,
    block_if_semantic_facts,
)
from tbd.compiler_ops import CompilerOp, operation_indexes, translate_operations
from tbd.facts import Evidence, NamedPass, fact_key, facts_by_kind, latest_store, reads
from tbd.ir import Fact, Operation
from tbd.operation_helpers import contiguous as _contiguous
from tbd.operation_helpers import fact_inside as _inside
from tbd.operation_helpers import following as _following
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_expression,
    resolve_slot,
)

_MATERIALIZED_RELATIONS = {
    0x77: "<",
    0x73: "<=",
    0x72: ">",
    0x76: ">=",
    0x74: "=",
    0x75: "<>",
    0x7F: ">",
    0x7C: "<",
    0x7D: ">=",
    0x7E: "<=",
}
_STRING_MATERIALIZED_RELATIONS = {
    0x74: "=",
    0x75: "<>",
    0x73: ">=",
    0x72: "<",
    0x77: ">",
    0x76: "<=",
}
_LOGICAL_GATES = {0x75: ("AND", "andaxbx"), 0x74: ("OR", "orax")}
_VALUE_COMBINERS = {"andaxbx": "AND", "oraxbx": "OR"}


def _resolve_bare_boolean(value: object, facts: frozenset[Fact]) -> Resolved | None:
    """Resolve a materialized boolean slot before falling back to memory."""

    if (
        isinstance(value, tuple)
        and len(value) >= 2
        and value[0] == "memory"
        and isinstance(value[1], int)
    ):
        slot = resolve_slot(value[1], facts)
        if slot is not None:
            return slot
    return resolve_expression(value, facts)


def _prefer_boolean_slots(value: object, facts: frozenset[Fact]) -> object:
    """Replace materialized boolean memory operands with their typed slots."""

    if isinstance(value, tuple) and value and value[0] == "memory":
        resolved = _resolve_bare_boolean(value, facts)
        return value if resolved is None else resolved.value
    if isinstance(value, tuple):
        return tuple(_prefer_boolean_slots(item, facts) for item in value)
    return value


def _normalize_boolean_condition(value: object) -> object:
    """Preserve truth tests and explicit OR grouping in boolean conditions."""

    if not isinstance(value, tuple) or not value:
        return value
    if value[0] in {"var", "slot", "fn-param", "proc-param"}:
        return ("truth", value)
    if value[0] == "unary" and len(value) == 3 and value[1] == "NOT":
        return ("truth", value)
    if value[0] not in {"AND", "OR"} or len(value) != 3:
        return value
    left = _normalize_boolean_condition(value[1])
    right = _normalize_boolean_condition(value[2])
    if (
        value[0] == "OR"
        and _sortable_string_relation(left)
        and _sortable_string_relation(right)
    ):
        left, right = sorted((left, right), key=repr)
    if value[0] == "AND" and isinstance(right, tuple) and right[:1] == ("OR",):
        right = (
            "group",
            ("OR", ("group", right[1]), ("group", right[2])),
        )
    return value[0], left, right


def _sortable_string_relation(value: object) -> bool:
    """Identify pure string relations safe to canonicalize within an OR."""

    return (
        isinstance(value, tuple)
        and len(value) == 3
        and value[0] in {"=", "<>", "<", "<=", ">", ">="}
        and isinstance(value[2], tuple)
        and value[2][:1] == ("call",)
    )


_INTEGER_MATERIALIZED_RELATIONS = {
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


@reads(
    "expression.value",
    "constant",
    "expression.compare",
    "expression.string_compare",
    "expression.system",
    "layout.array",
    "slot",
    "tb.runtime",
    "x86.fcomp",
    "x86.inc",
    "x86.j",
    "x86.mov_imm",
)
def materialized_relation_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover relations whose comparison result is materialized in memory."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    for comparison in facts:
        if (
            comparison.kind not in {"expression.compare", "expression.string_compare"}
            or (
                comparison.kind == "expression.compare" and len(comparison.subject) != 1
            )
            or (
                comparison.kind == "expression.string_compare"
                and len(comparison.subject) != 2
            )
            or len(comparison.value) != 2
            or not comparison.evidence
        ):
            continue
        is_string = comparison.kind == "expression.string_compare"
        compare = (
            instructions.get(comparison.subject[1] - 2)
            if is_string
            else next(
                (
                    instructions.get(offset)
                    for offset in reversed(comparison.evidence)
                    if instructions.get(offset) is not None
                    and (
                        instructions[offset].kind.startswith("x86.fcomp")
                        or instructions[offset].raw.startswith("cd 34")
                    )
                ),
                instructions.get(comparison.evidence[-1]),
            )
        )
        status = (
            None
            if is_string
            else instructions.get(compare.end)
            if compare is not None
            else None
        )
        materialize = (
            instructions.get(
                compare.end
                if is_string and compare is not None
                else status.end
                if status is not None
                else 0
            )
            if (compare is not None and (is_string or status is not None))
            else None
        )
        spill = None
        if materialize is not None and materialize.raw in {"89 c3", "8b d8"}:
            spill = materialize
            materialize = instructions.get(materialize.end)
        branch = instructions.get(materialize.end) if materialize is not None else None
        increment = instructions.get(branch.end) if branch is not None else None
        raw = bytes.fromhex(branch.raw) if branch is not None else b""
        relation = (
            (
                _STRING_MATERIALIZED_RELATIONS if is_string else _MATERIALIZED_RELATIONS
            ).get(raw[0])
            if raw
            else None
        )
        if not (
            (
                is_string
                or (
                    status is not None
                    and status.kind == "tb.runtime"
                    and status.operands == (0x99,)
                )
            )
            and materialize is not None
            and materialize.kind == "x86.mov_imm"
            and materialize.operands == ("ax", 0xFFFF)
            and branch is not None
            and branch.kind.startswith("x86.j")
            and increment is not None
            and increment.kind == "x86.inc"
            and increment.operands == ("ax",)
            and branch.operands == (increment.end,)
            and relation is not None
        ):
            continue

        left_value, right_value = (
            comparison.value
            if is_string
            else (comparison.value[1], comparison.value[0])
        )
        left = resolve_expression(left_value, facts)
        right = resolve_expression(right_value, facts)
        if left is None or right is None:
            continue
        value: tuple[object, ...] = (relation, left.value, right.value)
        if is_string and any(
            isinstance(operand, tuple) and operand[:1] == ("call",)
            for operand in (left.value, right.value)
        ):
            value = ("group", value)
        support = combine_evidence(
            comparison.evidence,
            (
                *(() if status is None else (status.offset,)),
                materialize.offset,
                branch.offset,
                increment.offset,
            ),
            () if spill is None else (spill.offset,),
            left.evidence,
            right.evidence,
        )
        yield Fact(
            "expression.relation_value",
            (comparison.subject[0], increment.end),
            value,
            support,
            "anchored",
        )


@reads(
    "constant",
    "expression.system",
    "layout.array",
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
def materialized_system_relation_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover materialized relations based on system-variable comparisons."""

    operations = translate_operations(evidence.instructions)
    for index in range(1, len(operations) - 4):
        load, compare = operations[index : index + 2]
        if (
            load.kind != "movax"
            or compare.kind != "cmpax_m"
            or load.end != compare.offset
            or len(load.args) != 1
            or len(compare.args) != 1
        ):
            continue
        cursor = index + 2
        support = [load, compare]
        preserved = operations[cursor : cursor + 2]
        if [operation.kind for operation in preserved] == ["movaxbx", "movbxax"]:
            if (
                preserved[0].offset != compare.end
                or preserved[0].end != preserved[1].offset
            ):
                continue
            support.extend(preserved)
            cursor += 2
        tail = operations[cursor : cursor + 3]
        if len(tail) != 3:
            continue
        materialize, branch, increment = tail
        if (
            materialize.kind != "movax"
            or materialize.args != (0xFFFF,)
            or branch.kind != "jcc"
            or increment.kind != "incax"
            or support[-1].end != materialize.offset
            or materialize.end != branch.offset
            or branch.end != increment.offset
            or len(branch.args) != 2
            or branch.args[1] != increment.end
        ):
            continue
        if not isinstance(branch.args[0], int):
            continue
        relation = _INTEGER_MATERIALIZED_RELATIONS.get(branch.args[0])
        system = resolve_expression(("memory", compare.args[0], "integer"), facts)
        if (
            relation is None
            or system is None
            or not isinstance(system.value, tuple)
            or system.value[:2] not in {("call", "ERR"), ("call", "ERL")}
        ):
            continue
        previous = operations[index - 1]
        start = (
            previous.offset
            if previous.kind == "movbxax" and previous.end == load.offset
            else load.offset
        )
        yield Fact(
            "expression.relation_value",
            (start, increment.end),
            (relation, system.value, ("const", load.args[0])),
            combine_evidence(
                tuple(
                    operation.offset
                    for operation in (*support, materialize, branch, increment)
                ),
                system.evidence,
                () if start == load.offset else (previous.offset,),
            ),
            "anchored",
        )


# ``cmp ax,bx`` with the function value in AX and the constant in BX.
AX_BX_RELATIONS = {
    0x72: "<",
    0x73: ">=",
    0x74: "=",
    0x75: "<>",
    0x76: "<=",
    0x77: ">",
    0x7C: "<",
    0x7D: ">=",
    0x7E: "<=",
    0x7F: ">",
}


def function_constant_compare(
    instructions: tuple[Operation, ...], index: int, facts: frozenset[Fact]
) -> tuple[int, Fact, int] | None:
    """Read ``cmp ax,bx`` of a numeric function call with a constant in BX.

    The constant is loaded into AX and register moves leave it in BX (a
    later term of a compound condition first saves the earlier truth, from
    ``mov bx,ax`` just before, in another register). The function call at
    ``index`` then leaves its value in AX. Returns the position the
    comparison starts at, the function's one agreeing value, and the
    constant.
    """
    call = instructions[index]
    if call.kind != "tb.function" or call.operands[:1] != ("numeric",):
        return None
    load = index - 1
    while load >= 0 and _register_move(instructions[load]) is not None:
        load -= 1
    if load < 0 or instructions[load].kind != "x86.mov_imm":
        return None
    register, constant = instructions[load].operands
    registers: dict[str, object] = {"ax": "constant"}
    for move in instructions[load + 1 : index]:
        destination, source = _register_move(move)
        registers[destination] = registers.get(source)
    if (
        register != "ax"
        or not isinstance(constant, int)
        or registers.get("bx") != "constant"
        or index + 1 >= len(instructions)
        or instructions[index + 1].raw != "3b c3"
    ):
        return None
    value = _agreeing_value(
        fact
        for fact in facts_by_kind(facts).get("expression.value", ())
        if fact.subject == (call.offset,)
    )
    if value is None:
        return None
    start = load
    if start > 0 and instructions[start - 1].raw == "89 c3":
        start -= 1
    if not _contiguous(instructions[start : index + 2]):
        return None
    return start, value, constant


def _agreeing_value(candidates: Iterable[Fact]) -> Fact | None:
    """Return the one value these facts agree on, refusing a disagreement."""
    matches = set(candidates)
    if not matches or len({fact.value for fact in matches}) != 1:
        return None
    return min(matches, key=lambda fact: (fact.subject, fact.evidence))


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "register.compare",
    "semantic.local",
    "semantic.sub_def",
    "slot",
    "tb.fn_call",
    "tb.fn_return",
    "tb.fp",
    "tb.fp_far",
    "tb.function",
    "tb.fwait",
    "tb.runtime",
    "tb.statement",
    "x86.cmp",
    "x86.inc",
    "x86.j",
    "x86.jg",
    "x86.jge",
    "x86.jl",
    "x86.jle",
    "x86.jmp",
    "x86.mov_acc_mem",
    "x86.mov_imm",
)
def materialized_integer_relation_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover a materialized integer relation without an FP compare fact."""

    yield from _compared_relations(evidence, facts)


def _compared_relations(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """``cmp ax,operand; ...; mov ax,-1; jcc +1; inc ax``: a relation's truth.

    Register moves between the compare and the materialization leave the
    flags alone, however the compiler rotates the pending truths of a
    compound condition, and moves before the relation's code belong to it
    too.
    """
    instructions = evidence.instructions
    position = {item.offset: index for index, item in enumerate(instructions)}
    for compared in facts_by_kind(facts).get("register.compare", ()):
        index = position.get(compared.subject[0])
        if index is None:
            continue
        cursor = index + 1
        while cursor < len(instructions) and _moves(instructions[cursor]):
            cursor += 1
        tail = instructions[cursor : cursor + 3]
        if len(tail) != 3 or not _contiguous(instructions[index : cursor + 3]):
            continue
        materialize, branch, increment = tail
        if (
            materialize.kind != "x86.mov_imm"
            or materialize.operands != ("ax", 0xFFFF)
            or not branch.kind.startswith("x86.j")
            or branch.operands != (increment.end,)
            or increment.raw != "40"
        ):
            continue
        relation = tracked_relation(compared, branch, facts)
        start = position.get(relation.start) if relation is not None else None
        if relation is None or start is None:
            continue
        while start > 0 and _moves(instructions[start - 1]):
            start -= 1
        if not _contiguous(instructions[start : cursor + 3]):
            continue
        yield Fact(
            "expression.relation_value",
            (instructions[start].offset, increment.end),
            relation.value,
            combine_evidence(
                relation.evidence,
                tuple(item.offset for item in instructions[start : cursor + 3]),
            ),
            "anchored",
        )


def tracked_relation(
    compared: Fact, branch: Operation, facts: frozenset[Fact]
) -> Resolved | None:
    """Return the relation a tracked ``cmp ax,operand`` and its jump test.

    The value is ``(REL, left, right)``, true when ``branch`` is taken.
    Turbo Basic leaves a relation's left operand in memory when it is a
    variable or a pooled constant and loads the right one into AX, so
    ``cmp ax,[m]`` is ``m REL AX`` with the jump mirrored; otherwise it
    loads the right operand first, saves it in BX, and ``cmp ax,bx`` is
    ``AX REL BX``. ``cmp [m],ax`` tests ``m REL AX`` as the jump reads. The
    relation starts at the first instruction computing either operand.
    """
    raw = bytes.fromhex(branch.raw)
    form = compared.value[2] if len(compared.value) > 2 else "memory"
    relation = (
        _INTEGER_MATERIALIZED_RELATIONS if form == "memory" else AX_BX_RELATIONS
    ).get(raw[0] if raw else -1)
    ax, other = (resolve_expression(value, facts) for value in compared.value[:2])
    if relation is None or ax is None or other is None:
        return None
    starts = [*compared.evidence]
    for value in compared.value[:2]:
        for call in _call_results_in(value):
            result = resolve_expression(call, facts)
            if result is None or result.start is None:
                return None
            starts.append(result.start)
    return Resolved(
        (relation, ax.value, other.value)
        if form == "bx"
        else (relation, other.value, ax.value),
        combine_evidence(compared.evidence, ax.evidence, other.evidence),
        min(starts),
    )


def _call_results_in(expression: object) -> list[object]:
    """Every call result a tracked expression holds."""
    if not isinstance(expression, tuple) or not expression:
        return []
    if expression[0] == "result":
        return [expression]
    return [call for part in expression[1:] for call in _call_results_in(part)]


def _moves(instruction: Operation) -> bool:
    """Whether an instruction only moves one register into another."""
    return _register_move(instruction) is not None


@reads(
    "constant",
    "expression.relation_value",
    "expression.system",
    "expression.value",
    "flow.branch",
    "flow.call",
    "flow.goto",
    "layout.array",
    "machine.store",
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
def compound_condition_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Combine adjacent relation facts into compound boolean conditions."""

    # A branch reaching in lands on code its own source runs without
    # evaluating anything before it, so a condition covering that destination
    # would be claiming instructions that are not part of it.  A condition
    # jumps within itself to short-circuit, and those jumps are its own
    # evidence, which is what separates them from one arriving from elsewhere.
    entries: dict[int, list[int]] = {}
    by_kind = facts_by_kind(facts)
    for kind in ("flow.call", "flow.goto", "flow.branch"):
        for fact in by_kind.get(kind, ()):
            source = fact.subject[0] if len(fact.subject) == 2 else None
            target = (
                fact.value[1]
                if kind == "flow.branch"
                else (fact.value[0] if fact.value else None)
            )
            if isinstance(source, int) and isinstance(target, int):
                entries.setdefault(target, []).append(source)
    targets = sorted(entries)
    # A jump that lands on a conditional jump hands it the flags it tested:
    # the short-circuit of a longer condition, not the target of this one.
    tests = {
        instruction.offset
        for instruction in evidence.instructions
        if instruction.kind.startswith("x86.j")
        and instruction.kind not in {"x86.jmp", "x86.jmp_far"}
    }
    for fact in _compound_conditions(evidence, facts):
        start, end = fact.subject
        if len(fact.value) > 2 and fact.value[2] in tests:
            continue
        covered = targets[bisect_right(targets, start) : bisect_left(targets, end)]
        support = frozenset(fact.evidence)
        if any(
            any(source not in support for source in entries[target])
            for target in covered
        ):
            continue
        yield fact


_REGISTERS = ("ax", "cx", "dx", "bx")
_GATES = {"23 c3": "AND", "21 d8": "AND", "0b c3": "OR", "09 d8": "OR"}


def _register_tracked_conditions(
    instructions: tuple[Operation, ...], relations: list[Fact]
) -> Iterable[Fact]:
    """Combine three or more adjacent truth values by following the registers.

    Each relation leaves its truth in AX.  A compound condition saves the
    earlier ones with register moves while it computes the next, and its
    gates combine whatever AX and BX then hold, so the condition is what the
    registers carry to the ``jne`` over the jump to the false target.  Every
    relation of the chain has to reach the gates exactly once.
    """
    position = {item.offset: index for index, item in enumerate(instructions)}
    offsets = [item.offset for item in instructions]
    # A relation's truth is complete after the ``inc ax`` it may end on.
    completing: dict[int, list[Fact]] = {}
    for relation in relations:
        end = relation.subject[1]
        index = position.get(end)
        if index is not None and instructions[index].raw == "40":
            end = instructions[index].end
        completing.setdefault(end, []).append(relation)
    for index in range(1, len(instructions) - 1):
        branch, jump = instructions[index], instructions[index + 1]
        if branch.raw != "75 03" or jump.kind != "x86.jmp" or not jump.operands:
            continue
        first_gate = index
        while first_gate > 0 and (
            instructions[first_gate - 1].raw in _GATES
            or _register_move(instructions[first_gate - 1]) is not None
        ):
            first_gate -= 1
        if instructions[first_gate].raw not in _GATES:
            continue
        chain: list[Fact] = []
        point = instructions[first_gate].offset
        while True:
            candidates = completing.get(point, [])
            if not candidates:
                # ``or ax,ax; jne +3; jmp test`` short-circuits an AND: the
                # jump reaches this condition's final test with AX false, and
                # otherwise the truth goes on in AX.
                skip = _short_circuit_before(instructions, position, point, branch)
                if skip is not None:
                    point = skip
                    continue
            if len({fact.value for fact in candidates}) != 1:
                break
            relation = min(candidates, key=lambda fact: (fact.subject, fact_key(fact)))
            chain.insert(0, relation)
            point = relation.subject[0]
        if len(chain) < 3:
            continue
        ends = {}
        for number, relation in enumerate(chain):
            end = relation.subject[1]
            at = position.get(end)
            if at is not None and instructions[at].raw == "40":
                end = instructions[at].end
            ends[end] = number
        start = bisect_left(offsets, chain[0].subject[0])
        condition = _track(instructions[start:index], ends)
        if condition is None or sorted(_leaves(condition)) != list(range(len(chain))):
            continue
        yield Fact(
            "control.compound_condition",
            (chain[0].subject[0], jump.end),
            (
                _render(condition, chain, top=True),
                0x75,
                jump.operands[0],
                branch.end,
            ),
            combine_evidence(
                *(relation.evidence for relation in chain),
                tuple(item.offset for item in instructions[start : index + 2]),
            ),
            "anchored",
        )


def _short_circuit_before(
    instructions: tuple[Operation, ...],
    position: dict[int, int],
    point: int,
    test: Operation,
) -> int | None:
    """Return where ``or ax,ax; jne +3; jmp test`` ending at ``point`` starts."""
    index = position.get(point)
    if index is None or index < 3:
        return None
    check, skip, jump = instructions[index - 3 : index]
    if (
        check.raw == "09 c0"
        and skip.raw == "75 03"
        and jump.kind == "x86.jmp"
        and jump.operands == (test.offset,)
        and jump.end == point
    ):
        return check.offset
    return None


def _register_move(operation: Operation) -> tuple[str, str] | None:
    """Return the (destination, source) of a ``mov r16,r16``."""
    parts = operation.raw.split()
    if len(parts) != 2 or parts[0] != "89":
        return None
    modrm = int(parts[1], 16)
    if modrm >> 6 != 3:
        return None
    source, destination = (modrm >> 3) & 7, modrm & 7
    if source >= 4 or destination >= 4:
        return None
    return _REGISTERS[destination], _REGISTERS[source]


def _track(operations: tuple[Operation, ...], ends: dict[int, int]) -> object | None:
    """Follow truth values through registers; return what AX holds at the end."""
    registers: dict[str, object] = {}
    for operation in operations:
        if operation.offset in ends:
            registers["ax"] = ends[operation.offset]
        move = _register_move(operation)
        if move is not None:
            destination, source = move
            registers[destination] = registers.get(source)
            continue
        gate = _GATES.get(operation.raw)
        if gate is not None:
            left, right = registers.get("ax"), registers.get("bx")
            registers["ax"] = (
                None if left is None or right is None else (gate, left, right)
            )
            continue
        # Compares, jumps and the truth test leave the registers as they are.
        if operation.kind in {"tb.runtime", "x86.cmp"} or operation.kind.startswith(
            "x86.j"
        ):
            continue
        if operation.raw == "09 c0":
            continue
        if operation.kind in {"x86.mov_imm", "x86.inc"} and operation.operands:
            registers[str(operation.operands[0])] = None
            continue
        if operation.raw in {"31 c0", "33 c0"}:
            registers["ax"] = None
            continue
        return None
    return registers.get("ax")


def _leaves(condition: object) -> list[int]:
    if isinstance(condition, int):
        return [condition]
    if isinstance(condition, tuple) and len(condition) == 3:
        return _leaves(condition[1]) + _leaves(condition[2])
    return [-1]


def _render(condition: object, chain: list[Fact], *, top: bool = False) -> object:
    if isinstance(condition, int):
        return chain[condition].value
    assert isinstance(condition, tuple)
    operator, left, right = condition
    rendered = (operator, _render(left, chain), _render(right, chain))
    return rendered if top else ("group", rendered)


def _compound_conditions(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    operations = translate_operations(evidence.instructions)
    indexes, by_offset = operation_indexes(operations)
    # Several relations can share a span, and the decisions built from them are
    # extended and completed against each other in list order, so the order has
    # to be total rather than only by span.
    relations = sorted(
        (
            fact
            for fact in facts
            if fact.kind == "expression.relation_value" and len(fact.subject) == 2
        ),
        key=lambda fact: (fact.subject, fact_key(fact)),
    )
    # A bare boolean term is materialized as ``mov ax,[scratch]; not ax;
    # or ax`` before its short-circuit branch.  It has no compare fact, but it
    # is still a valid relation value for the compound-condition machinery.
    for cursor, operation in enumerate(operations):
        if operation.kind != "orax" or cursor == 0:
            continue
        load = operations[cursor - 1]
        if load.kind != "movaxmem" or load.args != (0x2C,):
            continue
        # AX holds whatever the last store to the scratch word left there, so
        # the store has to be chosen by position rather than by set order.
        stored = latest_store(
            fact
            for fact in facts_by_kind(facts).get("machine.store", ())
            if fact.subject == (0x2C,)
            and fact.evidence
            and max(fact.evidence) <= load.offset
        )
        if stored is None or len(stored.value) != 1:
            continue
        bare_value = _resolve_bare_boolean(stored.value[0], facts)
        if bare_value is None:
            continue
        relations.append(
            Fact(
                "expression.relation_value",
                (load.offset, operation.end),
                (("unary", "NOT", bare_value.value),),
                combine_evidence(stored.evidence, (operation.offset,)),
                "anchored",
            )
        )
    relations.sort(key=lambda fact: (fact.subject, fact_key(fact)))
    yield from _register_tracked_conditions(evidence.instructions, relations)
    # Several values can share a start address, and keying them by that
    # address keeps only one, so the survivor is chosen by a total order
    # rather than by whichever the set happened to yield last.
    values: dict[int, Fact] = {}
    for fact in sorted(
        (
            fact
            for fact in facts_by_kind(facts).get("expression.value", ())
            if len(fact.subject) == 1 and isinstance(fact.value, tuple)
        ),
        key=fact_key,
    ):
        values.setdefault(fact.subject[0], fact)
    for relation in relations:
        gate = by_offset.get(relation.subject[1])
        if gate is None or gate.kind != "andaxbx":
            continue
        gate_index = indexes.get(gate.offset)
        if gate_index is None or gate_index < 3:
            continue
        branch, jump = operations[gate_index + 1 : gate_index + 3]
        if (
            branch.kind != "jcc"
            or branch.args[0] != 0x75
            or jump.kind != "jmp"
            or len(jump.args) != 1
        ):
            continue
        first_index = next(
            (
                cursor
                for cursor in range(gate_index - 1, -1, -1)
                if operations[cursor].kind == "orax"
            ),
            None,
        )
        if first_index is None or first_index + 2 >= gate_index:
            continue
        first_branch = operations[first_index + 1 : first_index + 3]
        if (
            first_branch[0].kind != "jcc"
            or first_branch[0].args[0] != 0x75
            or first_branch[1].kind != "jmp"
        ):
            continue
        first_value = max(
            (
                fact
                for offset, fact in values.items()
                if offset < first_branch[0].offset
            ),
            key=lambda fact: (fact.subject[0], fact_key(fact)),
            default=None,
        )
        if first_value is None:
            continue
        if isinstance(first_value.value[0], tuple) and first_value.value[0][:1] == (
            "memory",
        ):
            call_value = next(
                (
                    fact
                    for fact in facts
                    if fact.kind == "expression.value"
                    and fact.subject[0] == first_value.subject[0]
                    and isinstance(fact.value[0], tuple)
                    and fact.value[0][:1] == ("call",)
                ),
                None,
            )
            if call_value is not None:
                first_value = call_value
        yield Fact(
            "control.compound_condition",
            (first_value.subject[0], jump.end),
            (
                ("AND", first_value.value[0], relation.value),
                0x75,
                jump.args[0],
                branch.args[1],
            ),
            combine_evidence(
                first_value.evidence,
                relation.evidence,
                (gate.offset, branch.offset, jump.offset),
            ),
            "anchored",
        )
    # String CASE dispatches can materialize two adjacent equality tests by
    # incrementing each comparison result before combining the flags.  The
    # relation span therefore ends immediately before the logical gate rather
    # than at the gate itself.
    for first, second in zip(relations, relations[1:]):
        if second.subject[0] < first.subject[1]:
            continue
        gate = next(
            (
                operation
                for operation in operations
                if operation.offset >= second.subject[1] and operation.kind == "oraxbx"
            ),
            None,
        )
        if gate is None:
            continue
        gate_index = indexes.get(gate.offset)
        if gate_index is None:
            continue
        combine_op = (
            operations[gate_index + 1] if gate_index + 1 < len(operations) else None
        )
        branch_op = (
            operations[gate_index + 2] if gate_index + 2 < len(operations) else None
        )
        jump_op = (
            operations[gate_index + 3] if gate_index + 3 < len(operations) else None
        )
        if (
            combine_op is None
            or combine_op.kind != "andaxbx"
            or branch_op is None
            or branch_op.kind != "jcc"
            or jump_op is None
            or jump_op.kind != "jmp"
            or len(branch_op.args) != 2
            or len(jump_op.args) != 1
            or branch_op.args[0] != 0x75
        ):
            continue
        assert combine_op is not None and branch_op is not None and jump_op is not None
        yield Fact(
            "control.compound_condition",
            (first.subject[0], jump_op.end),
            (
                ("OR", first.value, second.value),
                branch_op.args[0],
                jump_op.args[0],
                branch_op.args[1],
            ),
            combine_evidence(
                first.evidence,
                second.evidence,
                (gate.offset, combine_op.offset, branch_op.offset, jump_op.offset),
            ),
            "anchored",
        )
    if len(relations) >= 3:
        for first, second, third in zip(relations, relations[1:], relations[2:]):
            or_gate = by_offset.get(first.subject[1])
            and_gate = by_offset.get(third.subject[1])
            if or_gate is None or and_gate is None:
                continue
            if or_gate.kind != "orax" or and_gate.kind != "andaxbx":
                continue
            or_index = indexes[or_gate.offset]
            and_index = indexes[and_gate.offset]
            if or_index + 2 >= len(operations) or and_index + 2 >= len(operations):
                continue
            or_branch, or_jump = operations[or_index + 1 : or_index + 3]
            and_branch, and_jump = operations[and_index + 1 : and_index + 3]
            if (
                or_branch.kind != "jcc"
                or or_jump.kind != "jmp"
                or and_branch.kind != "jcc"
                or and_jump.kind != "jmp"
                or or_jump.args[0] != and_gate.offset + 2
                or not isinstance(and_jump.args[0], int)
                or not isinstance(and_branch.args[1], int)
                or and_jump.args[0] <= and_branch.args[1]
            ):
                continue
            if second.subject[0] > first.subject[1] and and_branch.args[0] == 0x75:
                yield Fact(
                    "control.compound_condition",
                    (first.subject[0], and_jump.args[0]),
                    (
                        ("AND", first.value, second.value),
                        0x75,
                        and_jump.args[0],
                        and_branch.args[1],
                    ),
                    combine_evidence(
                        first.evidence,
                        second.evidence,
                        (and_gate.offset, and_branch.offset, and_jump.offset),
                    ),
                    "anchored",
                )
            # One materialized comparison yields two relation values, and the
            # pair overlaps whichever way it is built: a string compare gives
            # the bare relation ending at its logical gate and a grouped one
            # ending a byte earlier at the `incax`, sharing a start; an integer
            # compare gives two readings that share the gate but begin at
            # different operand loads.  Either pair is one comparison read
            # twice, so spending it as two operands invents a term.  Three
            # operands need three comparisons, which is the adjacency the pair
            # builders above already require.
            if (
                second.subject[0] < first.subject[1]
                or third.subject[0] < second.subject[1]
            ):
                continue
            yield Fact(
                "control.compound_condition",
                (first.subject[0], and_branch.args[1]),
                (
                    ("OR", first.value, ("group", ("AND", second.value, third.value))),
                    and_branch.args[0],
                    and_jump.args[0],
                    and_branch.args[1],
                ),
                combine_evidence(
                    first.evidence,
                    second.evidence,
                    third.evidence,
                    (
                        or_gate.offset,
                        or_branch.offset,
                        or_jump.offset,
                        and_gate.offset,
                        and_branch.offset,
                        and_jump.offset,
                    ),
                ),
                "anchored",
            )
    for first, second in zip(relations, relations[1:]):
        if second.subject[0] < first.subject[1]:
            continue
        gate = by_offset.get(second.subject[1])
        if gate is None or gate.kind not in {"andaxbx", "orax"}:
            continue
        first_gate = by_offset.get(first.subject[1])
        first_index = indexes.get(first_gate.offset) if first_gate is not None else None
        if (
            first_gate is None
            or first_index is None
            or first_index + 2 >= len(operations)
        ):
            continue
        first_jump = operations[first_index + 2]
        if first_jump.kind != "jmp" or first_jump.args not in {
            (gate.offset,),
            (gate.offset + 2,),
        }:
            continue
        gate_index = indexes.get(gate.offset)
        if gate_index is None or gate_index + 2 >= len(operations):
            continue
        branch, jump = operations[gate_index + 1 : gate_index + 3]
        if (
            branch.kind != "jcc"
            or jump.kind != "jmp"
            or len(branch.args) != 2
            or len(jump.args) != 1
        ):
            continue
        operator = "AND" if gate.kind == "andaxbx" else "OR"
        yield Fact(
            "control.compound_condition",
            (first.subject[0], branch.args[1]),
            (
                (operator, first.value, second.value),
                branch.args[0],
                jump.args[0],
                branch.args[1],
            ),
            combine_evidence(
                first.evidence,
                second.evidence,
                (gate.offset, branch.offset, jump.offset),
            ),
            "anchored",
        )
    for cursor, gate in enumerate(operations):
        if gate.kind != "orax" or cursor == 0:
            continue
        load = operations[cursor - 1]
        if load.kind != "movaxmem" or load.args != (0x2C,):
            continue
        # AX holds whatever the last store to the scratch word left there, so
        # the store has to be chosen by position rather than by set order.
        stored = latest_store(
            fact
            for fact in facts_by_kind(facts).get("machine.store", ())
            if fact.subject == (0x2C,)
            and fact.evidence
            and max(fact.evidence) <= load.offset
        )
        branch_op = operations[cursor + 1] if cursor + 1 < len(operations) else None
        jump_op = operations[cursor + 2] if cursor + 2 < len(operations) else None
        second_relation = next(
            (
                fact
                for fact in relations
                if fact.subject[0] <= (jump_op.end if jump_op else -1) < fact.subject[1]
            ),
            None,
        )
        final_gate = (
            by_offset.get(second_relation.subject[1])
            if second_relation is not None
            else None
        )
        final_index = indexes.get(final_gate.offset) if final_gate is not None else None
        final_branch = (
            operations[final_index + 1]
            if final_index is not None and final_index + 1 < len(operations)
            else None
        )
        final_jump = (
            operations[final_index + 2]
            if final_index is not None and final_index + 2 < len(operations)
            else None
        )
        if not all(
            (
                stored,
                branch_op,
                jump_op,
                second_relation,
                final_gate,
                final_branch,
                final_jump,
            )
        ):
            continue
        assert stored is not None
        assert (
            branch_op is not None
            and jump_op is not None
            and second_relation is not None
        )
        assert (
            final_gate is not None
            and final_branch is not None
            and final_jump is not None
        )
        bare_value = _resolve_bare_boolean(stored.value[0], facts)
        if bare_value is None:
            continue
        if (
            branch_op.args[0] != 0x74
            or final_branch.args[0] != 0x74
            or final_jump.kind != "jmp"
        ):
            continue
        yield Fact(
            "control.compound_condition",
            (load.offset, final_jump.end),
            (
                ("OR", ("unary", "NOT", bare_value.value), second_relation.value),
                final_branch.args[0],
                final_jump.args[0],
                final_jump.end,
            ),
            combine_evidence(
                stored.evidence,
                bare_value.evidence,
                second_relation.evidence,
                (
                    load.offset,
                    gate.offset,
                    branch_op.offset,
                    jump_op.offset,
                    final_gate.offset,
                    final_branch.offset,
                    final_jump.offset,
                ),
            ),
            "anchored",
        )
    raw_decisions: list[tuple[Fact, bool]] = []
    for first in relations:
        decision = _short_circuit_decision(
            first, relations, operations, indexes, by_offset
        )
        if decision is None:
            decision = _value_group_decision(
                first, relations, operations, indexes, by_offset
            )
        prefix_only = False
        if decision is None:
            decision = _relation_branch_decision(first, operations, indexes, by_offset)
            prefix_only = decision is not None
        if decision is not None:
            raw_decisions.append((decision, prefix_only))

    emitted: set[Fact] = set()
    decisions = [decision for decision, _prefix_only in raw_decisions]
    for decision, prefix_only in raw_decisions:
        extended = _extend_decision(decision, decisions, by_offset)
        if not _complete_decision(extended, facts, decisions, by_offset):
            continue
        if prefix_only and extended == decision:
            extended = Fact(
                "control.condition_prefix",
                extended.subject,
                extended.value,
                extended.evidence,
                extended.confidence,
            )
        if extended in emitted:
            continue
        emitted.add(extended)
        yield extended


@reads("control.compound_condition", "control.condition_prefix")
def inline_if_region_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover inline IF regions from condition-prefix facts."""

    prefixes = tuple(
        fact
        for fact in facts
        if fact.kind == "control.condition_prefix"
        and len(fact.value) == 4
        and len(fact.subject) == 2
    )
    for decision in facts:
        if (
            decision.kind != "control.compound_condition"
            or len(decision.value) != 4
            or not isinstance(decision.value[0], tuple)
            or decision.value[0][:1] != ("AND",)
        ):
            continue
        condition, polarity, target, body_start = decision.value
        if (
            polarity != 0x75
            or not isinstance(target, int)
            or not isinstance(body_start, int)
        ):
            continue
        for prefix in prefixes:
            if prefix.subject[1] != decision.subject[0]:
                continue
            prefix_condition = prefix.value[0]
            combined = (
                ("AND", ("AND", prefix_condition, condition[1]), condition[2])
                if len(condition) == 3
                else ("AND", prefix_condition, condition)
            )
            yield Fact(
                "region.if_inline",
                (prefix.subject[0], target),
                (combined, body_start, target),
                combine_evidence(prefix.evidence, decision.evidence),
                "anchored",
            )

    for decision in facts:
        if decision.kind != "control.compound_condition" or len(decision.value) != 4:
            continue
        condition, polarity, target, body_start = decision.value
        if (
            polarity == 0x75
            and isinstance(target, int)
            and isinstance(body_start, int)
            and target > body_start
        ):
            yield Fact(
                "region.if_inline",
                (decision.subject[0], target),
                (condition, body_start, target),
                decision.evidence,
                "anchored",
            )


@reads(
    "constant",
    "control.compound_condition",
    "expression.relation_value",
    "expression.system",
    "layout.array",
    "semantic.if_goto_condition",
    "semantic.print",
    "semantic.statement",
    "slot",
)
def compound_if_goto_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover compound IF statements that branch to a shared target."""

    outer = [
        fact
        for fact in facts
        if fact.kind == "semantic.if_goto_condition"
        and len(fact.value) == 3
        and isinstance(fact.value[1], int)
        and isinstance(fact.value[2], int)
    ]
    for decision in outer:
        condition, body_start, false_target = decision.value
        condition = _normalize_boolean_condition(
            _prefer_boolean_slots(condition, facts)
        )
        if (
            not isinstance(condition, tuple)
            or len(condition) != 3
            or condition[0] != "<>"
        ):
            continue
        relation_facts = [
            fact
            for fact in facts
            if fact.kind == "expression.relation_value"
            and len(fact.value) == 2
            and fact.value[0] == "group"
            and isinstance(fact.value[1], tuple)
            and len(fact.value[1]) == 3
            and isinstance(fact.subject[0], int)
            and body_start <= fact.subject[0] < false_target
        ]
        # The AND's second operand is evaluated where the truth test
        # continues, so its first relation starts at ``body_start`` and the
        # second is the next one after it.  Relations anywhere else in the
        # range belong to other statements.
        firsts = {
            fact.value[1] for fact in relation_facts if fact.subject[0] == body_start
        }
        if len(firsts) != 1:
            continue
        left_fact = min(
            (fact for fact in relation_facts if fact.subject[0] == body_start),
            key=lambda fact: (fact.subject, fact_key(fact)),
        )
        followers = [
            fact
            for fact in relation_facts
            if len(left_fact.subject) == 2 and fact.subject[0] >= left_fact.subject[1]
        ]
        if not followers:
            continue
        nearest = min(fact.subject[0] for fact in followers)
        right_values = {
            fact.value[1] for fact in followers if fact.subject[0] == nearest
        }
        if len(right_values) != 1:
            continue
        left, right = left_fact.value[1], next(iter(right_values))
        if not (
            left[1] == right[1]
            and frozenset((left[0], right[0]))
            in {frozenset(("=",)), frozenset(("<", ">")), frozenset(("<=", ">="))}
            and left[2] != right[2]
        ):
            continue
        nested = ("OR", left, right)
        resolved_condition = _normalize_boolean_condition(("AND", condition[1], nested))
        body = sorted(
            (
                fact
                for fact in facts
                if fact.kind == "semantic.print"
                and len(fact.subject) == 2
                and isinstance(fact.subject[0], int)
                and fact.subject[0] > false_target
            ),
            key=lambda fact: (fact.subject[0], fact_key(fact)),
        )
        if not body:
            continue
        body_start = body[0].subject[0]
        next_decision = min(
            (fact.subject[0] for fact in outer if fact.subject[0] > body_start),
            default=None,
        )
        body_end = next_decision or min(
            (
                fact.subject[0]
                for fact in facts
                if fact.kind == "semantic.statement"
                and fact.value[:1] == ("END",)
                and len(fact.subject) == 2
                and fact.subject[0] > body_start
            ),
            default=false_target,
        )
        yield Fact(
            "semantic.if_inline",
            decision.subject,
            (resolved_condition, body_start, body_end, None),
            decision.evidence,
            "anchored",
        )

    for decision in facts:
        if decision.kind != "control.compound_condition" or len(decision.value) != 4:
            continue
        condition, polarity, target, false_target = decision.value
        if (
            polarity != 0x74
            or not isinstance(condition, tuple)
            or not isinstance(target, int)
            or target < decision.subject[0]
        ):
            continue
        if len(condition) != 3:
            yield Fact(
                "semantic.if_goto_condition",
                decision.subject,
                (condition, target, false_target),
                decision.evidence,
                "anchored",
            )
            continue
        yield Fact(
            "semantic.if_goto",
            decision.subject,
            (*condition, target, false_target),
            decision.evidence,
            "anchored",
        )


@reads(
    "control.compound_condition",
    "flow.branch",
    "flow.goto",
    "region.if_inline",
    "semantic.",
    "semantic.def_fn",
    "semantic.goto",
    "semantic.if_goto",
    "semantic.if_goto_condition",
    "semantic.if_inline",
    "semantic.sub_def",
)
def region_body_goto_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover the source body and target of structured IF regions."""

    flows = [
        fact
        for fact in facts
        if fact.kind == "flow.goto"
        and len(fact.subject) == 2
        and len(fact.value) == 1
        and isinstance(fact.value[0], int)
    ]
    semantic = [fact for fact in facts if fact.kind.startswith("semantic.")]
    by_kind = facts_by_kind(facts)
    for region in facts:
        if region.kind != "region.if_inline" or len(region.value) != 3:
            continue
        _condition, body_start, body_end = region.value
        if not isinstance(body_start, int) or not isinstance(body_end, int):
            continue
        for flow in flows:
            source = flow.subject[0]
            if not isinstance(source, int) or not body_start < source < body_end:
                continue
            predecessor = [
                fact
                for fact in semantic
                if fact.kind not in {"semantic.if_inline", "semantic.if_goto"}
                and len(fact.subject) == 2
                and fact.subject[1] == source
                and _inside(fact, body_start, body_end)
            ]
            owned = any(
                source in fact.evidence
                for kind in (
                    "control.compound_condition",
                    "semantic.if_goto",
                    "semantic.if_goto_condition",
                )
                for fact in by_kind.get(kind, ())
            )
            if len(predecessor) != 1 or owned:
                continue
            yield Fact(
                "semantic.goto",
                flow.subject,
                flow.value,
                combine_evidence(
                    flow.evidence,
                    predecessor[0].evidence,
                    region.evidence,
                ),
                "anchored",
            )

    # A plain top-level GOTO has no enclosing inline region to provide the
    # ownership context above.  Preserve it directly, while leaving jumps
    # already consumed by an IF/GOTO template inside that template's span.
    consumed = tuple(
        fact
        for fact in facts
        if fact.kind in {"semantic.if_goto", "semantic.if_goto_condition"}
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    )
    existing = {fact.subject for fact in facts if fact.kind == "semantic.goto"}
    # An IF template branches over its jump to the false arm; a branch
    # elsewhere leaves the jump after it a GOTO of its own.
    skipped = {
        (fact.subject[1], fact.value[1])
        for fact in facts
        if fact.kind == "flow.branch"
        and len(fact.subject) == 2
        and isinstance(fact.subject[1], int)
        and len(fact.value) == 2
    }
    procedure_entries = {
        (fact.subject[0], fact.subject[1])
        for fact in facts
        if fact.kind == "semantic.sub_def"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    }
    procedure_entries |= {
        (fact.subject[0], fact.subject[1])
        for fact in facts
        if fact.kind == "semantic.def_fn"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    }
    for flow in flows:
        if flow.subject in existing:
            continue
        source, end = flow.subject
        if (source, flow.value[0]) in procedure_entries:
            continue
        if (source, end) in skipped:
            continue
        if any(
            item.subject[0] <= source and end <= item.subject[1] for item in consumed
        ):
            continue
        yield Fact(
            "semantic.goto",
            flow.subject,
            flow.value,
            flow.evidence,
            "anchored",
        )


@reads(
    "constant",
    "expression.system",
    "layout.array",
    "region.if_inline",
    "semantic.",
    "semantic.if_inline",
    "slot",
)
def inline_if_semantic_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Convert recovered inline IF regions into semantic statement facts."""

    for region in facts:
        if region.kind != "region.if_inline" or len(region.value) != 3:
            continue
        condition, body_start, body_end = region.value
        condition = _normalize_boolean_condition(
            _prefer_boolean_slots(condition, facts)
        )
        if not isinstance(body_start, int) or not isinstance(body_end, int):
            continue
        body = [
            fact
            for fact in facts
            if fact.kind.startswith("semantic.")
            and fact.kind != "semantic.if_inline"
            and _inside(fact, body_start, body_end)
        ]
        if not body:
            continue
        yield Fact(
            "semantic.if_inline",
            region.subject,
            (condition, body_start, body_end, None),
            combine_evidence(region.evidence, *(fact.evidence for fact in body)),
            "anchored",
        )


def _short_circuit_decision(
    first: Fact,
    relations: list[Fact],
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_offset: dict[int, CompilerOp],
) -> Fact | None:
    gate_op = by_offset.get(first.subject[1])
    tail = _following(operations, indexes, gate_op, 2)
    if gate_op is None or gate_op.kind != "orax" or tail is None:
        return None
    dispatch_op, jump_op = tail
    if not _dispatch_pair(dispatch_op, jump_op):
        return None
    if not isinstance(dispatch_op.args[0], int):
        return None
    logical = _LOGICAL_GATES.get(dispatch_op.args[0])
    if logical is None:
        return None
    operator, _combine_kind = logical
    matched = _next_term(relations, by_offset, jump_op, logical)
    if matched is None:
        return None
    second, combine_op = matched
    condition = (operator, first.value, second.value)
    support_facts = [first, second]
    support_ops = [gate_op, dispatch_op, jump_op, combine_op]
    while True:
        final = _following(operations, indexes, combine_op, 2)
        if final is None:
            return None
        final_dispatch_op, final_jump_op = final
        if not _dispatch_pair(final_dispatch_op, final_jump_op):
            return None
        support_ops.extend(final)
        join = (
            _LOGICAL_GATES.get(final_dispatch_op.args[0])
            if isinstance(final_dispatch_op.args[0], int)
            else None
        )
        continuation = (
            None
            if join is None
            else _next_term(relations, by_offset, final_jump_op, join)
        )
        if continuation is None:
            return _decision(
                first,
                support_facts,
                condition,
                final_dispatch_op,
                final_jump_op,
                support_ops,
            )
        assert join is not None
        following, combine_op = continuation
        condition = (join[0], condition, following.value)
        support_facts.append(following)
        support_ops.append(combine_op)


def _value_group_decision(
    first: Fact,
    relations: list[Fact],
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_offset: dict[int, CompilerOp],
) -> Fact | None:
    candidates = []
    for second in relations:
        if second.subject[0] != first.subject[1]:
            continue
        combine = by_offset.get(second.subject[1])
        final = _following(operations, indexes, combine, 2)
        if combine is None or combine.kind not in _VALUE_COMBINERS or final is None:
            continue
        final_dispatch, final_jump = final
        if _dispatch_pair(final_dispatch, final_jump):
            candidates.append((second, combine, final_dispatch, final_jump))
    if len(candidates) != 1:
        return None
    second, combine, final_dispatch, final_jump = candidates[0]
    operator = _VALUE_COMBINERS[combine.kind]
    first_string = _uses_operation(first, operations, "strcmp")
    second_string = _uses_operation(second, operations, "strcmp")
    if first_string != second_string:
        return None

    left = second.value if first_string else ("group", second.value)
    right = first.value if first_string else ("group", first.value)
    condition = ("group", (operator, left, right))
    return _decision(
        first,
        [first, second],
        condition,
        final_dispatch,
        final_jump,
        [combine, final_dispatch, final_jump],
    )


def _relation_branch_decision(
    relation: Fact,
    operations: tuple[CompilerOp, ...],
    indexes: dict[int, int],
    by_offset: dict[int, CompilerOp],
) -> Fact | None:

    gate = by_offset.get(relation.subject[1])
    tail = _following(operations, indexes, gate, 2)
    if gate is None or gate.kind != "orax" or tail is None:
        return None
    dispatch, jump = tail
    if not _dispatch_pair(dispatch, jump) or dispatch.args[0] not in _LOGICAL_GATES:
        return None
    return _decision(
        relation,
        [relation],
        relation.value,
        dispatch,
        jump,
        [gate, dispatch, jump],
    )


def _extend_decision(
    first: Fact,
    decisions: list[Fact],
    by_offset: dict[int, CompilerOp],
) -> Fact:

    decision = first
    consumed = {first.subject}
    while True:
        condition, polarity, target, false_target = decision.value
        logical = _LOGICAL_GATES.get(polarity)
        if logical is None or not isinstance(target, int):
            return decision
        matches = [
            candidate
            for candidate in decisions
            if candidate.subject not in consumed
            and candidate.subject[0] == false_target
            and _decision_converges_at(candidate, target, by_offset)
        ]
        if len(matches) != 1:
            return decision
        following = matches[0]
        next_condition, next_polarity, next_target, next_false = following.value
        decision = Fact(
            "control.compound_condition",
            (decision.subject[0], following.subject[1]),
            (
                (logical[0], condition, next_condition),
                next_polarity,
                next_target,
                next_false,
            ),
            combine_evidence(decision.evidence, following.evidence),
            "anchored",
        )
        consumed.add(following.subject)


def _decision_converges_at(
    decision: Fact,
    target: int,
    by_offset: dict[int, CompilerOp],
) -> bool:

    at_target = by_offset.get(target)
    before_target = by_offset.get(target - 2)
    return (
        at_target is not None
        and at_target.kind == "orax"
        and at_target.offset in decision.evidence
    ) or (
        before_target is not None
        and before_target.kind in _VALUE_COMBINERS
        and before_target.end == target
        and before_target.offset in decision.evidence
    )


def _decision(
    first: Fact,
    relations: list[Fact],
    condition: object,
    dispatch: CompilerOp,
    jump: CompilerOp,
    operations: list[CompilerOp],
) -> Fact:
    return Fact(
        "control.compound_condition",
        (first.subject[0], jump.end),
        (condition, dispatch.args[0], jump.args[0], jump.end),
        combine_evidence(
            *(relation.evidence for relation in relations),
            tuple(operation.offset for operation in operations),
        ),
        "anchored",
    )


def _next_term(
    relations: list[Fact],
    by_offset: dict[int, CompilerOp],
    jump: CompilerOp,
    logical: tuple[str, str],
) -> tuple[Fact, CompilerOp] | None:
    operator, combine_kind = logical
    matches = []
    for relation in relations:
        if not (relation.subject[0] <= jump.end < relation.subject[1]):
            continue
        combine = by_offset.get(relation.subject[1])
        if (
            combine is not None
            and combine.kind == combine_kind
            and jump.args[0] == combine.offset + (2 if operator == "AND" else 0)
            and relation.subject[0] <= jump.end < relation.subject[1]
        ):
            matches.append((relation, combine))
    return matches[0] if len(matches) == 1 else None


def _uses_operation(fact: Fact, operations: tuple[CompilerOp, ...], kind: str) -> bool:
    return any(
        operation.kind == kind and operation.offset in fact.evidence
        for operation in operations
    )


def _complete_decision(
    decision: Fact,
    facts: frozenset[Fact],
    decisions: list[Fact],
    by_offset: dict[int, CompilerOp],
) -> bool:

    start, end = decision.subject
    _condition, _polarity, target, false_target = decision.value
    if not all(isinstance(value, int) for value in (start, end, target, false_target)):
        return False

    if any(
        fact.kind == "flow.goto"
        and len(fact.subject) == 2
        and len(fact.value) == 1
        and isinstance(fact.subject[0], int)
        and isinstance(fact.value[0], int)
        # A jump into the decision splits it; one to its end lands on the
        # statement after it.
        and fact.subject[0] < start < fact.value[0] < end
        for fact in facts_by_kind(facts).get("flow.goto", ())
    ):
        return False

    # A relation at the body boundary is only a compound continuation when its
    # decision converges at this decision's target. Nested block IFs begin at
    # the same address but converge at their own target (TBX t1_nestelse and
    # t1_nestif2); suppressing solely by adjacency loses the outer block.
    return not any(
        candidate.subject[0] == false_target
        and _decision_converges_at(candidate, target, by_offset)
        for candidate in decisions
        if candidate.subject != decision.subject
    )


def _dispatch_pair(branch: CompilerOp, jump: CompilerOp) -> bool:
    return (
        branch.kind == "jcc"
        and len(branch.args) == 2
        and jump.kind == "jmp"
        and len(jump.args) == 1
        and branch.args[1] == jump.end
    )


REGION_FACT_PASSES: tuple[NamedPass, ...] = (
    ("materialized-relations", materialized_relation_facts),
    ("materialized-system-relations", materialized_system_relation_facts),
    ("materialized-integer-relations", materialized_integer_relation_facts),
    ("compound-conditions", compound_condition_facts),
    ("block-if-regions", block_if_region_facts),
    ("inline-if-regions", inline_if_region_facts),
    ("compound-if-gotos", compound_if_goto_facts),
    ("region-body-gotos", region_body_goto_facts),
    ("inline-if-semantics", inline_if_semantic_facts),
    ("block-if-semantics", block_if_semantic_facts),
    ("block-body-gotos", block_body_goto_facts),
)
