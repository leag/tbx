"""Resolve symbolic expressions while preserving compiler evidence."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from tbd.cache import identity_cache
from tbd.ir import Fact

_PRECEDENCE = {"+": 5, "-": 5, "*": 8, "/": 8}


@identity_cache
def _fact_index(
    facts: frozenset[Fact],
) -> dict[tuple[str, tuple[object, ...]], Fact | None]:
    """Index a fact snapshot once, preserving duplicate detection."""
    index: dict[tuple[str, tuple[object, ...]], Fact | None] = {}
    for fact in facts:
        lookup = fact.kind, fact.subject
        if lookup in index:
            index[lookup] = None
        else:
            index[lookup] = fact
    return index


@identity_cache
def _array_layouts(facts: frozenset[Fact]) -> tuple[Fact, ...]:
    """Select unique array layouts without rescanning unrelated facts."""
    return tuple(
        fact
        for (kind, _subject), fact in _fact_index(facts).items()
        if kind == "layout.array" and fact is not None
    )


@dataclass(frozen=True)
class Resolved:
    """An expression value together with its source offsets."""

    value: object
    evidence: tuple[int, ...] = ()
    start: int | None = None


def resolve_expression(value: Any, facts: frozenset[Fact]) -> Resolved | None:
    """Resolve a symbolic expression using the available facts."""
    if not isinstance(value, tuple):
        return Resolved(value)
    if value and value[0] == "memory":
        return _resolve_memory(value, facts)
    if value and value[0] in _FRAME_WORDS:
        return _resolve_frame(value, facts)
    if value and value[0] == "binary" and len(value) == 4:
        return _resolve_binary(value, facts)
    if value and value[0] == "unary" and len(value) == 3:
        operand = resolve_expression(value[2], facts)
        if operand is None:
            return None
        return Resolved(
            ("unary", value[1], operand.value),
            operand.evidence,
        )
    if value and value[0] in {"const", "string"}:
        return Resolved(value)
    if value and value[0] == "result" and len(value) == 2:
        return _call_results(facts).get(value[1])
    if value and value[0] == "call" and len(value) == 3:
        if not isinstance(value[2], tuple):
            return None
        arguments = tuple(resolve_expression(argument, facts) for argument in value[2])
        if any(argument is None for argument in arguments):
            return None
        resolved = tuple(argument for argument in arguments if argument is not None)
        return Resolved(
            ("call", value[1], tuple(argument.value for argument in resolved)),
            combine_evidence(*(argument.evidence for argument in resolved)),
        )
    if value and value[0] in {
        "array",
        "slot",
        "var",
        "fn-param",
        "fn-local",
        "fn-local-array",
        "fn-local-array-element",
        "proc-param",
        "proc-local",
        "proc-array-element",
    }:
        return Resolved(value)
    if value and value[0] == "fn-call" and len(value) in {3, 4}:
        if not isinstance(value[2], tuple):
            return None
        arguments = tuple(resolve_expression(argument, facts) for argument in value[2])
        if any(argument is None for argument in arguments):
            return None
        resolved = tuple(argument for argument in arguments if argument is not None)
        return Resolved(
            (
                "fn-call",
                value[1],
                tuple(argument.value for argument in resolved),
                *value[3:],
            ),
            combine_evidence(*(argument.evidence for argument in resolved)),
        )
    return None


_CALL_REACH = 64


@identity_cache
def _call_results(facts: frozenset[Fact]) -> dict[int, Resolved]:
    """Map each call instruction to the one value recovered for it.

    A call's value fact starts at its operands' code, shortly before the
    call, and names the call in its evidence; the evidence also lists every
    reference to the slots it reads, so only calls near the start count.
    """
    found: dict[int, set[tuple[object, int]]] = {}
    evidence: dict[tuple[int, object], tuple[int, ...]] = {}
    for fact in _expression_candidates(facts):
        if (
            fact.kind != "expression.value"
            or len(fact.value) != 1
            or not isinstance(fact.value[0], tuple)
            or fact.value[0][:1] != ("call",)
            or not isinstance(fact.subject[0], int)
            # A value built on a call result is not that call's own value.
            or "'result'" in repr(fact.value[0])
        ):
            continue
        start = fact.subject[0]
        for offset in fact.evidence:
            if 0 <= offset - start <= _CALL_REACH:
                found.setdefault(offset, set()).add((fact.value[0], start))
                evidence[(offset, fact.value[0])] = fact.evidence
    return {
        offset: Resolved(value, evidence[(offset, value)], start)
        for offset, values in found.items()
        if len({value for value, _start in values}) == 1
        for value, start in [min(values, key=repr)]
    }


def resolve_slot(address: object, facts: frozenset[Fact]) -> Resolved | None:
    """Resolve a variable-slot address to its symbolic slot expression."""
    if not isinstance(address, int):
        return None
    slot = unique_fact(facts, "slot", (address,)) or agreeing_fact(
        facts, "slot", (address,)
    )
    if slot is None:
        return None
    return Resolved(("slot", slot.value[0], address), slot.evidence)


@lru_cache(maxsize=16_384)
def resolve_array_element(address: object, facts: frozenset[Fact]) -> Resolved | None:
    """Resolve a linear array address when exactly one layout matches."""
    if not isinstance(address, int):
        return None
    matches = []
    for fact in _array_layouts(facts):
        if len(fact.value) != 7:
            continue
        _order, name, bounds, _kind, base, element_size, count = fact.value
        if not all(isinstance(value, int) for value in (base, element_size, count)):
            continue
        relative = address - base
        if relative < 0 or relative >= element_size * count:
            continue
        if relative % element_size:
            continue
        indices = _array_indices(relative // element_size, bounds)
        if indices is not None:
            matches.append((fact, indices))
    if len(matches) != 1:
        return None
    fact, indices = matches[0]
    return Resolved(
        ("array", fact.value[1], tuple(("const", index) for index in indices)),
        fact.evidence,
    )


def resolve_string(address: object, facts: frozenset[Fact]) -> Resolved | None:
    """Resolve a string-pool address to its unique constant."""
    if not isinstance(address, int):
        return None
    constant = unique_fact(facts, "constant", ("string", address))
    return Resolved(constant.value, constant.evidence) if constant else None


@identity_cache
def _grouped(
    facts: frozenset[Fact],
) -> dict[tuple[str, tuple[object, ...]], list[Fact]]:
    """Group a snapshot's facts by kind and subject once."""
    groups: dict[tuple[str, tuple[object, ...]], list[Fact]] = {}
    for fact in facts:
        groups.setdefault((fact.kind, fact.subject), []).append(fact)
    return groups


def agreeing_fact(
    facts: frozenset[Fact], kind: str, subject: tuple[object, ...]
) -> Fact | None:
    """Return the fact for a subject when every fact recorded for it agrees.

    A pass can record the same fact again with more evidence in a later
    round, and two facts that agree on the value are one fact, with their
    evidence joined.  Facts that disagree leave the subject ambiguous.
    """
    index = _fact_index(facts)
    if (kind, subject) not in index:
        return None
    if index[(kind, subject)] is not None:
        return index[(kind, subject)]
    # Only a subject recorded more than once needs grouping.
    group = _grouped(facts).get((kind, subject), [])
    if not group or len({fact.value for fact in group}) != 1:
        return None
    if len(group) == 1:
        return group[0]
    first = min(group, key=lambda fact: (fact.evidence, fact.confidence))
    return Fact(
        first.kind,
        first.subject,
        first.value,
        tuple(sorted({address for fact in group for address in fact.evidence})),
        first.confidence,
    )


@lru_cache(maxsize=16_384)
def unique_fact(
    facts: frozenset[Fact], kind: str, subject: tuple[object, ...]
) -> Fact | None:
    """Return the unique fact matching ``kind`` and ``subject``."""
    return _fact_index(facts).get((kind, subject))


def function_parameter_at(
    facts: frozenset[Fact],
    address: int,
    displacement: int,
    kind: str,
) -> object | None:
    """Resolve a BP-relative function parameter within its owning frame."""

    matches = []
    for fact in facts:
        if (
            fact.kind != "semantic.def_fn"
            or len(fact.subject) != 2
            or not all(isinstance(value, int) for value in fact.subject)
            or not (fact.subject[0] < address < fact.subject[1])
            or len(fact.value) != 5
            or not isinstance(fact.value[0], int)
            or not isinstance(fact.value[2], tuple)
        ):
            continue
        expected = ("fn-param", fact.value[0], displacement, kind)
        if expected in fact.value[2]:
            matches.append(expected)
    return matches[0] if len(matches) == 1 else None


def combine_evidence(*groups: tuple[int, ...]) -> tuple[int, ...]:
    """Merge evidence offsets into a sorted, duplicate-free tuple."""
    return tuple(sorted({address for group in groups for address in group}))


def resolve_expression_before(
    offset: int,
    facts: frozenset[Fact],
    instruction_ends: dict[int, int],
    *,
    register: str = "ax",
) -> Resolved | None:
    """Resolve an expression whose evidence ends immediately before ``offset``."""

    matches = []
    for fact in _expression_candidates(facts):
        if fact.kind == "reference.array_value" and fact.subject[1:] == (offset,):
            matches.append(Resolved(fact.value[0], fact.evidence, fact.subject[0]))
            continue
        if fact.kind not in {"expression.value", "register.value"} or not fact.evidence:
            continue
        if fact.kind == "register.value" and fact.subject[1:] != (register,):
            continue
        explicit_span = (
            fact.kind == "expression.value"
            and len(fact.subject) == 2
            and fact.subject[1] == offset
            and isinstance(fact.subject[0], int)
        )
        if not explicit_span and instruction_ends.get(fact.evidence[-1]) != offset:
            continue
        resolved = resolve_expression(fact.value[0], facts)
        if resolved is not None:
            start = (
                # An expression value starts at its subject; its evidence
                # also names every reference to the slots it reads.
                fact.subject[0]
                if explicit_span or fact.kind == "expression.value"
                # A register's value starts where its first instruction or
                # any call result it holds does.
                else min([fact.evidence[0], *result_starts(fact.value[0], facts)])
            )
            matches.append(
                Resolved(
                    resolved.value,
                    combine_evidence(fact.evidence, resolved.evidence),
                    start,
                )
            )
    # Two facts that agree on the value are one value.
    if not matches or len({match.value for match in matches}) != 1:
        return None
    return min(matches, key=lambda match: (match.start is None, match.start or 0))


def result_starts(expression: object, facts: frozenset[Fact]) -> list[int]:
    """Return where each call result a tracked expression holds starts."""
    if not isinstance(expression, tuple) or not expression:
        return []
    if expression[0] == "result" and len(expression) == 2:
        call = _call_results(facts).get(expression[1])
        return [call.start] if call is not None and call.start is not None else []
    return [start for part in expression for start in result_starts(part, facts)]


@identity_cache
def _expression_candidates(facts: frozenset[Fact]) -> tuple[Fact, ...]:
    """Select expression evidence once while retaining snapshot iteration order."""
    return tuple(
        fact
        for fact in facts
        if fact.kind in {"reference.array_value", "expression.value", "register.value"}
    )


def orient_memory_fold(operator: str, memory: object, top: object) -> object:
    """Place a memory operand according to operator precedence and commutativity."""

    if not (
        isinstance(top, tuple)
        and len(top) == 4
        and top[0] == "binary"
        and top[1] in _PRECEDENCE
    ):
        return "binary", operator, memory, top
    if _PRECEDENCE[top[1]] < _PRECEDENCE[operator]:
        return "binary", operator, memory, top
    if operator in {"+", "*"}:
        return "binary", operator, top, memory
    return "binary", operator, memory, top


def _resolve_binary(value: tuple[Any, ...], facts: frozenset[Fact]) -> Resolved | None:
    left = resolve_expression(value[2], facts)
    right = resolve_expression(value[3], facts)
    if left is None or right is None:
        return None
    expression = "binary", value[1], left.value, right.value
    return Resolved(expression, combine_evidence(left.evidence, right.evidence))


def _resolve_memory(value: tuple[Any, ...], facts: frozenset[Fact]) -> Resolved | None:
    if len(value) < 2 or not isinstance(value[1], int):
        return None
    address = value[1]
    if value[2:] == ("integer",):
        system = unique_fact(facts, "expression.system", (address,))
        if system is not None and len(system.value) == 1:
            return Resolved(system.value[0], system.evidence)
    constant_kind = "string" if value[2:] == ("string",) else "memory"
    constant = unique_fact(facts, "constant", (constant_kind, address))
    if constant is None:
        constant = agreeing_fact(facts, "constant", (constant_kind, address))
    slot = resolve_slot(address, facts)
    array = resolve_array_element(address, facts)
    resolved = [item for item in (constant, slot, array) if item is not None]
    if len(resolved) != 1:
        return None
    if constant is not None:
        return Resolved(constant.value, constant.evidence)
    if array is not None:
        return array
    if slot is None or not isinstance(slot.value, tuple):
        return None
    suffix = value[2:] if len(value) > 2 else ()
    return Resolved(slot.value + suffix, slot.evidence)


def _array_indices(linear: int, bounds: object) -> tuple[int, ...] | None:
    if not isinstance(bounds, tuple):
        return None
    indices = []
    for bound in bounds:
        if (
            not isinstance(bound, tuple)
            or len(bound) != 2
            or not all(isinstance(value, int) for value in bound)
        ):
            return None
        low, high = bound
        extent = high - low + 1
        if extent <= 0:
            return None
        indices.append(low + linear % extent)
        linear //= extent
    return tuple(indices) if linear == 0 else None


"""Resolve symbolic expressions while preserving compiler evidence."""


@identity_cache
def frame_slots(facts: frozenset[Fact]) -> dict[int, dict[tuple[str, int], object]]:
    """Each procedure's parameters and locals, by entry and displacement."""
    found: dict[int, dict[tuple[str, int], object]] = {}
    for fact in facts:
        if fact.kind == "semantic.sub_def" and len(fact.value) == 2:
            slots = fact.value[1] if isinstance(fact.value[1], tuple) else ()
        elif fact.kind == "semantic.local" and len(fact.value) == 1:
            slots = fact.value[0] if isinstance(fact.value[0], tuple) else ()
        else:
            continue
        for slot in slots:
            if (
                isinstance(slot, tuple)
                and len(slot) == 4
                and slot[0] in {"proc-param", "proc-local"}
                and isinstance(slot[1], int)
                and isinstance(slot[2], int)
                and isinstance(slot[3], str)
            ):
                found.setdefault(slot[1], {})[(slot[0], slot[2])] = slot
    return found


def has_frame_word(expression: object) -> bool:
    """Whether a tracked expression reads a procedure frame word."""
    if not isinstance(expression, tuple) or not expression:
        return False
    if expression[0] in _FRAME_WORDS:
        return True
    # A head names the node; an argument list has none.
    parts = expression[1:] if isinstance(expression[0], str) else expression
    return any(has_frame_word(part) for part in parts)


_FRAME_WORDS = {"frame": "proc-local", "frame-param": "proc-param"}


def _resolve_frame(value: tuple[Any, ...], facts: frozenset[Fact]) -> Resolved | None:
    """Return the slot a tracked frame word names, or ``None``.

    The symbolic tracker names ``("frame", entry, d, kind)`` for the local
    word at ``[bp+d]`` of the procedure entered at ``entry``, and
    ``("frame-param", entry, d, kind)`` for the integer the parameter's far
    pointer there points to.
    """
    if len(value) != 4 or not isinstance(value[1], int):
        return None
    slot = frame_slots(facts).get(value[1], {}).get((_FRAME_WORDS[value[0]], value[2]))
    return Resolved(slot) if slot is not None else None
