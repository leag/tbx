"""Complete source statements with one adjacent string-push operand."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.matchers import string_push_scaffold
from tbd.semantic import combine_evidence, resolve_expression

_SINGLE_STRING_STATEMENTS = {
    0x10: ("CHDIR", ()),
    0x24: ("DATE_TIME_SET", ("DATE$",)),
    0x30: ("DRAW", ()),
    0x34: ("ENVIRON", ()),
    0x60: ("KILL", ()),
    0x6A: ("MKDIR", ()),
    0x98: ("PLAY", ()),
    0xC2: ("RMDIR", ()),
    0xCE: ("SHELL", ()),
    0xE0: ("DATE_TIME_SET", ("TIME$",)),
}
SINGLE_STRING_STATEMENT_NAMES = frozenset(
    name for name, _fixed in _SINGLE_STRING_STATEMENTS.values()
)


def string_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Resolve FILES and single-string statements from complete scaffolds."""

    by_end = {instruction.end: instruction for instruction in evidence.instructions}
    for instruction in evidence.instructions:
        fact = _files_fact(instruction, by_end, facts)
        if fact is None:
            fact = _single_string_fact(instruction, by_end, facts)
        if fact is not None:
            yield fact


def _files_fact(
    instruction: Operation,
    by_end: dict[int, Operation],
    facts: frozenset[Fact],
) -> Fact | None:
    if instruction.kind != "tb.statement":
        return None
    if instruction.operands == ("FILES_BARE", 0x42):
        return Fact(
            "semantic.files",
            (instruction.offset, instruction.end),
            (None,),
            (instruction.offset,),
            "signature",
        )
    if instruction.operands != ("FILES", 0x44):
        return None
    return _string_fact(instruction, "semantic.files", (), by_end, facts)


def _single_string_fact(
    instruction: Operation,
    by_end: dict[int, Operation],
    facts: frozenset[Fact],
) -> Fact | None:
    if instruction.kind != "tb.statement" or len(instruction.operands) < 2:
        return None
    sub = instruction.operands[1]
    source = _SINGLE_STRING_STATEMENTS.get(sub)
    if source is None:
        return None
    name, fixed_operands = source
    return _string_fact(
        instruction,
        "semantic.statement",
        (name, sub, *fixed_operands),
        by_end,
        facts,
    )


def _string_fact(
    instruction: Operation,
    kind: str,
    prefix: tuple[object, ...],
    by_end: dict[int, Operation],
    facts: frozenset[Fact],
) -> Fact | None:
    argument = _resolved_string_argument(instruction, by_end, facts)
    if argument is None:
        return None
    start, value, support = argument
    return Fact(
        kind,
        (start, instruction.end),
        (*prefix, value),
        support,
        "anchored",
    )


def _resolved_string_argument(
    instruction: Operation,
    by_end: dict[int, Operation],
    facts: frozenset[Fact],
) -> tuple[int, object, tuple[int, ...]] | None:
    scaffold = string_push_scaffold(instruction, by_end)
    if scaffold is None:
        return None
    setup, runtime = scaffold
    address = setup.operands[1]
    resolved = resolve_expression(("memory", address, "string"), facts)
    if resolved is None or not _supported_string_value(
        resolved.value, address, setup.offset, facts
    ):
        return None
    support = combine_evidence(
        (setup.offset, runtime.offset, instruction.offset),
        resolved.evidence,
    )
    return setup.offset, resolved.value, support


def _supported_string_value(
    value: object, address: int, start: int, facts: frozenset[Fact]
) -> bool:
    ambiguous = value == ("string", "") or (
        isinstance(value, tuple) and value[:1] == ("slot",)
    )
    if not ambiguous:
        return True
    return any(
        fact.kind == "memory.write"
        and fact.subject == (address,)
        and fact.evidence
        and fact.evidence[-1] < start
        for fact in facts
    )


STRING_STATEMENT_FACT_PASSES: tuple[NamedPass, ...] = (
    ("string-statements", string_statement_facts),
)
