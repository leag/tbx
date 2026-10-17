from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass, reads
from tbd.ir import Fact, Operation
from tbd.matchers import fp_ax_bridge, string_push_scaffold
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_expression,
    resolve_expression_before,
)

_SINGLE_STRING_STATEMENTS = {
    0x0E: ("CHAIN", ()),
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


@reads(
    "constant",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "layout.array",
    "memory.write",
    "reference.array_value",
    "register.value",
    "semantic.files",
    "semantic.statement",
    "signature",
    "slot",
    "tb.runtime",
    "tb.statement",
    "x86.mov_imm",
)
def string_statement_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover statements whose primary operand is a string expression."""

    by_end = {instruction.end: instruction for instruction in evidence.instructions}
    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    for instruction in evidence.instructions:
        fact = _key_def_fact(
            instruction, evidence.instructions, instruction_ends, facts
        )
        if fact is None:
            fact = _name_fact(instruction, facts)
        if fact is None:
            fact = _files_fact(instruction, by_end, facts)
        if fact is None:
            fact = _single_string_fact(instruction, by_end, facts)
        if fact is not None:
            yield fact


def _key_def_fact(
    instruction: Operation,
    instructions: tuple[Operation, ...],
    instruction_ends: dict[int, int],
    facts: frozenset[Fact],
) -> Fact | None:
    if instruction.kind != "tb.statement" or instruction.operands != ("KEY_DEF", 0x58):
        return None
    index = next(
        (
            index
            for index, node in enumerate(instructions)
            if node.offset == instruction.offset
        ),
        None,
    )
    if index is not None and index >= 10:
        window = instructions[index - 10 : index]
        (
            first,
            save,
            zero,
            chr0,
            restore,
            copy,
            value,
            chr_value,
            restore_value,
            concat,
        ) = window
        if (
            first.kind == "x86.mov_imm"
            and first.operands == ("ax", 15)
            and save.raw == "89 c3"
            and zero.raw == "31 c0"
            and chr0.kind == "tb.runtime"
            and chr0.operands == (0xB3,)
            and restore.raw == "89 d8"
            and copy.raw == "89 c3"
            and value.kind == "x86.mov_imm"
            and value.operands == ("ax", 70)
            and chr_value.kind == "tb.runtime"
            and chr_value.operands == (0xB3,)
            and restore_value.raw == "89 d8"
            and concat.kind == "tb.runtime"
            and concat.operands == (0x9B,)
        ):
            return Fact(
                "semantic.statement",
                (first.offset, instruction.end),
                (
                    "KEY_DEF",
                    0x58,
                    ("const", 15),
                    (
                        "binary",
                        "+",
                        ("call", "CHR$", (("const", 0),)),
                        ("call", "CHR$", (("const", 70),)),
                    ),
                ),
                tuple(node.offset for node in window) + (instruction.offset,),
                "anchored",
            )
    text = _sequential_string_arguments(instruction.offset, 1, facts)
    if text is None:
        return None
    text_start, values, text_support = text
    number = resolve_expression_before(text_start, facts, instruction_ends)
    if number is None:
        # A real key number reaches AX rounded through the scratch word.
        by_end = {node.end: node for node in instructions}
        bridge = fp_ax_bridge(by_end.get(text_start), by_end)
        source = resolve_expression(bridge[0], facts) if bridge is not None else None
        if bridge is None or source is None:
            return None
        number = Resolved(
            source.value, combine_evidence(source.evidence, bridge[1]), min(bridge[1])
        )
    start = number.start if number.start is not None else text_start
    return Fact(
        "semantic.statement",
        (min(start, text_start), instruction.end),
        ("KEY_DEF", 0x58, number.value, values[0]),
        combine_evidence(
            number.evidence,
            text_support,
            (instruction.offset,),
        ),
        "anchored",
    )


def _name_fact(instruction: Operation, facts: frozenset[Fact]) -> Fact | None:
    if instruction.kind != "tb.statement" or instruction.operands != ("NAME", 0x6E):
        return None
    arguments = _sequential_string_arguments(instruction.offset, 2, facts)
    if arguments is None:
        return None
    start, values, support = arguments
    return Fact(
        "semantic.statement",
        (start, instruction.end),
        ("NAME", 0x6E, *values),
        combine_evidence(support, (instruction.offset,)),
        "anchored",
    )


def _sequential_string_arguments(
    end: int, count: int, facts: frozenset[Fact]
) -> tuple[int, tuple[object, ...], tuple[int, ...]] | None:
    strings = tuple(
        fact
        for fact in facts
        if fact.kind == "expression.string_operand"
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
        and len(fact.value) == 1
    )
    cursor = end
    arguments = []
    for _ in range(count):
        matches = [fact for fact in strings if fact.subject[1] == cursor]
        if len(matches) != 1:
            return None
        argument = matches[0]
        arguments.append(argument)
        cursor = argument.subject[0]
    arguments.reverse()
    return (
        cursor,
        tuple(argument.value[0] for argument in arguments),
        combine_evidence(*(argument.evidence for argument in arguments)),
    )


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
        # The argument can be built on the string stack rather than pushed
        # whole, as a concatenation is.  The operand that ends where the
        # statement begins is that argument, and a composed value is never
        # the bare slot the push path has to guard against.
        composed = _sequential_string_arguments(instruction.offset, 1, facts)
        if composed is None:
            return None
        start, values, support = composed
        value = values[0]
        if not (isinstance(value, tuple) and value[:2] == ("binary", "+")):
            return None
        return start, value, combine_evidence(support, (instruction.offset,))
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
