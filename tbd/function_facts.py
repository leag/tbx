from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass, fact_key, facts_by_kind, indexed_facts, reads
from tbd.ir import Fact, Operation
from tbd.matchers import fp_ax_bridge
from tbd.operation_helpers import bridged, register_moves
from tbd.pool import decode_string_descriptors
from tbd.semantic import (
    Resolved,
    combine_evidence,
    resolve_expression,
    resolve_expression_before,
    resolve_slot,
    unique_fact,
)
from tbd.slots import VAR_BASE
from tbd.symbolic_facts import _fp_action


def _nearest_agreeing(candidates: list[Fact], _offset: int) -> Fact | None:
    """Return the nearest preceding candidate when the nearest ones agree.

    Several facts can start at the same place -- one of them built from an
    earlier round of the same recovery -- and picking between them by iteration
    order makes the decode depend on it.  Disagreement is contradictory
    evidence, so nothing is returned.
    """
    if not candidates:
        return None
    nearest = max(fact.subject[0] for fact in candidates)
    matches = {fact for fact in candidates if fact.subject[0] == nearest}
    if len({fact.value for fact in matches}) != 1:
        return None
    return min(matches, key=lambda fact: (fact.subject, fact.evidence))


# The conversion's code, from its start to its STR$ call, is short.
_CONVERSION_REACH = 64


@reads(
    "constant",
    "expression.string_operand",
    "expression.system",
    "expression.value",
    "layout.array",
    "layout.pool",
    "signature",
    "slot",
    "tb.fp",
    "tb.function",
    "tb.proc_return",
    "tb.runtime",
    "x86.in_al_dx",
    "x86.mov_imm",
)
def function_expression_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover intrinsic function calls from their runtime signatures."""

    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    ordered = evidence.instructions
    ending = {instruction.end: instruction for instruction in ordered}
    for call in ordered:
        if call.kind != "tb.function" or call.operands != ("string", 0):
            continue
        previous = next(
            (
                instruction
                for instruction in reversed(ordered)
                if instruction.end <= call.offset
                and instruction.kind in {"tb.fp", "fild", "fild32"}
            ),
            None,
        )
        if previous is None:
            continue
        if previous.kind == "tb.fp":
            prior = next(
                (
                    fact
                    for fact in facts_by_kind(facts).get("expression.value", ())
                    if fact.kind == "expression.value"
                    and fact.subject == (previous.offset,)
                    and len(fact.value) == 1
                ),
                None,
            )
            argument = (
                resolve_expression(prior.value[0], facts) if prior is not None else None
            )
        elif len(previous.operands) == 1:
            argument = resolve_expression(
                ("memory", previous.operands[0], "integer"), facts
            )
        else:
            argument = None
        if argument is None:
            continue
        yield Fact(
            "expression.value",
            (previous.offset, call.end),
            (("call", "BIN$", (argument.value,)),),
            combine_evidence(argument.evidence, (previous.offset, call.offset)),
            "anchored",
        )
    for call in ordered:
        if call.kind == "tb.runtime" and call.operands == (0xA8,):
            operands = [
                fact
                for fact in facts_by_kind(facts).get("expression.string_operand", ())
                if fact.kind == "expression.string_operand"
                and len(fact.subject) == 2
                and fact.subject[1] == call.offset
                and len(fact.value) == 1
            ]
            # An earlier string may belong to another statement. Waiting for
            # the actual argument prevents a guess persisting across rounds.
            operand = _nearest_agreeing(operands, call.offset)
            if operand is not None:
                yield Fact(
                    "expression.value",
                    (operand.subject[0], call.end),
                    (("call", "CVI", (operand.value[0],)),),
                    combine_evidence(operand.evidence, (call.offset,)),
                    "anchored",
                )
            continue
        if call.kind != "tb.function" or call.operands != ("numeric", 34):
            continue
        # The nearest conversion before the call is the one it measures.  Two
        # different conversions starting there are contradictory evidence, and
        # one of them is this pass reading back its own earlier result, so
        # neither is used.
        # It must also end just before the call, as ASC's operand does: the
        # conversion's own STR$ call is the instruction the LEN call follows.
        # Its evidence also names every reference to the slots it reads, so
        # neither its last evidence nor a nearby one locates it.
        producer = ending.get(call.offset)
        conversions = [
            fact
            for fact in facts_by_kind(facts).get("expression.value", ())
            if fact.kind == "expression.value"
            and producer is not None
            and producer.offset in fact.evidence
            and 0 <= producer.offset - fact.subject[0] <= _CONVERSION_REACH
            and len(fact.value) == 1
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:2] == ("call", "STR$")
        ]
        source = None
        if conversions:
            nearest = max(fact.subject[0] for fact in conversions)
            matches = {fact for fact in conversions if fact.subject[0] == nearest}
            if len({(fact.subject, fact.value) for fact in matches}) == 1:
                source = min(matches, key=lambda fact: (fact.evidence, fact_key(fact)))
        if source is not None:
            yield Fact(
                "expression.value",
                (source.subject[0], call.end),
                (("call", "LEN", (source.value[0],)),),
                combine_evidence(source.evidence, (call.offset,)),
                "anchored",
            )
    by_end_all = {instruction.end: instruction for instruction in ordered}
    for call in ordered:
        if call.kind != "tb.fp" or call.operands != (59, 6):
            continue
        # ASC's result reaches the FP stack through the conversion scratch
        # word; a load of any other word is that variable's value.
        if bytes.fromhex(call.raw)[3:5] != b"\x2c\x00":
            continue
        operands = [
            fact
            for fact in facts_by_kind(facts).get("expression.string_operand", ())
            if fact.kind == "expression.string_operand"
            and len(fact.subject) == 2
            and fact.subject[1] <= call.offset
            and len(fact.value) == 1
        ]
        if not operands:
            continue
        operand = max(operands, key=lambda fact: (fact.subject[0], fact_key(fact)))
        if call.offset - operand.subject[1] > 16:
            continue
        # ASC's value is stored in the scratch word straight from its call,
        # which takes the operand; arithmetic between them is another value's.
        store = by_end_all.get(call.offset)
        asc_call = by_end_all.get(store.offset) if store is not None else None
        if (
            store is None
            or asc_call is None
            or asc_call.kind != "tb.runtime"
            or asc_call.operands != (0xA6,)
            or asc_call.offset != operand.subject[1]
        ):
            continue
        if any(
            fact.kind == "expression.value"
            and len(fact.subject) == 2
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:2] == ("call", "CVI")
            and len(fact.value[0][2]) == 1
            and fact.value[0][2][0] == operand.value[0]
            for fact in facts_by_kind(facts).get("expression.value", ())
        ):
            continue
        # The RIGHT$ that built this operand starts where the operand does
        # and was computed inside it; a RIGHT$ of the same name elsewhere in
        # the program says nothing about this call.  Two disagreeing ones are
        # contradictory evidence, so neither is used.
        rights = {
            fact.value[0]
            for fact in facts_by_kind(facts).get("expression.value", ())
            if isinstance(fact.value[0], tuple)
            and fact.value[0][:2] == ("call", "RIGHT$")
            and len(fact.value[0][2]) >= 1
            and fact.value[0][2][0] == operand.value[0]
            and fact.subject[:1] == operand.subject[:1]
            and all(
                operand.subject[0] <= address < call.offset for address in fact.evidence
            )
        }
        if len(rights) > 1:
            continue
        source = next(iter(rights)) if rights else operand.value[0]
        if any(
            instruction.kind in {"tb.function", "tb.proc_return"}
            and operand.subject[1] <= instruction.offset < call.offset
            for instruction in ordered
        ):
            continue
        yield Fact(
            "expression.value",
            (operand.subject[0], call.end),
            (("call", "ASC", (source,)),),
            combine_evidence(operand.evidence, (call.offset,)),
            "anchored",
        )
    for block in evidence.blocks:
        nodes = tuple(
            instructions[offset]
            for offset in block.instruction_offsets
            if offset in instructions
        )
        for index in range(len(nodes) - 4):
            window = nodes[index : index + 5]
            if not _len_inkey_zero(window):
                continue
            zero, string_call, shuttle, numeric_call, compare = window
            value = ("call", "LEN", (("call", "INKEY$", ()),))
            support = tuple(node.offset for node in window)
            yield Fact(
                "expression.value",
                (zero.offset,),
                (value,),
                support[:-1],
                "signature",
            )
            yield Fact(
                "expression.compare",
                (zero.offset,),
                (value, ("const", 0)),
                support,
                "signature",
            )
    for call in evidence.instructions:
        if call.kind == "x86.in_al_dx":
            previous = next(
                (
                    item
                    for item in reversed(evidence.instructions)
                    if item.kind == "x86.mov_imm"
                    and item.operands[:1] == ("ax",)
                    and item.end <= call.offset
                ),
                None,
            )
            if previous is not None:
                yield Fact(
                    "expression.value",
                    (previous.offset,),
                    (("call", "INP", (("const", previous.operands[1]),)),),
                    (previous.offset, call.offset),
                    "signature",
                )
        if call.kind == "tb.function" and call.operands == ("numeric", 0x26):
            previous = next(
                (
                    item
                    for item in reversed(evidence.instructions)
                    if item.end == call.offset
                ),
                None,
            )
            if (
                previous is not None
                and previous.kind == "x86.mov_imm"
                and previous.operands[:1] == ("ax",)
                and len(previous.operands) == 2
            ):
                yield Fact(
                    "expression.value",
                    (previous.offset,),
                    (("call", "LOF", (("const", previous.operands[1]),)),),
                    (previous.offset, call.offset),
                    "signature",
                )
        if call.kind == "tb.function" and call.operands == ("numeric", 0x18):
            previous = next(
                (
                    item
                    for item in reversed(evidence.instructions)
                    if item.end == call.offset
                ),
                None,
            )
            if previous is not None and previous.raw == "31 c0":
                yield Fact(
                    "expression.value",
                    (previous.offset,),
                    (("call", "FRE", (("const", 0),)),),
                    (previous.offset, call.offset),
                    "signature",
                )
        if call.kind == "tb.function" and call.operands == ("string", 0x14):
            previous = next(
                (
                    item
                    for item in reversed(evidence.instructions)
                    if item.end == call.offset
                ),
                None,
            )
            if (
                previous is not None
                and previous.kind == "x86.mov_imm"
                and previous.operands[:1] == ("ax",)
                and len(previous.operands) == 2
            ):
                yield Fact(
                    "expression.value",
                    (previous.offset,),
                    (("call", "IOCTL$", (("const", previous.operands[1]),)),),
                    (previous.offset, call.offset),
                    "signature",
                )
        if call.kind != "tb.function" or call.operands != ("numeric", 0x16):
            continue
        previous_call = next(
            (
                item
                for item in reversed(evidence.instructions)
                if item.kind == "tb.function" and item.offset < call.offset
            ),
            None,
        )
        lower_bound = previous_call.offset if previous_call is not None else -1
        operands = [
            fact
            for fact in facts_by_kind(facts).get("expression.string_operand", ())
            if fact.kind == "expression.string_operand"
            and len(fact.subject) == 2
            and fact.subject[0] > lower_bound
            and fact.subject[1] <= call.offset
            and len(fact.value) == 1
        ]
        if True:
            previous = next(
                (
                    item
                    for item in reversed(evidence.instructions)
                    if item.end == call.offset
                ),
                None,
            )
            if (
                False
                and previous is not None
                and previous.kind == "tb.runtime"
                and previous.operands == (0x87,)
            ):
                yield Fact(
                    "expression.value",
                    (previous.offset,),
                    (("call", "FRE", (("string", ""),)),),
                    (previous.offset, call.offset),
                    "anchored",
                )
            else:
                layout = next(
                    (
                        fact
                        for fact in facts_by_kind(facts).get("layout.pool", ())
                        if fact.kind == "layout.pool" and len(fact.value) == 4
                    ),
                    None,
                )
                if layout is not None:
                    strings = (
                        decode_string_descriptors(
                            evidence.image,
                            layout.value[0],
                            layout.value[1],
                            layout.value[3],
                        )
                        or ()
                    )
                    referenced = {
                        fact.value[0][1]
                        for fact in facts_by_kind(facts).get(
                            "expression.string_operand", ()
                        )
                        if fact.kind == "expression.string_operand"
                        and len(fact.subject) == 2
                        and len(fact.value) == 1
                        and isinstance(fact.value[0], tuple)
                        and fact.value[0][0] == "string"
                    }
                    referenced.update(
                        fact.value[1]
                        for fact in facts_by_kind(facts).get("constant", ())
                        if fact.kind == "constant"
                        and fact.subject[:1] == ("string",)
                        and len(fact.value) == 2
                    )
                    hidden = sorted(
                        (item for item in strings if item[1] not in referenced),
                        reverse=True,
                    )
                    prior_calls = [
                        item
                        for item in evidence.instructions
                        if item.kind == "tb.function"
                        and item.operands == ("numeric", 0x16)
                        and item.offset < call.offset
                    ]
                    prior_hidden = 0
                    for prior_call in prior_calls:
                        prior_instruction = next(
                            (
                                item
                                for item in reversed(evidence.instructions)
                                if item.kind == "tb.function"
                                and item.offset < prior_call.offset
                            ),
                            None,
                        )
                        start = (
                            prior_instruction.offset
                            if prior_instruction is not None
                            else -1
                        )
                        if not any(
                            fact.kind == "expression.string_operand"
                            and len(fact.subject) == 2
                            and start
                            < fact.subject[0]
                            <= fact.subject[1]
                            <= prior_call.offset
                            for fact in facts
                        ) and not any(
                            fact.kind == "expression.value"
                            and prior_call.offset in fact.evidence
                            and len(fact.value) == 1
                            and isinstance(fact.value[0], tuple)
                            and fact.value[0][:2] == ("call", "FRE")
                            for fact in facts
                        ):
                            prior_hidden += 1
                    already_named = any(
                        fact.kind == "expression.value"
                        and call.offset in fact.evidence
                        and len(fact.value) == 1
                        and isinstance(fact.value[0], tuple)
                        and fact.value[0][:2] == ("call", "FRE")
                        for fact in facts
                    )
                    if not already_named and prior_hidden < len(hidden):
                        address, text = hidden[prior_hidden]
                        yield Fact(
                            "expression.value",
                            (call.offset,),
                            (("call", "FRE", (("string", text),)),),
                            (call.offset, layout.evidence[-1], address),
                            "anchored",
                        )
                    elif (
                        not already_named
                        and previous is not None
                        and previous.kind == "tb.runtime"
                        and previous.operands == (0x87,)
                    ):
                        yield Fact(
                            "expression.value",
                            (previous.offset,),
                            (("call", "FRE", (("string", ""),)),),
                            (previous.offset, call.offset),
                            "anchored",
                        )
        if call.kind != "tb.function" or call.operands != ("numeric", 0x1C):
            continue
        argument_facts = sorted(
            (
                fact
                for fact in facts_by_kind(facts).get("expression.string_operand", ())
                if fact.kind == "expression.string_operand"
                and len(fact.subject) == 2
                and fact.subject[1] <= call.offset
                and len(fact.value) == 1
            ),
            key=lambda fact: (fact.subject[0], fact_key(fact)),
        )
        if len(argument_facts) < 2:
            continue
        if len(argument_facts) >= 3 and argument_facts[-1].value[0][0] == "string":
            argument_facts = [argument_facts[-2], argument_facts[-1]]
        else:
            argument_facts = argument_facts[-2:]
        if argument_facts[0].value[0][0] == "string":
            continue
        if argument_facts[0].subject[1] > argument_facts[1].subject[0]:
            continue
        yield Fact(
            "expression.value",
            (argument_facts[0].subject[0],),
            (("call", "INSTR", tuple(fact.value[0] for fact in argument_facts)),),
            combine_evidence(
                *(fact.evidence for fact in argument_facts),
                (call.offset,),
            ),
            "anchored",
        )
    for call in evidence.instructions:
        if call.kind != "tb.function" or call.operands not in {
            ("numeric", 0x32),
            ("numeric", 0x36),
            ("numeric", 0x3A),
        }:
            continue
        values = sorted(
            (
                item
                for item in facts
                if item.kind == "expression.value"
                and len(item.value) == 1
                and item.subject[0] < call.offset
                and item.evidence
                and item.evidence[-1] <= call.offset
                # A result this very call produced is not one of its operands.
                # Without this the value nests itself once per round.
                and call.offset not in item.evidence
                and not (
                    isinstance(item.value[0], tuple)
                    and item.value[0][:2] == ("call", "PMAP")
                )
            ),
            key=lambda item: (item.subject[0], fact_key(item)),
        )
        if call.operands[1] == 0x36 and len(values) >= 2:
            arguments = tuple(item.value[0] for item in values[-2:])
            support = combine_evidence(
                *(item.evidence for item in values[-2:]), (call.offset,)
            )
            yield Fact(
                "expression.value",
                (values[-2].subject[0], call.end),
                (("call", "POINT", arguments),),
                support,
                "anchored",
            )
        elif call.operands[1] == 0x32 and values:
            previous = next(
                (
                    item
                    for item in reversed(evidence.instructions)
                    if item.end <= call.offset
                ),
                None,
            )
            if previous is not None and previous.raw == "31 c0":
                argument = values[-1].value[0]
                yield Fact(
                    "expression.value",
                    (values[-1].subject[0], call.end),
                    (("call", "PMAP", (argument, ("const", 0))),),
                    combine_evidence(
                        values[-1].evidence, (previous.offset, call.offset)
                    ),
                    "anchored",
                )
        elif call.operands[1] == 0x3A and len(values) >= 2:
            left, right = values[-2:]
            left_value = resolve_expression(left.value[0], facts)
            right_value = resolve_expression(right.value[0], facts)
            if left_value is None or right_value is None:
                continue
            yield Fact(
                "expression.value",
                (left.subject[0], call.end),
                (("binary", "^", right_value.value, left_value.value),),
                combine_evidence(left.evidence, right.evidence, (call.offset,)),
                "anchored",
            )
    # Some FRE$ calls are surrounded only by FP-stack operations, so the
    # ordinary operand window has no string fact to anchor them.  Once the
    # pool layout is known, recover the first unreferenced descriptor without
    # competing with an already materialized FRE expression.
    layout = next(
        (fact for fact in facts if fact.kind == "layout.pool" and len(fact.value) == 4),
        None,
    )
    if layout is not None:
        strings = (
            decode_string_descriptors(
                evidence.image, layout.value[0], layout.value[1], layout.value[3]
            )
            or ()
        )
        known = {
            fact.value[1]
            for fact in facts_by_kind(facts).get("constant", ())
            if fact.kind == "constant"
            and fact.subject[:1] == ("string",)
            and len(fact.value) == 2
        }
        hidden_strings = sorted(
            (item for item in strings if item[1] not in known), reverse=True
        )
        for call in evidence.instructions:
            if call.kind != "tb.function" or call.operands != ("numeric", 0x16):
                continue
            if any(
                fact.kind == "expression.value"
                and call.offset in fact.evidence
                and len(fact.value) == 1
                and isinstance(fact.value[0], tuple)
                and fact.value[0][:2] == ("call", "FRE")
                for fact in facts
            ):
                continue
            if hidden_strings:
                address, text = hidden_strings.pop(0)
                yield Fact(
                    "expression.value",
                    (call.offset,),
                    (("call", "FRE", (("string", text),)),),
                    (call.offset, layout.evidence[-1], address),
                    "anchored",
                )
    values = sorted(
        (
            fact
            for fact in facts_by_kind(facts).get("expression.value", ())
            if fact.kind == "expression.value"
            and len(fact.value) == 1
            and fact.subject[0] < 10**9
        ),
        # A fold accumulates at one start address, so ordering by start alone
        # leaves the two operands below to be chosen by set order.  The value
        # that ends later was produced later, and ties order on their contents.
        key=lambda fact: (fact.subject[0], fact.subject[-1], fact_key(fact)),
    )
    ending_at = {item.end: item.offset for item in evidence.instructions}

    def ends_at(fact: Fact, offset: int) -> bool:
        # Evidence also lists every reference to the slots a value reads,
        # so its last address need not be the value's own last instruction.
        if len(fact.subject) == 2:
            return fact.subject[1] == offset
        return ending_at.get(offset) in fact.evidence

    for instruction in evidence.instructions:
        if instruction.raw != "cd 3a c1":
            continue
        # FADDP adds the value computed right before it to the one pushed
        # right before that: the right operand ends at the instruction and
        # the left one where the right one starts.
        rights = [fact for fact in values if ends_at(fact, instruction.offset)]
        pairs = [
            (left, right)
            for right in rights
            for left in values
            if left is not right
            and left.subject[0] < right.subject[0]
            and ends_at(left, right.subject[0])
        ]
        if len(pairs) != 1:
            continue
        left, right = pairs[0]
        if (
            isinstance(left.value[0], tuple)
            and left.value[0][:2] == ("const", 1)
            and isinstance(right.value[0], tuple)
            and right.value[0][:2] == ("call", "FRE")
        ):
            left, right = right, left
        yield Fact(
            "expression.value",
            (left.subject[0], instruction.offset + instruction.size),
            (("binary", "+", left.value[0], right.value[0]),),
            combine_evidence(left.evidence, right.evidence, (instruction.offset,)),
            "anchored",
        )
    yield from _function_memory_arithmetic(evidence.instructions, values, facts)


def _function_memory_arithmetic(
    instructions: tuple[Operation, ...],
    values: list[Fact],
    facts: frozenset[Fact],
) -> Iterable[Fact]:
    """Apply an FP operation on memory to the function value just before it.

    ``VAL(A$) + 1`` calls VAL, which leaves its value on the FP stack, then
    ``fiadd word [1]``. The value is the numeric call's whose call
    instruction ends right at the operation.
    """
    ending_at = {item.end: item for item in instructions}
    for instruction in instructions:
        action = _fp_action(instruction)
        if action is None or action[0] != "binary":
            continue
        operator, operand = action[1]
        call = ending_at.get(instruction.offset)
        # A value the FP unit loaded, and INT of one, is the tracker's; VAL's
        # result reaches the stack without an FP instruction of its own.
        if call is None or call.kind != "tb.runtime" or call.operands != (0xAC,):
            continue
        functions = [
            fact
            for fact in values
            if call.offset in fact.evidence
            and len(fact.subject) == 1
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:1] == ("call",)
            and not str(fact.value[0][1]).endswith("$")
        ]
        resolved = resolve_expression(operand, facts)
        if len({fact.value for fact in functions}) != 1 or resolved is None:
            continue
        function = min(functions, key=fact_key)
        yield Fact(
            "expression.value",
            (function.subject[0],),
            (("binary", operator, function.value[0], resolved.value),),
            combine_evidence(
                function.evidence, resolved.evidence, (instruction.offset,)
            ),
            "anchored",
        )


def _len_inkey_zero(nodes: tuple[Operation, ...]) -> bool:
    if len(nodes) != 5:
        return False
    zero, string_call, shuttle, numeric_call, compare = nodes
    return (
        zero.raw == "31 c0"
        and string_call.kind == "tb.function"
        and string_call.operands == ("string", 0x0E)
        and shuttle.raw in {"89 c3", "8b d8"}
        and numeric_call.kind == "tb.function"
        and numeric_call.operands == ("numeric", 0x22)
        and compare.raw == "3b c3"
        and all(left.end == right.offset for left, right in zip(nodes, nodes[1:]))
    )


@reads("signature")
def system_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover expressions backed by Turbo Basic system variables."""

    cells = {0x74: "ERR", 0x72: "ERL"}
    for address, name in cells.items():
        support = tuple(
            instruction.offset
            for instruction in evidence.instructions
            if instruction.raw
            in {
                f"8b 06 {address:02x} 00",
                f"3b 06 {address:02x} 00",
            }
        )
        if support:
            yield Fact(
                "expression.system",
                (address,),
                (("call", name, ()),),
                support,
                "signature",
            )


def _staged_mid(
    call: Operation, ending: dict[int, Operation], facts: frozenset[Fact]
) -> tuple[Fact, Fact] | None:
    """Recover ``MID$(s$, start, n)`` staged as ``start; mov bx,ax; mov ax,n``.

    The start is a constant or an integer variable loaded into AX, the
    string is pushed just before it, and the call reads all three.
    """
    length = ending.get(call.offset)
    save = ending.get(length.offset) if length is not None else None
    load = ending.get(save.offset) if save is not None else None
    if (
        length is None
        or save is None
        or load is None
        or length.kind != "x86.mov_imm"
        or length.operands[:1] != ("ax",)
        or save.raw != "89 c3"
    ):
        return None
    start: object | None = None
    support: tuple[int, ...] = ()
    if load.kind == "x86.mov_imm" and load.operands[:1] == ("ax",):
        start = ("const", load.operands[1])
    elif load.raw.startswith("8b 06") and len(load.raw.split()) == 4:
        address = int.from_bytes(bytes.fromhex(load.raw[6:].replace(" ", "")), "little")
        slot = resolve_slot(address, facts)
        if slot is None:
            return None
        start, support = slot.value + ("integer",), slot.evidence
    if start is None:
        return None
    sources = {
        fact
        for fact in facts_by_kind(facts).get("expression.string_operand", ())
        if len(fact.subject) == 2
        and fact.subject[1] == load.offset
        and len(fact.value) == 1
    }
    if len({fact.value for fact in sources}) != 1:
        return None
    source = min(sources, key=fact_key)
    mid = ("call", "MID$", (source.value[0], start, ("const", length.operands[1])))
    evidence = combine_evidence(
        source.evidence, support, (load.offset, save.offset, length.offset, call.offset)
    )
    return (
        Fact("expression.value", (source.subject[0],), (mid,), evidence, "anchored"),
        Fact(
            "expression.string_operand",
            (source.subject[0], call.end),
            (mid,),
            evidence,
            "anchored",
        ),
    )


@reads(
    "expression.string_operand",
    "expression.value",
    "reference.array_value",
    "register.at_call",
    "register.value",
    "signature",
    "slot",
    "tb.function",
    "tb.runtime",
    "x86.mov",
    "x86.mov_imm",
)
def _ax_operand(
    ending: dict[int, Operation],
    offset: int,
    facts: frozenset[Fact],
    ends: dict[int, int],
) -> tuple[Resolved, int] | None:
    """Read the integer AX holds at ``offset`` and where its code starts.

    A constant (``mov ax,n``), a variable (``mov ax,[m]``), or a real
    converted through the scratch word (``fld [m]; fistp [2Ch]; fwait;
    mov ax,[2Ch]``).
    """
    setup = ending.get(offset)
    if setup is None:
        return None
    if setup.kind == "x86.mov_imm" and setup.operands[:1] == ("ax",):
        if len(setup.operands) != 2:
            return None
        return Resolved(("const", setup.operands[1]), (setup.offset,)), setup.offset
    raw = setup.raw.split()
    if len(raw) == 4 and raw[:2] == ["8b", "06"]:
        address = int(raw[3] + raw[2], 16)
        resolved = resolve_expression(("memory", address, "integer"), facts)
        return (resolved, setup.offset) if resolved is not None else None
    bridge = fp_ax_bridge(setup, ending)
    if bridge is None:
        # A value the register tracker computed in AX, e.g. ``N% - 4``.
        computed = resolve_expression_before(offset, facts, ends)
        if computed is None or not isinstance(computed.start, int):
            return None
        return computed, computed.start
    source, evidence = bridge
    resolved = resolve_expression(source, facts)
    if resolved is None:
        return None
    value = Resolved(resolved.value, resolved.evidence + evidence)
    return value, min(evidence)


def _tracked_mid(
    call: Operation, facts: frozenset[Fact], moves: dict[int, int]
) -> tuple[tuple[Resolved, int], tuple[Resolved, int], dict[object, Fact]] | None:
    """Read MID$'s start (BX) and length (AX) from the registers at its call.

    The compiler may compute the length after the start, keeping the start
    in CX meanwhile (``MID$(A$, 2, LEN(A$) - 1)``); the string argument is
    the operand that ends where that code begins.
    """
    at_call = unique_fact(facts, "register.at_call", (call.offset,))
    if at_call is None or not at_call.evidence:
        return None
    length = resolve_expression(_implicit_integer(at_call.value[0]), facts)
    start = resolve_expression(_implicit_integer(at_call.value[1]), facts)
    begin = min(at_call.evidence)
    sources = {
        fact.value[0]: fact
        for fact in facts_by_kind(facts).get("expression.string_operand", ())
        if len(fact.subject) == 2
        and bridged(fact.subject[1], begin, moves)
        and len(fact.value) == 1
    }
    if length is None or start is None:
        return None
    return (start, begin), (length, begin), sources


def _implicit_integer(value: object) -> object:
    """Drop the integer conversion BASIC applies to an integer argument."""
    if (
        isinstance(value, tuple)
        and len(value) == 3
        and value[:2] == ("conversion", "integer")
    ):
        return value[2]
    return value


def string_function_expression_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover string-valued runtime function expressions."""

    moves = register_moves(evidence.instructions)
    ending = {item.end: item for item in evidence.instructions}
    instruction_ends = {item.offset: item.end for item in evidence.instructions}
    for instruction in evidence.instructions:
        names = {
            0x02: "COMMAND$",
            0x04: "DATE$",
            0x0E: "INKEY$",
            0x26: "TIME$",
        }
        name = (
            names.get(instruction.operands[1])
            if len(instruction.operands) == 2 and instruction.operands[0] == "string"
            else None
        )
        if name is not None:
            yield Fact(
                "expression.value",
                (instruction.offset,),
                (("call", name, ()),),
                (instruction.offset,),
                "signature",
            )
            # The call leaves its result on the string stack exactly where a
            # push would, so a comparison reading the stack finds it there
            # instead of reaching back past it for an earlier statement's push.
            yield Fact(
                "expression.string_operand",
                (instruction.offset, instruction.end),
                (("call", name, ()),),
                (instruction.offset,),
                "signature",
            )
        # ``INPUT$(n)`` takes its count in AX and leaves its result on the
        # string stack, where an enclosing function or a store reads it.
        count = ending.get(instruction.offset)
        if (
            instruction.kind == "tb.function"
            and instruction.operands == ("string", 0x10)
            and count is not None
            and count.kind == "x86.mov_imm"
            and count.operands[:1] == ("ax",)
            and len(count.operands) == 2
            and isinstance(count.operands[1], int)
        ):
            value = ("call", "INPUT$", (("const", count.operands[1]),))
            yield Fact(
                "expression.string_operand",
                (count.offset, instruction.end),
                (value,),
                (count.offset, instruction.offset),
                "signature",
            )
        if instruction.kind == "tb.function" and instruction.operands == (
            "string",
            0x08,
        ):
            operands = [
                fact
                for fact in facts_by_kind(facts).get("expression.string_operand", ())
                if fact.kind == "expression.string_operand"
                and len(fact.subject) == 2
                and fact.subject[1] == instruction.offset
                and len(fact.value) == 1
            ]
            if len(operands) == 1:
                operand = operands[0]
                yield Fact(
                    "expression.value",
                    (operand.subject[0],),
                    (("call", "ENVIRON$", (operand.value[0],)),),
                    combine_evidence(operand.evidence, (instruction.offset,)),
                    "anchored",
                )
        string_names = {0x16: "LCASE$", 0x28: "UCASE$"}
        if (
            instruction.kind == "tb.function"
            and len(instruction.operands) == 2
            and instruction.operands[0] == "string"
            and instruction.operands[1] in string_names
        ):
            operands = [
                fact
                for fact in facts_by_kind(facts).get("expression.string_operand", ())
                if fact.kind == "expression.string_operand"
                and len(fact.subject) == 2
                and fact.subject[1] == instruction.offset
                and len(fact.value) == 1
            ]
            if len(operands) == 1:
                operand = operands[0]
                yield Fact(
                    "expression.value",
                    (operand.subject[0],),
                    (
                        (
                            "call",
                            string_names[instruction.operands[1]],
                            (operand.value[0],),
                        ),
                    ),
                    combine_evidence(operand.evidence, (instruction.offset,)),
                    "anchored",
                )
                # Like LEFT$, the result stays on the string stack.
                yield Fact(
                    "expression.string_operand",
                    (operand.subject[0], instruction.end),
                    (
                        (
                            "call",
                            string_names[instruction.operands[1]],
                            (operand.value[0],),
                        ),
                    ),
                    combine_evidence(operand.evidence, (instruction.offset,)),
                    "anchored",
                )
        if instruction.kind == "tb.function" and instruction.operands == (
            "string",
            0x0A,
        ):
            yield Fact(
                "expression.value",
                (instruction.offset,),
                (("call", "ERDEV$", ()),),
                (instruction.offset,),
                "signature",
            )
        if instruction.kind == "tb.function" and instruction.operands == (
            "string",
            0x1E,
        ):
            previous = next(
                (
                    item
                    for item in reversed(evidence.instructions)
                    if item.end == instruction.offset
                ),
                None,
            )
            if (
                previous is not None
                and previous.kind == "x86.mov_imm"
                and previous.operands[:1] == ("ax",)
                and len(previous.operands) == 2
            ):
                yield Fact(
                    "expression.value",
                    (previous.offset,),
                    (("call", "SPACE$", (("const", previous.operands[1]),)),),
                    (previous.offset, instruction.offset),
                    "signature",
                )
        if instruction.kind == "tb.function" and instruction.operands == (
            "string",
            0x22,
        ):
            loads = [
                item
                for item in evidence.instructions
                if item.kind == "x86.mov_imm"
                and item.operands[:1] == ("ax",)
                and item.offset < instruction.offset
            ]
            if len(loads) >= 2:
                count, character = loads[-2:]
                yield Fact(
                    "expression.value",
                    (count.offset,),
                    (
                        (
                            "call",
                            "STRING$",
                            (
                                ("const", count.operands[1]),
                                ("const", character.operands[1]),
                            ),
                        ),
                    ),
                    (count.offset, character.offset, instruction.offset),
                    "signature",
                )
        numeric_to_string = {0x0C: "HEX$", 0x1C: "OCT$", 0x20: "STR$"}
        if (
            instruction.kind == "tb.function"
            and len(instruction.operands) == 2
            and instruction.operands[0] == "string"
            and instruction.operands[1] in numeric_to_string
        ):
            candidates = [
                fact
                for fact in facts_by_kind(facts).get("expression.value", ())
                if fact.kind == "expression.value"
                and fact.subject[0] < instruction.offset
                and len(fact.value) == 1
                and not (
                    isinstance(fact.value[0], tuple)
                    and fact.value[0][:2]
                    == ("call", numeric_to_string[instruction.operands[1]])
                )
            ]
            operand = _nearest_agreeing(candidates, instruction.offset)
            # The operand may name a call result the tracker could not yet
            # match to its value; wait for it.
            argument = (
                resolve_expression(operand.value[0], facts)
                if operand is not None
                else None
            )
            if operand is not None and argument is not None:
                yield Fact(
                    "expression.value",
                    (operand.subject[0],),
                    (
                        (
                            "call",
                            numeric_to_string[instruction.operands[1]],
                            (argument.value,),
                        ),
                    ),
                    combine_evidence(operand.evidence, (instruction.offset,)),
                    "anchored",
                )
        if instruction.kind == "tb.runtime" and instruction.operands in {
            (0xAD,),
            (0xB2,),
        }:
            loaded = _ax_operand(ending, instruction.offset, facts, instruction_ends)
            if loaded is None:
                continue
            count, count_start = loaded
            operands = [
                fact
                for fact in facts_by_kind(facts).get("expression.string_operand", ())
                if fact.kind == "expression.string_operand"
                and len(fact.subject) == 2
                and bridged(fact.subject[1], count_start, moves)
                and len(fact.value) == 1
            ]
            if not operands:
                # A string array element is read into the string stack the
                # same way, and recovered as the element read.
                operands = [
                    Fact(
                        "expression.string_operand",
                        fact.subject,
                        (fact.value[0],),
                        fact.evidence,
                        fact.confidence,
                    )
                    for fact in facts_by_kind(facts).get("reference.array_value", ())
                    if len(fact.subject) == 2
                    and fact.subject[1] == count_start
                    and len(fact.value) == 2
                    and fact.value[1] == "string"
                ]
            if not operands:
                continue
            operand = max(operands, key=lambda fact: (fact.subject[0], fact_key(fact)))
            name = "LEFT$" if instruction.operands == (0xAD,) else "RIGHT$"
            value = ("call", name, (operand.value[0], count.value))
            support = combine_evidence(
                operand.evidence, count.evidence, (count_start, instruction.offset)
            )
            yield Fact(
                "expression.value",
                (operand.subject[0],),
                (value,),
                support,
                "anchored",
            )
            # The result stays on the string stack, where a push would leave
            # it, so a comparison reads it there.
            yield Fact(
                "expression.string_operand",
                (operand.subject[0], instruction.end),
                (value,),
                support,
                "anchored",
            )
        if instruction.kind == "tb.runtime" and instruction.operands == (0xAC,):
            operands = [
                fact
                for fact in facts_by_kind(facts).get("expression.string_operand", ())
                if fact.kind == "expression.string_operand"
                and len(fact.subject) == 2
                and fact.subject[1] == instruction.offset
                and len(fact.value) == 1
            ]
            if len(operands) == 1:
                operand = operands[0]
                yield Fact(
                    "expression.value",
                    (operand.subject[0],),
                    (("call", "VAL", (operand.value[0],)),),
                    combine_evidence(operand.evidence, (instruction.offset,)),
                    "anchored",
                )
        if instruction.kind == "tb.runtime" and instruction.operands == (0xB1,):
            staged = _staged_mid(instruction, ending, facts)
            if staged is not None:
                yield from staged
                continue
        if instruction.kind == "tb.runtime" and instruction.operands == (0xB1,):
            # MID$(s, start, length): the length is in AX at the call, the
            # start was moved to BX before it, and s ends where start begins.
            length = _ax_operand(ending, instruction.offset, facts, instruction_ends)
            stage = ending.get(length[1]) if length is not None else None
            start = (
                _ax_operand(ending, stage.offset, facts, instruction_ends)
                if stage is not None and stage.raw == "89 c3"
                else None
            )
            sources = {
                fact.value[0]: fact
                for fact in facts_by_kind(facts).get("expression.string_operand", ())
                if start is not None
                and len(fact.subject) == 2
                and fact.subject[1] == start[1]
                and len(fact.value) == 1
            }
            if length is None or start is None or len(sources) != 1:
                tracked = _tracked_mid(instruction, facts, moves)
                if tracked is not None:
                    start, length, sources = tracked
                    stage = instruction
            if length is not None and start is not None and len(sources) == 1:
                source = next(iter(sources.values()))
                mid = (
                    "call",
                    "MID$",
                    (source.value[0], start[0].value, length[0].value),
                )
                support = combine_evidence(
                    source.evidence,
                    start[0].evidence,
                    length[0].evidence,
                    (stage.offset, instruction.offset),
                )
                yield Fact(
                    "expression.value",
                    (source.subject[0],),
                    (mid,),
                    support,
                    "anchored",
                )
                # Like LEFT$ and RIGHT$, the result stays on the string stack.
                yield Fact(
                    "expression.string_operand",
                    (source.subject[0], instruction.end),
                    (mid,),
                    support,
                    "anchored",
                )
        if instruction.kind == "tb.runtime" and instruction.operands == (0xB0,):
            sources = [
                item
                for item in facts
                if item.kind == "expression.string_operand"
                and len(item.subject) == 2
                and item.subject[1] <= instruction.offset
                and len(item.value) == 1
            ]
            target_setup = next(
                (
                    item
                    for item in evidence.instructions
                    if item.kind == "x86.mov_imm"
                    and item.operands[:1] == ("si",)
                    and item.offset == instruction.end
                ),
                None,
            )
            store = next(
                (
                    item
                    for item in evidence.instructions
                    if item.kind == "tb.runtime"
                    and item.operands == (0xA0,)
                    and target_setup is not None
                    and item.offset == target_setup.end
                ),
                None,
            )
            if sources and target_setup is not None and store is not None:
                source = max(
                    sources, key=lambda item: (item.subject[0], fact_key(item))
                )
                mid_start: object | None = None
                previous_operations = [
                    item
                    for item in evidence.instructions
                    if item.end <= instruction.offset
                ]
                if (
                    previous_operations
                    and previous_operations[-1].kind == "x86.mov_imm"
                    and previous_operations[-1].operands[:1] == ("ax",)
                ):
                    mid_start = ("const", previous_operations[-1].operands[1])
                elif previous_operations and previous_operations[-1].kind == "x86.mov":
                    raw = bytes.fromhex(previous_operations[-1].raw)
                    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
                        resolved_start = resolve_slot(
                            int.from_bytes(raw[2:], "little"), facts
                        )
                        mid_start = (
                            None if resolved_start is None else resolved_start.value
                        )
                if mid_start is not None:
                    yield Fact(
                        "expression.value",
                        (source.subject[0],),
                        (("call", "MID$", (source.value[0], mid_start)),),
                        combine_evidence(source.evidence, (instruction.offset,)),
                        "anchored",
                    )


@reads("expression.string_operand", "tb.function", "x86.mov")
def len_expression_facts(evidence: Evidence, facts: frozenset[Fact]) -> Iterable[Fact]:
    """Recover LEN expressions and their string operands."""
    instructions = {
        instruction.offset: instruction for instruction in evidence.instructions
    }
    # Register moves that save other values can separate the push from LEN.
    moves = register_moves(evidence.instructions)
    for string in facts:
        if (
            string.kind != "expression.string_operand"
            or len(string.subject) != 2
            or not isinstance(string.subject[0], int)
            or not isinstance(string.subject[1], int)
            or len(string.value) != 1
        ):
            continue
        end = string.subject[1]
        while end in moves:
            end = moves[end]
        call = instructions.get(end)
        if (
            call is None
            or call.kind != "tb.function"
            or call.operands != ("numeric", 0x22)
        ):
            continue
        yield Fact(
            "expression.value",
            (string.subject[0],),
            (("call", "LEN", (string.value[0],)),),
            combine_evidence(string.evidence, (call.offset,)),
            "anchored",
        )


@reads("expression.string_operand", "expression.value", "tb.runtime", "x86.mov")
def stack_asc_expression_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover ``ASC`` of the string on top of the string stack (runtime A6).

    The operand is a pushed string, or a string function whose result the
    stack holds; either ends at the call, perhaps past register moves that
    save an earlier term's value.
    """
    moves = register_moves(evidence.instructions)
    ends = {item.offset: item.end for item in evidence.instructions}
    by_kind = facts_by_kind(facts)
    for call in evidence.instructions:
        if call.kind != "tb.runtime" or call.operands != (0xA6,):
            continue
        candidates = [
            (fact.subject[0], fact.value[0], fact.evidence)
            for fact in by_kind.get("expression.string_operand", ())
            if len(fact.subject) == 2
            and len(fact.value) == 1
            and bridged(fact.subject[1], call.offset, moves)
        ]
        candidates += [
            (fact.subject[0], fact.value[0], fact.evidence)
            for fact in by_kind.get("expression.value", ())
            if len(fact.subject) == 1
            and fact.evidence
            and len(fact.value) == 1
            and isinstance(fact.value[0], tuple)
            and fact.value[0][:1] == ("call",)
            and fact.value[0][1] in {"LEFT$", "RIGHT$", "MID$"}
            # A slot's evidence names every reference to it, so the value's
            # own call is the evidence instruction that ends at this one.
            and any(
                bridged(ends.get(address), call.offset, moves)
                for address in fact.evidence
            )
        ]
        if len({value for _start, value, _evidence in candidates}) != 1:
            continue
        start, value, source = min(candidates, key=lambda item: (item[0], item[2]))
        yield Fact(
            "expression.value",
            (start, call.end),
            (("call", "ASC", (value,)),),
            combine_evidence(source, (call.offset,)),
            "anchored",
        )


@reads("layout.array", "signature", "tb.function", "x86.mov_imm")
def ax_function_expression_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover numeric functions whose result returns through AX."""

    for load, call in zip(evidence.instructions, evidence.instructions[1:]):
        if load.end != call.offset or call.kind != "tb.function":
            continue
        immediate_functions = {0x10: "EOF", 0x24: "LOC", 0x3C: "REG"}
        zero_functions = {
            0x28: "LPOS",
            0x2E: "PEN",
            0x48: "STICK",
            0x4A: "STRIG",
        }
        sub = (
            call.operands[1]
            if len(call.operands) == 2
            and call.operands[0] == "numeric"
            and isinstance(call.operands[1], int)
            else None
        )
        name = None
        argument = None
        if (
            sub in immediate_functions
            and load.kind == "x86.mov_imm"
            and load.operands[:1] == ("ax",)
            and len(load.operands) == 2
            and isinstance(load.operands[1], int)
        ):
            name, argument = immediate_functions[sub], load.operands[1]
        elif sub in zero_functions and load.raw == "31 c0":
            name, argument = zero_functions[sub], 0
        if name is None or argument is None:
            continue
        yield Fact(
            "expression.value",
            (load.offset,),
            (("call", name, (("const", argument),)),),
            (load.offset, call.offset),
            "signature",
        )
    arrays = indexed_facts(
        (
            fact
            for fact in facts_by_kind(facts).get("layout.array", ())
            if len(fact.value) == 7
            and len(fact.subject) == 2
            and isinstance(fact.subject[1], int)
        ),
        lambda fact: fact.subject[1],
        lambda fact: fact.value[1],
    )
    for index, call in enumerate(evidence.instructions):
        if (
            call.kind != "tb.function"
            or call.operands not in {("numeric", 0x4E), ("numeric", 0x20)}
            or index == 0
        ):
            continue
        loaded_operation = next(
            (
                item
                for item in reversed(evidence.instructions[max(0, index - 6) : index])
                if item.kind == "x86.mov_imm" and item.operands == ("ax", 288)
            ),
            None,
        )
        if loaded_operation is None:
            continue
        name = arrays.get(288)
        if name is None:
            continue
        function = "UBOUND" if call.operands[1] == 0x4E else "LBOUND"
        yield Fact(
            "expression.value",
            (load.offset,),
            (("call", function, (("array", name, (("const", 1),)),)),),
            (load.offset, call.offset),
            "signature",
        )


@reads("signature", "tb.function")
def zero_ax_function_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover AX functions with a zero-initialized accumulator."""

    functions = {
        0x0A: ("CSRLIN", ()),
        0x1A: ("INSTAT", ()),
        0x30: ("PLAY", (("const", 0),)),
        0x38: ("POS", (("const", 0),)),
    }
    for instruction in evidence.instructions:
        if (
            instruction.kind != "tb.function"
            or len(instruction.operands) != 2
            or instruction.operands[0] != "numeric"
        ):
            continue
        function = functions.get(instruction.operands[1])
        if function is None:
            continue
        name, arguments = function
        yield Fact(
            "expression.value",
            (instruction.offset,),
            (("call", name, arguments),),
            (instruction.offset,),
            "signature",
        )


@reads("signature", "tb.function", "x86.mov", "x86.mov_imm")
def screen_function_expression_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover SCREEN and related coordinate function expressions."""

    call_positions = [
        index
        for index, item in enumerate(evidence.instructions)
        if item.kind == "tb.function" and item.operands == ("numeric", 0x42)
    ]
    for first, second in zip(call_positions, call_positions[1:]):
        if second - first > 16:
            continue
        start = max(0, first - 10)
        window = evidence.instructions[start : second + 1]
        calls = [item for item in window if item.kind == "tb.function"]
        immediates = [
            item.operands[1]
            for item in window
            if item.kind == "x86.mov_imm"
            and len(item.operands) == 2
            and item.operands[0] == "ax"
        ]
        if (
            len(calls) != 2
            or any(call.operands != ("numeric", 0x42) for call in calls)
            or immediates != [16, 3, 4, 1]
            or sum(item.kind == "x86.mov" for item in window) < 5
        ):
            continue
        inner = ("call", "SCREEN", (("const", 4), ("const", 1)))
        yield Fact(
            "expression.value",
            (window[0].offset,),
            (
                (
                    "binary",
                    "\\",
                    ("call", "SCREEN", (("const", 3), inner)),
                    ("const", 16),
                ),
            ),
            tuple(item.offset for item in window),
            "anchored",
        )
        break

    for index in range(len(evidence.instructions) - 3):
        first_op, preserve_op, second_op, call_op = evidence.instructions[
            index : index + 4
        ]
        if (
            first_op.kind != "x86.mov_imm"
            or first_op.operands[:1] != ("ax",)
            or len(first_op.operands) != 2
            or preserve_op.raw not in {"89 c3", "8b d8"}
            or second_op.kind != "x86.mov_imm"
            or second_op.operands[:1] != ("ax",)
            or len(second_op.operands) != 2
            or call_op.kind != "tb.function"
            or call_op.operands != ("numeric", 0x42)
            or any(
                left.end != right.offset
                for left, right in zip(
                    (first_op, preserve_op, second_op),
                    (preserve_op, second_op, call_op),
                )
            )
        ):
            continue
        yield Fact(
            "expression.value",
            (first_op.offset,),
            (
                (
                    "call",
                    "SCREEN",
                    (
                        ("const", first_op.operands[1]),
                        ("const", second_op.operands[1]),
                    ),
                ),
            ),
            (first_op.offset, preserve_op.offset, second_op.offset, call_op.offset),
            "signature",
        )


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "reference.array_value",
    "register.value",
    "slot",
    "tb.function",
)
def fp_argument_ax_function_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover floating-point functions receiving an AX argument."""

    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    functions = {0x2C: "PEEK", 0x46: "SGN"}
    for call in evidence.instructions:
        if (
            call.kind != "tb.function"
            or len(call.operands) != 2
            or call.operands[0] != "numeric"
            or call.operands[1] not in functions
        ):
            continue
        argument = resolve_expression_before(call.offset, facts, instruction_ends)
        if argument is None:
            continue
        start = argument.start if argument.start is not None else argument.evidence[0]
        yield Fact(
            "expression.value",
            (start, call.end),
            (("call", functions[call.operands[1]], (argument.value,)),),
            combine_evidence(argument.evidence, (call.offset,)),
            "anchored",
        )


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "reference.array_value",
    "register.value",
    "slot",
    "tb.function",
    "x86.mov_imm",
)
def staged_ax_bx_function_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover functions whose arguments are staged through AX and BX."""
    instruction_ends = {
        instruction.offset: instruction.end for instruction in evidence.instructions
    }
    for index in range(len(evidence.instructions) - 4):
        staged, shuttle, argument_setup, call, combine = evidence.instructions[
            index : index + 5
        ]
        operator = {
            b"\x23\xc3": "AND",
            b"\x09\xd8": "OR",
            b"\x0b\xc3": "OR",
        }.get(bytes.fromhex(combine.raw))
        if not (
            shuttle.raw in {"89 c3", "8b d8"}
            and call.kind == "tb.function"
            and operator is not None
            and all(
                left.end == right.offset
                for left, right in zip(
                    (staged, shuttle, argument_setup, call),
                    (shuttle, argument_setup, call, combine),
                )
            )
        ):
            continue
        if (
            staged.kind == "x86.mov_imm"
            and staged.operands[:1] == ("ax",)
            and len(staged.operands) == 2
        ):
            left_value: object = ("const", staged.operands[1])
            left_evidence: tuple[int, ...] = (staged.offset,)
        else:
            left = resolve_expression_before(shuttle.offset, facts, instruction_ends)
            if left is None:
                continue
            left_value = left.value
            left_evidence = left.evidence
        right = resolve_expression_before(combine.offset, facts, instruction_ends)
        if right is None:
            continue
        yield Fact(
            "register.value",
            (combine.offset, "ax"),
            (("binary", operator, right.value, left_value),),
            combine_evidence(
                left_evidence,
                right.evidence,
                (shuttle.offset, combine.offset),
            ),
            "anchored",
        )


@reads(
    "constant",
    "expression.system",
    "expression.value",
    "layout.array",
    "machine.store",
    "memory.read",
    "reference.array_value",
    "register.value",
    "slot",
)
def transient_constant_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover short-lived constants consumed by runtime functions."""

    addresses = {
        fact.subject[0]
        for fact in facts_by_kind(facts).get("machine.store", ())
        if fact.kind == "machine.store"
        and fact.subject
        and isinstance(fact.subject[0], int)
        and fact.subject[0] < VAR_BASE
    }
    for address in addresses:
        stores = [
            fact
            for fact in facts_by_kind(facts).get("machine.store", ())
            if fact.kind == "machine.store" and fact.subject == (address,)
        ]
        reads = [
            fact
            for fact in facts_by_kind(facts).get("memory.read", ())
            if fact.kind == "memory.read" and fact.subject == (address,)
        ]
        if (
            len(stores) != 1
            or not reads
            or len(stores[0].value) != 1
            or not stores[0].evidence
            or not any(
                read.evidence and stores[0].evidence[-1] < read.evidence[0]
                for read in reads
            )
        ):
            continue
        value = stores[0].value[0]
        value_evidence: tuple[int, ...] = ()
        if isinstance(value, tuple) and value == ("register", "ax"):
            resolved = resolve_expression_before(
                stores[0].evidence[-1],
                facts,
                {
                    instruction.offset: instruction.end
                    for instruction in evidence.instructions
                },
            )
            if resolved is None:
                continue
            value = resolved.value
            value_evidence = resolved.evidence
        elif not (isinstance(value, tuple) and value[:1] == ("const",)):
            continue
        yield Fact(
            "constant",
            ("memory", address),
            value,
            combine_evidence(
                stores[0].evidence,
                value_evidence,
                *(read.evidence for read in reads),
            ),
            "anchored",
        )


FUNCTION_FACT_PASSES: tuple[NamedPass, ...] = (
    ("function-expressions", function_expression_facts),
    ("system-expressions", system_expression_facts),
    ("string-function-expressions", string_function_expression_facts),
    ("len-expressions", len_expression_facts),
    ("stack-asc-expressions", stack_asc_expression_facts),
    ("ax-function-expressions", ax_function_expression_facts),
    ("zero-ax-function-expressions", zero_ax_function_expression_facts),
    ("screen-function-expressions", screen_function_expression_facts),
    ("fp-argument-ax-functions", fp_argument_ax_function_facts),
    ("staged-ax-bx-functions", staged_ax_bx_function_facts),
    ("transient-constants", transient_constant_facts),
)
