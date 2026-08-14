"""TRON/TROFF region facts over immutable compiler trace hooks."""

from __future__ import annotations

from collections.abc import Iterable

from tbd.facts import Evidence, NamedPass
from tbd.ir import Fact, Operation
from tbd.semantic import combine_evidence

_SOURCE_FACTS = {
    "semantic.assign",
    "semantic.call",
    "semantic.delay",
    "semantic.defseg",
    "semantic.gosub",
    "semantic.if_goto",
    "semantic.print",
    "semantic.return",
    "semantic.resume",
    "semantic.run",
    "semantic.statement",
}
_CONTROL = {
    "tb.return_to",
    "x86.call",
    "x86.call_far",
    "x86.iret",
    "x86.jmp",
    "x86.jmp_far",
    "x86.loop",
    "x86.loope",
    "x86.loopne",
    "x86.ret",
    "x86.retf",
}


def trace_region_facts(
    evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover toggles only where hook boundaries positively prove them."""

    hooks = tuple(
        instruction
        for instruction in evidence.instructions
        if instruction.kind == "tb.trace"
    )
    if not _proves_region_start(hooks, evidence.instructions):
        return
    source = _source_facts(facts)
    first_support = (hooks[1].offset,) if len(hooks) > 1 else ()
    yield _toggle("semantic.tron", hooks[0], first_support)
    for left, right in zip(hooks, hooks[1:]):
        payload, marker = _payload_start(left, evidence.instructions)
        witnesses = _between(source, payload, right.offset)
        if not witnesses or _has_control(evidence.instructions, left.end, right.offset):
            continue
        support = combine_evidence(
            () if marker is None else (marker,),
            witnesses[0].evidence,
        )
        yield _toggle("semantic.troff", left, support)
        yield _toggle("semantic.tron", right, support)
    last_payload, marker = _payload_start(hooks[-1], evidence.instructions)
    following = next(
        (fact for fact in source if _span(fact)[0] > last_payload),
        None,
    )
    if following is not None and not _has_control(
        evidence.instructions, hooks[0].end, _span(following)[0]
    ):
        support = combine_evidence(
            () if marker is None else (marker,),
            following.evidence,
        )
        yield _toggle("semantic.troff", hooks[-1], support)


def _proves_region_start(
    hooks: tuple[Operation, ...], instructions: tuple[Operation, ...]
) -> bool:
    if len(hooks) > 1:
        return True
    if not hooks:
        return False
    previous = next(
        (
            instruction
            for instruction in reversed(instructions)
            if instruction.end <= hooks[0].offset
        ),
        None,
    )
    return (
        previous is not None
        and previous.kind == "tb.prologue"
        and previous.end == hooks[0].offset
    )


def _source_facts(facts: frozenset[Fact]) -> tuple[Fact, ...]:
    return tuple(
        sorted(
            (
                fact
                for fact in facts
                if fact.kind in _SOURCE_FACTS and _span(fact) is not None
            ),
            key=lambda fact: (*_span(fact), fact.kind),
        )
    )


def _payload_start(
    hook: Operation, instructions: tuple[Operation, ...]
) -> tuple[int, int | None]:
    following = next(
        (instruction for instruction in instructions if instruction.offset == hook.end),
        None,
    )
    if following is not None and following.kind == "x86.int3":
        return following.end, following.offset
    return hook.end, None


def _between(
    facts: tuple[Fact, ...], start: int, end: int
) -> tuple[Fact, ...]:
    return tuple(fact for fact in facts if start < _span(fact)[0] < end)


def _has_control(
    instructions: tuple[Operation, ...], start: int, end: int
) -> bool:
    return any(
        start <= instruction.offset < end
        and (
            instruction.kind in _CONTROL
            or instruction.kind.startswith("x86.j")
        )
        for instruction in instructions
    )


def _toggle(kind: str, hook: Operation, support: tuple[int, ...]) -> Fact:
    return Fact(
        kind,
        (hook.offset, hook.end),
        (),
        combine_evidence((hook.offset,), support),
        "signature",
    )


def _span(fact: Fact) -> tuple[int, int] | None:
    if len(fact.subject) != 2:
        return None
    start, end = fact.subject
    if not isinstance(start, int) or not isinstance(end, int) or start >= end:
        return None
    return start, end


TRACE_FACT_PASSES: tuple[NamedPass, ...] = (
    ("trace-regions", trace_region_facts),
)
