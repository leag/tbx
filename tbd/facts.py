"""Monotonic fact collection over immutable discovery evidence."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from tbd.ir import BasicBlock, CrossReference, Fact, FactReport, Operation


@dataclass(frozen=True)
class Evidence:
    """Inputs shared by pure fact passes."""

    image: bytes
    instructions: tuple[Operation, ...]
    blocks: tuple[BasicBlock, ...]
    xrefs: tuple[CrossReference, ...]


FactPass = Callable[[Evidence, frozenset[Fact]], Iterable[Fact]]
NamedPass = tuple[str, FactPass]


def analyze(
    evidence: Evidence,
    *,
    rounds: int,
    passes: tuple[NamedPass, ...] | None = None,
) -> tuple[tuple[Fact, ...], tuple[FactReport, ...], bool]:
    """Run additive passes to a fixed point without pass-order mutation."""

    selected = passes if passes is not None else EVIDENCE_PASSES
    facts: set[Fact] = set()
    reports = []
    converged = False
    for round_number in range(1, rounds + 1):
        snapshot = frozenset(facts)
        additions: set[Fact] = set()
        for name, fact_pass in selected:
            proposed = set(fact_pass(evidence, snapshot))
            unseen = proposed - snapshot
            additions.update(unseen)
            reports.append(
                FactReport(round_number, name, len(unseen), len(snapshot | additions))
            )
        if not additions:
            converged = True
            break
        facts.update(additions)
    return tuple(sorted(facts, key=_fact_key)), tuple(reports), converged


def instruction_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    for instruction in evidence.instructions:
        yield Fact(
            "instruction",
            (instruction.offset,),
            (instruction.kind, instruction.size, instruction.raw),
            (instruction.offset,),
            "structural",
        )


def signature_facts(
    evidence: Evidence, _facts: frozenset[Fact]
) -> Iterable[Fact]:
    for instruction in evidence.instructions:
        if instruction.confidence == "signature":
            yield Fact(
                "signature",
                (instruction.offset,),
                (instruction.kind, _freeze(instruction.operands)),
                (instruction.offset,),
                "signature",
            )


def block_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    for block in evidence.blocks:
        yield Fact(
            "block",
            (block.start,),
            (block.end, block.instruction_offsets, block.successors),
            block.instruction_offsets,
            "structural",
        )


def xref_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    for xref in evidence.xrefs:
        yield Fact(
            "xref",
            (xref.source,),
            (xref.kind, xref.target),
            (xref.source,),
            "structural",
        )


def _freeze(value: Any) -> Any:
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, dict):
        return tuple(sorted((key, _freeze(item)) for key, item in value.items()))
    return value


def _fact_key(fact: Fact) -> tuple[str, str, str, tuple[int, ...], str]:
    return (
        fact.kind,
        repr(fact.subject),
        repr(fact.value),
        fact.evidence,
        fact.confidence,
    )


EVIDENCE_PASSES: tuple[NamedPass, ...] = (
    ("instructions", instruction_facts),
    ("signatures", signature_facts),
    ("blocks", block_facts),
    ("xrefs", xref_facts),
)
