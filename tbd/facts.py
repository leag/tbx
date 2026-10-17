"""Evidence records and fixed-point semantic fact analysis."""

from __future__ import annotations

import multiprocessing
import os
import pickle
import threading
import traceback
from collections.abc import Callable, Iterable
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from tbd.cache import identity_cache
from tbd.compiler_ops import translate_operations
from tbd.ir import BasicBlock, CrossReference, Fact, FactReport, Operation


@dataclass(frozen=True)
class Evidence:
    """Immutable machine-level evidence shared by fact passes."""

    image: bytes
    instructions: tuple[Operation, ...]
    blocks: tuple[BasicBlock, ...]
    xrefs: tuple[CrossReference, ...]


FactPass = Callable[[Evidence, frozenset[Fact]], Iterable[Fact]]
NamedPass = tuple[str, FactPass]


def fact_key(fact: Fact) -> tuple[object, ...]:
    """Return a total order for facts, so ties never depend on set order."""
    return (fact.kind, repr(fact.subject), repr(fact.value), fact.evidence)


def indexed_facts(
    facts: Iterable[Fact],
    key: Callable[[Fact], Any],
    value: Callable[[Fact], Any] = lambda fact: fact,
) -> dict[Any, Any]:
    """Index facts by ``key``, keeping one entry when several share a key.

    Several facts can share the address a caller indexes them by, and a plain
    comprehension keeps whichever the set yielded last.  The survivor and the
    resulting order are decided by ``fact_key`` instead.
    """
    result: dict[Any, Any] = {}
    for fact in sorted(facts, key=fact_key):
        result.setdefault(key(fact), value(fact))
    return result


@identity_cache
def ordered_by_kind(
    facts: frozenset[Fact] | tuple[Fact, ...],
) -> dict[str, tuple[Fact, ...]]:
    """Group a snapshot by kind in a total order, for passes that select."""
    return {
        kind: tuple(sorted(items, key=fact_key))
        for kind, items in facts_by_kind(facts).items()
    }


def latest_store(stores: Iterable[Fact]) -> Fact | None:
    """Return the store whose evidence ends last, ordered when several tie."""
    candidates = [fact for fact in stores if fact.evidence]
    if not candidates:
        return None
    return max(candidates, key=lambda fact: (max(fact.evidence), fact_key(fact)))


@identity_cache
def facts_by_kind(
    facts: frozenset[Fact] | tuple[Fact, ...],
) -> dict[str, tuple[Fact, ...]]:
    """Group a snapshot once, preserving its iteration order and duplicates."""
    groups: dict[str, list[Fact]] = {}
    for fact in facts:
        groups.setdefault(fact.kind, []).append(fact)
    return {kind: tuple(items) for kind, items in groups.items()}


def reads(*kinds: str) -> Callable[[FactPass], FactPass]:
    """Declare the fact kinds a pass reads.

    An entry ending in ``.`` or ``_`` is a prefix; any other is an exact kind.
    A declared pass sees only those kinds, and in any round after the first it
    is skipped when none of them gained a fact in the previous round.
    """
    if not kinds:
        raise ValueError("reads() needs at least one kind")
    declared = frozenset(kinds)

    def declare(fact_pass: FactPass) -> FactPass:
        fact_pass.reads = declared  # type: ignore[attr-defined]
        return fact_pass

    return declare


def kind_matches(kind: str, declared: frozenset[str]) -> bool:
    """Return whether a ``reads`` declaration covers ``kind``."""
    return kind in declared or any(
        entry.endswith((".", "_")) and kind.startswith(entry) for entry in declared
    )


def _view(
    snapshot: frozenset[Fact],
    declared: frozenset[str],
    views: dict[frozenset[str], frozenset[Fact]],
) -> frozenset[Fact]:
    """Return the facts a declaration covers, built once per round."""
    view = views.get(declared)
    if view is None:
        view = frozenset(
            fact
            for kind, items in facts_by_kind(snapshot).items()
            if kind_matches(kind, declared)
            for fact in items
        )
        views[declared] = view
    return view


def _run_one(
    evidence: Evidence,
    snapshot: frozenset[Fact],
    name: str,
    fact_pass: FactPass,
    view: frozenset[Fact],
    verify: bool,
) -> tuple[frozenset[Fact], float]:
    """Run one pass on its view and return its new facts and duration."""
    started = perf_counter()
    unseen = frozenset(
        fact for fact in fact_pass(evidence, view) if fact not in snapshot
    )
    seconds = perf_counter() - started
    if verify and view is not snapshot:
        full = frozenset(
            fact for fact in fact_pass(evidence, snapshot) if fact not in snapshot
        )
        if full != unseen:
            lost = sorted({fact.kind for fact in full - unseen})
            gained = sorted({fact.kind for fact in unseen - full})
            raise AssertionError(
                f"fact pass {name!r} reads an undeclared kind: its view lost "
                f"{lost} and gained {gained}"
            )
    return unseen, seconds


def _verify_skip(
    evidence: Evidence, snapshot: frozenset[Fact], name: str, fact_pass: FactPass
) -> None:
    """Fail when a pass the engine skipped would have added facts."""
    added = sorted(
        {fact.kind for fact in fact_pass(evidence, snapshot) if fact not in snapshot}
    )
    if added:
        raise AssertionError(f"fact pass {name!r} was skipped but would add {added}")


class FactPassError(RuntimeError):
    """A fact pass failed inside a forked worker."""

    def __init__(self, pass_name: str, detail: str) -> None:
        super().__init__(
            f"fact pass {pass_name!r} failed in a forked worker:\n{detail}"
        )
        self.pass_name = pass_name


_Scheduled = tuple[int, str, FactPass, frozenset[Fact]]
_Round = tuple[Evidence, frozenset[Fact], tuple[_Scheduled, ...], bool]
_FORKED: _Round | None = None
"""The round a forked worker runs; set only inside workers, by ``_install``."""


_FORK_LOCK = threading.Lock()
"""Held while a round runs in forked workers.

A fork copies only the calling thread, so a lock another thread holds at that
moment stays held forever in the child.  Two threads forking rounds at once
did exactly that, and the pool then waited on a child that could not run.
"""


def _install(state: _Round) -> None:
    """Hand a forked worker its round, inherited rather than pickled."""
    global _FORKED
    _FORKED = state


def _run_forked(
    position: int,
) -> tuple[int, frozenset[Fact] | None, float, tuple[str, BaseException, str] | None]:
    """Run one scheduled pass in a forked worker, returning failures as data."""
    assert _FORKED is not None
    evidence, snapshot, scheduled, verify = _FORKED
    index, name, fact_pass, view = scheduled[position]
    try:
        unseen, seconds = _run_one(evidence, snapshot, name, fact_pass, view, verify)
    except BaseException as error:
        detail = traceback.format_exc()
        # The parent must be able to rebuild the error, not only receive it:
        # an exception that pickles but cannot be unpickled would break the
        # pool's result handling instead of reporting the pass.
        try:
            pickle.loads(pickle.dumps(error))
        except Exception:
            error = RuntimeError(f"{type(error).__name__}: {error}")
        return index, None, 0.0, (name, error, detail)
    return index, unseen, seconds, None


def _run_scheduled(
    evidence: Evidence,
    snapshot: frozenset[Fact],
    scheduled: list[_Scheduled],
    jobs: int,
    verify: bool,
    last_seconds: dict[str, float],
) -> dict[int, tuple[frozenset[Fact], float]]:
    """Run a round's passes, in forked workers when there is work to share."""
    if jobs == 1 or len(scheduled) < 2:
        return {
            index: _run_one(evidence, snapshot, name, fact_pass, view, verify)
            for index, name, fact_pass, view in scheduled
        }
    # Warm the caches every pass consults, so each worker inherits them.
    facts_by_kind(snapshot)
    translate_operations(evidence.instructions)
    order = sorted(
        range(len(scheduled)),
        key=lambda position: (-last_seconds.get(scheduled[position][1], 0.0), position),
    )
    with _FORK_LOCK:
        return _run_forked_round(evidence, snapshot, scheduled, jobs, verify, order)


def _run_forked_round(
    evidence: Evidence,
    snapshot: frozenset[Fact],
    scheduled: list[_Scheduled],
    jobs: int,
    verify: bool,
    order: list[int],
) -> dict[int, tuple[frozenset[Fact], float]]:
    """Run one round's passes in a pool of forked workers, in ``order``."""
    results: dict[int, tuple[frozenset[Fact], float]] = {}
    pool = ProcessPoolExecutor(
        max_workers=min(jobs, len(scheduled)),
        mp_context=multiprocessing.get_context("fork"),
        initializer=_install,
        initargs=((evidence, snapshot, tuple(scheduled), verify),),
    )
    futures = {
        pool.submit(_run_forked, position): scheduled[position][1] for position in order
    }
    try:
        for future in as_completed(futures):
            index, unseen, seconds, failure = future.result()
            if failure is not None:
                name, error, detail = failure
                raise FactPassError(name, detail) from error
            assert unseen is not None
            results[index] = (unseen, seconds)
    except BrokenProcessPool as error:
        lost = [
            name
            for future, name in futures.items()
            if future.done() and isinstance(future.exception(), BrokenProcessPool)
        ]
        raise FactPassError(
            ", ".join(lost), "a worker process died while running one of these"
        ) from error
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return results


def analyze(
    evidence: Evidence,
    *,
    rounds: int | None,
    passes: tuple[NamedPass, ...] | None = None,
    jobs: int = 1,
) -> tuple[tuple[Fact, ...], tuple[FactReport, ...], bool]:
    """Run named fact passes until convergence or the round limit.

    A pass declared with ``reads`` sees only those kinds and is skipped in any
    round where none of them changed; its output would repeat its last run.
    With ``TBD_VERIFY_READS=1`` each declared pass is also run on the whole
    snapshot, and a difference fails.  ``jobs`` above 1 runs each round's
    passes in that many forked processes; the result does not depend on it.
    Forked rounds run one at a time in a process, and as with any ``fork``, a
    lock another thread holds outside this module is not released in the
    workers.
    """
    if jobs < 1:
        raise ValueError("jobs must be positive")
    if jobs > 1 and "fork" not in multiprocessing.get_all_start_methods():
        raise ValueError("jobs above 1 need the fork start method")
    if jobs > 1 and multiprocessing.current_process().daemon:
        raise ValueError("jobs above 1 cannot run inside a daemonic process")
    verify = os.environ.get("TBD_VERIFY_READS") == "1"
    selected = passes if passes is not None else EVIDENCE_PASSES
    facts: set[Fact] = set()
    reports: list[FactReport] = []
    converged = False
    structural = frozenset({"instructions", "signatures", "blocks", "xrefs"})
    changed_kinds: frozenset[str] = frozenset()
    last_seconds: dict[str, float] = {}
    round_number = 0
    while rounds is None or round_number < rounds:
        round_number += 1
        snapshot = frozenset(facts)
        views: dict[frozenset[str], frozenset[Fact]] = {}
        active: list[tuple[int, str, bool]] = []
        scheduled: list[_Scheduled] = []
        for index, (name, fact_pass) in enumerate(selected):
            if round_number > 1 and name in structural:
                continue
            declared = getattr(fact_pass, "reads", None)
            if declared is None:
                view = snapshot
            elif round_number > 1 and not any(
                kind_matches(kind, declared) for kind in changed_kinds
            ):
                if verify:
                    _verify_skip(evidence, snapshot, name, fact_pass)
                active.append((index, name, True))
                continue
            else:
                view = _view(snapshot, declared, views)
            active.append((index, name, False))
            scheduled.append((index, name, fact_pass, view))
        results = _run_scheduled(
            evidence, snapshot, scheduled, jobs, verify, last_seconds
        )
        additions: set[Fact] = set()
        for index, name, skipped in active:
            if skipped:
                reports.append(
                    FactReport(round_number, name, 0, len(snapshot) + len(additions))
                )
                continue
            unseen, seconds = results[index]
            additions.update(unseen)
            last_seconds[name] = seconds
            reports.append(
                FactReport(
                    round_number,
                    name,
                    len(unseen),
                    len(snapshot) + len(additions),
                    seconds,
                )
            )
        if not additions:
            converged = True
            break
        facts.update(additions)
        changed_kinds = frozenset(fact.kind for fact in additions)
    return tuple(sorted(facts, key=_fact_key)), tuple(reports), converged


def instruction_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    """Emit structural facts for every decoded machine instruction."""
    for instruction in evidence.instructions:
        yield Fact(
            "instruction",
            (instruction.offset,),
            (instruction.kind, instruction.size, instruction.raw),
            (instruction.offset,),
            "structural",
        )


def signature_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    """Emit facts for instructions recognized by a compiler signature."""
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
    """Emit control-flow block boundaries and successor facts."""
    for block in evidence.blocks:
        yield Fact(
            "block",
            (block.start,),
            (block.end, block.instruction_offsets, block.successors),
            block.instruction_offsets,
            "structural",
        )


def xref_facts(evidence: Evidence, _facts: frozenset[Fact]) -> Iterable[Fact]:
    """Emit structural cross-reference facts from the discovered image."""
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
"""Evidence records and fixed-point semantic fact analysis."""
