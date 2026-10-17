from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from tbd.cache import identity_cache
from tbd.facts import Evidence, fact_key, reads
from tbd.ir import Fact
from tbd.operation_helpers import fact_inside as _inside
from tbd.semantic import combine_evidence

_STRUCTURED_SEMANTICS = {"semantic.if_block", "semantic.if_inline"}


@reads(
    "control.compound_condition",
    "control.condition_prefix",
    "flow.goto",
    "semantic.",
    "semantic.do",
    "semantic.exit_def",
    "semantic.exit_sub",
    "semantic.for",
    "semantic.gosub",
    "semantic.goto",
    "semantic.if_block",
    "semantic.if_goto",
    "semantic.if_goto_condition",
    "semantic.if_inline",
    "semantic.loop",
    "semantic.next",
    "semantic.on_gosub",
    "semantic.on_goto",
    "semantic.on_trap",
    "semantic.resume",
    "semantic.select_case",
)
def block_if_region_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover TBX's folded block-IF shape from immutable control-flow facts.

    Each completed arm ends in an unconditional jump to one common merge. The
    false edge either starts another condition (an ELSEIF) or the final ELSE
    body. A block without ELSE has no common-exit jump and ends at its false
    target. This is the address-level rule used by ``tbx.decode0._fold_if``;
    only the representation differs here.
    """

    flows = _goto_facts(facts)
    terminating_exits = frozenset(
        fact.subject
        for fact in facts
        if fact.kind in {"semantic.exit_def", "semantic.exit_sub"}
        and len(fact.subject) == 2
    )
    decisions = _condition_facts(facts)
    branch_targets = _semantic_branch_targets(facts)
    decisions_by_start: dict[int, list[Fact]] = {}
    for decision in decisions:
        decisions_by_start.setdefault(decision.subject[0], []).append(decision)
    semantic = tuple(
        fact
        for fact in facts
        if fact.kind.startswith("semantic.") and fact.kind not in _STRUCTURED_SEMANTICS
    )
    candidates: list[tuple[Fact, Fact]] = []
    continuation_starts: set[int] = set()
    for decision in sorted(decisions, key=lambda fact: (fact.subject, fact_key(fact))):
        shape = _block_if_shape(
            decision,
            decisions_by_start,
            flows,
            semantic,
            branch_targets,
            terminating_exits,
        )
        if shape is None:
            continue
        arms, else_bounds, region_end, support, continuations = shape
        loop_back = next(
            (
                flow
                for flow in flows
                if else_bounds is not None
                and flow.subject[0] >= else_bounds[0]
                and flow.value[0] == decision.subject[0]
            ),
            None,
        )
        if loop_back is not None and else_bounds is not None:
            region_end = else_bounds[0]
            else_bounds = None
        exit_flow = None
        if loop_back is not None and else_bounds is None:
            exit_flow = next(
                (
                    flow
                    for flow in flows
                    if flow.value[0] == loop_back.subject[1]
                    and any(
                        start <= flow.subject[0] <= end
                        for _condition, start, end in arms
                    )
                ),
                None,
            )
            if exit_flow is not None:
                arms = tuple(
                    (
                        condition,
                        start,
                        exit_flow.subject[1] if end == exit_flow.subject[0] else end,
                    )
                    for condition, start, end in arms
                )
        continuation_starts.update(continuations)
        candidates.append(
            (
                decision,
                Fact(
                    "region.if_block",
                    (decision.subject[0], region_end),
                    (arms, else_bounds),
                    combine_evidence(decision.evidence, *support),
                    "anchored",
                ),
            )
        )
        if loop_back is not None and else_bounds is None:
            yield Fact(
                "semantic.do_codeless",
                (decision.subject[0],),
                (None, None),
                decision.evidence + loop_back.evidence,
                "anchored",
            )
            if exit_flow is not None:
                yield Fact(
                    "semantic.exit_loop",
                    exit_flow.subject,
                    (exit_flow.value[0],),
                    exit_flow.evidence,
                    "anchored",
                )
            yield Fact(
                "semantic.loop",
                (loop_back.subject[0], loop_back.subject[1]),
                (None, None, decision.subject[0]),
                decision.evidence + loop_back.evidence,
                "anchored",
            )
    for decision, region in candidates:
        is_root = region.subject[0] not in continuation_starts
        block_evidence = (
            decision.kind == "control.condition_prefix"
            or _has_common_exit(decision, flows)
            or _requires_block_body(region, facts)
        )
        if is_root and block_evidence and not _claimed_as_loop(decision, facts):
            yield region


def _goto_facts(facts: frozenset[Fact]) -> tuple[Fact, ...]:
    # Loop-back and loop-exit edges are picked by taking the first match, so
    # the edges have to arrive in address order rather than in set order.
    return tuple(
        sorted(
            (
                fact
                for fact in facts
                if fact.kind == "flow.goto"
                and len(fact.subject) == 2
                and len(fact.value) == 1
                and all(
                    isinstance(value, int) for value in (*fact.subject, *fact.value)
                )
            ),
            key=fact_key,
        )
    )


def _condition_facts(facts: frozenset[Fact]) -> tuple[Fact, ...]:
    return tuple(
        sorted(
            (
                fact
                for fact in facts
                if fact.kind
                in {"control.condition_prefix", "control.compound_condition"}
                and len(fact.subject) == 2
                and len(fact.value) == 4
                and fact.value[1] == 0x75
                and all(isinstance(value, int) for value in fact.subject)
                and isinstance(fact.value[2], int)
                and isinstance(fact.value[3], int)
                and fact.value[2] > fact.value[3]
            ),
            key=fact_key,
        )
    )


def _semantic_branch_targets(facts: frozenset[Fact]) -> frozenset[int]:
    targets: set[int] = set()
    for fact in facts:
        targets.update(_fact_branch_targets(fact))
    return frozenset(targets)


def _fact_branch_targets(fact: Fact) -> tuple[int, ...]:
    values: tuple[object, ...] = ()
    if fact.kind in {"semantic.goto", "semantic.gosub", "semantic.resume"}:
        values = fact.value[:1]
    elif fact.kind == "semantic.if_goto" and len(fact.value) == 5:
        values = fact.value[3:4]
    elif fact.kind == "semantic.if_goto_condition" and len(fact.value) == 3:
        values = fact.value[1:2]
    elif fact.kind in {"semantic.on_goto", "semantic.on_gosub"}:
        values = fact.value[1:]
    elif fact.kind == "semantic.on_trap" and len(fact.value) == 3:
        values = fact.value[2:3]
    return tuple(value for value in values if isinstance(value, int))


def _block_if_shape(
    first: Fact,
    decisions_by_start: dict[int, list[Fact]],
    flows: tuple[Fact, ...],
    semantic: tuple[Fact, ...],
    branch_targets: frozenset[int],
    terminating_exits: frozenset[tuple[object, ...]],
) -> (
    tuple[
        tuple[tuple[object, int, int], ...],
        tuple[int, int] | None,
        int,
        tuple[tuple[int, ...], ...],
        tuple[int, ...],
    ]
    | None
):
    arms: list[tuple[object, int, int]] = []
    support: list[tuple[int, ...]] = []
    continuations: list[int] = []
    decision = first
    region_end: int | None = None
    while True:
        condition, _polarity, false_target, body_start = decision.value
        extent = _arm_extent(
            false_target,
            region_end,
            flows,
            terminating_exits,
            body_start,
        )
        if extent is None:
            return None
        body_end, region_end, exit_evidence = extent
        body = _body_facts(semantic, body_start, body_end)
        if body_end <= body_start or not body:
            return None
        arms.append((condition, body_start, body_end))
        support.extend((exit_evidence, *(fact.evidence for fact in body)))
        if false_target == region_end:
            return tuple(arms), None, region_end, tuple(support), tuple(continuations)
        following = decisions_by_start.get(false_target, [])
        if len(following) == 1 and _continues_block_if(following[0], region_end, flows):
            decision = following[0]
            continuations.append(decision.subject[0])
            support.append(decision.evidence)
            continue
        else_body = _body_facts(semantic, false_target, region_end)
        targeted = any(false_target <= target < region_end for target in branch_targets)
        if not else_body or targeted or _closes_outer_loop(else_body):
            return None
        # The ELSE starts where the arm's jump lands; code there that no
        # statement reads is most likely an ELSEIF whose condition was not
        # recognized, and a block over it would drop its branches.
        if min(fact.subject[0] for fact in else_body) != false_target:
            return None
        support.extend(fact.evidence for fact in else_body)
        return (
            tuple(arms),
            (false_target, region_end),
            region_end,
            tuple(support),
            tuple(continuations),
        )


def _arm_extent(
    false_target: int,
    region_end: int | None,
    flows: tuple[Fact, ...],
    terminating_exits: frozenset[tuple[object, ...]],
    body_start: int,
) -> tuple[int, int, tuple[int, ...]] | None:
    # An arm ends at a jump over the ELSE body, which must leave room for the
    # arm's own statements.  A jump starting at ``body_start`` is the arm's only
    # statement, so the region ends at the false target and there is no ELSE.
    exits = [
        flow
        for flow in flows
        if flow.subject[1] == false_target
        and flow.value[0] > false_target
        and flow.subject[0] > body_start
        and (region_end is None or flow.value[0] == region_end)
    ]
    terminating = [flow for flow in exits if flow.subject in terminating_exits]
    if region_end is None and len(terminating) == 1:
        exit_flow = terminating[0]
        return false_target, false_target, exit_flow.evidence
    if region_end is None and not exits:
        return false_target, false_target, ()
    if region_end is not None and false_target == region_end:
        return false_target, region_end, ()
    if len(exits) != 1:
        return None
    exit_flow = exits[0]
    return exit_flow.subject[0], exit_flow.value[0], exit_flow.evidence


def _continues_block_if(
    decision: Fact, region_end: int, flows: tuple[Fact, ...]
) -> bool:
    _condition, _polarity, false_target, _body_start = decision.value
    return false_target == region_end or any(
        flow.subject[1] == false_target and flow.value[0] == region_end
        for flow in flows
    )


def _has_common_exit(decision: Fact, flows: tuple[Fact, ...]) -> bool:
    _condition, _polarity, false_target, _body_start = decision.value
    return any(
        flow.subject[1] == false_target and flow.value[0] > false_target
        for flow in flows
    )


def _claimed_as_loop(decision: Fact, facts: frozenset[Fact]) -> bool:
    return any(
        fact.kind in {"semantic.do", "semantic.loop"}
        and len(fact.subject) == 2
        and fact.subject[0] == decision.subject[0]
        for fact in facts
    )


def _requires_block_body(region: Fact, facts: frozenset[Fact]) -> bool:
    arms, else_bounds = region.value
    ranges = _body_ranges(arms, else_bounds)
    body = tuple(
        fact
        for fact in facts
        if fact.kind.startswith("semantic.")
        and any(_inside(fact, start, end) for start, end in ranges)
    )
    if any(fact.kind in {"semantic.if_block", "semantic.select_case"} for fact in body):
        return True
    return any(_conditional_precedes_statement(fact, body) for fact in body)


def _conditional_precedes_statement(fact: Fact, body: tuple[Fact, ...]) -> bool:
    if (
        fact.kind not in {"semantic.if_inline", "semantic.if_goto"}
        or len(fact.subject) != 2
        or not all(isinstance(value, int) for value in fact.subject)
    ):
        return False
    return any(
        following is not fact
        and len(following.subject) == 2
        and all(isinstance(value, int) for value in following.subject)
        and following.subject[0] >= fact.subject[1]
        for following in body
    )


def _closes_outer_loop(body: tuple[Fact, ...]) -> bool:
    depth = 0
    for fact in sorted(body, key=lambda item: (item.subject, fact_key(item))):
        if fact.kind in {"semantic.do", "semantic.for"}:
            depth += 1
        elif fact.kind in {"semantic.loop", "semantic.next"}:
            if depth == 0:
                return True
            depth -= 1
    return False


@reads(
    "region.if_block",
    "semantic.",
    "semantic.if_block",
    "semantic.if_goto",
    "semantic.if_inline",
)
def block_if_semantic_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Convert recovered block-IF regions into semantic facts."""
    for region in facts:
        if region.kind != "region.if_block" or len(region.value) != 2:
            continue
        arms, else_bounds = region.value
        ranges = _body_ranges(arms, else_bounds)
        if not isinstance(arms, tuple) or not arms or len(ranges) < len(arms):
            continue
        body = _semantic_body(facts, ranges[: len(arms)])
        else_body = _semantic_body(facts, ranges[len(arms) :])
        if not body or (else_bounds is not None and not else_body):
            continue
        yield Fact(
            "semantic.if_block",
            region.subject,
            (arms, else_bounds),
            combine_evidence(
                region.evidence,
                *(fact.evidence for fact in (*body, *else_body)),
            ),
            "anchored",
        )


def _semantic_body(
    facts: frozenset[Fact], ranges: tuple[tuple[int, int], ...]
) -> tuple[Fact, ...]:
    if not ranges:
        return ()
    return tuple(
        fact
        for fact in _semantic_body_candidates(facts)
        if any(_inside(fact, start, end) for start, end in ranges)
    )


@identity_cache
def _semantic_body_candidates(facts: frozenset[Fact]) -> tuple[Fact, ...]:
    """Exclude dispatch alternatives once per snapshot, before filtering regions."""
    branch_counts = Counter(
        fact.subject[0]
        for fact in facts
        if fact.kind == "semantic.if_goto" and fact.subject
    )
    dispatch_starts = {
        fact.subject[0]
        for fact in facts
        if fact.kind == "semantic.if_goto"
        and len(fact.subject) == 2
        and branch_counts[fact.subject[0]] > 1
    }
    return tuple(
        fact
        for fact in facts
        if fact.kind.startswith("semantic.")
        and fact.kind not in _STRUCTURED_SEMANTICS
        and not (
            fact.kind == "semantic.if_goto"
            and fact.subject
            and fact.subject[0] in dispatch_starts
        )
    )


@reads(
    "flow.goto",
    "region.if_block",
    "semantic.",
    "semantic.if_block",
    "semantic.if_inline",
)
def block_body_goto_facts(
    _evidence: Evidence, facts: frozenset[Fact]
) -> Iterable[Fact]:
    """Recover GOTOs belonging to the body of a block IF."""
    flows = _goto_facts(facts)
    semantic = tuple(
        fact
        for fact in facts
        if fact.kind.startswith("semantic.")
        and len(fact.subject) == 2
        and all(isinstance(value, int) for value in fact.subject)
    )
    for region in facts:
        if region.kind != "region.if_block" or len(region.value) != 2:
            continue
        ranges = _body_ranges(*region.value)
        targets = {
            fact.subject[0]: fact
            for fact in semantic
            if fact.kind not in _STRUCTURED_SEMANTICS
            and any(_inside(fact, start, end) for start, end in ranges)
        }
        for flow in flows:
            target_fact = targets.get(flow.value[0])
            if flow.subject[0] < region.subject[1] or target_fact is None:
                continue
            yield Fact(
                "semantic.goto",
                flow.subject,
                flow.value,
                combine_evidence(flow.evidence, region.evidence, target_fact.evidence),
                "anchored",
            )


def _body_ranges(arms: object, else_bounds: object) -> tuple[tuple[int, int], ...]:
    if not isinstance(arms, tuple):
        return ()
    ranges = tuple(
        (arm[1], arm[2])
        for arm in arms
        if isinstance(arm, tuple)
        and len(arm) == 3
        and isinstance(arm[1], int)
        and isinstance(arm[2], int)
    )
    if else_bounds is None:
        return ranges
    if (
        isinstance(else_bounds, tuple)
        and len(else_bounds) == 2
        and all(isinstance(value, int) for value in else_bounds)
    ):
        return ranges + (else_bounds,)
    return ()


def _body_facts(facts: tuple[Fact, ...], start: int, end: int) -> tuple[Fact, ...]:
    return tuple(fact for fact in facts if _inside(fact, start, end))
