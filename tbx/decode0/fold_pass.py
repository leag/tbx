"""Folding inline IFs from the record, after the walk rather than during it.

The walk folds as it decodes: a frame opens when a skip is recognised and
closes when decoding reaches its target, and the statement list is rewritten
on the spot. Chapter 6's swap is to stop doing that and fold afterwards, from
the recorded control graph.

This is that pass. It reads the branch and arrival events, sizes each region
the way `control_graph.predict_fold_extents` does, and applies the folds to the
committed statement stream. It touches no decode state and is not wired into
the decoder -- it exists to be run against what the walk actually did, so the
two can be compared before the walk stops folding.

Positions here are *commit* coordinates: how many statements had been
committed when an event was recorded. That is the coordinate system a deferred
pass necessarily works in, since nothing has folded yet when it starts.

Measured against the walk: 76 of the fixture corpus's 80 inline-IF folds and
all 26 of its SELECTs come out identical, and 755 of the wild corpus's 771
inline IFs and 15 of its 16 SELECTs. The corpus cannot speak for the shift
arithmetic -- a fixture is too small for a boundary keyed on the wrong
coordinate to land anywhere different -- so the wild numbers are the ones that
move when this pass is wrong.

The differences that remain are another walk-time fold, not a gap in the
record: a body that holds a `SELECT CASE` the walk had already built (4 in the
corpus), or a region sitting in a list a loop lift had spliced (16 wild inline
IFs across five programs, and the last SELECT in tbd73.exe). Commit
coordinates and list coordinates agree until one of those runs, which is the
precise reason the folds have to move together.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from typing import Any

from tbx import ir
from tbx.decode0.events import committed, replay_events
from tbx.decode0.lift import _fold_body_ifgotos


@dataclass(frozen=True)
class FoldRegion:
    """One inline-IF body, in commit coordinates, with what to fold it into.

    ``close`` is the event at which the region ended -- the arrival at the
    branch's target. Regions are applied in that order, because it is the
    order the walk folds in: whatever closes first is innermost.
    """

    start: int
    stop: int
    cond: Any
    address: int | None
    target: int
    close: int = 0
    block: bool = False


@dataclass(frozen=True)
class ArmRegion:
    """One CASE arm or CASE ELSE body, in commit coordinates, with its guards.

    ``guards`` is empty for a CASE ELSE, which matches by exclusion and
    records nothing to match on.
    """

    start: int
    stop: int
    guards: tuple
    kind: str
    close: int = 0
    start_address: int | None = None
    end_address: int | None = None


@dataclass(frozen=True)
class SelectRegion:
    """One SELECT CASE, with the selector it switches on.

    It owns the arms whose bodies lie inside its address range; the innermost
    enclosing SELECT owns an arm, since a SELECT can sit inside another's arm.
    """

    close: int
    selector: Any
    start_address: int
    end_address: int


def _positions(program):
    """A map from event ``seq`` to how many statements had been committed."""
    commits = [event.seq for event in committed(program.events)]

    def position(seq: int) -> int:
        return bisect_left(commits, seq)

    return position


def arm_regions(program) -> tuple[ArmRegion, ...]:
    """Every CASE arm body the record describes, in commit coordinates.

    An arm ends where its arm-close jmp is reached, and that address owns no
    statement -- it is glue. The moment is recorded instead: the region's end
    is a wanted address, so decoding arriving there is an event, and the arm's
    extent is the list length then. This is the same construction the inline-IF
    extent uses, which is the point: an arm is a region like any other.

    An arm whose close is never arrived at is skipped rather than guessed.
    """
    position = _positions(program)
    arrivals: dict[int, int] = {}
    for event in program.events:
        if event.kind == "arrive":
            arrivals.setdefault(event.payload.address, event.seq)

    regions = []
    for event in program.events:
        if event.kind != "region" or event.payload.kind not in (
            "case_arm",
            "case_else",
        ):
            continue
        arrival = arrivals.get(event.payload.end)
        if arrival is None or arrival < event.seq:
            continue
        regions.append(
            ArmRegion(
                start=position(event.seq),
                stop=position(arrival),
                guards=event.payload.detail or (),
                kind=event.payload.kind,
                close=arrival,
                start_address=event.payload.start,
                end_address=event.payload.end,
            )
        )
    return tuple(regions)


def select_regions(program) -> tuple[SelectRegion, ...]:
    """Every SELECT the record describes, in the order they close."""
    return tuple(
        SelectRegion(
            close=event.seq,
            selector=event.payload.detail,
            start_address=event.payload.start,
            end_address=event.payload.end,
        )
        for event in program.events
        if event.kind == "region" and event.payload.kind == "select"
    )


def fold_regions(program) -> tuple[FoldRegion, ...]:
    """Every inline-IF region the record describes, in the order to fold them.

    Innermost first within one arrival -- frames sharing a target are nested,
    and folding the enclosing one first would swallow the body the inner one
    still needs -- and by arrival otherwise.
    """
    position = _positions(program)
    arrivals: dict[int, int] = {}
    for event in program.events:
        if event.kind == "arrive":
            arrivals.setdefault(event.payload.address, event.seq)

    opened: dict[int, list[Any]] = {}
    for event in program.events:
        if event.kind != "branch" or event.payload.frame != "if":
            continue
        arrival = arrivals.get(event.payload.target)
        if arrival is None or arrival < event.seq:
            continue  # never reached, or reached before the branch opened
        opened.setdefault(arrival, []).append(event)

    regions = []
    for arrival in sorted(opened):
        stop = position(arrival)
        for event in reversed(opened[arrival]):
            regions.append(
                FoldRegion(
                    start=position(event.seq),
                    stop=stop,
                    cond=event.payload.cond,
                    address=event.address,
                    target=event.payload.target,
                    close=arrival,
                    block=event.payload.block,
                )
            )
    return tuple(regions)


def fold_inline_ifs(program) -> list:
    """The committed statements with every recorded inline-IF region folded.

    Each fold replaces its region with one statement, so the regions that
    follow move. Rather than recompute them, the shift is applied as it
    happens: a fold at ``[start, stop)`` pulls everything from ``stop`` onward
    back by what it removed. A region nested inside a later one then lands
    exactly where the walk's own arithmetic put it -- one past where the inner
    body began.

    Every position is in the commit coordinates the regions were read in, and
    ``shifts`` is keyed the same way -- a fold's boundary is where its region
    ended, not where its splice landed. The two agree for the first fold and
    diverge from there, and mixing them makes a fold look as though it
    precedes a region really nested inside it.
    """
    statements = list(replay_events(program.events))
    shifts: list[tuple[int, int]] = []

    def shifted(position: int) -> int:
        return position - sum(size for at, size in shifts if position >= at)

    for region in fold_regions(program):
        start, stop = shifted(region.start), shifted(region.stop)
        body = tuple(statements[start:stop])
        if not body:
            raise ValueError(
                f"empty inline-IF body for the branch at {region.address:#x}"
            )
        body = _fold_body_ifgotos(body, region.target)
        statements[start:stop] = [ir.IfInline(region.cond, body)]
        shifts.append((region.stop, (stop - start) - 1))
    return statements


def fold_constructs(program) -> list:
    """The committed statements with every recorded construct folded.

    Inline IFs, CASE arms and SELECTs, applied in the order they *close*. That
    ordering is the whole trick: the walk folds whatever finishes first, so a
    construct nested inside another closes first and is folded first, and the
    enclosing one then sees a single statement where its body used to be. It
    also settles the two ties. An inline IF closing a CASE arm skips to the
    arm-close jmp, so both close at the same arrival and the IF has to go
    first -- which is exactly what `_fold_arm` does by calling `close_ifs`
    before it snapshots. A SELECT closes after the last arm that named its END
    SELECT.

    Bodies are block-folded with `_fold_if`, as the walk does, from the same
    inputs: the jump-target set of the statements at hand, the addresses they
    were committed at, and which IFs the bytes say were spelled multi-line.
    """
    from tbx.decode0.addresses import AddressOwnership
    from tbx.decode0.lift import _fold_if, _jump_targets

    events = committed(program.events)
    statements = [event.payload for event in events]
    addresses = [event.address for event in events]

    # The address each committed statement owns. The walk keeps the same map
    # and adds to it as folding moves statements; here it starts from what was
    # committed, which is all a pass reading the log has.
    stmt_addr = AddressOwnership()
    for statement, address in zip(statements, addresses):
        if address is not None:
            stmt_addr.claim(statement, address)
    block_ifs = {
        event.address
        for event in program.events
        if event.kind == "branch" and event.payload.block
    }

    shifts: list[tuple[int, int]] = []

    def shifted(position: int) -> int:
        return position - sum(size for at, size in shifts if position >= at)

    def replace(start: int, stop: int, statement, address, at: int) -> None:
        statements[start:stop] = [statement]
        addresses[start:stop] = [address]
        if address is not None:
            # The statement this pass just built owns the address too, and a
            # later fold looks that up rather than carrying an address list
            # into nested bodies: `_fold_body` reconstructs an ELSE arm from
            # `stmt_addr.get(id(b))` for statements that are no longer top
            # level. The walk claims here for the same reason.
            stmt_addr.claim(statement, address)
        # Keyed on where the region ended, never on where the splice landed:
        # the two diverge after the first fold, and comparing an unshifted
        # position against a shifted boundary makes a fold look as though it
        # precedes a region nested inside it.
        shifts.append((at, (stop - start) - 1))

    arms: dict[int, list] = {}  # SELECT close -> the arms it owns, in order
    selects = select_regions(program)

    def owner(arm) -> int | None:
        """The innermost SELECT whose address range holds this arm."""
        enclosing = [
            s
            for s in selects
            if s.start_address <= arm.start_address <= s.end_address
        ]
        return max(enclosing, key=lambda s: s.start_address).close if enclosing else None

    operations = []
    for region in fold_regions(program):
        operations.append((region.close, 0, region))
    for arm in arm_regions(program):
        # A CASE ELSE closes after the arms, and has to: the walk opens one
        # provisionally, whenever the op after an arm's jmp is not recognisably
        # another arm header, and a real arm turning up next simply overwrites
        # where the else body was thought to start. What is left of the else
        # region once the arms inside it are folded away is empty, which is how
        # the walk decides the source had no CASE ELSE at all.
        operations.append((arm.close, 1 if arm.kind == "case_arm" else 2, arm))
    for select in selects:
        operations.append((select.close, 3, select))

    for _, _, operation in sorted(operations, key=lambda o: (o[0], o[1])):
        if isinstance(operation, FoldRegion):
            start, stop = shifted(operation.start), shifted(operation.stop)
            body = tuple(statements[start:stop])
            if not body:
                raise ValueError(
                    f"empty inline-IF body for the branch at {operation.address:#x}"
                )
            body = _fold_body_ifgotos(body, operation.target, stmt_addr)
            replace(
                start,
                stop,
                ir.IfInline(operation.cond, body),
                operation.address,
                operation.stop,
            )
        elif isinstance(operation, ArmRegion):
            start, stop = shifted(operation.start), shifted(operation.stop)
            if operation.kind == "case_else":
                # Whatever the arms of this SELECT have already taken is not
                # the else's, however far back its provisional start was put.
                taken = arms.get(owner(operation), [])
                start = max(
                    [start] + [shifted(a.start) + len(body) for a, body in taken]
                )
                stop = max(start, stop)
            folded, folded_addrs = _fold_if(
                statements[start:stop],
                addresses[start:stop],
                bound=operation.end_address,
                targets=_jump_targets(statements),
                stmt_addr=stmt_addr,
                block_ifs=block_ifs,
            )
            statements[start:stop], addresses[start:stop] = folded, folded_addrs
            shifts.append((operation.stop, (stop - start) - len(folded)))
            arms.setdefault(owner(operation), []).append(
                (operation, tuple(folded))
            )
        else:  # a SELECT: its arms are folded, so its own span is theirs
            owned = arms.pop(operation.close, [])
            if not owned:
                continue  # nothing recorded closed inside it; leave it alone
            # The span the arms occupy *now*, recomputed rather than summed:
            # a construct folded inside one of them has already shortened it,
            # and assuming the arms are still contiguous overwrites whatever
            # sits between them -- a nested SELECT, in wild tbd73.exe.
            start = min(shifted(a.start) for a, _ in owned)
            stop = max(shifted(a.start) + len(body) for a, body in owned)
            case_else = next(
                (body for a, body in owned if a.kind == "case_else"), None
            )
            replace(
                start,
                stop,
                ir.SelectCase(
                    operation.selector,
                    tuple(
                        ir.CaseArm(a.guards, body)
                        for a, body in owned
                        if a.kind == "case_arm"
                    ),
                    case_else or None,
                ),
                operation.start_address,
                # In commit coordinates a SELECT ends where its last arm did.
                # Its own `start`/`stop` above are already current positions,
                # derived from the arms rather than from a recorded region, so
                # they cannot key the shift.
                max(a.stop for a, _ in owned),
            )
    return statements
