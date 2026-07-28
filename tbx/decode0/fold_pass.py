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

Measured against the walk: 76 of the fixture corpus's 80 inline-IF folds come
out identical, and 388 of the wild corpus's 403. Every difference is another
walk-time fold, not a gap in the record — a body that holds a `SELECT CASE`
the walk had already built (4 in each corpus), or a region sitting in a list
that `select_case`, the procedure-body fold or a loop lift had spliced (11,
wild only). Commit coordinates and list coordinates agree until one of those
runs, which is the precise reason the three folds have to move together.
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
    """One inline-IF body, in commit coordinates, with what to fold it into."""

    start: int
    stop: int
    cond: Any
    address: int | None
    target: int


def fold_regions(program) -> tuple[FoldRegion, ...]:
    """Every inline-IF region the record describes, in the order to fold them.

    Innermost first within one arrival -- frames sharing a target are nested,
    and folding the enclosing one first would swallow the body the inner one
    still needs -- and by arrival otherwise.
    """
    commits = [event.seq for event in committed(program.events)]

    def position(seq: int) -> int:
        """How many statements had been committed when event ``seq`` happened."""
        return bisect_left(commits, seq)

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
        shifts.append((stop, (stop - start) - 1))
    return statements
