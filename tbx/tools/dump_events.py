"""Dump the commit-time decoded-event log for Turbo Basic EXEs.

Usage::

    uv run python -m tbx.tools.dump_events PROGRAM.EXE
    uv run python -m tbx.tools.dump_events --reconcile wild/hits/*.exe

Events are recorded as the decoder commits statements, with addresses still
unresolved. Control-flow folding rewrites the statement list afterwards, so
the log and the final program differ by design; ``--reconcile`` reports that
difference per program instead of listing events.

The reconciliation is the input the control-flow extraction needs: it says how
much of the final program the commit-time log actually accounts for.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tbx.decode0 import decode_user_code


def _dump(program) -> None:
    for event in program.events:
        address = "--------" if event.address is None else f"{event.address:08X}"
        print(
            f"{event.seq:05d} {address} {event.kind} "
            f"{type(event.payload).__name__}"
        )


def _dump_edits(program) -> None:
    """Why each change to the statement list happened, in order.

    An unattributed append is an ordinary decode-time commit; everything else
    names the pass responsible, which is what tells a fold apart from a
    handler patch or a declaration reconstructed from layout facts.
    """
    for n, edit in enumerate(program.statement_edits):
        span = "" if edit.index is None else f"@{edit.index}"
        if edit.stop is not None:
            span += f":{edit.stop}"
        payload = ",".join(type(s).__name__ for s in edit.payload) or "-"
        origin = edit.origin or "commit"
        print(f"{n:05d} {edit.kind:8} {span:10} {origin:36} {payload}")


def _dump_branches(name: str, program) -> None:
    """What became of each committed branch, and which pass decided it.

    A branch the handlers folded without ever committing does not appear:
    the commit log cannot show a decision it never recorded. That gap is the
    remaining distance to control-flow recovery running off the graph.
    """
    from tbx.decode0.control_graph import classify_branches

    outcomes = classify_branches(program)
    if not outcomes:
        print(f"{name}: no committed branches")
        return
    for branch in outcomes:
        address = "--------" if branch.address is None else f"{branch.address:08X}"
        flag = "" if branch.resolvable else "  UNRESOLVED"
        print(
            f"{branch.seq:05d} {address} -> {branch.target:08X} "
            f"{branch.outcome:9} {branch.decided_by or '-':20}{flag}"
        )


def _dump_folds(name: str, program) -> None:
    """Each inline-IF fold region, as predicted from the record and as folded.

    The two columns are the question deferring the fold turns on: a pass
    reading only the event log has to size a region the same way the handler's
    frame bookkeeping did. A `?` marks a region the record predicts but no
    fold matches, which is where to look first when the two disagree.
    """
    from tbx.decode0.control_graph import predict_fold_extents

    predicted = predict_fold_extents(program)
    actual = [
        (edit.index, edit.stop)
        for edit in program.statement_edits
        if edit.origin == "close_ifs" and edit.kind == "splice"
    ]
    if not predicted and not actual:
        print(f"{name}: no inline-IF fold")
        return
    for start, stop in predicted:
        mark = " " if (start, stop) in actual else "?"
        print(f"{name:24} predicted [{start}:{stop}] {mark}")
    for region in actual:
        if region not in predicted:
            print(f"{name:24} folded    [{region[0]}:{region[1]}] MISSING")


def _reconcile_line(name: str, program) -> str:
    report = program.event_reconciliation
    events = len(program.events)
    pct = 100.0 * report.matched / events if events else 100.0
    return (
        f"{name:24} {events:6} events {len(program):6} stmts "
        f"matched={report.matched:6} ({pct:5.1f}%) "
        f"absorbed={len(report.absorbed):6} "
        f"rewritten={len(report.rewritten):6} "
        f"synthesized={len(report.synthesized):6} "
        f"reconstructed={len(report.reconstructed):6}"
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path, nargs="+")
    parser.add_argument(
        "--reconcile",
        action="store_true",
        help="report event/program divergence instead of the event list",
    )
    parser.add_argument(
        "--branches",
        action="store_true",
        help="dump each committed branch: what became of it and which pass decided",
    )
    parser.add_argument(
        "--edits",
        action="store_true",
        help="dump the statement edit log: which pass made each change",
    )
    parser.add_argument(
        "--folds",
        action="store_true",
        help="dump each inline-IF fold region, predicted from the record vs folded",
    )
    args = parser.parse_args(argv)

    decoded = failed = 0
    for path in args.exe:
        try:
            program = decode_user_code(path.read_bytes())
        except ValueError as exc:
            if not args.reconcile:
                raise
            failed += 1
            print(f"{path.name:24} FAILED {str(exc)[:60]}")
            continue
        decoded += 1
        if args.reconcile:
            print(_reconcile_line(path.name, program))
        elif args.branches:
            _dump_branches(path.name, program)
        elif args.edits:
            _dump_edits(program)
        elif args.folds:
            _dump_folds(path.name, program)
        else:
            _dump(program)

    if args.reconcile and len(args.exe) > 1:
        print(f"\n{decoded} decoded, {failed} failed")


if __name__ == "__main__":
    main()
