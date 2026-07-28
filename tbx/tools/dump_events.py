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


def _reconcile_line(name: str, program) -> str:
    report = program.event_reconciliation
    events = len(program.events)
    pct = 100.0 * report.matched / events if events else 100.0
    return (
        f"{name:24} {events:6} events {len(program):6} stmts "
        f"matched={report.matched:6} ({pct:5.1f}%) "
        f"absorbed={len(report.absorbed):6} "
        f"rewritten={len(report.rewritten):6} "
        f"synthesized={len(report.synthesized):6}"
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
        "--edits",
        action="store_true",
        help="dump the statement edit log: which pass made each change",
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
        elif args.edits:
            _dump_edits(program)
        else:
            _dump(program)

    if args.reconcile and len(args.exe) > 1:
        print(f"\n{decoded} decoded, {failed} failed")


if __name__ == "__main__":
    main()
