"""Dump the committed decoded-event boundary for one Turbo Basic EXE.

Usage::

    uv run python -m tbx.tools.dump_events PROGRAM.EXE

The dump is intentionally compact: addresses and IR node types are stable
replay evidence, while the normal decoder/emitter remains responsible for
rendering complete source.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tbx.decode0 import decode_user_code


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    args = parser.parse_args(argv)
    program = decode_user_code(args.exe.read_bytes())
    for i, event in enumerate(program.events):
        address = "--------" if event.address is None else f"{event.address:08X}"
        print(f"{i:05d} {address} {event.kind} {type(event.payload).__name__}")


if __name__ == "__main__":
    main()
