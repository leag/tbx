"""Command line interface for the compact best-effort decoder."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tbd.core import decode


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tbd",
        description="Best-effort Turbo Basic decoder that always returns recovery IR.",
    )
    parser.add_argument("exe", type=Path, help="DOS executable or raw binary")
    parser.add_argument("-o", "--output", type=Path, help="write IR here (default: stdout)")
    parser.add_argument("--text", action="store_true", help="render compact text instead of JSON")
    parser.add_argument("--compact", action="store_true", help="emit JSON on one line")
    parser.add_argument(
        "--instructions",
        action="store_true",
        help="include discovered machine instructions as well as lifted IR",
    )
    parser.add_argument(
        "--facts",
        action="store_true",
        help="include immutable analysis facts and their pass reports",
    )
    parser.add_argument("--max-bytes", type=lambda value: int(value, 0))
    parser.add_argument("--rounds", type=int, default=8, help="maximum lifting rounds")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        payload = args.exe.read_bytes()
    except OSError as error:
        print(f"tbd: {error}", file=sys.stderr)
        return 1
    try:
        program = decode(payload, max_bytes=args.max_bytes, rounds=args.rounds)
    except ValueError as error:
        print(f"tbd: {error}", file=sys.stderr)
        return 1
    text = (
        program.render(show_instructions=args.instructions, show_facts=args.facts)
        if args.text
        else json.dumps(
            program.to_dict(
                include_instructions=args.instructions,
                include_facts=args.facts,
            ),
            indent=None if args.compact else 2,
        ) + "\n"
    )
    if args.output is None:
        sys.stdout.write(text)
    else:
        try:
            args.output.write_text(text, encoding="utf-8", newline="")
        except OSError as error:
            print(f"tbd: {error}", file=sys.stderr)
            return 1
    return 0
