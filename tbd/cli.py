"""Command-line interface for the Turbo Basic decoder."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from tbd.basic import to_basic
from tbd.core import decode


def _package_version() -> str:
    """Return the installed package version, including source checkouts."""
    try:
        return version("turbo-basic-decoder")
    except PackageNotFoundError:
        return "development"


class _HelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter
):
    """Show useful defaults while preserving the examples' line breaks."""


class _Console:
    """Small terminal presenter that keeps machine-readable output untouched."""

    def __init__(self, *, quiet: bool, no_color: bool) -> None:
        self.enabled = not quiet and sys.stderr.isatty()
        self.console = Console(
            stderr=True,
            no_color=no_color or os.environ.get("NO_COLOR") is not None,
            quiet=not self.enabled,
        )
        self.progress = Progress(
            SpinnerColumn(), TextColumn("{task.description}"), console=self.console
        )
        self.task_id = self.progress.add_task("starting", total=4)
        self.started = time.monotonic()

    def stage(self, number: int, total: int, label: str) -> None:
        if not self.enabled:
            return
        if not self.progress.live.is_started:
            self.progress.start()
        self.progress.update(self.task_id, completed=number, description=label)

    def finish(self, message: str) -> None:
        if self.enabled:
            elapsed = time.monotonic() - self.started
            self.progress.stop()
            self.console.print(
                f"[green]✓[/green] {message} [dim]({elapsed:.2f}s)[/dim]"
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tbd",
        description=(
            "Decode DOS programs built with Borland Turbo Basic and recover "
            "their IR or source."
        ),
        epilog=(
            "examples:\n"
            "  tbd PROGRAM.EXE                         # JSON IR\n"
            "  tbd PROGRAM.EXE --text                 # readable IR\n"
            "  tbd PROGRAM.EXE --basic -o recovered.bas\n\n"
            "Output goes to stdout unless --output is used. Progress is shown "
            "on stderr when connected to a terminal."
        ),
        formatter_class=_HelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {_package_version()}"
    )
    parser.add_argument(
        "exe",
        type=Path,
        metavar="INPUT",
        help="DOS executable or raw binary to analyze",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-o", "--output", type=Path, metavar="PATH", help="write output to PATH"
    )
    formats = output.add_mutually_exclusive_group()
    formats.add_argument(
        "--text", action="store_true", help="render readable IR instead of JSON"
    )
    formats.add_argument(
        "--basic", action="store_true", help="render recovered Turbo Basic source"
    )
    output.add_argument("--compact", action="store_true", help="emit JSON on one line")
    analysis = parser.add_argument_group("analysis")
    analysis.add_argument(
        "--instructions",
        action="store_true",
        help="include decoded machine instructions in JSON or text output",
    )
    analysis.add_argument(
        "--facts",
        action="store_true",
        help="include inferred facts and pass reports",
    )
    analysis.add_argument(
        "--max-bytes",
        type=lambda value: int(value, 0),
        metavar="N",
        help="analyze at most N bytes (decimal or 0x-prefixed)",
    )
    analysis.add_argument(
        "--rounds",
        type=int,
        default=None,
        metavar="N",
        help="limit fact-analysis rounds",
    )
    analysis.add_argument(
        "--jobs",
        type=int,
        default=1,
        metavar="N",
        help="run each round's fact passes in N forked processes",
    )
    terminal = parser.add_argument_group("terminal")
    terminal.add_argument(
        "-q", "--quiet", action="store_true", help="hide progress messages"
    )
    terminal.add_argument(
        "--no-color", action="store_true", help="disable colored terminal output"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Decode the requested executable and write IR or recovered source."""
    args = _parser().parse_args(argv)
    console = _Console(quiet=args.quiet, no_color=args.no_color)
    console.stage(1, 4, "📦 reading")
    try:
        payload = args.exe.read_bytes()
    except OSError as error:
        print(f"tbd: {error}", file=sys.stderr)
        return 1
    console.stage(2, 4, "🔍 decoding")
    try:
        program = decode(
            payload, max_bytes=args.max_bytes, rounds=args.rounds, jobs=args.jobs
        )
    except ValueError as error:
        print(f"tbd: {error}", file=sys.stderr)
        return 1
    console.stage(3, 4, "✨ rendering")
    text = (
        to_basic(program)
        if args.basic
        else (
            program.render(show_instructions=args.instructions, show_facts=args.facts)
            if args.text
            else json.dumps(
                program.to_dict(
                    include_instructions=args.instructions,
                    include_facts=args.facts,
                ),
                indent=None if args.compact else 2,
            )
            + "\n"
        )
    )
    if args.output is None:
        sys.stdout.write(text)
    else:
        try:
            args.output.write_text(
                text, encoding="latin-1" if args.basic else "utf-8", newline=""
            )
        except OSError as error:
            print(f"tbd: {error}", file=sys.stderr)
            return 1
    console.stage(4, 4, "🚀 complete")
    console.finish(f"decoded {args.exe.name} — Turbo vibes restored")
    return 0
