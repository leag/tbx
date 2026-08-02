"""Command-line interface: decompile a Turbo Basic 1.0/1.1 EXE to source.

    tbx PROGRAM.EXE                 # recovered source on stdout
    tbx PROGRAM.EXE -o PROGRAM.BAS  # write to a file
    tbx PROGRAM.EXE -o PROGRAM.BAS --split  # add .INC files when over 64 KiB
    tbx PROGRAM.EXE --ops           # canonical op-stream dump (debugging aid)
    tbx PROGRAM.EXE --data          # readable DATA-pool dump (non-source)

Decoding is fail-loud by design: an EXE that uses a construct outside the
calibrated vocabulary raises instead of guessing, so any output that does
appear can be trusted to recompile byte-identically.
"""

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from tbx import decode0, emit0
from tbx import ir


def _version() -> str:
    try:
        return version("tbx")
    except PackageNotFoundError:  # running from a source tree without install
        return "unknown"


def _dump_ops(exe: bytes) -> str:
    start, dia = decode0.find_prologue(exe)
    commits: set[int] = set()
    ops = decode0._scan(exe, start, dia, commits)
    lines = [f"# dialect={dia.name} start={start:05X}"]
    for addr, kind, *args in ops:
        lines.append(":".join([f"{addr:05X}:{kind}", *map(str, args)]))
    lines.append("# commits")
    lines += [f"{c:05X}" for c in sorted(commits)]
    return "\n".join(lines) + "\n"


def _escape_data(text: str) -> str:
    """Render a Latin-1 DATA item without terminal-dependent glyphs."""

    out: list[str] = []
    for byte in text.encode("latin-1"):
        if byte == 0x22:
            out.append(r'\"')
        elif byte == 0x5C:
            out.append(r"\\")
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def _dump_data(program: list[object]) -> str:
    """Dump DATA constants with escaped bytes for human inspection."""

    lines: list[str] = []
    index = 0
    for statement in program:
        if not isinstance(statement, ir.Data):
            continue
        for item in statement.items:
            kind = "string" if item.is_str else "number"
            value = _escape_data(item.text) if item.is_str else item.text
            lines.append(f"{index:03d} {kind}: {value}")
            index += 1
    return "\n".join(lines) + ("\n" if lines else "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="tbx",
        description="Byte-exact decompiler for Borland Turbo Basic 1.0/1.1 DOS EXEs.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    ap.add_argument("exe", type=Path, help="compiled Turbo Basic .EXE")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="BAS",
        help="write recovered source here (default: stdout)",
    )
    ap.add_argument(
        "--ops",
        action="store_true",
        help="dump the canonical op stream instead of source",
    )
    ap.add_argument(
        "--data",
        action="store_true",
        help="dump DATA constants with escaped bytes instead of source",
    )
    ap.add_argument(
        "--split",
        action="store_true",
        help="split source over 64 KiB into procedure-boundary .INC files "
        "(requires --output)",
    )
    args = ap.parse_args(argv)
    if args.ops and args.data:
        print("tbx: --ops and --data are mutually exclusive", file=sys.stderr)
        return 1
    if args.split and (args.output is None or args.ops or args.data):
        print("tbx: --split requires --output and cannot be used with --ops/--data", file=sys.stderr)
        return 1

    try:
        exe = args.exe.read_bytes()
    except OSError as e:
        print(f"tbx: {e}", file=sys.stderr)
        return 1
    bundle = None
    try:
        if args.ops:
            text = _dump_ops(exe)
        else:
            prog = decode0.decode_user_code(exe)
            if args.data:
                text = _dump_data(prog)
            else:
                bundle = (
                    emit0.emit_split(prog, prefix=args.output.stem)
                    if args.split
                    else None
                )
                text = bundle.root if bundle is not None else emit0.emit(prog)
            # IDE compiler toggles have no source form (see emit0); surface them
            # out-of-band so `-o` output stays exactly the recompiling source.
            toggles = getattr(prog, "toggles", "")
            if toggles:
                print(
                    f"tbx: {args.exe}: compiled with Options toggles "
                    f"{decode0.toggle_names(toggles)}",
                    file=sys.stderr,
                )
    except ValueError as e:
        print(f"tbx: {args.exe}: {e}", file=sys.stderr)
        return 1

    if args.output:
        if bundle is not None:
            collisions = [
                args.output.parent / name
                for name, _ in bundle.includes
                if (args.output.parent / name).exists()
            ]
            if collisions:
                names = ", ".join(p.name for p in collisions[:3])
                print(
                    f"tbx: refusing to overwrite existing include file(s): {names}",
                    file=sys.stderr,
                )
                return 1
            for name, include in bundle.includes:
                (args.output.parent / name).write_text(
                    include, encoding="latin-1", newline=""
                )
        args.output.write_text(text, encoding="latin-1", newline="")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
