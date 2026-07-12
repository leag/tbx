"""Command-line interface: decompile a Turbo Basic 1.0/1.1 EXE to source.

    tbx PROGRAM.EXE                 # recovered source on stdout
    tbx PROGRAM.EXE -o PROGRAM.BAS  # write to a file
    tbx PROGRAM.EXE --ops           # canonical op-stream dump (debugging aid)

Decoding is fail-loud by design: an EXE that uses a construct outside the
calibrated vocabulary raises instead of guessing, so any output that does
appear can be trusted to recompile byte-identically.
"""

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from tbx import decode0, emit0


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
        "--emit-c",
        action="store_true",
        help="recompile to portable C for modern platforms (experimental; "
        "build the output with `cc out.c -lm`)",
    )
    args = ap.parse_args(argv)

    try:
        exe = args.exe.read_bytes()
    except OSError as e:
        print(f"tbx: {e}", file=sys.stderr)
        return 1
    try:
        if args.ops:
            text = _dump_ops(exe)
        elif args.emit_c:
            from tbx import c0

            text = c0.emit_c(decode0.decode_user_code(exe))
        else:
            prog = decode0.decode_user_code(exe)
            text = emit0.emit(prog)
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
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
