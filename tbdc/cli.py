"""tbdc — decompile a Borland Turbo Basic 1.0/1.1 DOS executable.

    tbdc PROGRAM.EXE                    # recovered source on stdout
    tbdc PROGRAM.EXE -o PROGRAM.BAS     # write source (+ .INC/inline files if needed)
    tbdc PROGRAM.EXE -o P.BAS --verify  # also recompile with Turbo Basic in QEMU
    tbdc DIR -o OUTDIR                  # every .EXE in DIR

The calibrated byte-exact decoder (tbx) runs first; programs it cannot decode
fall back to the best-effort analyzer (tbd). LZEXE-packed files are unpacked.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tbdc.pipeline import ENGINES, DecompileError, Recovery, decompile
from tbdc.unpack import UnpackError


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="tbdc",
        description="Decompile Borland Turbo Basic 1.0/1.1 DOS executables to BASIC source.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n\n", 1)[1],
    )
    ap.add_argument("input", type=Path, help="Turbo Basic .EXE, or a directory of them")
    ap.add_argument("-o", "--output", type=Path, help="output .BAS (or directory for a directory input)")
    ap.add_argument("--engine", choices=ENGINES, default="auto", help="decoder to use (default: auto)")
    ap.add_argument("--dense", action="store_true", help="also remove optional spaces")
    ap.add_argument("--numbered", action="store_true", help="number every line, not only jump targets")
    ap.add_argument("--no-split", action="store_true", help="never split large programs into .INC files")
    ap.add_argument("--report", type=Path, help="write a JSON report about the recovery")
    ap.add_argument("--force", action="store_true", help="overwrite existing include files")
    ap.add_argument("--verify", action="store_true", help="recompile the output with Turbo Basic in QEMU and compare")
    ap.add_argument("--repair", action="store_true", help="with --verify: comment out lines Turbo Basic rejects until it compiles")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print errors")
    return ap


def _dos(text: str) -> bytes:
    """Source as DOS tools read it: Latin-1 with CRLF line ends."""

    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("latin-1", errors="replace")


def _write(recovery: Recovery, output: Path, force: bool) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    extra = [(name, _dos(text)) for name, text in recovery.includes]
    extra += list(recovery.assets)
    if not force:
        clash = [name for name, _ in extra if (output.parent / name).exists()]
        if clash:
            raise FileExistsError(f"refusing to overwrite {', '.join(clash[:3])} (use --force)")
    for name, payload in extra:
        (output.parent / name).write_bytes(payload)
    output.write_bytes(_dos(recovery.source))


def _one(path: Path, output: Path | None, args) -> dict:
    data = path.read_bytes()
    prefix = (output.stem if output else path.stem).upper()[:6] or "TBX"
    recovery = decompile(
        data,
        engine=args.engine,
        prefix=prefix,
        dense=args.dense,
        numbered=args.numbered,
        split=not args.no_split,
    )
    report = recovery.summary()
    report["input"] = str(path)
    if output is None:
        if recovery.includes:
            sys.stderr.write("tbdc: program needs include files; use -o to write them\n")
        sys.stdout.write(recovery.source)
    else:
        _write(recovery, output, args.force)
        report["output"] = str(output)
        if args.verify:
            from tbdc.verify import verify

            report["verify"] = verify(path, output, recovery, repair=args.repair)
    if not args.quiet:
        note = f"{recovery.engine}, TB {recovery.dialect or '?'}, {recovery.statements} statements"
        if recovery.toggles:
            note += f", toggles {recovery.toggles}"
        if recovery.packer:
            note += f", unpacked {recovery.packer}"
        if recovery.placeholders:
            note += f", {recovery.placeholders} placeholders"
        if recovery.warnings:
            note += f", {len(recovery.warnings)} warnings"
        verdict = report.get("verify")
        if verdict:
            note += f"; recompile {verdict['compile']}"
            if verdict.get("compile_error"):
                note += f" ({verdict['compile_error']})"
            if verdict.get("repairs"):
                note += f" after commenting out {len(verdict['repairs'])} line(s)"
            if verdict.get("identical") is not None:
                note += ", identical" if verdict["identical"] else f", {verdict['byte_match']:.1%} bytes match"
        print(f"tbdc: {path.name}: {note}", file=sys.stderr)
    return report


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    reports: list[dict] = []
    status = 0
    if args.input.is_dir():
        if args.output is None:
            print("tbdc: a directory input needs -o OUTDIR", file=sys.stderr)
            return 2
        inputs = sorted(p for p in args.input.iterdir() if p.suffix.lower() == ".exe")
        for path in inputs:
            out = args.output / path.stem.lower() / (path.stem.upper()[:8] + ".BAS")
            try:
                reports.append(_one(path, out, args))
            except (DecompileError, UnpackError, OSError) as exc:
                print(f"tbdc: {path.name}: {exc}", file=sys.stderr)
                reports.append({"input": str(path), "error": str(exc)})
                status = 1
    else:
        try:
            reports.append(_one(args.input, args.output, args))
        except (DecompileError, UnpackError, OSError) as exc:
            print(f"tbdc: {args.input}: {exc}", file=sys.stderr)
            return 1
    if args.report:
        payload = reports[0] if len(reports) == 1 and not args.input.is_dir() else reports
        args.report.write_text(json.dumps(payload, indent=1))
    return status


if __name__ == "__main__":
    sys.exit(main())
