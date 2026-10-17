"""Decompile a corpus, recompile every output with Turbo Basic, and compare.

    uv run python scripts/evaluate.py wild/hits --out build/eval [--jobs 6] [--only k.exe ...]

For each executable: decompile with ``tbdc`` (in a subprocess with a time
limit), compile the recovered source with the matching Turbo Basic in QEMU,
and compare the rebuilt executable with the original. Writes
``OUT/report.json`` and one directory per input holding the source, the
rebuilt EXE and any compiler error screen.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oracle_qemu.qemu_harness import HarnessError, QemuHarness  # noqa: E402

IMAGES = Path(os.environ.get("TBDC_IMAGES", ROOT.parent / "tbx" / "oracle"))
COMPILERS = {"1.0": "tb10_floppy.img", "1.1": "tb_floppy.img"}
ERROR = re.compile(r"Error\s+\d+:[^║\n]*")


def harness(dialect: str, snapshots: Path) -> QemuHarness:
    return QemuHarness(
        IMAGES / "freedos.img",
        IMAGES / COMPILERS.get(dialect, "tb_floppy.img"),
        snapshot_directory=snapshots / dialect,
    )


def decompile(exe: Path, work: Path, timeout: float) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    source = work / (exe.stem.upper()[:8] + ".BAS")
    report = work / "decompile.json"
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "tbdc", str(exe), "-o", str(source),
             "--report", str(report), "--force"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        return {"decode": "timeout", "seconds": timeout}
    elapsed = time.monotonic() - started
    (work / "decompile.stderr").write_text(proc.stderr)
    if proc.returncode != 0 or not source.is_file():
        tail = proc.stderr.strip().splitlines()[-1:] or [""]
        return {"decode": "error", "error": tail[0][:400], "seconds": elapsed}
    meta = json.loads(report.read_text()) if report.is_file() else {}
    return {"decode": "ok", "seconds": round(elapsed, 2), "source": str(source), **meta}


def compile_source(row: dict, work: Path, snapshots: Path, timeout: float) -> dict:
    source = Path(row["source"])
    output = work / "REBUILT.EXE"
    try:
        harness(row.get("dialect") or "1.1", snapshots).compile(
            source,
            output,
            toggles=row.get("toggles", ""),
            timeout=timeout,
            workspace=work / "compile",
            fast=None,
        )
    except HarnessError as exc:
        message = str(exc)
        (work / "error.txt").write_text(message)
        match = ERROR.search(message)
        return {"compile": "error", "compile_error": (match.group(0).strip() if match else message[:300])}
    return {"compile": "ok"}


def compare(exe: Path, work: Path) -> dict:
    from tbdc.unpack import unpack
    from tbx import decode0

    original = unpack(exe.read_bytes())[0]
    rebuilt = (work / "REBUILT.EXE").read_bytes()
    same = sum(a == b for a, b in zip(original, rebuilt))
    row = {
        "identical": original == rebuilt,
        "size_original": len(original),
        "size_rebuilt": len(rebuilt),
        "byte_match": round(same / max(len(original), len(rebuilt)), 4),
    }
    # The user program (prologue to end of file) does not depend on which
    # runtime revision the compiler linked in front of it.
    try:
        a = original[decode0.find_prologue(original)[0]:]
        b = rebuilt[decode0.find_prologue(rebuilt)[0]:]
    except ValueError:
        return row
    same_user = sum(x == y for x, y in zip(a, b))
    row["user_identical"] = a == b
    row["user_match"] = round(same_user / max(len(a), len(b)), 4)
    row["user_size_delta"] = len(b) - len(a)
    return row


def behave(exe: Path, work: Path, snapshots: Path, dialect: str, seconds: float) -> dict:
    """Run the original and the rebuilt program without input; compare screens."""

    from tbdc.unpack import unpack

    h = harness(dialect or "1.1", snapshots)
    original = work / "ORIGINAL.EXE"
    original.write_bytes(unpack(exe.read_bytes())[0])
    screens = []
    for name, path in (("original", original), ("rebuilt", work / "REBUILT.EXE")):
        try:
            result = h.run(path, output_directory=work / f"run-{name}", timeout=seconds)
        except HarnessError as exc:
            return {"behavior": "error", "behavior_error": str(exc)[:200]}
        (work / f"screen-{name}.txt").write_text(result.screen)
        screens.append(result.screen)
    if screens[0] == screens[1]:
        verdict = "same" if screens[0].strip() else "blank"
    else:
        verdict = "different"
    return {"behavior": verdict}


def evaluate(exe: Path, out: Path, snapshots: Path, args) -> dict:
    work = out / exe.name
    row: dict = {"name": exe.name}
    row.update(decompile(exe, work, args.decode_timeout))
    if row["decode"] != "ok" or args.no_compile:
        return row
    row.update(compile_source(row, work, snapshots, args.compile_timeout))
    if row["compile"] != "ok" and args.repair:
        import shutil

        from tbdc.verify import compile_with_repair

        fixed = work / "repaired"
        fixed.mkdir(exist_ok=True)
        for f in list(work.glob("*.BAS")) + list(work.glob("*.INC")) + list(work.glob("*.BIN")):
            shutil.copy(f, fixed / f.name)
        result = compile_with_repair(
            fixed / Path(row["source"]).name,
            fixed / "REBUILT.EXE",
            row.get("dialect"),
            row.get("toggles", ""),
        )
        row["repair"] = result["compile"]
        row["repairs"] = result.get("repairs", [])
    if row["compile"] == "ok":
        row.update(compare(exe, work))
        if args.behavior:
            row.update(behave(exe, work, snapshots, row.get("dialect"), args.behavior))
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpus", type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "eval")
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--decode-timeout", type=float, default=600)
    ap.add_argument("--compile-timeout", type=float, default=300)
    ap.add_argument("--no-compile", action="store_true")
    ap.add_argument("--repair", action="store_true",
                    help="for sources that fail, also try tbdc's comment-out repair loop")
    ap.add_argument("--behavior", type=float, default=0, metavar="SECONDS",
                    help="also run original and rebuilt for SECONDS and compare screens")
    args = ap.parse_args()
    exes = sorted(
        p for p in args.corpus.iterdir()
        if p.suffix.lower() == ".exe" and (not args.only or p.name in args.only)
    )
    args.out.mkdir(parents=True, exist_ok=True)
    snapshots = args.out / "snapshots"
    for dialect in COMPILERS:
        h = harness(dialect, snapshots)
        if not h.has_snapshot(""):
            h.prime()
    report_path = args.out / "report.json"
    results: dict[str, dict] = {}
    if args.only and report_path.is_file():
        results = json.loads(report_path.read_text())["results"]
    with ThreadPoolExecutor(args.jobs) as pool:
        futures = {pool.submit(evaluate, exe, args.out, snapshots, args): exe for exe in exes}
        for future in as_completed(futures):
            exe = futures[future]
            try:
                row = future.result()
            except Exception as exc:  # keep the sweep going
                row = {"name": exe.name, "decode": "crash", "error": repr(exc)[:400]}
            results[exe.name] = row
            print(json.dumps({k: row.get(k) for k in (
                "name", "decode", "engine", "compile", "identical", "user_identical", "user_match", "behavior",
                "compile_error", "error")}), flush=True)
    rows = list(results.values())
    summary = {
        "inputs": len(rows),
        "decoded": sum(r.get("decode") == "ok" for r in rows),
        "compiled": sum(r.get("compile") == "ok" for r in rows),
        "identical": sum(bool(r.get("identical")) for r in rows),
        "user_identical": sum(bool(r.get("user_identical")) for r in rows),
        "compiled_after_repair": sum(r.get("repair") == "ok" for r in rows),
        "behavior": {k: sum(r.get("behavior") == k for r in rows) for k in ("same", "blank", "different", "error")},
        "by_engine": {},
    }
    for r in rows:
        if r.get("decode") == "ok":
            summary["by_engine"][r.get("engine", "?")] = summary["by_engine"].get(r.get("engine", "?"), 0) + 1
    report_path.write_text(json.dumps({"summary": summary, "results": dict(sorted(results.items()))}, indent=1))
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
