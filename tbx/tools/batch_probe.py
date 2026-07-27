"""Batch-compile a directory of candidate .bas probes against the real
Turbo Basic oracle and feed each one straight back through decode0._scan,
to search for which SOURCE SHAPE reproduces a specific decoder gap.

    uv run python tbx/tools/batch_probe.py PROBE_DIR [--want SUBSTRING]
                                            [--dialect 1.0|1.1]
                                            [--jobs N] [--keep DIR]

PROBE_DIR holds one candidate .bas file per variant (case name = filename
stem). Each is compiled by the real compiler (oracle.compile_bas) and
scanned. Per file, prints one of:

    HIT   name: <ValueError message>   -- matched --want (the target gap)
    gap   name: <ValueError message>   -- decode failed, but a DIFFERENT gap
    clean name: N ops                  -- decoded with no error at all
    ERR   name: <first line of failure> -- oracle itself rejected the source

This is the same write-probe / compile / scan loop used throughout gap
investigations (see PLAN.md), just batched -- N variants compiled and
scanned in one run instead of one Bash call at a time. Like cfgview, this
is triage-only, never part of the decompile pipeline: a HIT here is a lead
to go implement and byte-exact-verify by hand, not itself a fix, and it
does not relax the calibration rule (no vocabulary changes without an
oracle-verified fixture).
"""

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tbx import decode0
from tbx.tools import oracle


def probe_one(bas_path: Path, dialect: str) -> tuple[str, str, bytes | None]:
    """Compile + scan one probe. Returns status, detail, and compiled bytes."""
    try:
        exe = oracle.compile_bas(bas_path, dialect=dialect)
    except Exception as e:
        return "ERR", str(e).splitlines()[0][:200], None
    try:
        start, dia = decode0.find_prologue(exe)
        ops = decode0._scan(exe, start, dia, set())
    except ValueError as e:
        return "gap", str(e), exe
    except Exception as e:
        return "ERR", f"{type(e).__name__}: {e}", exe
    return "clean", f"{len(ops)} ops", exe


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    probe_dir = Path(args[0])
    want = argv[argv.index("--want") + 1] if "--want" in argv else None
    dialect = argv[argv.index("--dialect") + 1] if "--dialect" in argv else "1.1"
    keep = Path(argv[argv.index("--keep") + 1]) if "--keep" in argv else None
    jobs = int(argv[argv.index("--jobs") + 1]) if "--jobs" in argv else 1
    if jobs < 1:
        print("--jobs must be at least 1", file=sys.stderr)
        return 2

    files = sorted(probe_dir.glob("*.bas"))
    if not files:
        print(f"no .bas files in {probe_dir}", file=sys.stderr)
        return 2

    try:
        oracle.preflight()
    except RuntimeError as exc:
        print(f"oracle infrastructure error: {exc}", file=sys.stderr)
        return 2
    if keep:
        keep.mkdir(parents=True, exist_ok=True)

    hits = 0

    def report(f: Path, result: tuple[str, str, bytes | None]) -> int:
        status, detail, exe = result
        matched = 0
        if status == "gap" and want and want in detail:
            status, matched = "HIT", 1
        if keep and exe is not None:
            (keep / f"{f.stem}.exe").write_bytes(exe)
        print(f"{status:6} {f.stem}: {detail}", flush=True)
        return matched

    if jobs == 1:
        for f in files:
            hits += report(f, probe_one(f, dialect))
    else:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            pending = {pool.submit(probe_one, f, dialect): f for f in files}
            for future in as_completed(pending):
                hits += report(pending[future], future.result())

    if want:
        print(f"\n{hits}/{len(files)} matched {want!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
