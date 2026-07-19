"""Batch-compile a directory of candidate .bas probes against the real
Turbo Basic oracle and feed each one straight back through decode0._scan,
to search for which SOURCE SHAPE reproduces a specific decoder gap.

    uv run python tbx/tools/batch_probe.py PROBE_DIR [--want SUBSTRING]
                                            [--dialect 1.0|1.1]

PROBE_DIR holds one candidate .bas file per variant (case name = filename
stem). Each is compiled by the real compiler (oracle.compile_bas) and
scanned. Per file, prints one of:

    HIT   name: <ValueError message>   -- matched --want (the target gap)
    gap   name: <ValueError message>   -- decode failed, but a DIFFERENT gap
    clean name: N ops                  -- decoded with no error at all
    ERR   name: <first line of failure> -- oracle itself rejected the source

This is the same write-probe / compile / scan loop used throughout gap
investigations (see HANDOFF.md), just batched -- N variants compiled and
scanned in one run instead of one Bash call at a time. Like cfgview, this
is triage-only, never part of the decompile pipeline: a HIT here is a lead
to go implement and byte-exact-verify by hand, not itself a fix, and it
does not relax the calibration rule (no vocabulary changes without an
oracle-verified fixture).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tbx import decode0
from tbx.tools import oracle


def probe_one(bas_path: Path, dialect: str) -> tuple[str, str]:
    """Compile + scan one probe. Returns (status, detail)."""
    try:
        exe = oracle.compile_bas(bas_path, dialect=dialect)
    except Exception as e:
        return "ERR", str(e).splitlines()[0][:200]
    try:
        start, dia = decode0.find_prologue(exe)
        ops = decode0._scan(exe, start, dia, set())
    except ValueError as e:
        return "gap", str(e)
    except Exception as e:
        return "ERR", f"{type(e).__name__}: {e}"
    return "clean", f"{len(ops)} ops"


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    probe_dir = Path(args[0])
    want = argv[argv.index("--want") + 1] if "--want" in argv else None
    dialect = argv[argv.index("--dialect") + 1] if "--dialect" in argv else "1.1"

    files = sorted(probe_dir.glob("*.bas"))
    if not files:
        print(f"no .bas files in {probe_dir}", file=sys.stderr)
        return 2

    hits = 0
    for f in files:
        status, detail = probe_one(f, dialect)
        if status == "gap" and want and want in detail:
            status, hits = "HIT", hits + 1
        print(f"{status:6} {f.stem}: {detail}")

    if want:
        print(f"\n{hits}/{len(files)} matched {want!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
