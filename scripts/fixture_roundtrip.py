"""Recompile tbdc's output for corpus fixtures and compare byte for byte.

    uv run python scripts/fixture_roundtrip.py [--step 25] [--jobs 4]
"""

import argparse
import json
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tbdc.pipeline import decompile  # noqa: E402
from tbdc.verify import compile_source  # noqa: E402


def one(path: Path) -> dict:
    try:
        rec = decompile(path.read_bytes(), prefix=path.stem[:5].upper())
    except Exception as exc:
        return {"name": path.name, "status": "decode-error", "error": str(exc)[:200]}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        src = work / "PROG.BAS"
        src.write_bytes(rec.source.replace("\n", "\r\n").encode("latin-1"))
        for name, text in rec.includes:
            (work / name).write_bytes(text.replace("\n", "\r\n").encode("latin-1"))
        for name, data in rec.assets:
            (work / name).write_bytes(data)
        out = work / "PROG.EXE"
        res = compile_source(src, out, rec.dialect, rec.toggles)
        if res["compile"] != "ok":
            return {"name": path.name, "status": "compile-error", "error": res.get("compile_error")}
        same = out.read_bytes() == path.read_bytes()
        return {"name": path.name, "status": "identical" if same else "different", "engine": rec.engine}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--step", type=int, default=25)
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    paths = sorted((ROOT / "tests" / "fixtures" / "corpus").glob("*.exe"))[:: args.step]
    # 1.0-early builds need a compiler we do not wire here
    with ThreadPoolExecutor(args.jobs) as pool:
        rows = list(pool.map(one, paths))
    for r in rows:
        print(json.dumps(r))
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
