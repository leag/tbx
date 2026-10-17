"""Recompile one evaluate.py work directory and show where it fails.

    uv run python scripts/recompile.py build/eval3/NAME.exe
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate import compile_source  # noqa: E402

work = Path(sys.argv[1])
row = json.loads((work / "decompile.json").read_text())
row["source"] = str(next(work.glob("*.BAS")))
snapshots = work.parent / "snapshots"
print(compile_source(row, work, snapshots, 300))
if (work / "error.txt").is_file() and row:
    subprocess.run([sys.executable, str(ROOT / "scripts" / "errline.py"), str(work)])
