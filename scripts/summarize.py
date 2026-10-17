"""Summarize an evaluate.py report as Markdown.

    uv run python scripts/summarize.py build/eval/report.json
"""

import json
import sys
from pathlib import Path


def main() -> int:
    report = json.loads(Path(sys.argv[1]).read_text())
    rows = list(report["results"].values())
    tb = [r for r in rows if r.get("decode") == "ok"]
    not_tb = [r for r in rows if r.get("decode") != "ok"]
    compiled = [r for r in tb if r.get("compile") == "ok"]
    repaired = [r for r in tb if r.get("compile") != "ok" and r.get("repair") == "ok"]
    engines = {}
    for r in tb:
        engines[r.get("engine")] = engines.get(r.get("engine"), 0) + 1
    behavior = {}
    for r in compiled:
        behavior[r.get("behavior")] = behavior.get(r.get("behavior"), 0) + 1
    near = [r for r in compiled if r.get("user_match", 0) >= 0.99 and not r.get("user_identical")]
    print("| Measure | Programs |")
    print("| --- | ---: |")
    print(f"| Executables in the corpus | {len(rows)} |")
    print(f"| Not Turbo Basic (archives, other compilers) — rejected | {len(not_tb)} |")
    print(f"| Turbo Basic programs decompiled | {len(tb)} of {len(tb)} |")
    print(f"| … by tbx / by tbd fallback | {engines.get('tbx', 0)} / {engines.get('tbd', 0)} |")
    print(f"| Output compiles with Turbo Basic as emitted | {len(compiled)} of {len(tb)} |")
    print(f"| … after `--repair` comments out rejected lines | {len(compiled) + len(repaired)} of {len(tb)} |")
    print(f"| Rebuilt EXE byte-identical | {sum(bool(r.get('identical')) for r in compiled)} |")
    print(f"| Rebuilt user code (prologue on) byte-identical | {sum(bool(r.get('user_identical')) for r in compiled)} |")
    print(f"| … not identical but ≥ 99 % of user-code bytes in place | {len(near)} |")
    print(f"| Same screen as the original after 8 s, no input | {behavior.get('same', 0)} |")
    print(f"| Both screens blank after 8 s | {behavior.get('blank', 0)} |")
    print(f"| Different screen | {behavior.get('different', 0)} |")
    if repaired:
        print()
        print("Programs that need `--repair` (lines commented out):")
        print()
        for r in sorted(repaired, key=lambda r: r["name"]):
            print(f"- `{r['name']}` ({r.get('engine')}): {len(r.get('repairs', []))}")
    if not_tb:
        print()
        print("Rejected as not Turbo Basic: " + ", ".join(f"`{r['name']}`" for r in sorted(not_tb, key=lambda r: r["name"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
