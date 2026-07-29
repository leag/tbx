"""Compare two ``scan_wild --report`` JSON checkpoints.

Usage::

    python -m tbx.tools.compare_gap_reports OLD.json NEW.json

The comparator refuses to compare different report schemas or corpora. It
classifies per-file movement separately from signature movement, so an earlier
fix that exposes a later blocker is visible as progress rather than a failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _load(path: Path) -> dict:
    data = json.loads(path.read_text())
    if data.get("schema_version") != 1:
        raise ValueError(f"unsupported report schema in {path}")
    return data


def compare(old: dict, new: dict) -> dict[str, list[str]]:
    if old.get("schema_version") != new.get("schema_version"):
        raise ValueError("report schema versions differ")
    if old.get("corpus_fingerprint") != new.get("corpus_fingerprint"):
        raise ValueError("reports refer to different corpus contents")

    def failures(report: dict) -> dict[str, str]:
        return {item["name"]: item["signature"] for item in report["failures"]}

    def hits(report: dict) -> set[str]:
        return {item["name"] for item in report["hits"]}

    old_fail, new_fail = failures(old), failures(new)
    old_hit, new_hit = hits(old), hits(new)
    names = set(old_fail) | set(new_fail) | old_hit | new_hit
    return {
        "newly_decoded": sorted(old_fail.keys() & new_hit),
        "regressed": sorted(old_hit & set(new_fail)),
        "advanced": sorted(
            name for name in names if name in old_fail and name in new_fail
            and old_fail[name] != new_fail[name]
        ),
        "unchanged": sorted(
            name for name in names if name in old_fail and name in new_fail
            and old_fail[name] == new_fail[name]
        ),
        "new_signatures": sorted(set(new_fail.values()) - set(old_fail.values())),
        "removed_signatures": sorted(set(old_fail.values()) - set(new_fail.values())),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        result = compare(_load(Path(argv[0])), _load(Path(argv[1])))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for key, values in result.items():
        print(f"{key}: {len(values)}")
        for value in values:
            print(f"  {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
