"""Shared test fixtures.

`wild/hits/` (third-party shareware found in the wild, see CLAUDE.md) is
gitignored and never committed -- present on a maintainer's machine after a
scan, but absent on a fresh checkout (including GitHub CI). Tests that pin
decoder behavior against it must use `wild_hits_bytes` below instead of
reading the path directly, so they skip cleanly when the corpus isn't
present rather than failing with FileNotFoundError.
"""

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_HITS = _ROOT / "wild" / "hits"


def wild_hits_bytes(name: str) -> bytes:
    """Read `wild/hits/<name>`, skipping the test if the corpus is absent."""
    path = _HITS / name
    if not path.is_file():
        pytest.skip(f"wild/hits/{name} not present (gitignored, local-only corpus)")
    return path.read_bytes()
