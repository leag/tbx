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


def pytest_addoption(parser):
    group = parser.getgroup("tbx oracle")
    group.addoption(
        "--oracle",
        action="store_true",
        help="run snapshot-backed Turbo Basic oracle smoke tests",
    )
    group.addoption(
        "--oracle-slow",
        action="store_true",
        help="also run multi-minute Turbo Basic oracle tests (implies --oracle)",
    )


def pytest_collection_modifyitems(config, items):
    run_oracle = config.getoption("--oracle") or config.getoption("--oracle-slow")
    run_slow = config.getoption("--oracle-slow")
    skip_oracle = pytest.mark.skip(reason="needs --oracle")
    skip_slow = pytest.mark.skip(reason="needs --oracle-slow")
    for item in items:
        if "oracle" in item.keywords and not run_oracle:
            item.add_marker(skip_oracle)
        if "oracle_slow" in item.keywords and not run_slow:
            item.add_marker(skip_slow)


def wild_hits_bytes(name: str) -> bytes:
    """Read `wild/hits/<name>`, skipping the test if the corpus is absent."""
    path = _HITS / name
    if not path.is_file():
        pytest.skip(f"wild/hits/{name} not present (gitignored, local-only corpus)")
    return path.read_bytes()
