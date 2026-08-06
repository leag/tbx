"""Tests for the snapshot-based fast-compile path (oracle.prime_snapshot /
compile_bas(fast=True)). See vendor/turbo_basic_oracle/tb_v86_fast.js's
module docstring for the mechanism.
"""

from pathlib import Path

import pytest

from tbx.tools import oracle

_BAS = Path(__file__).parent.parent / "fixtures" / "usercode" / "t1_erasepre.bas"


def _oracle_available() -> bool:
    try:
        oracle.preflight()
    except RuntimeError:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _oracle_available(), reason="Turbo Basic oracle not provisioned locally"
)


def test_compile_bas_fast_without_a_primed_snapshot_raises_clearly():
    with pytest.raises(RuntimeError, match="no primed snapshot"):
        oracle.compile_bas(_BAS, dialect="1.1", toggles="ZZ-never-primed", fast=True)


def test_prime_then_fast_compile_matches_the_plain_path_byte_exact():
    oracle.prime_snapshot(dialect="1.1", toggles="")
    fast = oracle.compile_bas(_BAS, dialect="1.1", toggles="", fast=True)
    plain = oracle.compile_bas(_BAS, dialect="1.1", toggles="", fast=False)
    assert fast == plain
