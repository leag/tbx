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


def test_compile_bas_names_the_too_large_editor_limit_clearly(tmp_path):
    # TB's editor rejects a source past its own buffer size with a modal
    # "<name> too large. Truncate? (Y/N)" prompt instead of loading it --
    # witnessed on real wild files (cal.exe, 81KB source; k.exe, 551KB).
    # The prompt names the loaded file, which used to read as a false
    # "loaded successfully" to the harness's own `scr().includes(filename)`
    # check, so it blindly pressed on into a still-open dialog and reported
    # a misleading "did not enter the compile screen" instead of this.
    oracle.prime_snapshot(dialect="1.1", toggles="")
    big = tmp_path / "TOOBIG.BAS"
    lines = "\n".join(f"{n} PRINT {n}" for n in range(10, 10 * 9000, 10))
    big.write_text(lines + "\n", encoding="latin-1", newline="")

    with pytest.raises(RuntimeError, match="too large"):
        oracle.compile_bas(big, dialect="1.1", toggles="", fast=True)
