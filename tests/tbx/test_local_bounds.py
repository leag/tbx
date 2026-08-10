"""Bounds-toggle vectors 94/96 for SUB-local dynamic arrays."""

from pathlib import Path

import pytest

from tbx import decode0, emit0
from tbx.decode0 import scan
from tbx.decode0.dialect import TB11

_ROOT = Path(__file__).resolve().parents[2]


def test_scan_local_bounds_vectors():
    ops = []
    assert scan._scan_int(b"\xcd\x94\x08\x00", 0, set(), TB11, ops, 0, 0x94) == 4
    assert ops == [(0, "bchk_base_bp", 8)]

    ops = []
    assert scan._scan_int(b"\xcd\x96\x0e\x00", 0, set(), TB11, ops, 0, 0x96) == 4
    assert ops == [(0, "bchk_idx_bp", 14)]


@pytest.mark.parametrize("stem", ["t1_localarrunused", "v10_t1_localarrunused"])
def test_undimensioned_local_array_cleanup(stem):
    program = decode0.decode_user_code(
        (_ROOT / "tests" / "fixtures" / "corpus" / f"{stem}.exe").read_bytes()
    )
    assert "  LOCAL V0(), V1()\n  DIM V0(2)\n" in emit0.emit(program)


@pytest.mark.parametrize("stem", ["crossref.exe"])
def test_wild_local_bounds_remain_closed(stem):
    """The LOCAL bounds path stays closed on crossref.exe, which now decodes.

    Its `ERASE of undimensioned LOCAL block` was a DEF FN body opened on a
    GOSUB subroutine, not a bounds or naming problem -- see
    `core._fn_body_opens_here`.
    """
    from conftest import wild_hits_bytes

    data = wild_hits_bytes(stem)
    assert tuple(decode0.decode_user_code(data))
