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


@pytest.mark.parametrize(
    ("stem", "exc", "next_gap"),
    [
        ("cleanup.exe", ValueError, "jump target 0xf317 is not a statement start"),
        ("crossref.exe", ValueError, "displacement 0x324 is neither scalar nor array element"),
        ("reformat.exe", ValueError, "jump target 0xf6a2 is not a statement start"),
    ],
)
def test_wild_local_bounds_remain_closed(stem, exc, next_gap):
    from conftest import wild_hits_bytes

    data = wild_hits_bytes(stem)
    with pytest.raises(exc, match=next_gap):
        decode0.decode_user_code(data)
