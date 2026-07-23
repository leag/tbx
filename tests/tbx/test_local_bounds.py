"""Bounds-toggle vectors 94/96 for SUB-local dynamic arrays."""

from pathlib import Path

import pytest

from tbx import decode0
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


@pytest.mark.parametrize(
    ("stem", "next_gap"),
    [
        ("cleanup.exe", "DGROUP layout not solvable"),
        ("crossref.exe", "unhandled INT EC sub 38 at 0x11a63"),
        ("reformat.exe", "DGROUP layout not solvable"),
    ],
)
def test_wild_local_bounds_remain_closed(stem, next_gap):
    data = (_ROOT / "wild" / "hits" / stem).read_bytes()
    with pytest.raises(ValueError, match=next_gap):
        decode0.decode_user_code(data)
