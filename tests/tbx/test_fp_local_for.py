"""SINGLE LOCAL variables and BP-relative variable-STEP FOR templates."""

from pathlib import Path

import pytest

from tbx import decode0
from tbx.decode0 import scan

_ROOT = Path(__file__).resolve().parents[2]


def test_scan_testw_bp_is_exact():
    ops = []
    data = bytes.fromhex("f7 46 18 00 80")
    assert scan._scan_direct(data, 0, data[0], decode0.TB11, ops, 0) == 5
    assert ops == [(0, "testw_bp", 0x18, 0x8000)]


@pytest.mark.parametrize(
    ("stem", "next_gap"),
    [
        ("cleanup.exe", "unhandled op testw_bp at 0xb248"),
        ("crossref.exe", "unhandled INT EC sub 38 at 0x11a63"),
        ("reformat.exe", "unhandled op testw_bp at 0xb241"),
    ],
)
def test_fp_local_for_advances_wild_program(stem, next_gap):
    data = (_ROOT / "wild" / "hits" / stem).read_bytes()
    with pytest.raises(ValueError, match=next_gap):
        decode0.decode_user_code(data)


def test_ziptest_advances_to_forward_fn_resolution_gap():
    data = (_ROOT / "wild" / "hits" / "ziptest.exe").read_bytes()
    with pytest.raises(KeyError, match="42193"):
        decode0.decode_user_code(data)
