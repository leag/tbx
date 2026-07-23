"""Runtime-array layout with scalar evidence beyond an unreferenced hole."""

from pathlib import Path

import pytest

from tbx import decode0
from tbx.decode0.core import find_prologue
from tbx.decode0.layout import _layout
from tbx.decode0.scan import _scan

_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("stem", "string_disp", "single_disp"),
    [
        ("cleanup.exe", 0x228, 0x20A),
        ("reformat.exe", 0x22E, 0x212),
    ],
)
def test_runtime_layout_recovers_scalars_after_hole(stem, string_disp, single_disp):
    exe = (_ROOT / "wild" / "hits" / stem).read_bytes()
    start, dialect = find_prologue(exe)
    layout = _layout(exe, _scan(exe, start, dialect, set()))

    assert layout["scalar_base"] == 0x1C2
    assert layout["pool_base"] == 0x2C4
    assert layout["delta"] == 0xF0
    assert layout["scalars"][string_disp] == 4
    assert string_disp in layout["strs"]
    assert layout["scalars"][single_disp] == 4


@pytest.mark.parametrize(
    ("stem", "next_gap"),
    [
        ("cleanup.exe", "string BP argument store with empty stack"),
        ("reformat.exe", "string BP argument store with empty stack"),
    ],
)
def test_runtime_layout_witnesses_reach_next_gap(stem, next_gap):
    exe = (_ROOT / "wild" / "hits" / stem).read_bytes()
    with pytest.raises(ValueError, match=next_gap):
        decode0.decode_user_code(exe)
