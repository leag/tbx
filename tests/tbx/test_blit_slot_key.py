"""Static array slots are keyed by the GRID base, not by `vb`.

`_initialize_array_slots` builds `slot_info` as
`{static_base + 0x36*i: array}`, and GET/PUT resolves its array by looking the
blit operand's displacement up in exactly that map. The two disagree under a
LINE box-fill cell: the cell moves `vb` to VAR_BASE+4 but leaves the array
grid on its VAR_BASE anchor, so keying on `vb` puts every slot 4 bytes high
and a lookup by a real slot disp misses.

Wild menu.exe, night.exe and sprogh.exe are the witnesses -- `GET/PUT blit
array slot 0x01f8 unknown`, where 0x01f8 is exactly VAR_BASE + 4*0x36 while
`slot_info` held 0x01fc. They reached this only after the grid anchor itself
was fixed (see test_line_cell_grid.py); before that they failed earlier, in
the layout phase.

`t1_linearr` does NOT cover this: its array is read at a CONSTANT index, which
resolves through the array's element base and never consults the slot record.
GET/PUT is what looks the record up, so this fixture pairs a static array with
both a LINE box-fill and a blit. Verified byte-exact in both dialects.
"""

import os

import pytest

from tbx import decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")


@pytest.mark.parametrize("stem", ("t1_blitline", "v10_t1_blitline"))
def test_a_blit_resolves_its_slot_under_a_line_box_fill(stem):
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as handle:
        exe = handle.read()

    source = "\n".join(str(s) for s in decode0.decode_user_code(exe))

    assert "GetGfx" in source, source
    assert "PutGfx" in source, source
    # Both blits name the array rather than raising "blit array slot unknown".
    assert source.count("V0%") >= 3, source


def test_the_wild_witness_decodes():
    """menu.exe goes all the way through once the slot keys line up."""
    hits = os.path.join(os.path.dirname(_ROOT), "wild", "hits", "menu.exe")
    if not os.path.isfile(hits):  # wild/hits is gitignored
        pytest.skip("menu.exe not present")

    with open(hits, "rb") as handle:
        exe = handle.read()

    assert len(tuple(decode0.decode_user_code(exe))) == 1838
