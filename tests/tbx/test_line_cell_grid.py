"""The LINE box-fill cell shifts the scalar band, not the array grid.

A `LINE ...,B`/`,BF` links a runtime unit that owns a 4-byte DGROUP cell, and
`_layout` accounts for it by moving `vb` from VAR_BASE (0x120) to 0x124. The
existing witnesses for that -- t1_lineb, t1_linevb -- have NO arrays, so the
array grid is empty in all of them and "the grid starts at vb" and "the grid
starts at VAR_BASE" are indistinguishable. Only the SCALAR band moved.

Wild stat.exe shows they are different claims. Its runtime array blocks are
perfectly 0x36-contiguous and start at 0x1f8, which is exactly four blocks past
VAR_BASE and a ragged 50 bytes past `vb` -- and since a grid is a whole number
of 0x36 records, only VAR_BASE can be its base. The decoder used to divide by
`vb` unconditionally and raise `runtime blocks are not 0x36-contiguous after
statics`.

The stamp path already half-knew this: its n=0 branch accepted a base of
either `vb` or VAR_BASE ("VAR_BASE covers the LINE-cell form"), while its n>0
branch demanded `vb` exactly. `t1_linearr` is the authored witness that closes
that half -- `DIM A(3)` plus `LINE (0,0)-(10,10),,B`, whose stamp reports
gb=VAR_BASE with `vb` at 0x124. Before the fix it did not merely mis-locate
anything: the rejected stamp left the walk path to "solve" a layout that then
read a pooled value past the end of the image and died in `struct.unpack_from`.

Both dialects verified byte-exact through the oracle.
"""

import os

import pytest

from tbx import decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")


@pytest.mark.parametrize("stem", ("t1_linearr", "v10_t1_linearr"))
def test_an_array_keeps_its_var_base_grid_under_a_line_box_fill(stem):
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as handle:
        exe = handle.read()

    source = "\n".join(str(s) for s in decode0.decode_user_code(exe))

    # The DIM survives, which is what a mis-anchored grid loses.
    assert "Dim(name='V0', bounds=(3,)" in source, source
    assert "box='B'" in source, source
    assert "ArrayRef(name='V0'" in source, source


def test_the_wild_witness_advances_past_the_layout_phase():
    """stat.exe must get out of `layout` -- it still stops later, in `lift`.

    Pinned as "not a layout failure" rather than "decodes", so this test keeps
    its meaning when the remaining lift-phase gap is closed.
    """
    hits = os.path.join(os.path.dirname(_ROOT), "wild", "hits", "stat.exe")
    if not os.path.isfile(hits):  # wild/hits is gitignored
        pytest.skip("stat.exe not present")

    with open(hits, "rb") as handle:
        exe = handle.read()

    try:
        decode0.decode_user_code(exe)
    except ValueError as exc:
        assert "phase=layout" not in str(exc), str(exc)
