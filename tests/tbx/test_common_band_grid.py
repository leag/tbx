"""COMMON moves the array grid, and a runtime-DIM program must still find it.

The slot grid does not begin at VAR_BASE by decree. It begins past the
CHAIN-persistent COMMON band and that band's own 16-byte stamp:

    grid_base = align16(0x110 + s_num + s_str) + 0x10

which is exactly VAR_BASE (0x120) for the DEGENERATE stamp a program without
COMMON still carries -- so the old `vb` anchor was this formula's n=0 case all
along, not a separate rule.

Programs with runtime DIM carry no ORDINARY band stamp (only the COMMON one),
so they take the grid-anchored path, which divided `rt_blocks[0] - vb` by 0x36
and raised `runtime blocks are not 0x36-contiguous after statics` whenever a
COMMON band pushed the grid. Wild tutordos.exe (4-byte band) and probe
q_commonrt (16-byte band) both land their first runtime block at 0x166, which
is one 0x36 slot past a grid at 0x130 and a ragged 70 bytes past 0x120.

The second half matters as much as the anchor: the COMMON band sits BELOW the
grid, so the scalar walk starts past it and never visits its cells. Recovering
the base alone made q_commonrt DECODE -- and silently drop its `COMMON`
statement, constant-folding `C1#` so the program printed `+ 3` where the source
says `+ C1#`. COMMON compiles to no ops at all, so the band is the only
evidence the declaration existed. Both fixtures verified byte-exact in both
dialects.
"""

import os

import pytest

from tbx import decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")


@pytest.mark.parametrize("stem", ("t1_commonrt", "v10_t1_commonrt"))
def test_common_is_recovered_alongside_a_runtime_array(stem):
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as handle:
        exe = handle.read()

    stmts = tuple(decode0.decode_user_code(exe))
    source = "\n".join(str(s) for s in stmts)

    # The declaration exists at all -- the silent-drop symptom.
    assert type(stmts[0]).__name__ == "Common", source
    # ...and the referenced slot keeps its double type rather than tiling as
    # integers, which is what happens with VAR_BASE-filtered evidence sets.
    assert "A#" in str(stmts[0]), str(stmts[0])
    # The variable reaches the PRINT instead of being folded to its value.
    assert "A#" in source.split("Print")[-1], source


@pytest.mark.parametrize("stem", ("t1_commonrt", "v10_t1_commonrt"))
def test_both_array_kinds_survive_the_shifted_grid(stem):
    """One static and one runtime array, on a grid that does not start at
    VAR_BASE -- the case that used to raise in the layout phase."""
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as handle:
        exe = handle.read()

    source = "\n".join(str(s) for s in decode0.decode_user_code(exe))

    assert source.count("Dim(") == 2, source


def test_the_wild_witness_clears_the_layout_phase():
    """tutordos.exe still stops later, in lift, on a COMMON-band store."""
    hits = os.path.join(os.path.dirname(_ROOT), "wild", "hits", "tutordos.exe")
    if not os.path.isfile(hits):  # wild/hits is gitignored
        pytest.skip("tutordos.exe not present")

    with open(hits, "rb") as handle:
        exe = handle.read()

    try:
        decode0.decode_user_code(exe)
    except ValueError as exc:
        assert "phase=layout" not in str(exc), str(exc)
