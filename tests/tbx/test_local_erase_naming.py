"""`ERASE A` on a LOCAL array that was declared but never DIMensioned.

A LOCAL dynamic array that is never DIMensioned has no populated runtime
record, so the only definitive evidence that its zero-filled 30-word span IS
an array descriptor is an operation that treats it as one. The procedure
epilogue's implicit `local_arr_free` was the only such site the decoder knew,
and it names the array there. An explicit source `ERASE` is a second one, and
it sits EARLIER in address order, so it is the site that has to do the naming
when present -- `ERASE of undimensioned LOCAL block` otherwise.

Both sites now go through `_name_undimensioned_local_array`, because they must
name identically; two copies of the numbering would drift.

`t1_lerase2` is the reason this needs two fixtures. Its source is
`LOCAL A()` / `ERASE A` / `DIM A(N%)` -- the ERASE names the block, and then
the LATER DIM of that SAME block used to allocate a SECOND name, emitting
`ERASE V0` against a `LOCAL V1()` that never declared it. The DIM reuses the
existing name now.

That reuse is scoped to blocks an ERASE actually named (`local_named_by_erase`)
and NOT to any block whose entry happens to end in `()`: a plain LOCAL
declaration leaves that spelling too, and reusing it renumbered every later
LOCAL array, moving wild cleanup.exe and reformat.exe 25 bytes off their
recorded shapes. Those two are comparable programs and are what caught it.

All four builds (both probes, both dialects) verified byte-exact.
"""

import os
from pathlib import Path

import pytest

from tbx import decode0, emit0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")


def _emit(stem):
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as handle:
        return emit0.emit(decode0.decode_user_code(handle.read()))


@pytest.mark.parametrize("stem", ("t1_lerase", "v10_t1_lerase"))
def test_erase_of_a_never_dimensioned_local(stem):
    """`LOCAL A(), B()` / `DIM B(N%)` / `ERASE A`: A is only ever ERASEd."""
    source = _emit(stem)

    assert "LOCAL V1(), V0()" in source, source
    assert "DIM V0(A%)" in source, source
    assert "ERASE V1" in source, source


@pytest.mark.parametrize("stem", ("t1_lerase2", "v10_t1_lerase2"))
def test_a_later_dim_reuses_the_name_the_erase_gave(stem):
    """`LOCAL A()` / `ERASE A` / `DIM A(N%)`: one array, one name.

    The ERASE names the block first; the DIM must not allocate a second name,
    which produced `ERASE V0` against `LOCAL V1()`.
    """
    source = _emit(stem)

    assert "LOCAL V0()" in source, source
    assert "ERASE V0" in source, source
    assert "DIM V0(A%)" in source, source
    assert "V1" not in source, source


@pytest.mark.parametrize("name", ("cleanup.exe", "reformat.exe"))
def test_the_calibrated_programs_keep_their_numbering(name):
    """Reuse must not fire on a plain LOCAL declaration.

    These two are what the epilogue naming path was calibrated on, and a
    too-broad reuse rule renumbered their LOCAL arrays. They are comparable
    programs, so a shape change here is a byte-visible regression.
    """
    from conftest import wild_hits_bytes

    try:
        data = wild_hits_bytes(name)
    except Exception:  # wild/hits is gitignored
        pytest.skip(f"{name} not present")

    source = emit0.emit(decode0.decode_user_code(data))

    # Sizes come from wild_roundtrip.json, which is the committed record of
    # what these programs decode to; do not retype them from memory.
    import json

    manifest = json.loads(
        (Path(_ROOT) / "fixtures" / "wild_roundtrip.json").read_text()
    )
    expected = next(
        e["source_bytes"] for e in manifest["programs"] if e["name"] == name
    )

    assert len(source) == expected, f"{name} emitted {len(source)} bytes"
