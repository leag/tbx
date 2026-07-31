"""The wild subset the oracle can judge, guarded without running the oracle.

`wild/hits` is gitignored, so `tests/fixtures/wild_roundtrip.json` is the
committed half of it: what each program decodes to, and whether a byte-exact
round-trip is meaningful for it at all. Most wild programs cannot match this
oracle's output whatever the decoder does -- 19 of 36 carry IDE Options
toggles, and 5 more were built by a different Turbo Basic release -- so the
manifest records the reason per program rather than leaving a reader to
conclude the decoder is 24 programs worse than it is.

These checks are the parts that need no compiler: the subset still decodes,
still produces the recorded shape, and still emits loadable source. Re-measuring
the byte deltas is `python -m tbx.tools.verify_wild`, which is far too slow for
a test suite -- one program is minutes inside the v86 harness.
"""

import json

import pytest

from tbx import decode0, emit0
from tbx.tools.verify_wild import BUILD_MATCH_FLOOR, MANIFEST, build_match

_ENTRIES = json.loads(MANIFEST.read_text())["programs"]
_COMPARABLE = [e for e in _ENTRIES if not e["excluded"]]


def test_the_manifest_records_a_comparable_subset():
    """The point of the file: not every wild program is evidence about bytes."""
    assert len(_ENTRIES) == 39
    assert len(_COMPARABLE) == 23
    for entry in _ENTRIES:
        if entry["excluded"] is None:
            continue
        assert entry["toggles"] or entry["build_match"] < BUILD_MATCH_FLOOR, (
            f"{entry['name']} is excluded for no recorded reason"
        )


@pytest.mark.parametrize("entry", _COMPARABLE, ids=lambda e: e["name"])
def test_a_comparable_program_still_decodes_to_its_recorded_shape(entry):
    """Statement count and emitted size, which move when a fold changes.

    Cheap, and it fails for the same reasons a byte delta would -- without
    the twenty minutes of v86 the byte delta costs.
    """
    from conftest import wild_hits_bytes

    data = wild_hits_bytes(entry["name"])
    prog = decode0.decode_user_code(data)

    assert len(tuple(prog)) == entry["statements"]
    assert len(emit0.emit(prog)) == entry["source_bytes"]
    assert getattr(prog, "toggles", "") == entry["toggles"]


@pytest.mark.parametrize("entry", _COMPARABLE, ids=lambda e: e["name"])
def test_a_comparable_program_is_still_built_by_our_oracles_compiler(entry):
    """The split is not marginal: comparable programs sit at 99%, others at 5%.

    If this ever lands in between, the floor is doing real work and wants
    looking at rather than nudging.
    """
    from conftest import wild_hits_bytes

    match = build_match(wild_hits_bytes(entry["name"]))

    assert match == entry["build_match"]
    assert match >= BUILD_MATCH_FLOOR
