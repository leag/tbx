"""The string char record is found by its shape, not inside a fixed window.

The pooled string characters live in a bracketed record --
`(total|0x8000) 00 00 00 00 <chars> (total|0x8000)` -- somewhere past the
descriptor chain. `_find_string_char_base` used to scan a fixed 0x400 bytes
from `align16(after_disp)`, which is not a property of the compiler's layout:
gap 30 already had to re-anchor `after_disp` itself once a long descriptor
chain (a static string array chains its per-element descriptors into the same
table) pushed the record out of that window, and wild month086.exe/month386.exe
put the record 0x470 past `lo` -- 0x70 beyond the old cap -- and failed with
`string char record not found`.

The search now runs to the end of the image. That is a strict superset of the
old behaviour: the first match ascending is still what is returned, so a
program whose record was already inside 0x400 cannot resolve differently. It
is safe to widen because the bracket shape is highly specific -- over the 507
corpus and wild programs that reach this search, a whole-image scan finds
exactly ONE match in every single case.
"""

from pathlib import Path

import pytest

from tbx import decode0

_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", ("month086.exe", "month386.exe"))
def test_a_record_past_the_old_window_is_found(name):
    hits = _ROOT / "wild" / "hits" / name
    if not hits.is_file():  # wild/hits is gitignored
        pytest.skip(f"{name} not present")

    program = decode0.decode_user_code(hits.read_bytes())

    assert len(tuple(program)) == 831


def test_the_widened_range_still_covers_the_old_window():
    """The bound is a FLOOR of `lo + 0x400`, never less.

    Written because getting this wrong is exactly what the first attempt did:
    bounding the scan by `len(exe) - dsd - total` made the range SHORTER than
    the old fixed window for short images, and t1_cmppool, t1_inpfilearr and
    t1_times -- whose records sit near the end of a small image -- stopped
    resolving. `max(...)` is the whole guard, so it gets a test of its own.
    """
    for stem in ("t1_cmppool", "t1_inpfilearr", "t1_times"):
        exe = (_ROOT / "tests" / "fixtures" / "corpus" / f"{stem}.exe").read_bytes()

        program = decode0.decode_user_code(exe)

        assert tuple(program), stem
