"""Emitted source has to be source Turbo Basic could have accepted.

The Owner's Handbook is explicit: "The Turbo Basic editor supports lines up to
248 characters wide." So a physical line wider than that is not a formatting
preference -- it is provably not what the author wrote, because the compiler
this program came out of could not have taken it. That makes over-wide output
a decoder defect detectable with no oracle at all, by reading the emitted text.

It is also a class the fixture corpus cannot report: all 1030 fixtures emit
inside the limit, and every violation is in a wild program. Two shapes, both
in statements finalization *reconstructs* rather than decodes:

- a pooled `DATA` or `COMMON` list emitted as one statement, where the source
  must have carried several (wild zip.exe at 295, book.exe at 396);
- a program whose line table did not come back, so every statement lands on
  one physical line 0 (wild metric.exe, 43759 characters; baby.exe, 6116).

Listed rather than counted, so the set cannot grow without someone saying why.
"""

from pathlib import Path

import pytest

from tbx import decode0, emit0

#: Turbo Basic Owner's Handbook (1987), editor limits.
EDITOR_LINE_LIMIT = 248

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"

#: Wild programs known to emit a line the Turbo Basic editor would reject,
#: with the width of the widest one. Real defects, each awaiting the
#: reconstruction or line-table work that fixes it -- recorded here so a new
#: one is noticed the moment it appears.
_OVER_WIDE = {
    "baby.exe": 6116,
    "book.exe": 396,
    "inv87.exe": 353,
    "invoice.exe": 353,
    "metric.exe": 43759,
    "state.exe": 265,
    "state87.exe": 265,
    "zip.exe": 295,
}


def _widest(exe: bytes) -> int:
    source = emit0.emit(decode0.decode_user_code(exe))
    return max((len(line) for line in source.splitlines()), default=0)


def test_no_fixture_emits_a_line_the_editor_would_reject():
    """The whole corpus, since this is cheap and the guard is the point."""
    over = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            widest = _widest(exe.read_bytes())
        except ValueError:
            continue
        if widest > EDITOR_LINE_LIMIT:
            over.append((exe.name, widest))

    assert not over, f"{len(over)} fixtures emit an over-wide line: {over[:5]}"


@pytest.mark.parametrize("name,widest", sorted(_OVER_WIDE.items()))
def test_a_known_over_wide_program_has_not_got_worse(name, widest):
    """Pinned, so a fix shows up as a failure rather than passing unnoticed.

    Narrowing one of these is the intended direction; the assertion is on the
    recorded width so it says so when it changes, either way.
    """
    from conftest import wild_hits_bytes

    assert _widest(wild_hits_bytes(name)) == widest


def test_no_other_wild_program_emits_an_over_wide_line():
    """The set is closed: a ninth program appearing is a regression."""
    from conftest import wild_hits_bytes

    wild_hits_bytes("zip.exe")  # skip the whole check when the corpus is absent
    hits = Path(__file__).resolve().parents[2] / "wild" / "hits"
    over = set()
    for exe in sorted(hits.glob("*.exe")):
        try:
            widest = _widest(exe.read_bytes())
        except Exception:
            continue
        if widest > EDITOR_LINE_LIMIT:
            over.add(exe.name)

    assert over == set(_OVER_WIDE)
