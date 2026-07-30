"""Emitted source has to be source Turbo Basic could have accepted.

The Owner's Handbook is explicit: "The Turbo Basic editor supports lines up to
248 characters wide." So a physical line wider than that is not a formatting
preference -- it is provably not what the author wrote, because the compiler
this program came out of could not have taken it. That makes over-wide output
a decoder defect detectable with no oracle at all, by reading the emitted text.

It is also a class the fixture corpus cannot report: all 1030 fixtures emit
inside the limit, and every violation is in a wild program. Three shapes:

- a pooled `DATA` or `COMMON` list emitted as one statement, where the source
  must have carried several. `emit0._split_list_statement` now divides those,
  which is free: the compiler is lossy about how such a list was divided.
  Fixed wild zip.exe (295), book.exe (396) and baby.exe (6116) -- and zip.exe
  went from failing to reach the compiler at all to compiling.
- an inline IF whose folded body does not fit, respelled as a block IF. Free
  for the compound conditions these carry: `t1_ifin` and `t1_orrel` compile
  byte-identically either way, checked through the oracle. A *simple*
  condition is not interchangeable -- its inline form does not materialize,
  which is what `decode0`'s `block_ifs` turns on -- so it is left alone.
  Fixed wild inv87/invoice (353) and state/state87 (265).
- a program whose recorded line table has one distinct value, so every
  statement was grouped onto it. Such a table distinguishes nothing and cannot
  be the source's numbering -- 1789 statements do not fit 248 characters -- so
  `emit0` treats it as absent and renumbers. Fixed wild metric.exe (43759), the
  last of them, and it now compiles where before it could not be loaded.

No program in either corpus emits an over-wide line any more, so the guard is
stated as the invariant rather than as a list of exceptions.
"""

from pathlib import Path

import pytest

from tbx import decode0, emit0, ir

#: Turbo Basic Owner's Handbook (1987), editor limits.
EDITOR_LINE_LIMIT = 248
#: "The editor integrated within Turbo Basic allows source programs to be no
#: larger than 64K in size", and `$INCLUDE` is how the handbook says to compile
#: anything bigger. A single emitted file over this is the same kind of defect
#: as an over-wide line: not source that could have been handed to the editor.
EDITOR_FILE_LIMIT = 65536

#: Wild programs whose unsplit emitted source exceeds that, with its size.
#: Keep the sizes pinned while also requiring emit_split to make compiler-sized
#: root and include files below.
_OVER_LONG = {
    "banker.exe": 98245,
    "horses.exe": 67425,
    "inv87.exe": 88341,
    "invoice.exe": 88341,
    "state.exe": 69191,
    "state87.exe": 69191,
}
_SPLITTABLE = set(_OVER_LONG) - {"horses.exe"}

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"




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


def test_no_wild_program_emits_an_over_wide_line():
    """The wild corpus is where every one of these was found, and is now clean."""
    from conftest import wild_hits_bytes

    wild_hits_bytes("zip.exe")  # skip the whole check when the corpus is absent
    hits = Path(__file__).resolve().parents[2] / "wild" / "hits"
    over = []
    for exe in sorted(hits.glob("*.exe")):
        try:
            widest = _widest(exe.read_bytes())
        except Exception:
            continue
        if widest > EDITOR_LINE_LIMIT:
            over.append((exe.name, widest))

    assert not over, f"{len(over)} wild programs emit an over-wide line: {over}"


def test_a_long_literal_concatenation_uses_optional_spacing_to_fit():
    value = ir.StrLit("1234567890")
    expr = value
    for _ in range(16):
        expr = ir.BinOp("+", expr, value)
    program = [ir.Assign(ir.Var("A$"), expr)]

    line = emit0.emit(program).rstrip()

    assert len(line) <= EDITOR_LINE_LIMIT
    assert "+" in line


def test_a_line_table_that_distinguishes_nothing_is_not_used():
    """The condition the metric.exe fix turns on, stated directly.

    Grouping is driven by statements sharing a recorded line number. A table
    with one distinct value groups the entire program onto one line, which no
    source could have contained. Every corpus table has real numbers in it, so
    this path is reached by no fixture.
    """
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("metric.exe"))

    assert len(set(prog.lines)) == 1, "fixture drifted: table is no longer degenerate"
    assert _widest(wild_hits_bytes("metric.exe")) <= EDITOR_LINE_LIMIT


def _size(exe: bytes) -> int:
    return len(emit0.emit(decode0.decode_user_code(exe)))


def test_no_fixture_emits_a_file_the_editor_could_not_load():
    over = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            size = _size(exe.read_bytes())
        except ValueError:
            continue
        if size > EDITOR_FILE_LIMIT:
            over.append((exe.name, size))

    assert not over, f"{len(over)} fixtures emit over 64K: {over[:5]}"


@pytest.mark.parametrize("name,size", sorted(_OVER_LONG.items()))
def test_a_known_over_long_program_has_not_got_worse(name, size):
    """Pinned like the widths, so a change in either direction is visible."""
    from conftest import wild_hits_bytes

    assert _size(wild_hits_bytes(name)) == size


@pytest.mark.parametrize("name", sorted(_SPLITTABLE))
def test_an_over_long_program_splits_into_compiler_sized_files(name):
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes(name))
    bundle = emit0.emit_split(prog, prefix=Path(name).stem)

    assert bundle.includes
    assert len(bundle.root.encode("latin-1")) < EDITOR_FILE_LIMIT
    assert all(
        len(text.encode("latin-1")) <= emit0.INCLUDE_LIMIT
        for _, text in bundle.includes
    )


def test_an_over_long_program_with_scanned_subs_uses_compact_numbering():
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("horses.exe"))
    bundle = emit0.emit_split(prog, prefix="horses")

    assert not bundle.includes
    assert len(bundle.root.encode("latin-1")) < EDITOR_FILE_LIMIT
    assert "GOTO " in bundle.root
