"""One print statement can hold more than one USING clause.

    LPRINT TAB(5); "n "; TAB(25); USING f1$; A#; TAB(37); USING f2$; B$

is a SINGLE Turbo Basic statement, and no split spelling reproduces its bytes:
the four candidates tried come back 15-20 bytes off (t1_usingtwice). So the
second and later USING become ITEMS of the open print chain rather than ending
it. A LONE USING after items is byte-identical either way, so it keeps its own
statement -- t1_lpusing must not merge.

Two conditions gate the nesting, and both are load-bearing:
  - another `rt CA` before this statement's flush, and
  - no per-statement commit marker in the SPAN between the two.
The second is what separates wild banker.exe (no marker: one statement) from
wild inv87.exe and invoice.exe (a marker before the second clause: genuinely
two, and merging them costs those programs bytes). Ledger
RO-COMMIT-MARKER-BOUNDARY records the gates that did NOT work.
"""

from pathlib import Path

from tbx import decode0, emit0, ir

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _prog(stem):
    return decode0.decode_user_code((_CORPUS / f"{stem}.exe").read_bytes())


def test_two_using_clauses_stay_one_statement():
    prog = _prog("t1_usingtwice")
    lprints = [s for s in prog if isinstance(s, ir.Lprint)]
    assert len(lprints) == 1, [type(s).__name__ for s in prog]
    nested = [i for i in lprints[0].items if isinstance(i, ir.PrintUsing)]
    assert len(nested) == 2
    assert all(not n.newline for n in nested)  # the chain decides the newline


def test_it_emits_as_one_line_with_both_clauses():
    assert (
        '30 LPRINT TAB(5); "n "; TAB(25); USING "####.###"; A#; '
        'TAB(37); USING "\\ \\"; B$\n'
    ) in emit0.emit(_prog("t1_usingtwice"))


def test_a_nested_using_gets_its_variables_renamed():
    # It is a STATEMENT node in an expression list, so the rename walk has to
    # dispatch on it or raw slot names leak into the source.
    src = emit0.emit(_prog("t1_usingtwice"))
    assert "V0120" not in src and "V0128" not in src


def test_a_lone_using_still_gets_its_own_statement():
    prog = _prog("t1_lpusing")
    assert sum(isinstance(s, ir.PrintUsing) for s in prog) == 1
    assert emit0.emit(prog).count("LPRINT") == 3


def test_a_marker_in_the_span_blocks_the_merge():
    from conftest import wild_hits_bytes

    # inv87.exe has two USING begins before a flush AND a commit marker between
    # them: two statements. Merging them regressed it 649 -> 733 bytes off.
    prog = decode0.decode_user_code(wild_hits_bytes("inv87.exe"))
    nested = [
        i
        for s in prog
        if isinstance(s, (ir.Print, ir.Lprint))
        for i in s.items
        if isinstance(i, ir.PrintUsing)
    ]
    assert nested == []


def test_a_helper_payload_drops_the_bytes_the_compiler_re_adds():
    """CB and, under EVENT trapping, the CC poll stamp before it.

    Both are Turbo Basic's contribution, not the payload's. Re-emitting either
    makes the recompiled body longer than the original, which is enough to miss
    `find_opaque_helpers`' exact-body match -- and then our own output does not
    scan (wild resume.exe: six helpers, 113 bytes in and 114 out,
    `unhandled byte c4`).
    """
    from tbx.ir.render import _without_appended_tail

    assert _without_appended_tail(bytes.fromhex("558bec5dcccb")) == bytes.fromhex("558bec5d")
    assert _without_appended_tail(bytes.fromhex("558bec5dcb")) == bytes.fromhex("558bec5d")
    # No trailing CB: nothing to strip but the stamps.
    assert _without_appended_tail(bytes.fromhex("558bec5d")) == bytes.fromhex("558bec5d")


def test_resume_helper_payloads_round_trip_byte_exact():
    from conftest import wild_hits_bytes

    import tbx.decode0.scan as sc
    from tbx import decode0 as d0

    data = wild_hits_bytes("resume.exe")
    start, dia = d0.find_prologue(data)
    ops = sc._scan(data, start, dia, set())
    bodies = [o[2] for o in ops if o[1] in ("opaque_helper", "inline_sub")]
    assert [len(b) for b in bodies] == [113, 128, 120, 112, 111, 107]
    # Every one ends with the compiler's own stamp+ret, which must not be
    # emitted back into the source.
    assert all(b.endswith(bytes.fromhex("cccb")) for b in bodies)
