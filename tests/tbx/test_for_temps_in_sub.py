"""A FOR inside a SUB reserves frame words that are not declared LOCALs.

The compiler puts a literal-bound integer FOR's [limit, step] temp pair at the
tail of the procedure's bp-relative frame -- and it does so whether the loop
variable is a LOCAL or an ordinary DGROUP scalar. `_retire_for_temps` already
walks the tail and drops untouched words, but it only ran for a FOR over a
LOCAL loop variable (`cmp_bpi8`), so a FOR over a DGROUP scalar left its two
temps in the frame table and they were emitted as declared LOCALs.

Re-emitting them makes the compiler reserve a SECOND pair, which is what wild
zip.exe and ziptest.exe were losing bytes to: every one of their affected SUBs
came back with a 4-word frame where the original had 2.
"""

from pathlib import Path

from tbx import decode0, emit0

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _exe(name):
    return (_CORPUS / name).read_bytes()


def test_for_over_dgroup_scalar_declares_no_locals():
    # t1_forsubdg.bas has no LOCAL statement at all; the two frame words are
    # the FOR's temps and nothing else.
    prog = decode0.decode_user_code(_exe("t1_forsubdg.exe"))
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n"
        "  FOR A% = 3 TO 5\n  PRINT A%\n  NEXT A%\nEND SUB\n"
        "20 CALL SUB1\n30 END\n"
    )


def test_a_declared_local_survives_the_temp_retirement():
    # t1_forsubloc.bas declares one LOCAL and then loops over a DGROUP scalar:
    # the tail walk must stop at the touched word, not clear the frame.
    prog = decode0.decode_user_code(_exe("t1_forsubloc.exe"))
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n"
        "  LOCAL A%\n  A% = 1\n"
        "  FOR B% = 3 TO 5\n  PRINT B%; A%\n  NEXT B%\nEND SUB\n"
        "20 CALL SUB1\n30 END\n"
    )
