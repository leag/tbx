"""A PRINT that is nothing but comma zones keeps them.

`PRINT ,,` advances two print zones and suppresses the newline, and it compiles
to exactly `rt C1, rt C1`. The decoder recovers that as
`Print(items=(), newline=False, commas=(2,))` -- correctly -- but the renderer
gated all comma output on `if s.items`, so an item-less PRINT printed as
`PRINT;` and both zones were lost.

It only shows when nothing printable follows: with a PRINT next, the zones
attach to it as leading commas (`PRINT ,, "b"`), which is byte-identical. In
wild pz.exe the next statement is a LOCATE, so they had nowhere to go and two
`INT BBh` calls went missing from the recompile.
"""

from pathlib import Path

from tbx import decode0, emit0, ir

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def test_an_item_less_print_keeps_its_comma_zones():
    prog = decode0.decode_user_code((_CORPUS / "t1_printcommatail.exe").read_bytes())
    bare = [s for s in prog if isinstance(s, ir.Print) and not s.items]
    assert bare == [ir.Print((), newline=False, file=None, commas=(2,))]
    assert emit0.emit(prog) == (
        '10 PRINT "a"\n'
        "20 PRINT ,,\n"
        "30 LOCATE 5,5\n"
        '40 PRINT "b"\n'
        "50 END\n"
    )


def test_a_bare_semicolon_print_is_still_a_semicolon():
    # No commas recorded: the `;` spelling must survive the fix.
    assert ir.unparse_stmt(ir.Print((), newline=False)) == "PRINT;"
    assert ir.unparse_stmt(ir.Lprint((), newline=False)) == "LPRINT;"
