"""TAB(n)/SPC(n) print items, console + file."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_tab():
    from tbx import decode0

    L, S, V, C = ir.Lit, ir.StrLit, ir.Var, ir.Call
    n = V("A")
    want = [
        ir.Input(None, n),
        ir.Print((S("A"), C("TAB", (L(7),)), n)),
        ir.Print((C("SPC", (L(3),)), S("B"))),
        ir.Print((C("TAB", (n,)), S("C"))),
        ir.Open(S("O"), 1, S("R.TXT")),
        ir.Print((S("X"), C("TAB", (L(7),)), S("Y"), C("SPC", (L(8),)), n), file=1),
        ir.Close(1),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_tab.exe")) == want


def test_dialect_invariant():
    from tbx import decode0

    assert decode0.decode_user_code(_exe("v10_t1_tab.exe")) == decode0.decode_user_code(
        _exe("t1_tab.exe")
    )


def test_emit_tab_spc():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_tab.exe"))) == (
        "10 INPUT A\n"
        '20 PRINT "A"; TAB(7); A\n'
        '30 PRINT SPC(3); "B"\n'
        '40 PRINT TAB(A); "C"\n'
        '50 OPEN "O",#1,"R.TXT"\n'
        '60 PRINT #1, "X"; TAB(7); "Y"; SPC(8); A\n'
        "70 CLOSE #1\n"
        "80 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_tab()
    test_dialect_invariant()
    test_emit_tab_spc()
    print("ALL PASS")
