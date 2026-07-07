"""Far string arrays, base-0 far-IDX, far INPUT#."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_sarr", "t1_sarr2"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_sarr():
    from tbx import decode0

    L, S, V, A = ir.Lit, ir.StrLit, ir.Var, ir.ArrayRef
    n = V("A")
    want = [
        ir.Input(None, n),
        ir.Dim("V0$", (n,)),
        ir.Assign(A("V0$", (L(1),)), S("AB")),
        ir.Assign(A("V0$", (n,)), S("CD")),
        ir.Assign(V("B$"), A("V0$", (n,))),
        ir.Print((A("V0$", (L(1),)),)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_sarr.exe")) == want


def test_decode_t1_sarr2():
    from tbx import decode0

    L, S, V, A = ir.Lit, ir.StrLit, ir.Var, ir.ArrayRef
    n = V("A")
    want = [
        ir.Input(None, n),
        ir.Dim("V1$", (n,)),
        ir.Dim("V0", (n, L(5))),
        ir.Open(S("I"), 1, S("X.DAT")),
        ir.InputFile(1, (A("V0", (n, L(5))), A("V1$", (n,)))),
        ir.Close(1),
        ir.Print((A("V0", (L(1), L(1))), A("V1$", (n,)))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_sarr2.exe")) == want


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_far_strings():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_sarr.exe"))) == (
        "10 INPUT A\n"
        "20 DIM V0$(A)\n"
        '30 V0$(1) = "AB"\n'
        '40 V0$(A) = "CD"\n'
        "50 B$ = V0$(A)\n"
        "60 PRINT V0$(1)\n"
        "70 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_sarr2.exe"))) == (
        "10 INPUT A\n"
        "20 DIM V1$(A)\n"
        "30 DIM V0(A,5)\n"
        '40 OPEN "I",#1,"X.DAT"\n'
        "50 INPUT #1, V0(A,5), V1$(A)\n"
        "60 CLOSE #1\n"
        "70 PRINT V0(1,1); V1$(A)\n"
        "80 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_sarr()
    test_decode_t1_sarr2()
    test_dialect_invariant()
    test_emit_far_strings()
    print("ALL PASS")
