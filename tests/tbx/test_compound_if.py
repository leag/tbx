"""Compound IF conditions (AND/OR) + intrinsics."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_and", "t1_or", "t1_fn", "t1_erase"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_and():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    want = [
        ir.Input(None, V("A")),
        ir.Input(None, V("B")),
        ir.IfGoto(
            ir.LogOp("AND", ir.RelOp(">", V("A"), L(1)), ir.RelOp("<", V("B"), L(5))), 5
        ),
        ir.Print(L(0)),
        ir.Goto(6),
        ir.Print(L(1)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_and.exe")) == want


def test_decode_t1_or():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    want = [
        ir.Input(None, V("A")),
        ir.IfGoto(
            ir.LogOp("OR", ir.RelOp("<", V("A"), L(0)), ir.RelOp(">", V("A"), L(9))), 4
        ),
        ir.Print(L(0)),
        ir.Goto(5),
        ir.Print(L(1)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_or.exe")) == want


def test_decode_t1_fn():
    from tbx import decode0

    V = ir.Var
    x = V("A")
    want = [
        ir.Input(None, x),
        ir.Assign(V("B"), ir.Call("ABS", (x,))),
        ir.Assign(V("C"), ir.Call("SQR", (x,))),
        ir.Assign(V("D"), ir.Call("INT", (x,))),
        ir.Assign(V("E"), ir.Call("SGN", (x,))),
        ir.Print(
            ir.BinOp("+", ir.BinOp("+", ir.BinOp("+", V("B"), V("C")), V("D")), V("E"))
        ),  # parens are source-faithful
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_fn.exe")) == want


def test_decode_t1_erase():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    n = V("A")
    want = [
        ir.Input(None, n),
        ir.Dim("V0", (n,)),
        ir.Assign(ir.ArrayRef("V0", (L(1),)), L(2)),
        ir.Erase("V0"),
        ir.Dim("V0", (n,)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_erase.exe")) == want


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_compound_if():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_and.exe"))) == (
        "10 INPUT A\n"
        "20 INPUT B\n"
        "30 IF A > 1 AND B < 5 THEN 60\n"
        "40 PRINT 0\n"
        "50 GOTO 70\n"
        "60 PRINT 1\n"
        "70 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_or.exe"))) == (
        "10 INPUT A\n"
        "20 IF A < 0 OR A > 9 THEN 50\n"
        "30 PRINT 0\n"
        "40 GOTO 60\n"
        "50 PRINT 1\n"
        "60 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_fn.exe"))) == (
        "10 INPUT A\n"
        "20 B = ABS(A)\n"
        "30 C = SQR(A)\n"
        "40 D = INT(A)\n"
        "50 E = SGN(A)\n"
        "60 PRINT B + C + D + E\n"
        "70 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_and()
    test_decode_t1_or()
    test_decode_t1_fn()
    test_decode_t1_erase()
    test_dialect_invariant()
    test_emit_compound_if()
    print("ALL PASS")
