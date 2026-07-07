"""Symbolic far-index machine -- variable/bridged subscripts, multi-element
statements, and array-elements-as-subscripts."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_dimw", "t1_dimw2", "t1_dimw3"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_dimw():
    from tbx import decode0

    L, V, A = ir.Lit, ir.Var, ir.ArrayRef
    n, i, j = V("A"), V("B"), V("C")
    want = [
        ir.OptionBase(1),
        ir.Input(None, n),
        ir.Dim("V1", (n, L(3))),
        ir.Dim("V0", (n,)),
        ir.Assign(i, L(2)),
        ir.Assign(j, L(1)),
        ir.Assign(A("V0", (i,)), L(4)),
        ir.Assign(A("V1", (i, j)), ir.BinOp("+", A("V1", (j, i)), A("V0", (i,)))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_dimw.exe")) == want


def test_decode_t1_dimw2():
    from tbx import decode0

    L, V, A = ir.Lit, ir.Var, ir.ArrayRef
    n, i, j = V("A"), V("B"), V("C")
    el = A("V0", (i, j))
    want = [
        ir.OptionBase(1),
        ir.Input(None, n),
        ir.Dim("V0", (n, L(3))),
        ir.Assign(i, L(2)),
        ir.Assign(j, L(1)),
        ir.Assign(el, ir.BinOp("+", el, L(4))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_dimw2.exe")) == want


def test_decode_t1_dimw3():
    from tbx import decode0

    L, V, A = ir.Lit, ir.Var, ir.ArrayRef
    n, i, x = V("A"), V("B"), V("C")
    k1 = A("V0", (i, L(1)))
    k2 = A("V0", (i, L(2)))
    want = [
        ir.OptionBase(1),
        ir.Input(None, n),
        ir.Dim("V1", (n, L(3))),
        ir.Dim("V0", (n, L(2))),
        ir.Assign(i, L(2)),
        ir.Assign(A("V1", (k1, k2)), L(7)),
        ir.Assign(x, A("V1", (k1, L(1)))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_dimw3.exe")) == want


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_far_index():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_dimw.exe"))) == (
        "10 OPTION BASE 1\n"
        "20 INPUT A\n"
        "30 DIM V1(A,3)\n"
        "40 DIM V0(A)\n"
        "50 B = 2\n"
        "60 C = 1\n"
        "70 V0(B) = 4\n"
        "80 V1(B,C) = V1(C,B) + V0(B)\n"
        "90 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_dimw3.exe"))) == (
        "10 OPTION BASE 1\n"
        "20 INPUT A\n"
        "30 DIM V1(A,3)\n"
        "40 DIM V0(A,2)\n"
        "50 B = 2\n"
        "60 V1(V0(B,1),V0(B,2)) = 7\n"
        "70 C = V1(V0(B,1),1)\n"
        "80 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_dimw()
    test_decode_t1_dimw2()
    test_decode_t1_dimw3()
    test_dialect_invariant()
    test_emit_far_index()
    print("ALL PASS")
