"""Unified slot layout -- mixed static+runtime arrays, near static access,
DIM ranges."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_mix", "t1_mix2", "t1_mix3"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def _want_mix(abound):
    L, V, A = ir.Lit, ir.Var, ir.ArrayRef
    n = V("A")
    return [
        ir.OptionBase(1),
        ir.Dim("V0", (abound,)),  # static A -> slot#1 -> textual name V0
        ir.Dim("V1", (3, 2)),  # static C -> slot#0 -> V1
        ir.Input(None, n),
        ir.Dim("V2", (n,)),  # runtime B -> slot#2
        ir.Assign(A("V0", (L(1),)), L(2)),
        ir.Assign(A("V0", (n,)), ir.BinOp("+", A("V0", (L(2),)), L(1))),
        ir.Assign(A("V1", (L(1), L(2))), A("V0", (n,))),
        ir.Assign(A("V1", (n, L(1))), L(4)),
        ir.Assign(A("V2", (L(1),)), A("V1", (L(1), L(1)))),
        ir.Print((A("V0", (n,)), A("V1", (n, L(2))), A("V2", (n,)))),
        ir.End(),
    ]


def test_decode_t1_mix():
    from tbx import decode0

    assert decode0.decode_user_code(_exe("t1_mix.exe")) == _want_mix(4)


def test_decode_t1_mix2():
    from tbx import decode0

    assert decode0.decode_user_code(_exe("t1_mix2.exe")) == _want_mix(5)


def test_decode_t1_mix3():
    from tbx import decode0

    L, V, A = ir.Lit, ir.Var, ir.ArrayRef
    n = V("A")
    want = [
        ir.OptionBase(1),
        ir.Dim("V0", ((0, 4),)),  # static A(0:4) -> range bound
        ir.Dim("V1", ((2, 3), (0, 2))),  # static C(2:3,0:2)
        ir.Input(None, n),
        ir.Dim("V2", (n,)),
        ir.Assign(A("V0", (L(0),)), L(2)),
        ir.Assign(A("V0", (n,)), ir.BinOp("+", A("V0", (L(2),)), L(1))),
        ir.Assign(A("V1", (L(2), L(0))), A("V0", (n,))),
        ir.Assign(A("V1", (n, L(2))), L(4)),
        ir.Assign(A("V2", (L(1),)), A("V1", (L(3), L(1)))),
        ir.Print((A("V0", (n,)), A("V1", (n, L(2))), A("V2", (n,)))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_mix3.exe")) == want


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_slot_layout():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_mix.exe"))) == (
        "10 OPTION BASE 1\n"
        "20 DIM V0(4)\n"
        "30 DIM V1(3,2)\n"
        "40 INPUT A\n"
        "50 DIM V2(A)\n"
        "60 V0(1) = 2\n"
        "70 V0(A) = V0(2) + 1\n"
        "80 V1(1,2) = V0(A)\n"
        "90 V1(A,1) = 4\n"
        "100 V2(1) = V1(1,1)\n"
        "110 PRINT V0(A); V1(A,2); V2(A)\n"
        "120 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_mix3.exe"))) == (
        "10 OPTION BASE 1\n"
        "20 DIM V0(0:4)\n"
        "30 DIM V1(2:3,0:2)\n"
        "40 INPUT A\n"
        "50 DIM V2(A)\n"
        "60 V0(0) = 2\n"
        "70 V0(A) = V0(2) + 1\n"
        "80 V1(2,0) = V0(A)\n"
        "90 V1(A,2) = 4\n"
        "100 V2(1) = V1(3,1)\n"
        "110 PRINT V0(A); V1(A,2); V2(A)\n"
        "120 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_mix()
    test_decode_t1_mix2()
    test_decode_t1_mix3()
    test_dialect_invariant()
    test_emit_slot_layout()
    print("ALL PASS")
