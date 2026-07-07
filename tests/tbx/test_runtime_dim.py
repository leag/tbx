"""Runtime DIM / OPTION BASE / far arrays (the sub-2C/2E allocation brackets)."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_dimv", "t1_dimv2"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_dimv():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    want = [
        ir.Input(None, V("A")),
        ir.Dim("V0", (V("A"),)),
        ir.Assign(ir.ArrayRef("V0", (L(1),)), L(2)),
        ir.Print(ir.ArrayRef("V0", (L(1),))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_dimv.exe")) == want


def test_decode_t1_dimv2():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    a = V("A%")
    el = ir.ArrayRef("V0", (L(1), L(1)))
    want = [
        ir.OptionBase(1),  # byte-significant: default-lo
        ir.Input(None, a),  # stores sit AFTER the hi store
        ir.Dim("V0", (a, L(3))),  #
        ir.Assign(el, ir.BinOp("+", a, L(2))),
        ir.Assign(V("B"), ir.BinOp("*", el, a)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_dimv2.exe")) == want


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_runtime_dim():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_dimv.exe"))) == (
        "10 INPUT A\n20 DIM V0(A)\n30 V0(1) = 2\n40 PRINT V0(1)\n50 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_dimv2.exe"))) == (
        "10 OPTION BASE 1\n"
        "20 INPUT A%\n"
        "30 DIM V0(A%,3)\n"
        "40 V0(1,1) = A% + 2\n"
        "50 B = V0(1,1) * A%\n"
        "60 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_dimv()
    test_decode_t1_dimv2()
    test_dialect_invariant()
    test_emit_runtime_dim()
    print("ALL PASS")
