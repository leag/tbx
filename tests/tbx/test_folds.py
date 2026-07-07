"""Inline IF, long NEXT, pooled IEEE singles, fold orientation / minimal parens."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_fp", "t1_fp2", "t1_ifin", "t1_for2"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_fp():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    import struct

    b = struct.unpack("<f", ir.f32_enc(float("1.3552527e-20")))[0]
    want = [
        ir.Assign(V("A"), L(0.5)),
        ir.Assign(V("B"), L(b)),
        ir.Assign(V("C"), L(struct.unpack("<f", ir.f32_enc(2.5e10))[0])),
        ir.Print((V("A"), V("B"), V("C"))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_fp.exe")) == want


def test_decode_t1_fp2():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_fp2.exe"))) == (
        "10 A = 0!\n20 B = 1!\n30 C = 5!\n40 PRINT A; B; C\n50 END\n"
    )


def test_decode_t1_ifin():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    want = [
        ir.Input(None, V("A")),
        ir.Input(None, V("B")),
        ir.IfInline(
            ir.LogOp("AND", ir.RelOp(">", V("A"), L(1)), ir.RelOp("<", V("B"), L(5))),
            (ir.Assign(V("C"), L(1)), ir.Assign(V("D"), L(2))),
        ),
        ir.Print((V("C"), V("D"))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_ifin.exe")) == want


def test_emit_t1_ifin_t1_for2():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_ifin.exe"))) == (
        "10 INPUT A\n"
        "20 INPUT B\n"
        "30 IF A > 1 AND B < 5 THEN C = 1: D = 2\n"
        "40 PRINT C; D\n"
        "50 END\n"
    )
    out = emit0.emit(decode0.decode_user_code(_exe("t1_for2.exe")))
    assert out.startswith("10 FOR A = 1 TO 3\n20 B = B + 1\n")
    assert out.endswith("120 NEXT A\n130 PRINT B\n140 END\n")


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


if __name__ == "__main__":
    test_decode_t1_fp()
    test_decode_t1_fp2()
    test_decode_t1_ifin()
    test_emit_t1_ifin_t1_for2()
    test_dialect_invariant()
    print("ALL PASS")
