"""String variables + INPUT / LINE INPUT (including `INPUT "prompt", X$`, flags 0x0040)."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = [
    "t1_str",
    "t1_inp",
    "t1_inp2",
    "t1_inp3",
    "t1_inp4",
    "t1_inpsemi",
    "t1_inparr",
    "t1_icmpmat",
]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_str():
    from tbx import decode0

    a, b = ir.Var("A$"), ir.Var("B$")
    want = [
        ir.Assign(a, ir.StrLit("HI")),
        ir.Assign(b, a),
        ir.Print(a),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_str.exe")) == want


def test_decode_t1_inp():
    from tbx import decode0

    want = [
        ir.Input(None, ir.Var("A")),
        ir.Input(None, ir.Var("B$")),
        ir.Print(ir.Var("B$")),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_inp.exe")) == want


def test_decode_t1_inp2():
    from tbx import decode0

    want = [ir.Input(ir.StrLit("X"), ir.Var("A")), ir.End()]
    assert decode0.decode_user_code(_exe("t1_inp2.exe")) == want


def test_decode_t1_inp3():
    from tbx import decode0

    want = [
        ir.LineInput(None, ir.Var("A$")),
        ir.LineInput(ir.StrLit("X"), ir.Var("B$")),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_inp3.exe")) == want


def test_decode_t1_inp4():
    from tbx import decode0

    want = [ir.Input(ir.StrLit("X"), ir.Var("A$"), comma=True), ir.End()]
    assert decode0.decode_user_code(_exe("t1_inp4.exe")) == want


def test_decode_t1_inpsemi():
    # Flag bit 0x0080 = the leading `INPUT;` form (stay on the line after
    # entry); numeric leg carries 0x4000 too, string leg (t1_inpsemis) just
    # 0x0080 -- both witnessed against wild inv87/invoice's 0x40C0
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_inpsemi.exe"))
    assert prog[0] == ir.Input(ir.StrLit("GIVE"), ir.Var("A"), semi=True)
    prog = decode0.decode_user_code(_exe("t1_inpsemis.exe"))
    assert prog[0] == ir.Input(ir.StrLit("NAME"), ir.Var("A$"), semi=True)


def test_decode_t1_inparr():
    # INPUT into an array element at a computed index (wild schart.exe): the
    # index computation runs BETWEEN read_num and the element store, so the
    # parsed value waits on the FP stack as the _INPUTREAD sentinel and the
    # fstp_si terminal names the target
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_inparr.exe"))
    assert prog[2] == ir.Input(
        None, ir.ArrayRef("V0", (ir.Var("A"),))
    )


def test_decode_t1_icmpmat():
    # Signed materialization jccs (7F/7C/7D/7E) in _JCC_RELOP_TRUE: an
    # integer cmpax_bx compare feeding a compound-IF term materializes with
    # signed jcc rows, FORWARD-oriented (pend_cmp is (lhs, rhs), unlike the
    # reversed FP rows) -- all four ops witnessed in this one fixture
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_icmpmat.exe")))
    assert "30 IF LEN(A$) > 2 AND LEN(A$) < 9 THEN B = 1" in src
    assert "40 IF LEN(A$) >= 3 OR LEN(A$) <= 1 THEN B = 2" in src


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_strings_input():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_str.exe"))) == (
        '10 A$ = "HI"\n20 B$ = A$\n30 PRINT A$\n40 END\n'
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_inp.exe"))) == (
        "10 INPUT A\n20 INPUT B$\n30 PRINT B$\n40 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_inp4.exe"))) == (
        '10 INPUT "X", A$\n20 END\n'
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_inp3.exe"))) == (
        '10 LINE INPUT A$\n20 LINE INPUT "X"; B$\n30 END\n'
    )


if __name__ == "__main__":
    test_decode_t1_str()
    test_decode_t1_inp()
    test_decode_t1_inp2()
    test_decode_t1_inp3()
    test_decode_t1_inp4()
    test_decode_t1_inpsemi()
    test_decode_t1_inparr()
    test_decode_t1_icmpmat()
    test_dialect_invariant()
    test_emit_strings_input()
    print("ALL PASS")
