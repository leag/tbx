import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_int():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    want = [
        A(V("A%"), L(5)),
        A(V("B%"), ir.BinOp("+", V("A%"), L(2))),
        A(V("C"), V("B%")),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_int.exe")) == want


def test_decode_t1_int2():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    a, b = V("A%"), V("B%")
    want = [
        A(a, L(5)),
        A(b, L(2)),
        A(V("C%"), ir.BinOp("+", a, b)),
        A(V("D%"), ir.BinOp("-", a, b)),
        A(V("E%"), ir.BinOp("*", a, b)),
        A(V("F%"), ir.BinOp("+", a, L(3))),
        A(V("G"), ir.BinOp("+", a, b)),
        A(V("H%"), V("G")),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_int2.exe")) == want


def test_emit_integers():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_int.exe"))) == (
        "10 A% = 5\n20 B% = A% + 2\n30 C = B%\n40 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_int2.exe"))) == (
        "10 A% = 5\n"
        "20 B% = 2\n"
        "30 C% = A% + B%\n"
        "40 D% = A% - B%\n"
        "50 E% = A% * B%\n"
        "60 F% = A% + 3\n"
        "70 G = A% + B%\n"
        "80 H% = G\n"
        "90 END\n"
    )


def test_old_corpus_still_decodes():
    from tbx import decode0

    for f in [
        "tier0_trivial.exe",
        "tier1_expr.exe",
        "t1_for.exe",
        "t1_while.exe",
        "t1_arr_mix.exe",
        "t1_print2.exe",
    ]:
        assert decode0.decode_user_code(_exe(f)), f


if __name__ == "__main__":
    test_decode_t1_int()
    test_decode_t1_int2()
    test_emit_integers()
    test_old_corpus_still_decodes()
    print("ALL PASS")
