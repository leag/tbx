import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def AR(name, *idx):
    return ir.ArrayRef(name, tuple(idx))


def test_dim_node():
    d = ir.Dim("V0", (10,))
    assert ir.unparse_stmt(d) == "DIM V0(10)"
    assert ir.unparse_stmt(ir.Dim("V0", (5, 5))) == "DIM V0(5,5)"


def test_decode_t1_arr1():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    want = [
        ir.Dim("V0", (10,)),
        A(AR("V0", L(1)), L(5)),
        A(AR("V0", L(2)), ir.BinOp("+", AR("V0", L(1)), L(1))),
        A(V("A"), AR("V0", L(2))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_arr1.exe")) == want


def test_decode_t1_arr2():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    want = [
        ir.Dim("V0", (5, 5)),
        A(AR("V0", L(1), L(2)), L(7)),
        A(V("A"), AR("V0", L(1), L(2))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_arr2.exe")) == want


def test_decode_t1_arrv():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    a, b = V("A"), V("B")  # original I -> A, A -> B
    want = [
        ir.Dim("V0", (10,)),
        A(a, L(3)),
        A(AR("V0", a), L(2)),
        A(b, ir.BinOp("+", AR("V0", a), AR("V0", L(1)))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_arrv.exe")) == want


def test_decode_t1_arr_two():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    want = [
        ir.Dim("V0", (10,)),  # V0 = first DIM (highest base)
        ir.Dim("V1", (5,)),
        A(AR("V0", L(1)), L(5)),
        A(AR("V1", L(2)), L(6)),
        A(V("A"), ir.BinOp("+", AR("V0", L(1)), AR("V1", L(2)))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_arr_two.exe")) == want


def test_decode_t1_arr_mix():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    a, b, c = V("A"), V("B"), V("C")
    want = [
        ir.Dim("V0", (3,)),
        A(a, L(1)),
        A(b, L(2)),
        A(c, ir.BinOp("+", a, b)),
        A(AR("V0", L(1)), c),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_arr_mix.exe")) == want


def test_old_corpus_still_decodes():
    from tbx import decode0

    for f in [
        "tier0_trivial.exe",
        "tier1_expr.exe",
        "t1_for.exe",
        "t1_while.exe",
        "t1_gosub.exe",
        "t1_relops.exe",
    ]:
        stmts = decode0.decode_user_code(_exe(f))
        assert stmts, f


def test_emit_arrays():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_arr1.exe"))) == (
        "10 DIM V0(10)\n20 V0(1) = 5\n30 V0(2) = V0(1) + 1\n40 A = V0(2)\n50 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_arr_two.exe"))) == (
        "10 DIM V0(10)\n"
        "20 DIM V1(5)\n"
        "30 V0(1) = 5\n"
        "40 V1(2) = 6\n"
        "50 A = V0(1) + V1(2)\n"
        "60 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_arrv.exe"))) == (
        "10 DIM V0(10)\n20 A = 3\n30 V0(A) = 2\n40 B = V0(A) + V0(1)\n50 END\n"
    )


if __name__ == "__main__":
    test_dim_node()
    test_decode_t1_arr1()
    test_decode_t1_arr2()
    test_decode_t1_arrv()
    test_decode_t1_arr_two()
    test_decode_t1_arr_mix()
    test_old_corpus_still_decodes()
    test_emit_arrays()
    print("ALL PASS")
