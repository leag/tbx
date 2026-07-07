import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_ir_nodes():
    s = ir.StrLit("HELLO")
    assert ir.unparse(s) == '"HELLO"'
    assert ir.unparse_stmt(ir.Print(s)) == 'PRINT "HELLO"'
    assert ir.unparse_stmt(ir.Print(ir.Var("A"))) == "PRINT A"


def test_decode_t1_print():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    a = V("A")
    want = [
        A(a, L(5)),
        ir.Print(ir.StrLit("HELLO")),
        ir.Print(a),
        ir.Print(ir.BinOp("+", a, L(1))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_print.exe")) == want


def test_decode_t1_print2():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    a = V("A")
    want = [
        A(a, L(5)),
        ir.Print(ir.StrLit("HELLO")),
        ir.Print(ir.StrLit("WORLD!")),
        ir.Print(a),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_print2.exe")) == want


def test_emit_print():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_print.exe"))) == (
        '10 A = 5\n20 PRINT "HELLO"\n30 PRINT A\n40 PRINT A + 1\n50 END\n'
    )


def test_old_corpus_still_decodes():
    from tbx import decode0

    for f in ["tier0_trivial.exe", "t1_arr_two.exe", "t1_for.exe", "t1_while.exe"]:
        assert decode0.decode_user_code(_exe(f)), f


if __name__ == "__main__":
    test_ir_nodes()
    test_decode_t1_print()
    test_decode_t1_print2()
    test_emit_print()
    test_old_corpus_still_decodes()
    print("ALL PASS")
