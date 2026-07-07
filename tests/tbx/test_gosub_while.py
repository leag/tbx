import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_ir_nodes():
    assert ir.Gosub(4).target == 4
    assert ir.unparse_stmt(ir.Return()) == "RETURN"
    w = ir.While(ir.RelOp("<", ir.Var("A"), ir.Lit(5)))
    assert isinstance(w.cond, ir.RelOp)
    assert w.cond.op == "<"
    assert ir.unparse_stmt(ir.Wend()) == "WEND"


def test_decode_t1_gosub():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    want = [
        A(V("A"), L(1)),
        ir.Gosub(4),
        A(V("A"), L(3)),
        ir.End(),
        A(V("B"), L(2)),
        ir.Return(),
    ]
    assert decode0.decode_user_code(_exe("t1_gosub.exe")) == want


def test_decode_t1_while():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    a = V("A")
    # Pre-test WHILE loops canonicalize to DO WHILE ... LOOP (byte-identical, modern form).
    want = [
        A(a, L(0)),
        ir.Do("WHILE", ir.RelOp("<", a, L(5))),
        A(a, ir.BinOp("+", a, L(1))),
        ir.Loop(None),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_while.exe")) == want


def test_old_corpus_still_decodes():
    # END-termination change must not disturb the existing corpus.
    from tbx import decode0

    for f in ["tier0_trivial.exe", "tier1_expr.exe", "t1_goto.exe", "t1_for.exe"]:
        stmts = decode0.decode_user_code(_exe(f))
        assert stmts[-1] == ir.End(), (f, stmts[-1])


def test_emit_gosub_while():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_gosub.exe"))) == (
        "10 A = 1\n20 GOSUB 50\n30 A = 3\n40 END\n50 B = 2\n60 RETURN\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_while.exe"))) == (
        "10 A = 0\n20 DO WHILE A < 5\n30 A = A + 1\n40 LOOP\n50 END\n"
    )


if __name__ == "__main__":
    test_ir_nodes()
    test_decode_t1_gosub()
    test_decode_t1_while()
    test_old_corpus_still_decodes()
    test_emit_gosub_while()
    print("ALL PASS")
