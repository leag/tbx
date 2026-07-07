import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_ir_nodes():
    r = ir.RelOp("<", ir.Var("A"), ir.Var("B"))
    assert (r.op, r.lhs, r.rhs) == ("<", ir.Var("A"), ir.Var("B"))
    assert ir.Goto(3).target == 3
    assert ir.IfGoto(r, 5) == ir.IfGoto(ir.RelOp("<", ir.Var("A"), ir.Var("B")), 5)
    f = ir.For(ir.Var("I"), ir.Lit(1), ir.Lit(5), ir.Lit(1))
    assert ir.unparse_stmt(f) == "FOR I = 1 TO 5"  # STEP omitted when 1
    f2 = ir.For(ir.Var("I"), ir.Lit(1), ir.Lit(9), ir.Lit(2))
    assert ir.unparse_stmt(f2) == "FOR I = 1 TO 9 STEP 2"
    assert ir.unparse_stmt(ir.NextStmt(ir.Var("I"))) == "NEXT I"


def test_decode_t1_goto():
    from tbx import decode0

    A, L = ir.Assign, ir.Lit
    want = [
        A(ir.Var("A"), L(1)),
        ir.Goto(3),
        A(ir.Var("A"), L(2)),
        A(ir.Var("B"), L(3)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_goto.exe")) == want


def test_decode_t1_if():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    a, b, c = V("A"), V("B"), V("C")
    want = [
        A(a, L(1)),
        A(b, L(2)),
        ir.IfGoto(ir.RelOp(">=", a, b), 4),  # original: IF A < B THEN C = 5
        A(c, L(5)),
        ir.IfGoto(ir.RelOp("=", a, b), 6),  # original: IF A = B THEN 60
        A(c, ir.BinOp("+", a, L(1))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_if.exe")) == want


def test_decode_t1_for():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    s, i = V("A"), V("B")  # canonical letters: S->A, I->B
    want = [
        A(s, L(0)),
        ir.For(i, L(1), L(5), L(1)),
        A(s, ir.BinOp("+", s, i)),
        ir.NextStmt(i),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_for.exe")) == want


def test_decode_t1_relops():
    from tbx import decode0

    A, L, V = ir.Assign, ir.Lit, ir.Var
    a, b = V("A"), V("B")
    want = (
        [A(a, L(1)), A(b, L(2))]
        + [ir.IfGoto(ir.RelOp(op, a, b), 8) for op in ["=", "<>", "<", "<=", ">", ">="]]
        + [ir.End()]
    )
    assert decode0.decode_user_code(_exe("t1_relops.exe")) == want


def test_emit_control_flow():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_goto.exe"))) == (
        "10 A = 1\n20 GOTO 40\n30 A = 2\n40 B = 3\n50 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_if.exe"))) == (
        "10 A = 1\n"
        "20 B = 2\n"
        "30 IF A >= B THEN 50\n"
        "40 C = 5\n"
        "50 IF A = B THEN 70\n"
        "60 C = A + 1\n"
        "70 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_for.exe"))) == (
        "10 A = 0\n20 FOR B = 1 TO 5\n30 A = A + B\n40 NEXT B\n50 END\n"
    )


if __name__ == "__main__":
    test_ir_nodes()
    test_decode_t1_goto()
    test_decode_t1_if()
    test_decode_t1_for()
    test_decode_t1_relops()
    test_emit_control_flow()
    print("ALL PASS")
