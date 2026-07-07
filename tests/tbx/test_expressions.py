import os
from tbx import ir, decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def B(op, l, r):
    return ir.BinOp(op, l, r)


def V(n):
    return ir.Var(n)


def A(t, v):
    return ir.Assign(t, v)


def test_decode_tier1_expr():
    a, b, c, d = V("A"), V("B"), V("C"), V("D")
    want = [
        A(a, ir.Lit(5)),
        A(b, ir.Lit(2)),
        A(c, B("+", a, b)),
        A(d, B("-", a, b)),
        A(V("E"), B("*", a, b)),
        A(V("F"), B("/", a, b)),
        A(V("G"), B("+", B("*", b, c), a)),  # fold chain: running expr stays left
        A(V("H"), B("*", ir.Group(B("+", a, b)), c)),  # (A+B)*C: group explicit in IR
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("tier1_expr.exe")) == want


def test_decode_tier1_expr2():
    a, b, c, d = V("A"), V("B"), V("C"), V("D")
    G = ir.Group
    want = [
        A(a, ir.Lit(5)),
        A(b, ir.Lit(2)),
        A(c, B("-", G(B("+", a, b)), b)),  # (A+B)-B: group for lower-prec lhs
        A(d, B("/", G(B("+", a, b)), b)),
        A(V("E"), B("-", a, B("*", b, c))),
        A(V("F"), B("/", a, G(B("+", b, c)))),  # A/(B+C): group for lower-prec rhs
        A(V("G"), ir.Neg(a)),
        A(V("H"), B("*", G(B("-", a, b)), G(B("+", c, d)))),  # (A-B)*(C+D): both groups
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("tier1_expr2.exe")) == want


def test_decode_tier1_expr3():
    # Textual canonical rename: targets/leaves in reading order ->
    # original X,Y become C,D; original C,D,E,F become E,F,G,H.
    a, b, c, d = V("A"), V("B"), V("C"), V("D")
    e, f = V("E"), V("F")
    G = ir.Group
    want = [
        A(a, ir.Lit(1)),
        A(b, B("+", c, d)),  # B = X + Y
        A(e, B("+", a, ir.Lit(1))),  # C = A + 1
        A(f, B("*", ir.Lit(2), a)),  # D = 2 * A
        A(V("G"), B("+", G(B("+", a, b)), G(B("+", e, f)))),  # (A+B)+(E+F): both groups
        A(V("H"), B("*", a, ir.Lit(10))),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("tier1_expr3.exe")) == want


def test_trivial_still_decodes():
    want = [A(V("A"), ir.Lit(1)), ir.End()]
    assert decode0.decode_user_code(_exe("tier0_trivial.exe")) == want


if __name__ == "__main__":
    test_decode_tier1_expr()
    test_decode_tier1_expr2()
    test_decode_tier1_expr3()
    test_trivial_still_decodes()
    print("ALL PASS")
