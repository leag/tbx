from tbx import ir


def test_unparse_roundtrips_node_shapes():
    # literal, unknown, var
    assert ir.unparse(ir.Lit(5)) == "5"
    assert ir.unparse(ir.Unknown()) == "?"
    assert ir.unparse(ir.Var("IDX%")) == "IDX%"
    # binop renders with minimal parens, single spaces around the operator
    e = ir.BinOp("+", ir.Var("VN"), ir.Var("BN"))
    assert ir.unparse(e) == "VN + BN", ir.unparse(e)
    # nested binop: parens only where precedence/tree shape requires them
    e2 = ir.BinOp("*", ir.BinOp("+", ir.Var("A"), ir.Lit(1)), ir.Var("B"))
    assert ir.unparse(e2) == "(A + 1) * B", ir.unparse(e2)
    e3 = ir.BinOp("+", ir.Var("A"), ir.BinOp("+", ir.Var("B"), ir.Var("C")))
    assert ir.unparse(e3) == "A + (B + C)", ir.unparse(e3)
    # A calibrated compiler-template wrapper preserves syntax that is
    # algebraically equivalent but byte-distinct in Turbo Basic.
    sub = ir.Template(
        "subtraction",
        ir.BinOp("+", ir.Var("A%"), ir.Group(ir.Neg(ir.Var("B%")))),
    )
    assert ir.unparse(sub) == "A% - B%"
    assert ir.unparse(ir.BinOp("\\", sub, ir.Lit(2))) == "(A% - B%) \\ 2"
    # array ref: no space after commas
    a = ir.ArrayRef("NU", (ir.Lit(7), ir.Var("V_0AE0")))
    assert ir.unparse(a) == "NU(7,V_0AE0)", ir.unparse(a)
    # intrinsic call renders the same shape
    c = ir.Call("SQR", (ir.Var("V_0A40"),))
    assert ir.unparse(c) == "SQR(V_0A40)", ir.unparse(c)


def test_var_type_from_suffix():
    assert ir.Var("IDX%").ty == "INT"
    assert ir.Var("X!").ty == "SGL"
    assert ir.Var("Y#").ty == "DBL"
    assert ir.Var("S$").ty == "STR"
    assert ir.Var("NN").ty == "NUM"  # no suffix -> default numeric


def test_parse_expr():
    # variable, literal, unknown
    assert ir.parse_expr("NN") == ir.Var("NN")
    assert ir.parse_expr("5") == ir.Lit(5)
    assert ir.parse_expr("?") == ir.Unknown()
    # binop (fully parenthesized) -> BinOp tree
    assert ir.parse_expr("(VN + BN)") == ir.BinOp("+", ir.Var("VN"), ir.Var("BN"))
    # nested
    assert ir.parse_expr("((A + 1) * B)") == ir.BinOp(
        "*", ir.BinOp("+", ir.Var("A"), ir.Lit(1)), ir.Var("B")
    )
    # array ref (NAME not an intrinsic) with expression indices
    assert ir.parse_expr("NU(7,V_0AE0)") == ir.ArrayRef(
        "NU", (ir.Lit(7), ir.Var("V_0AE0"))
    )
    # intrinsic call (NAME in INTRINSICS) -> Call, not ArrayRef
    assert ir.parse_expr("SQR(V_0A40)") == ir.Call("SQR", (ir.Var("V_0A40"),))
    # unary negation (FCHS), rendered with minimal parens
    assert ir.parse_expr("(-DX)") == ir.Neg(ir.Var("DX"))
    assert ir.unparse(ir.Neg(ir.Var("DX"))) == "-DX"
    assert ir.parse_expr("((-DX) / LB)") == ir.BinOp(
        "/", ir.Neg(ir.Var("DX")), ir.Var("LB")
    )
    # a deep real shape: nested array ref as an index (parse accepts the old
    # fully-parenthesized form; unparse re-renders it minimally)
    s = "SC(4,VI((V_0D2A + V_0A70),V_0A9C))"
    assert ir.unparse(ir.parse_expr(s)) == "SC(4,VI(V_0D2A + V_0A70,V_0A9C))", (
        ir.unparse(ir.parse_expr(s))
    )


def test_parse_rejects_trailing_garbage():
    try:
        ir.parse_expr("(A + B) C")
        assert False, "expected ValueError on trailing tokens"
    except ValueError:
        pass


def test_lift_assign():
    # a scalar assignment
    a = ir.lift_assign("V_0B04 = VN")
    assert a == ir.Assign(ir.Var("V_0B04"), ir.Var("VN")), a
    # array target with an expression value
    a2 = ir.lift_assign("NU(2,V_0AE0) = 0")
    assert a2 == ir.Assign(
        ir.ArrayRef("NU", (ir.Lit(2), ir.Var("V_0AE0"))), ir.Lit(0)
    ), a2
    # unknown-valued assignment (INPUT-sourced)
    a3 = ir.lift_assign("NN = ?")
    assert a3 == ir.Assign(ir.Var("NN"), ir.Unknown()), a3
    # round-trips back to the original BAS text
    assert ir.unparse_stmt(a2) == "NU(2,V_0AE0) = 0"
    # a non-assignment BAS line returns None (the adapter only models assignments here)
    assert ir.lift_assign("stmt_18") is None


if __name__ == "__main__":
    test_unparse_roundtrips_node_shapes()
    test_var_type_from_suffix()
    test_parse_expr()
    test_parse_rejects_trailing_garbage()
    test_lift_assign()
    print("ALL PASS")


def test_zero_arg_fncall_unparses_without_parens():
    # `DEF FNCurvideo` is declared with no parameter list and called as
    # `FNCurvideo`; Turbo Basic REJECTS `FNCurvideo()`, so the empty-parens
    # spelling produced source that would not recompile at all (t1_fnintarith).
    assert ir.unparse(ir.FnCall("FNFN1%", ())) == "FNFN1%"
    assert ir.unparse(ir.FnCall("FNFN1%", (ir.Lit(2),))) == "FNFN1%(2)"
