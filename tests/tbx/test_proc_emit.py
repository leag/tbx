"""Block emit for SubDef / CallStmt / DefFn."""

from tbx import emit0, ir


def test_emit_sub_block_and_call():
    stmts = [
        ir.SubDef("SUB1", (), (ir.Print((ir.StrLit("HI"),)),)),
        ir.CallStmt("SUB1", ()),
    ]
    assert emit0.emit(stmts) == '10 SUB SUB1\n  PRINT "HI"\nEND SUB\n20 CALL SUB1\n'


def test_emit_sub_with_params_and_call_args():
    stmts = [
        ir.SubDef("SUB1", ("A", "B"), (ir.Print((ir.Var("A"), ir.Var("B"))),)),
        ir.CallStmt("SUB1", (ir.Lit(7), ir.Lit(9))),
    ]
    assert (
        emit0.emit(stmts)
        == "10 SUB SUB1(A, B)\n  PRINT A; B\nEND SUB\n20 CALL SUB1(7,9)\n"
    )


def test_emit_opaque_helper_as_inline_payload():
    raw = b"\x55\x8b\xec\x5d\xcb"
    stmts = [ir.SubDef("SUB1", ("A",), (ir.OpaqueHelper(raw),))]
    assert emit0.emit(stmts) == (
        "10 SUB SUB1 INLINE\n"
        "  $INLINE &H55, &H8B, &HEC, &H5D\n"
        "END SUB\n"
    )


def test_emit_inline_deffn_and_fncall():
    stmts = [
        ir.DefFn("FNFN1", ("A",), ir.BinOp("*", ir.Var("A"), ir.Lit(2))),
        ir.Print((ir.FnCall("FNFN1", (ir.Lit(21),)),)),
    ]
    assert emit0.emit(stmts) == "10 DEF FNFN1(A) = A * 2\n20 PRINT FNFN1(21)\n"
