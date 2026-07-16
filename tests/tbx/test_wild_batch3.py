"""FCOMPP / variable-limit int FOR / string IF / LPRINT string+TAB / 2-arg
MID$ / PAINT tile / far by-ref compare -- PC-SIG wild-scan batch 3."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_fcmp():
    # FCOMPP (ESC DE D9): both relational sides FP-computed; LHS pushes
    # first, so ST0-vs-ST1 flags keep the reversed FP jcc orientation
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_fcmp.exe"))
    a, b = ir.Var("A"), ir.Var("B")
    assert prog[2].cond == ir.RelOp(
        "<=", ir.BinOp("+", a, L(1)), ir.BinOp("*", b, L(2))
    )
    assert prog[4].cond == ir.RelOp(
        "<>", ir.BinOp("*", a, a), ir.BinOp("+", b, L(1))
    )


def test_decode_t1_fori():
    # 39 06 = cmp [I%],ax: the integer FOR test with a VARIABLE limit
    # (`mov ax,[limit]; cmp [I%],ax; jle body`)
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_fori.exe"))
    assert prog[1] == ir.For(ir.Var("B%"), L(1), ir.Var("A%"), L(1))
    assert prog[3] == ir.NextStmt(ir.Var("B%"))


def test_decode_t1_strif():
    # INT 9A outside SELECT CASE: string relational IF; flags are FORWARD
    # (lhs cmp rhs), riding _JCC_RELOP_STR
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_strif.exe"))
    a, b = ir.Var("A$"), ir.Var("B$")
    assert prog[2].cond == ir.RelOp("<>", a, b)
    assert prog[4].cond == ir.RelOp(">=", a, ir.StrLit("M"))


def test_decode_t1_lpstr():
    # INT BF = LPRINT string item (BC stays numeric); a bare LPRINT is a
    # lone B9 flush
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_lpstr.exe"))
    assert prog[0] == ir.Lprint((ir.StrLit("HELLO"),))
    assert prog[2] == ir.Lprint((ir.Var("A$"), ir.StrLit("Y")))
    assert prog[3] == ir.Lprint(())


def test_decode_t1_ltab():
    # INT C8/C5 = the printer legs of TAB/SPC
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_ltab.exe"))
    assert prog[0] == ir.Lprint((ir.Call("TAB", (L(5),)), ir.StrLit("X")))
    assert prog[1] == ir.Lprint((ir.Call("SPC", (L(3),)), ir.StrLit("Y")))


def test_decode_t1_mid2():
    # INT B0 = 2-arg MID$(s$, start): s$ on the sstack, start in ax
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_mid2.exe"))
    a = ir.Var("A$")
    assert prog[2] == ir.Assign(
        ir.Var("C$"), ir.Call("MID$", (a, ir.Var("B%")))
    )
    assert prog[3] == ir.Assign(ir.Var("D$"), ir.Call("MID$", (a, L(4))))


def test_decode_t1_paintt():
    # EC sub DC = PAINT with a tile string: tile$ on the sstack, flag bit
    # 01 = border in cell [0x94]
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_paintt.exe"))
    assert prog[1] == ir.Paint(
        L(10), L(10), ir.Call("CHR$", (L(85),)), L(1)
    )


def test_decode_t1_dblarr():
    # DC /3 FCOMP m64 direct outside SELECT CASE (double scalar as the mem
    # side of an FP IF) + runtime-DIM type byte 06: the slot names '#' from
    # birth so the recompile keeps 8-byte elements
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_dblarr.exe")))
    assert "DIM V0#(5)" in src
    assert "IF B# <= V0#(A) THEN" in src


def test_decode_t1_dblar2():
    # DC /3 FCOMP m64 [si]: double ARRAY ELEMENT as the mem side of an FP IF
    # (source `IF A#(I) > X# THEN`; renders negated as a skip-goto, same
    # convention as test_decode_t1_dblarr)
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_dblar2.exe")))
    assert "IF V0#(A) <= B# THEN" in src


def test_decode_t1_cmpfar():
    # 26 3B 04 = cmp ax,es:[si]: relational value against a by-ref integer
    # SUB param; the far read types the param slot as '%'
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_cmpfar.exe")))
    assert "SUB SUB1(A%)" in src
    assert "B% = A% = 1" in src


if __name__ == "__main__":
    test_decode_t1_fcmp()
    test_decode_t1_fori()
    test_decode_t1_strif()
    test_decode_t1_lpstr()
    test_decode_t1_ltab()
    test_decode_t1_mid2()
    test_decode_t1_paintt()
    test_decode_t1_dblarr()
    test_decode_t1_dblar2()
    test_decode_t1_cmpfar()
    print("ALL PASS")
