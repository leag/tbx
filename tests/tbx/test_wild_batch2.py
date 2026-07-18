"""Bare CLOSE / KEY n,s$ / PRINT commas / string USING / cmp ax,bx --
the second PC-SIG wild-scan batch (EC subs 16/58, INT C1/CC, byte 3B C3)."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_close():
    # EC sub 16: bare CLOSE (all channels), zero operands
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_close.exe"))
    assert prog[2] == ir.Close(None)


def test_decode_t1_key():
    # EC sub 58: KEY n, s$ -- n in ax, macro on the string stack
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_key.exe"))
    assert prog[0] == ir.KeyDef(
        L(1), ir.BinOp("+", ir.StrLit("DIR"), ir.Call("CHR$", (L(13),)))
    )
    assert prog[1] == ir.Key(True)
    assert prog[2] == ir.KeyDef(L(2), ir.StrLit("X"))
    assert prog[3] == ir.Key(False)


def test_decode_t1_pcomma():
    # INT C1: comma zone advance between items; a trailing comma leaves the
    # chain open, so `PRINT "Z", : PRINT "W"` normalizes to one statement
    # (byte-identical, like DATA regrouping)
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_pcomma.exe"))
    assert prog[1] == ir.Print(
        (ir.StrLit("X"), ir.StrLit("Y"), ir.Var("A$")),
        commas=(0, 1, 1, 0),
    )
    assert prog[2] == ir.Print((L(1), L(2)), commas=(0, 1, 0))
    assert prog[3] == ir.Print(
        (ir.StrLit("Z"), ir.StrLit("W")), commas=(0, 1, 0)
    )


def test_decode_t1_using():
    # INT CC: string item inside a PRINT USING chain (CB stays numeric)
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_using.exe"))
    b = ir.Var("B$")
    assert prog[4] == ir.PrintUsing(ir.StrLit("\\ \\ !"), (b, b))


def test_decode_t1_cmpax():
    # 3B C3 = cmp ax,bx: source RHS evaluates first into bx, LHS in ax; the
    # signed Jcc rows of _JCC_RELOP carry the relop
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_cmpax.exe"))
    la = ir.Call("LEN", (ir.Var("A$"),))
    lb = ir.Call("LEN", (ir.Var("B$"),))
    assert prog[2].cond == ir.RelOp("<>", la, lb)
    assert prog[4].cond == ir.RelOp(
        "<=", ir.Call("INSTR", (ir.Var("A$"), ir.StrLit("B"))), lb
    )


def test_emit_batch2():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_pcomma.exe"))) == (
        '10 A$ = "AB"\n20 PRINT "X", "Y", A$\n30 PRINT 1, 2\n'
        '40 PRINT "Z", "W"\n50 END\n'
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_close.exe"))) == (
        '10 OPEN "O",#1,"A.TXT"\n20 PRINT #1, "X"\n30 CLOSE\n40 END\n'
    )


if __name__ == "__main__":
    test_decode_t1_close()
    test_decode_t1_key()
    test_decode_t1_pcomma()
    test_decode_t1_using()
    test_decode_t1_cmpax()
    test_emit_batch2()
    print("ALL PASS")
