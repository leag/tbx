"""FCOMPP / variable-limit int FOR / string IF / LPRINT string+TAB / 2-arg
MID$ / PAINT tile / far by-ref compare -- PC-SIG wild-scan batch 3.
Also carries later single-gap closures (double arrays, LOCAL statement)."""

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


def test_decode_t1_local1():
    # LOCAL's zero-fill prologue (push cx/di; ...; rep stosw; pop di/cx, right
    # after proc_enter) declares a true per-call stack int, read/written via
    # plain [bp+d8] ModRM (not the by-ref `les si,[bp+N]` params use)
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_local1.exe"))
    sub = prog[0]
    assert isinstance(sub, ir.SubDef) and sub.params == ()
    assert sub.body[0] == ir.Local(("A%",))
    assert sub.body[1] == ir.Assign(
        ir.Var("A%"), ir.BinOp("+", ir.Var("A%"), ir.Lit(1))
    )
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n"
        "  LOCAL A%\n  A% = A% + 1\n  PRINT A%\nEND SUB\n"
        "20 CALL SUB1\n30 CALL SUB1\n40 END\n"
    )


def test_decode_t1_local2():
    # Multiple LOCAL ints (frame base = 6 + 4*nparams, right after the
    # by-ref param slots) + `26 03 04` = add ax,es:[si]: arithmetic fold of
    # a by-ref int param (distinct from the existing far_cmpax_si compare);
    # the LOCAL frame's own span also rides the retf pop-count alongside
    # the params, so nparams must subtract it back out
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_local2.exe")))
    assert src == (
        "10 SUB SUB1(A%)\n"
        "  LOCAL B%, C%\n  B% = A% + 1\n  C% = B% * 2\n"
        "  PRINT B%, C%\nEND SUB\n"
        "20 D% = 5\n30 CALL SUB1(D%)\n40 END\n"
    )


def test_decode_t1_byref1():
    # By-ref int SUB param fast-path family, all via `les si,[bp+N]; 26 <op>
    # es:[si]`: plain read into ax (26 8b 04), bitwise AND fold (26 23 04),
    # write ax back into the param (26 89 04), write a constant into the
    # param (26 c7 04 <imm16>), and FILD onto the FP stack for PRINT
    # (INT 3C; ESC DF /0 [si]) -- plus the plain bp-relative LOCAL int read
    # (8b 46 <d8>) needed to copy one LOCAL into the param
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_byref1.exe")))
    assert src == (
        "10 SUB SUB1(A%)\n"
        "  LOCAL B%, C%, D%\n"
        "  B% = A%\n  C% = A% AND 5\n  D% = A% + 1\n"
        "  A% = 9\n  A% = B%\n"
        "  PRINT B%, C%, D%, A%\nEND SUB\n"
        "20 E% = 7\n30 CALL SUB1(E%)\n40 PRINT E%\n50 END\n"
    )


def test_decode_t1_incr1():
    # Bare INC [disp16] (FF /0) outside a FOR context is the INCR
    # normalization: `X% = X% + 1`, distinct from the FOR-NEXT step use of
    # the exact same opcode
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_incr1.exe")))
    assert src == "10 A% = 5\n20 A% = A% + 1\n30 PRINT A%\n40 END\n"


def test_decode_t1_poolrun():
    # Scalar band ending exactly on a paragraph boundary: the pool marker sits
    # at a movsi-referenced cell (the pooled "" literal doubles as the marker
    # record), so the greedy scalar walk runs away through the pool descriptors
    # and the no-prompt INPUT's marker-cell prompt rejects the layout; the
    # solver retries with the walk cut at 16-aligned string positions
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_poolrun.exe")))
    assert src == (
        '10 A$ = ""\n20 B$ = "HELLO"\n30 C$ = A$ + B$\n'
        "40 INPUT D$\n50 PRINT C$; D$\n60 END\n"
    )


def test_decode_t1_decr1():
    # Bare DEC [disp16] (FF /1): the DECR normalization, `X% = X% - 1`
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_decr1.exe")))
    assert src == "10 A% = 5\n20 A% = A% - 1\n30 PRINT A%\n40 END\n"


def test_decode_t1_sstat():
    # Static STRING array element at a constant index (`A$(2) = ...`): the
    # element movsi disp falls inside the array's span, not a scalar slot
    # or a pooled-literal descriptor -- layout.finish's descriptor check now
    # exempts movsi disps landing in a static string array's span, and the
    # rt-0x9C push leg now routes such disps through state.loc() (which
    # already resolved array spans generally) instead of treating them as
    # pooled literals
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_sstat.exe")))
    assert src == (
        '10 DIM V0$(5)\n20 V0$(2) = "HI"\n30 A$ = V0$(2)\n40 PRINT A$\n50 END\n'
    )


def test_decode_t1_run2():
    # RUN file$ (EC sub C4): loads and runs a different program -- distinct
    # from bare RUN's raw jmp-to-start (byte ff family closed it, this is a
    # separate INT EC statement dispatch, push + pop off sstack like CHAIN)
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_run2.exe"))
    assert prog[0] == ir.Run(ir.StrLit("X.BAS"))
    assert emit0.emit(prog) == '10 RUN "X.BAS"\n'


def test_decode_t1_byref2():
    # 26 F7 2C = imul word es:[si]: multiplicative fold of a by-ref int SUB
    # param (`A% * B%` with both params by-ref), alongside the pre-existing
    # far_addax_si/far_andax_si/far_cmpax_si folds for the same `les
    # si,[bp+N]; 26 <op> es:[si]` family
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_byref2.exe")))
    assert src == (
        "10 SUB SUB1(A%, B%)\n"
        "  C% = A% * B%\n  PRINT C%\nEND SUB\n"
        "20 D% = 3\n30 E% = 4\n40 CALL SUB1(D%,E%)\n50 END\n"
    )


def test_decode_t1_forstep():
    # 83 06 = add word [disp16], imm8: the integer FOR-NEXT increment for a
    # literal STEP other than +-1 (those use inc_m/dec_m instead). A literal
    # limit AND a literal non-+-1 step both fold directly into their
    # instructions (cmp_mi8 / addm_i8), so NEITHER temp word gets evidence --
    # both reserved words before I% are phantom (walk_run's existing single-
    # phantom bridge only covered one; this needed a second)
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_forstep.exe"))
    assert prog[0] == ir.For(ir.Var("A%"), ir.Lit(1), ir.Lit(100), ir.Lit(10))
    assert emit0.emit(prog) == (
        "10 FOR A% = 1 TO 100 STEP 10\n20 PRINT A%\n30 NEXT A%\n40 END\n"
    )


def test_decode_t1_forstepn():
    # Same addm_i8 fast path with a NEGATIVE literal step (imm8 sign-
    # extended): the loop-continuation test flips to JGE (0x7D) instead of
    # JLE/JBE, the signed-comparison mirror of the ascending case
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_forstepn.exe"))
    assert prog[0] == ir.For(ir.Var("A%"), ir.Lit(100), ir.Lit(1), ir.Lit(-10))
    assert emit0.emit(prog) == (
        "10 FOR A% = 100 TO 1 STEP -10\n20 PRINT A%\n30 NEXT A%\n40 END\n"
    )


def test_decode_t1_forbig():
    # 81 3E = cmp word [disp16], imm16: the int FOR-NEXT limit test when the
    # limit doesn't fit a signed imm8 (cmp_mi8's range), needed on both the
    # FOR-header recognition side and the NEXT-side test/jcc guard; paired
    # here with a literal STEP (addm_i8) to cover both fixes together
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_forbig.exe"))
    assert prog[0] == ir.For(ir.Var("A%"), ir.Lit(1), ir.Lit(200), ir.Lit(18))
    assert emit0.emit(prog) == (
        "10 FOR A% = 1 TO 200 STEP 18\n20 PRINT A%\n30 NEXT A%\n40 END\n"
    )


def test_decode_t1_addimm():
    # 01 06 = add [disp16], ax: the disp16 sibling of addm_ax_bp (t1_local1's
    # LOCAL combine-store) -- `X% = X% + <expr>` when the RHS isn't a bare
    # literal 1 (no INCR fast path applies), materializing the RHS into ax
    # first and folding the store back with ADD instead of a separate
    # load/add/MOV
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_addimm.exe")))
    assert src == "10 A% = 5\n20 A% = A% + 3\n30 PRINT A%\n40 END\n"


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
    test_decode_t1_local1()
    test_decode_t1_local2()
    test_decode_t1_byref1()
    test_decode_t1_incr1()
    test_decode_t1_poolrun()
    test_decode_t1_decr1()
    test_decode_t1_sstat()
    test_decode_t1_run2()
    test_decode_t1_byref2()
    test_decode_t1_forstep()
    test_decode_t1_forstepn()
    test_decode_t1_forbig()
    test_decode_t1_addimm()
    print("ALL PASS")
