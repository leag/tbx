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


def test_decode_wild_banker_nonadjacent_for():
    # banker.exe uses the x87 sign-test FOR template with limit/step/loop
    # slots that are not the usual v-4/v-8 neighbors.  Keep the corpus hit as
    # a regression witness rather than allowing the generic testw handler to
    # drift back to an unhandled opcode.
    from tbx import decode0

    exe = open(os.path.join(_ROOT, "..", "wild", "hits", "banker.exe"), "rb").read()
    prog = decode0.decode_user_code(exe)
    loops = [s for s in prog if isinstance(s, ir.For)]
    assert any(
        isinstance(s.limit, ir.BinOp)
        and s.limit.op == "-"
        and s.limit.lhs == ir.Lit(66)
        for s in loops
    )


def test_scan_wild_far_jump_group():
    # Seven runtime-revision wild binaries use EA far transfers.  The scanner
    # must preserve their rebased target (or the fixed zero-offset handoff)
    # instead of stopping at the raw x86 byte; later decoder failures are
    # separate, file-specific gaps.
    from tbx import decode0

    cases = (
        ("elec87.exe", 5),
        ("electron.exe", 5),
        ("mcmurphy.exe", 0),
        ("mf.exe", 8),
        ("sabpcv3.exe", 0),
        ("swbb.exe", 0),
        ("wb.exe", 3),
    )
    for name, count in cases:
        exe = open(os.path.join(_ROOT, "..", "wild", "hits", name), "rb").read()
        start, dialect = decode0.find_prologue(exe)
        ops = decode0._scan(exe, start, dialect, set())
        assert sum(op[1] == "jmpf" for op in ops) == count
        assert ops[-1][1] == "epilogue"


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


def test_decode_t1_svaridx():
    # Static STRING array element at a VARIABLE (computed) index used as a
    # string value (PRINT item here): the shl-si/addsi element-access chain
    # ends in `rt 0x9C` (push var desc) rather than one of the fld_si/
    # fstp_si/strassign/far_spush terminals int_alu already recognized --
    # same push-then-consume shape as the constant-index case (core.py's
    # movsi + rt-0x9C), just reached via a computed si. Only the push is
    # consumed; the following op (PRINT's own rt-0xBE item-eval here) runs
    # through the ordinary dispatch loop off the sstack push, unchanged.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_svaridx.exe")))
    assert src == (
        '10 DIM V0$(20)\n20 V0$(3) = "HELLO"\n30 A = 3\n40 PRINT V0$(A)\n50 END\n'
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


def test_decode_t1_forvarstep():
    # Computed (variable) STEP: the step's sign is unknown at compile time,
    # so the header copies the step expression into a temp cell (`mov
    # ax,step-expr; mov [temp],ax; mov [I%],init; mov ax,[temp]; jmp test`)
    # and the continuation test at `test` runs a runtime `or ax,ax; jns`
    # sign check that picks between two otherwise-identical ascending
    # (JLE/JBE) / descending (JGE) `cmp [I%],limit; jcc body` blocks --
    # wild menu.exe/stat.exe. This fixture uses the DIRECT (short-jcc) form
    # of both blocks; t1_forvarstep2 covers the indirect (far-body) form.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_forvarstep.exe"))
    assert prog[0] == ir.Assign(ir.Var("A%"), ir.Lit(2))
    assert prog[1] == ir.For(ir.Var("B%"), ir.Lit(1), ir.Lit(10), ir.Var("A%"))
    assert emit0.emit(prog) == (
        "10 A% = 2\n20 FOR B% = 1 TO 10 STEP A%\n30 PRINT B%\n40 NEXT B%\n50 END\n"
    )


def test_decode_t1_forvarstep2():
    # Same computed-STEP shape as t1_forvarstep, but with a body long enough
    # to force the INDIRECT (far-jump) form of both the ascending and
    # descending comparison blocks (inverse jcc skip + jmp, instead of a
    # direct short jcc to body) -- the same direct/indirect duality the
    # literal-step NEXT-side guard already has, now exercised for the
    # runtime-selected branch too.
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_forvarstep2.exe"))
    assert prog[0] == ir.Assign(ir.Var("A%"), ir.Lit(2))
    assert prog[1] == ir.For(ir.Var("B%"), ir.Lit(1), ir.Lit(10), ir.Var("A%"))
    assert prog[-2] == ir.NextStmt(ir.Var("B%"))


def test_decode_t1_for10arr():
    # Gap 16: a literal-limit FOR loop's variable + the ordinary scalars
    # allocated after it can land inside the LAST static array's own 0x36
    # ARR_BLOCK slot (that array's bookkeeping record is dead at runtime
    # once its constant-base addsi is compiled, so the compiler appears to
    # reuse the tail of its slot) -- find_statics's window, bounded at
    # `ds + sb`, cut off a few bytes short of the last record's populated
    # bytes whenever this reuse pushed the record run past that boundary;
    # widened by one ARR_BLOCK of slack (always < the largest reuse offset
    # witnessed, wild/probes_gap16/q_gap16{p,q,u}.bas: 32/48/32 bytes).
    # 10 static arrays is the smallest count this was witnessed to trigger
    # at (9 decodes clean; the reuse offset doesn't depend on array count
    # or on which array the loop happens to index, only on how much the
    # scalar band needs).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_for10arr.exe"))
    assert prog[17] == ir.For(ir.Var("H%"), ir.Lit(1), ir.Lit(6), ir.Lit(1))
    assert emit0.emit(prog) == (
        "10 DIM V0(20)\n20 DIM V1(20)\n30 DIM V2(20)\n40 DIM V3(20)\n"
        "50 DIM V4(20)\n60 DIM V5(20)\n70 DIM V6(20)\n80 DIM V7(20)\n"
        "90 DIM V8(20)\n100 DIM V9(20)\n110 A% = 1\n120 B% = 2\n"
        "130 C = 1.5\n140 D = 2.5\n150 E# = 3.5#\n160 F# = 4.5#\n"
        "170 G% = 3\n180 FOR H% = 1 TO 6\n190 V0(H%) = H%\n200 NEXT H%\n"
        "210 I% = V1(1) + V2(1) + V3(1) + V4(1) + V5(1) + V6(1) + V7(1) "
        "+ V8(1) + V9(1)\n"
        "220 PRINT A%, B%, C, G%, I%\n230 END\n"
    )


def test_decode_t1_strch():
    # A large-enough run of pooled string literals (260 here) chains the
    # per-literal descriptor table for well over 0x400 bytes past pool_base,
    # pushing the char-record's `(len|0x8000) 00 00 00 00 <chars> (len|0x8000)`
    # bracket outside the old fixed search window anchored at pool_base --
    # wild vhfprop.exe/inv87.exe/invoice.exe hit the same shape via a big
    # static string array's per-element descriptors chained into the same
    # table (469/513 entries). The search now anchors on `d`, which the
    # descriptor walk already leaves sitting just past the last matched
    # entry, rather than recomputing from pool_base.
    from tbx import decode0, emit0

    prog = decode0.decode_user_code(_exe("t1_strch.exe"))
    assert len(prog) == 261  # 260 PRINT + END
    lines = emit0.emit(prog).splitlines()
    assert lines[0] == '10 PRINT "S000"'
    assert lines[259] == '2600 PRINT "S259"'
    assert lines[260] == "2610 END"


def test_decode_t1_lpusing():
    # LPRINT USING (wild vhfprop.exe/inv87.exe/invoice.exe): the USING
    # emit's item vector is BF (printer) alongside the known BE console /
    # C0 file legs; a trailing-';' LPRINT chain also finalizes lazily like
    # console PRINT (the old code raised "LPRINT chain not flushed on b9"),
    # and B9 closes an open printer USING chain
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_lpusing.exe"))
    assert prog[2] == ir.Lprint((ir.Var("A$"),), newline=False)
    assert prog[3] == ir.PrintUsing(
        ir.StrLit("##.##"), (ir.Var("B"),), newline=False, lprint=True
    )
    assert emit0.emit(prog) == (
        '10 A$ = "AB"\n20 B = 1.5\n30 LPRINT A$;\n'
        '40 LPRINT USING "##.##"; B;\n50 LPRINT A$\n60 END\n'
    )


def test_decode_t1_errcmp():
    # IF ERR = n THEN <line>: cmpax_m against runtime cell [0074] (ERR;
    # [0072] = ERL, both already known to movax_m) in the direct-jcc IF
    # form -- cmpax_m previously ONLY had the relational-value form (movax
    # FFFF following); the IF forms consume their own jcc (+skip-jmp for
    # the forward spelling, wild inv87.exe), flags rhs-lhs REVERSED like
    # the FP rows and unlike cmpax_bx
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_errcmp.exe")))
    assert "60 IF ERR = 24 THEN 50" in src


def test_decode_t1_imulpool():
    # imul_m with a POOLED int-literal operand: `180 * (A > 0)` evaluates
    # the materialized right first, then multiplies the literal LEFT from
    # the const pool -- the same loc->pool_lit fallback addax_m got in gap
    # 34. ALSO pins popop's bare-emission rule for a first-pushed chain at
    # EQUAL precedence: `B * 2 - 1 + 180 * (A > 0)` must NOT respell
    # R-form, because the flipped textual order flips int-pool allocation
    # order (a 5-byte diff caught by oracle round-trip)
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_imulpool.exe")))
    assert "30 C = B * 2 - 1 + 180 * (A > 0)" in src


def test_decode_t1_cmppool():
    # cmpax_m with a POOLED int-literal LEFT operand: `IF 180 = LEN(A$)
    # THEN` pools the literal and compares it against the computed right
    # side -- the same loc->pool_lit fallback imul_m already has (gap 43),
    # cmpax_m was just missing it. Closed wild mymenu.exe fully; sabpcv3.exe
    # advances to a distinct, unrelated construct.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_cmppool.exe")))
    assert "20 IF 180 <> LEN(A$) THEN 40" in src


def test_decode_t1_cmpsival():
    # cmpax_si materialized as a VALUE, not a direct IF condition:
    # `B% = (A%(I%) = 5)` -- the shlsi element-access handler's cmpax_si
    # branch only recognized the IF-consumer forms (jcc+skip-jmp, bare
    # jcc); a following `movax 0xFFFF` (the generic boolean-value
    # materialization, control.py) had no witness for a computed array
    # element. Hands off to the same pend_cmp/movax-0xFFFF path the
    # scalar cmpax_m case already uses. Closed wild pfl.exe's blocker
    # (advances to a distinct gap); number.exe's own AND-chain shuffle
    # variant of this shape also now decodes past cmpax_si (advances
    # further too, to an unrelated "ax,bx combine with empty regs" gap).
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_cmpsival.exe")))
    assert "40 B% = (V0%(A%) = 5)" in src


def test_decode_t1_strgodo():
    # String direct conditional GOTO (`IF A$ = "X" THEN <line>`, backward
    # target): strcmp + bare jcc with no skip-jmp -- forward strcmp flags,
    # so the TRUE map is _JCC_RELOP_STR's inverse (wild schart.exe)
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_strgodo.exe")))
    assert '30 IF A$ = "X" THEN 10' in src


def test_decode_t1_ifgoto():
    # An IfInline whose body ends in a forward Goto normally block-folds into
    # IF/ELSE -- but when the would-be ELSE region contains a line that is a
    # jump target from anywhere (line 50 here, targeted by line 30's IF),
    # that reading is impossible in source (block-IF interiors aren't
    # addressable), so _fold_if now skips the fold and the statement emits as
    # `IF c THEN ...: GOTO n` with the region kept as separate lines.
    # The compound OR condition is what routes the outer IF through the
    # IfInline machinery (a simple string IF uses the direct-goto form and
    # never folds -- q_ifgoto1 witnessed that path decodes fine either way).
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_ifgoto.exe"))) == (
        "10 INPUT A$\n"
        '20 IF A$ = "T" OR A$ = "t" THEN CLS: GOTO 60\n'
        '30 IF A$ = "X" THEN 50\n'
        '40 PRINT "A"\n'
        '50 PRINT "B"\n'
        "60 END\n"
    )


def test_decode_t1_addpool():
    # addax_m folding a POOLED int literal as its LEFT operand: `15 - LEN(A$)`
    # evaluates the computed right first, negates, then `add ax,[disp16]`
    # where disp16 is a const-pool word, not a scalar slot -- addax_m
    # previously had no pool fallback (fpval/ifold already did). Also
    # surfaced the SECOND canonical_rename statement miss in a row (after
    # gap 31's ir.Color): ir.Locate's row/col/cursor were never walked, so
    # a V####$ placeholder leaked into LOCATE's col expression; an audit of
    # every stmt class against rn()'s isinstance checks confirms Locate and
    # Color were the only walkable-Expr statements missing.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_addpool.exe"))
    assert prog[1] == ir.Locate(
        ir.Lit(1),
        ir.BinOp("-", ir.Lit(15), ir.Call("LEN", (ir.Var("A$"),))),
    )
    assert emit0.emit(prog) == (
        '10 A$ = "AB"\n20 LOCATE 1,15 - LEN(A$)\n30 PRINT "X"\n40 END\n'
    )


def test_decode_t1_pcomma2():
    # PRINT commas LEADING the items (`PRINT ,,X`) and doubled (`PRINT A,,B`
    # skips a zone) -- wild schart.exe; ir.Print.commas migrated from
    # items-aligned bools to gap-aligned counts (len(items)+1 slots). The
    # trailing-comma form `PRINT A$,,` merges with the following statement's
    # items (identical bytes), so it canonicalizes to the merged spelling.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_pcomma2.exe"))
    assert prog[2] == ir.Print(
        (ir.Var("A$"), ir.Var("B$")), commas=(0, 2, 0)
    )
    assert prog[3] == ir.Print((ir.Var("A$"),), commas=(2, 0))
    assert emit0.emit(prog) == (
        '10 A$ = "A"\n20 B$ = "B"\n30 PRINT A$,, B$\n'
        '40 PRINT ,, A$\n50 PRINT A$,, B$\n60 END\n'
    )


def test_decode_t1_bigjmp():
    # GOTO/GOSUB spanning more than 32KB of code wrap around the 64KB code
    # segment (rel16 is signed; wild inv87.exe jumps +53KB early on): the
    # scan now normalizes e9/e8 targets into [start, start+64K). The fixture
    # is a 2800-statement filler with a wrapped forward GOTO and GOSUB.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_bigjmp.exe")))
    lines = src.splitlines()
    assert lines[0] == "10 GOSUB 28070"
    assert lines[1] == "20 GOTO 28050"
    assert lines[-4:] == [
        '28050 PRINT "OK"',
        "28060 END",
        '28070 PRINT "S"',
        "28080 RETURN",
    ]


def test_decode_t1_blkgoto():
    # GOTO into a block IF's interior: TB accepts a numbered line inside
    # IF..END IF as a jump target (wild inv87.exe). The inline-IF region
    # is forced to block form when a body statement's address is jump-
    # targeted, the short backward jmps lifts as Goto("addr"), the target
    # resolves to ir.BodyLine, and emit0 numbers just that physical line.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_blkgoto.exe")))
    assert src == (
        '10 A$ = "X"\n'
        '20 IF A$ <> "Q" THEN\n'
        '  PRINT "A"\n'
        '22 PRINT "B"\n'
        "END IF\n"
        '30 IF A$ = "X" THEN 50\n'
        "40 END\n"
        '50 A$ = "Q"\n'
        "60 GOTO 22\n"
    )


def test_decode_t1_miderr():
    # 3-arg MID$ decode clobbered DecodeState.start (`state.start = state.bx`
    # instead of a local), so any program that later needs the error-trap
    # line table crashed in _finalize with a Lit where the user-code start
    # address belongs (wild vhfprop.exe; it decodes fully after the fix).
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_miderr.exe")))
    assert src == (
        "10 ON ERROR GOTO 70\n"
        '20 A$ = MID$("ABCDE",2,3)\n'
        "30 PRINT A$\n"
        "40 ERROR 5\n"
        '50 PRINT "NO"\n'
        "60 END\n"
        "70 PRINT ERR\n"
        "80 RESUME 60\n"
    )


def test_decode_t1_strgoto():
    # _is_for_header crashed on three trailing STRING assigns before a GOTO
    # (wild inv87/invoice): vdisp can't parse the "$" placeholder suffix --
    # and consecutive string slots are ALSO 4 bytes apart, so merely teaching
    # vdisp "$" would risk false-positive FOR detection; string targets now
    # reject the header probe outright.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_strgoto.exe")))
    assert src == (
        '10 A$ = "A"\n20 B$ = "B"\n30 C$ = "C"\n40 GOTO 60\n'
        '50 PRINT "N"\n60 PRINT A$; B$; C$\n70 END\n'
    )


def test_decode_t1_orchain():
    # Integer relationals in a compound bool chain (vhfprop/inv87/invoice at
    # the "unhandled op orax" stop): `IF ERR = 25 OR ERR = 27 OR ERR = 57`
    # materializes each cmpax_m through the same 6-op template the FP
    # compound machinery lifts (movax FFFF; jcc; incax; orax; jcc; jmp) --
    # pend_icmp only knew the bare value form and left the orax unconsumed.
    # The fix hands the compare to pend_cmp when the comb op follows,
    # restricted to the orientation-neutral 74/75 codes (the signed
    # _JCC_RELOP_TRUE rows assume cmpax_bx's forward flag order).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_orchain.exe"))
    cond = ir.LogOp(
        "OR",
        ir.LogOp(
            "OR",
            ir.RelOp("=", ir.Err(), ir.Lit(25)),
            ir.RelOp("=", ir.Err(), ir.Lit(27)),
        ),
        ir.RelOp("=", ir.Err(), ir.Lit(57)),
    )
    assert prog[5] == ir.IfInline(
        cond,
        (
            ir.Print((ir.StrLit("Y"),), newline=True, file=None, commas=None),
            ir.Print((ir.StrLit("Z"),), newline=True, file=None, commas=None),
        ),
    )
    assert emit0.emit(prog) == (
        "10 ON ERROR GOTO 60\n"
        "20 ERROR 25\n"
        '30 PRINT "NO"\n'
        "40 END\n"
        '50 PRINT "X"\n'
        '60 IF ERR = 25 OR ERR = 27 OR ERR = 57 THEN PRINT "Y": PRINT "Z"\n'
        "70 RESUME 40\n"
    )


def test_decode_t1_andchain():
    # Integer relationals in a compound AND chain (wild schart.exe at the
    # "cmpax_m without a value/IF consumer" stop): unlike an OR chain
    # (t1_orchain), which resolves by pure short-circuit jumps, an AND
    # chain's 2nd+ term genuinely combines via `and ax,bx` -- the running
    # accumulator lives in bx, and the compiler round-trips ax<->bx (mov
    # ax,bx; mov bx,ax, a byte-exact no-op restoring bx) between the
    # compare and the value materialization. cmpax_m's value-form guard now
    # also recognizes that shuffled lookahead, not just a bare movax FFFF.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_andchain.exe"))
    cond = ir.LogOp(
        "AND",
        ir.LogOp(
            "AND",
            ir.RelOp("=", ir.Err(), ir.Lit(25)),
            ir.RelOp("=", ir.Err(), ir.Lit(27)),
        ),
        ir.RelOp("=", ir.Err(), ir.Lit(57)),
    )
    assert prog[5] == ir.IfInline(
        cond,
        (
            ir.Print((ir.StrLit("Y"),), newline=True, file=None, commas=None),
            ir.Print((ir.StrLit("Z"),), newline=True, file=None, commas=None),
        ),
    )
    assert emit0.emit(prog) == (
        "10 ON ERROR GOTO 60\n"
        "20 ERROR 25\n"
        '30 PRINT "NO"\n'
        "40 END\n"
        '50 PRINT "X"\n'
        '60 IF ERR = 25 AND ERR = 27 AND ERR = 57 THEN PRINT "Y": PRINT "Z"\n'
        "70 RESUME 40\n"
    )


def test_decode_t1_dataorph():
    # A codeless DATA statement with no READ/RESTORE anywhere in the program
    # (wild vhfprop.exe: the error-trap line table shows an "orphan" entry
    # -- a code offset shared by TWO OR MORE table rows, since a codeless
    # statement borrows whatever real code follows it -- but READ/RESTORE
    # was the ONLY trigger _read_data_pool had, so vhfprop's DATA silently
    # vanished from the IR entirely). Two same-line DATA statements now
    # trigger recovery from that orphan evidence alone; the item/statement
    # split point is unrecoverable from the pool (probe q_lt4 confirmed
    # `DATA 1: DATA 2,3,4` byte-for-byte equals `DATA 1,2: DATA 3,4`) so
    # every statement but the last gets exactly one item. DATA also
    # compiles in TEXTUAL order, not pool order (probe q_lt3): it's
    # repositioned to sit immediately before the statement whose offset it
    # borrowed, not unconditionally prepended.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_dataorph.exe"))
    assert getattr(prog, "lines", None) == [10, 10, 20, 20, 30, 40]
    assert prog[2] == ir.Data((ir.DataItem("1", False),))
    assert prog[3] == ir.Data(
        (ir.DataItem("2", False), ir.DataItem("3", False), ir.DataItem("4", False))
    )
    assert emit0.emit(prog) == (
        "10 A% = ERR: B% = ERL\n"
        "20 DATA 1: DATA 2,3,4\n"
        "30 A% = 2\n"
        "40 END\n"
    )


def test_decode_t1_dimorph():
    # A static array's DIM is codeless too (recovered from array bookkeeping
    # records, not a scanned op) and is normally repositioned to a canonical
    # spot right after any SUB/DEF FN bodies -- fine under free renumbering,
    # but wrong once the error-trap line table makes DIM's own line
    # byte-significant (wild vhfprop.exe: two static arrays, both showing
    # up as a matching pair of orphan table entries, both on line 500).
    # `len(dims) == len(data_orphan_lines)` in a single cluster repositions
    # + relines them at the table's evidence instead.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_dimorph.exe"))
    assert getattr(prog, "lines", None) == [10, 10, 20, 20, 20, 30, 40]
    assert prog[3] == ir.Dim("V0", (30,))
    assert prog[4] == ir.Dim("V1$", (5,))
    assert emit0.emit(prog) == (
        "10 A% = ERR: B% = ERL\n"
        '20 C$ = "N": DIM V0(30): DIM V1$(5)\n'
        "30 V0(1) = 25\n"
        "40 END\n"
    )


def test_decode_t1_color3():
    # COLOR's third argument (border) -- wild r.exe/book.exe at "COLOR mask
    # 07 != cells 06 (+{160: ...})": color_commit's mask bit 0x01 (border)
    # was unhandled, only fg(0x04)/bg(0x02) were ever popped from
    # state.color_cells, leaving cell 0xA0 unaccounted whenever a program
    # used the 3-argument form (`COLOR fg,bg,border`, GW-BASIC-style CGA
    # border color). ir.Color gained a `border` field; render.py builds the
    # comma list up to the highest set argument, matching how it already
    # skips a bare fg-only or fg,bg form.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_color3.exe"))
    assert prog[0] == ir.Color(ir.Lit(1), ir.Lit(2), ir.Lit(3))
    assert emit0.emit(prog) == "10 COLOR 1,2,3\n20 END\n"


def test_decode_t1_nestif2():
    # A GOTO into a NUMBERED line two block-IF levels deep (wild inv87.exe/
    # invoice.exe at "jump target ... is not a statement start", the
    # LINE-TABLE EPIC's remaining sub-problem): gap 51 only reached a
    # single-arm block IF's DIRECT body (ir.BodyLine(top_idx, phys), phys
    # counted flat via k+1). A target nested inside an IF-within-an-IF hits
    # three compounding gaps, all fixed together: (1) `_fold_body_ifgotos`
    # discarded the consumed IfGoto's own recorded address when negating it
    # into the replacement IfInline, orphaning stmt_addr's id-based lookup
    # for anything AT that position; (2) `_fold_if`/`_fold_body`'s "second
    # leg" (the block-IF-needed-for-addressability trigger) only checked
    # DIRECT body children for a jump target, not recursively through a
    # still-inline nested IF -- `_body_has_target` fixed that; (3)
    # `_resolve_targets`'s BodyLine walk was single-level only -- it now
    # recurses into a nested single-arm no-else IfBlock, whose own header +
    # body + END IF are fully accounted for (so flat counting can safely
    # continue past it, unlike the other multi-line cases it still can't
    # measure). Also surfaced a FOURTH, independent gap in emit0's free
    # line-renumbering: a fixed 10-line stride can't fit a deep BodyLine
    # phys, so the stride is now widened only for statements that need it.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_nestif2.exe"))
    assert prog[2] == ir.IfBlock(
        (
            (
                ir.RelOp("<>", ir.Var("A$"), ir.StrLit("Q")),
                (
                    ir.IfBlock(
                        (
                            (
                                ir.RelOp("<>", ir.Var("B$"), ir.StrLit("R")),
                                (
                                    ir.Print(
                                        (ir.StrLit("A"),),
                                        newline=True,
                                        file=None,
                                        commas=None,
                                    ),
                                    ir.Print(
                                        (ir.StrLit("B"),),
                                        newline=True,
                                        file=None,
                                        commas=None,
                                    ),
                                ),
                            ),
                        ),
                        else_body=None,
                    ),
                ),
            ),
        ),
        else_body=None,
    )
    assert prog[6] == ir.Goto(ir.BodyLine(stmt=2, phys=3))
    assert emit0.emit(prog) == (
        '10 A$ = "X"\n'
        '20 B$ = "Y"\n'
        '30 IF A$ <> "Q" THEN\n'
        '  IF B$ <> "R" THEN\n'
        '    PRINT "A"\n'
        "33 PRINT \"B\"\n"
        "  END IF\n"
        "END IF\n"
        "40 IF A$ = \"X\" THEN 60\n"
        "50 END\n"
        '60 A$ = "Q"\n'
        "70 GOTO 33\n"
    )


def test_decode_t1_gotoerr():
    # A bare backward jmps with no head-test frame is ALWAYS canonicalized
    # to synthesized `DO ... LOOP` (core.py's "bare backward jmps =
    # infinite DO"), since an explicit DO and a plain `<n> ... GOTO <n>`
    # compile to byte-identical code -- fine under free renumbering, but
    # DO gets its OWN codeless line-table entry (like DATA/DIM) that a
    # plain GOTO loop never had, so canonicalizing to DO once a line table
    # is active can recompile with an extra entry the original never had
    # (wild vhfprop.exe: two such loops, neither with orphan evidence).
    # When the table shows no orphan at the loop body's borrowed offset,
    # the synthesized Do/bare-Loop pair is un-synthesized back to a plain
    # Goto instead.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_gotoerr.exe"))
    assert not any(isinstance(s, ir.Do) for s in prog)
    assert prog[4] == ir.Goto(3)
    assert emit0.emit(prog) == (
        "10 A% = ERR: B% = ERL\n20 C% = 0\n30 C% = C% + 1\n40 GOTO 30\n"
    )


def test_decode_t1_doerr():
    # Companion to t1_gotoerr: a GENUINE `DO...LOOP` (explicit in source)
    # DOES leave its own orphan entry at the body's offset, so the
    # un-synthesis in test_decode_t1_gotoerr must NOT fire here -- the Do
    # stays, and gets its own line assigned from that orphan evidence
    # (same mechanism as DATA/DIM's orphan-driven line recovery).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_doerr.exe"))
    assert prog[3] == ir.Do(None)
    assert prog[5] == ir.Loop(None)
    assert getattr(prog, "lines", None) == [10, 10, 20, 30, 40, 50]
    assert emit0.emit(prog) == (
        "10 A% = ERR: B% = ERL\n20 C% = 0\n30 DO\n40 C% = C% + 1\n50 LOOP\n"
    )


def test_decode_t1_arrwrite():
    # A computed (variable) index write to a static INTEGER array element
    # (wild number.exe at "unhandled byte 89"): the shl-si/addsi element-
    # access chain's terminal-consumer dispatch (arith.py) already handled
    # the FP load/store, comparison, and string-value cases -- and gap 32
    # added the string READ (`rt 0x9C` push) -- but the raw integer STORE
    # `mov [si], ax` (no ES prefix; `26 89 04` is the by-ref-param FAR
    # sibling, already scanned) was never recognized at the scan level at
    # all. New op `movm_ax_si`; the array-index dispatch's existing
    # `pre + "..."` far/near naming convention picks up the by-ref-param
    # FAR form for free once the near form is wired in.
    #
    # A SEPARATE, more fundamental gap surfaced building this fixture: an
    # earlier version used a default-typed (SINGLE) array, which needs TWO
    # `shl si,1` for its 4-byte stride -- the shlsi handler's own gate
    # unconditionally required a second shl, so it never actually reached
    # this new code (a 2-byte INTEGER element's computed index needs only
    # ONE shl). The gate now accepts 1, 2, or 3 consecutive shl si
    # depending on element size, so this fixture (and t1_arrread) use a
    # genuine INTEGER array with an all-computed-index read/write to
    # actually exercise the new near-si ops end to end.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_arrwrite.exe"))
    assert prog[2] == ir.Assign(
        ir.ArrayRef("V0%", (ir.Var("A"),)), ir.Lit(42)
    )
    assert emit0.emit(prog) == (
        "10 DIM V0%(10)\n20 A = 3\n30 V0%(A) = 42\n40 B = 3\n"
        "50 PRINT V0%(B)\n60 END\n"
    )


def test_decode_t1_arrread():
    # Companion to t1_arrwrite: the READ half. `mov ax, [si]` (no ES
    # prefix; `26 8b 04` is the by-ref-param FAR sibling, already scanned
    # as far_movax_si) -- wild number.exe advances here right after the
    # write fix. New op `movax_si`; ax becomes the array-element value,
    # e.g. as an expression's first term. The `+ 1` also needed a THIRD
    # new op, `addax_si` (`add ax, [si]`, near sibling of far_addax_si) --
    # arith.py's array-index dispatch didn't have an arithmetic-fold
    # branch for a computed element at all before this.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_arrread.exe"))
    assert prog[4] == ir.Assign(
        ir.Var("C%"),
        ir.BinOp("+", ir.ArrayRef("V0%", (ir.Var("B"),)), ir.Lit(1)),
    )
    assert emit0.emit(prog) == (
        "10 DIM V0%(10)\n20 A = 3\n30 V0%(A) = 42\n40 B = 3\n"
        "50 C% = V0%(B) + 1\n60 PRINT C%\n70 END\n"
    )


def test_decode_t1_arrcmp():
    # Companion to t1_arrwrite/t1_arrread: the relational half. `cmp ax,
    # [si]` (no ES prefix; `26 3b 04` is the by-ref-param FAR sibling,
    # already scanned as far_cmpax_si) -- a FOURTH new op, `cmpax_si`,
    # completing the computed-static-int-array-element family (wild
    # number.exe). Same (mem, ax) reversed-flag orientation as cmpax_m;
    # only the IF forms are witnessed (here: jcc+skip-jmp).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_arrcmp.exe"))
    assert prog[4] == ir.IfGoto(
        ir.RelOp("<>", ir.ArrayRef("V0%", (ir.Var("B"),)), ir.Lit(42)), 7
    )
    assert emit0.emit(prog) == (
        "10 DIM V0%(10)\n20 A = 3\n30 V0%(A) = 42\n40 B = 3\n"
        '50 IF V0%(B) <> 42 THEN 80\n60 PRINT "YES"\n70 GOTO 90\n'
        '80 PRINT "NO"\n90 END\n'
    )


def test_decode_t1_subm():
    # `sub [disp16],ax` (byte 29 /6, wild number.exe at 0xb713) -- the
    # subtract sibling of addm_ax's `add [disp16],ax` (byte 01 /6), for a
    # compound `X% = X% - <expr>` where the store target coincides with
    # the left operand. Same disp16-direct addressing, mirrored handler.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_subm.exe"))
    assert prog[2] == ir.Assign(
        ir.Var("A%"), ir.BinOp("-", ir.Var("A%"), ir.Var("B%"))
    )
    assert emit0.emit(prog) == (
        "10 A% = 100\n20 B% = 5\n30 A% = A% - B%\n40 PRINT A%\n50 END\n"
    )


def test_decode_t1_arrswap():
    # SWAP of two computed static-int-array elements (wild number.exe at
    # 0xb8b9): the compiler can't XCHG two memory operands directly, so it
    # spills DS to a scratch cell (movm_ds, `mov [disp16],ds`) while the
    # first operand's index chain is still live in SI, computes the second
    # operand's address, then restores DS into ES from that scratch cell
    # (moves_m) so BOTH computed near addresses are reachable via an
    # ES-aliased `[bx]`/`[si]` pair: `mov bx,ax` (movbxax, new 8B D8
    # encoding of the same instruction already used for LOCATE row) / `mov
    # ax,es:[bx]` (far_movax_bx) / `xchg ax,[si]` (xchgsi) / `mov
    # es:[bx],ax` (far_movm_ax_bx). shlsi's consumer dispatch stages the
    # first ArrayRef on `state.pend_swap` at the movm_ds op and folds both
    # refs into ir.Swap once the second chain's moves_m + fixed tail land.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_arrswap.exe"))
    assert prog[5] == ir.Swap(
        ir.ArrayRef("V0%", (ir.Var("A"),)), ir.ArrayRef("V0%", (ir.Var("B"),))
    )
    assert emit0.emit(prog) == (
        "10 DIM V0%(10)\n20 V0%(1) = 11\n30 V0%(2) = 22\n40 A = 1\n50 B = 2\n"
        "60 SWAP V0%(A), V0%(B)\n70 C = 1\n80 D = 2\n"
        "90 PRINT V0%(C), V0%(D)\n100 END\n"
    )


def test_decode_t1_arrswapf():
    # SWAP of two computed SINGLE (4-byte) array elements (wild number.exe
    # at 0xc280): same ES-aliased tail as t1_arrswap's INTEGER case (ao=2
    # for the double `shl si,1`, one per byte of stride beyond the first),
    # but a 4-byte element needs the low-word swap AND a second, high-word
    # round at a fixed +2 byte offset: `mov ax,es:[bx+2]` (far_movax_bx2) /
    # `xchg ax,[si+2]` (xchgsi2) / `mov es:[bx+2],ax` (far_movm_ax_bx2).
    # The 8-byte (DOUBLE) case is left to raise -- unwitnessed.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_arrswapf.exe"))
    assert prog[5] == ir.Swap(
        ir.ArrayRef("V0", (ir.Var("A"),)), ir.ArrayRef("V0", (ir.Var("B"),))
    )
    assert emit0.emit(prog) == (
        "10 DIM V0(10)\n20 V0(1) = 1.5#\n30 V0(2) = 2.5#\n40 A = 1\n50 B = 2\n"
        "60 SWAP V0(A), V0(B)\n70 C = 1\n80 D = 2\n"
        "90 PRINT V0(C), V0(D)\n100 END\n"
    )


def test_decode_t1_openfor():
    # `OPEN file$ FOR mode AS #n` (wild nvginst.exe/photo.exe/pwinst.exe/
    # pz.exe/tamstart.exe/wb.exe -- the single most common wild gap this
    # session, 16 hits): the FOR-keyword desugars at compile time to a
    # PACKED 1-char string (char<<8 | len=1) stored to a fixed scratch
    # cell [002E], then a bare `INT CDh` (canonical; raw C7 in TB 1.0)
    # materializes it -- a completely different encoding than the comma
    # form's real pooled-literal mode string, and NOT byte-identical to
    # it, so ir.Open carries a for_as flag and the emitter reproduces the
    # original FOR-keyword spelling rather than normalizing to one form.
    # Confirmed all 5 modes via oracle probes: OUTPUT/INPUT/APPEND/RANDOM/
    # BINARY -> O/I/A/R/B.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_openfor.exe"))
    assert prog[0] == ir.Open(
        ir.StrLit("O"), 1, ir.StrLit("A.TXT"), None, for_as=True
    )
    assert emit0.emit(prog) == (
        '10 OPEN "A.TXT" FOR OUTPUT AS #1\n20 PRINT #1, "HI"\n'
        "30 CLOSE #1\n40 END\n"
    )


def test_decode_t1_lof():
    # LOF(n) (wild nvginst.exe et al., surfaced right after t1_openfor's
    # gap): INT ED sub 26, filenum in ax like EOF (sub 10) -- but unlike
    # EOF's boolean, a file's length can exceed 16 bits, so the result
    # comes back on the FP stack (fn_axfp, the same shape as FRE(n)/sub
    # 18) rather than in ax.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_lof.exe"))
    assert prog[1] == ir.Print(
        (ir.Call("LOF", (ir.Lit(1),)),), newline=True, file=None, commas=None
    )
    assert emit0.emit(prog) == (
        '10 OPEN "A.TXT" FOR OUTPUT AS #1\n20 PRINT LOF(1)\n'
        "30 CLOSE #1\n40 END\n"
    )


def test_decode_t1_loc2():
    # LOC(n) (wild be.exe/styllist.exe): `_AXARG_SUBS[0x24]` was mislabeled
    # "INP" -- INP(n) always compiles inline (movdx/xorah/in_al, witnessed
    # t1_inpf) and never reaches this ax-arg/ax-returning vector, so the
    # label was never actually exercised by any existing fixture. Oracle-
    # confirmed via `X = LOC(1)` reproducing the exact byte shape both
    # wild files stopped on. Also: unlike EOF(n) (fed into an orax/jcc
    # boolean test), LOC(n)'s ax result here flows STRAIGHT into an
    # `fstp` FP-typed target with no explicit fistp/movmem_ax/fild bridge
    # at all -- `fstp`'s handler now falls back to `state.ax` (an
    # ir.Call) when the FP stack is empty. Closes wild be.exe/
    # styllist.exe's blocker; both advance to a distinct, shared new gap
    # ("file flush without items").
    from tbx import decode0, emit0

    prog = decode0.decode_user_code(_exe("t1_loc2.exe"))
    assert emit0.emit(prog) == (
        '10 OPEN "T.DAT" FOR OUTPUT AS #1\n20 A = LOC(1)\n30 PRINT A\n'
        "40 CLOSE #1\n50 END\n"
    )


def test_decode_t1_lineinf():
    # LINE INPUT #n, var$ (wild billadd.exe/crossref.exe/file.exe/
    # grdscn.exe/strpfind.exe): the file-channel sibling of console LINE
    # INPUT -- `cd ec 66` (canonical; no operand -- there's no prompt for
    # a file read, unlike sub 64's `cd ec 64 <prompt_desc> 40`) + the
    # same `movsi; strassign` consumer, with [0060] carrying the file
    # number like OPEN/PRINT#/INPUT#. ir.LineInput grew a `file` field
    # (prompt and file are mutually exclusive).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_lineinf.exe"))
    assert prog[4] == ir.LineInput(None, ir.Var("A$"), 1)
    assert emit0.emit(prog) == (
        '10 OPEN "A.TXT" FOR OUTPUT AS #1\n20 PRINT #1, "HELLO"\n'
        '30 CLOSE #1\n40 OPEN "A.TXT" FOR INPUT AS #1\n'
        "50 LINE INPUT #1, A$\n60 PRINT A$\n70 CLOSE #1\n80 END\n"
    )


def test_decode_t1_icomp():
    # Mixed-type relational (`IF A% > B THEN` with A% INTEGER and B a
    # SINGLE variable, wild grdscn.exe/kinder.exe/night.exe/pfl.exe/
    # stat.exe): B is pushed onto the FP stack (fld), then A%'s slot is
    # compared against it via ESC DEh /3 (`icomp`, the m16-int compare
    # sibling of D8h /3's `fcomp`) rather than the fast direct-int
    # compare path -- the comparison itself forces int->FP promotion.
    # mem resolution (var slot or a pooled int literal) mirrors the
    # existing `ifold`/`ifold_n` arithmetic siblings exactly.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_icomp.exe"))
    assert prog[2] == ir.IfGoto(
        ir.RelOp("<=", ir.Var("A%"), ir.Var("B")), 5
    )
    assert emit0.emit(prog) == (
        "10 A% = 5\n20 B = 5.5\n30 IF A% <= B THEN 60\n40 PRINT \"YES\"\n"
        '50 GOTO 70\n60 PRINT "NO"\n70 END\n'
    )


def test_decode_t1_bload0():
    # BLOAD f$ with no offset argument (wild varamort.exe/kinder.exe,
    # right after `DEF SEG = &HB800`-style video-segment setup): INT EC
    # sub 04, a genuinely distinct compiled shape from sub 06's
    # with-offset form -- ir.Bload's offset field defaults to None rather
    # than folding this into "offset omitted == 0" or similar, since the
    # byte shapes differ (no FP-stack pop at all for the bare form).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_bload0.exe"))
    assert prog[1] == ir.Bload(ir.StrLit("X.BIN"))
    assert emit0.emit(prog) == (
        '10 DEF SEG = 100\n20 BLOAD "X.BIN"\n30 END\n'
    )


def test_decode_v10_t1_pow10():
    # `^` (exponentiation) under TB 1.0 (wild banker.exe/kinetics.exe):
    # dialect.py's own docstring already predicted this gap ("TB 1.0
    # encodes ^ without an ED sub"; TB 1.1 uses ED sub 3A/fpow). TB 1.0's
    # actual mechanism turns out to be `INT 3Eh` (the transcendental
    # dispatcher) selector 0x14 -- byte-identical operand push order to
    # fpow's (base then exponent), so it aliases straight onto the
    # existing "fpow" op kind rather than needing a new one; the dialect
    # difference is fully absorbed at scan time like every other TB
    # 1.0/1.1 numbering shift.
    from tbx import decode0, emit0, ir

    prog10 = decode0.decode_user_code(_exe("v10_t1_pow10.exe"))
    prog11 = decode0.decode_user_code(_exe("t1_pow10.exe"))
    assert prog10 == prog11
    assert prog10[2] == ir.Assign(
        ir.Var("C"), ir.BinOp("^", ir.Var("A"), ir.Var("B"))
    )
    assert emit0.emit(prog10) == (
        "10 A = 2.5\n20 B = 1.5\n30 C = A ^ B\n40 PRINT C\n50 END\n"
    )


def test_decode_t1_inline():
    # SUB name INLINE ... $INLINE byte, byte, ... END SUB (Appendix C of
    # the handbook's own worked example, the PC-speaker "Shriek" routine):
    # embedded raw machine code, copied verbatim into the compiled output
    # with NO proc_enter/proc_ret framing and an auto-appended bare far
    # RET (0xCB). _scan's linear pass can't interpret arbitrary bytes as
    # instructions -- some coincidentally match real opcodes first (`BA 00
    # 07` legitimately scans as mov dx,0700h before `E4`, IN AL,61h, has
    # no TB equivalent) -- so _try_inline_rescue only kicks in once the
    # ordinary scan has already failed: it finds the most recent `jmp`,
    # confirms its target's preceding byte is a bare 0xCB, and treats the
    # whole span as one opaque `inline_sub` blob rather than guessing at
    # individual bytes. The original 4-line $INLINE split has no separate
    # byte-level representation (confirmed byte-exact both ways), so the
    # emitter consolidates onto one line.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_inline.exe"))
    raw = bytes(
        [
            0xBA, 0x00, 0x07, 0xE4, 0x61, 0x24, 0xFC, 0x34, 0x02, 0xE6, 0x61,
            0xB9, 0x40, 0x01, 0xE2, 0xFE, 0x4A, 0x74, 0x02, 0xEB, 0xF2,
        ]
    )
    assert prog[0] == ir.SubDef("SUB1", (), (ir.Inline(raw),))
    assert prog[1] == ir.CallStmt("SUB1", ())
    assert emit0.emit(prog) == (
        "10 SUB SUB1 INLINE\n"
        "  $INLINE &HBA, &H00, &H07, &HE4, &H61, &H24, &HFC, &H34, &H02, "
        "&HE6, &H61, &HB9, &H40, &H01, &HE2, &HFE, &H4A, &H74, &H02, &HEB, "
        "&HF2\nEND SUB\n20 CALL SUB1\n30 END\n"
    )


def test_decode_t1_orax():
    # `DO...LOOP UNTIL <bare numeric value>` (wild metric.exe, an INKEY$
    # poll loop): `or ax,ax` testing a just-computed value's truthiness
    # DIRECTLY, with no preceding compare -- a genuinely different,
    # shorter compiled shape from _lift_do_tail's usual `movax 0FFFFh;
    # jcc; incax; or ax,ax; jcc` template (which needs an EXPLICIT
    # comparison first to materialize a -1/0 boolean). Byte-exact check
    # confirmed the two source forms compile differently: `LOOP UNTIL
    # LEN(K$) <> 0` (explicit compare) does NOT recompile this file's
    # bytes; only the bare `LOOP UNTIL LEN(K$)` does. ir.Loop.cond can
    # now hold a bare expression, not just RelOp/LogOp -- rename.py's
    # walk_cond and render.py's unparse_cond both needed a fallback case.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_orax.exe"))
    assert prog[2] == ir.Loop("UNTIL", ir.Call("LEN", (ir.Var("A$"),)))
    assert emit0.emit(prog) == (
        "10 DO\n20 A$ = INKEY$\n30 LOOP UNTIL LEN(A$)\n"
        "40 PRINT A$\n50 END\n"
    )


def test_decode_t1_deftype():
    # DEFINT/DEFSTR/DEFSNG/DEFDBL emit no executable code, but each leaves
    # an orphan entry in an active error-trap line table. The declaration's
    # exact keyword/range is otherwise erased once all emitted variables are
    # explicitly suffixed, so normalize each recovered declaration to the
    # byte-identical canonical spelling DEFSNG A-Z. This fixture deliberately
    # puts declarations before ON ERROR and before two self-referential IF
    # loops, matching all three placements seen in wild metric.exe.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_deftype.exe"))
    assert [i for i, s in enumerate(prog) if isinstance(s, ir.DefType)] == [0, 2, 4]
    assert emit0.emit(prog) == (
        "10 DEFSNG A-Z\n"
        "20 ON ERROR GOTO 100\n"
        "30 DEFSNG A-Z\n"
        "40 IF LEN(INKEY$) = 0 THEN 40\n"
        "50 DEFSNG A-Z\n"
        "60 IF LEN(INKEY$) = 0 THEN 60\n"
        "70 END\n"
        "100 RESUME NEXT\n"
    )


def test_decode_t1_dispill():
    # A nested SCREEN() used as the outer call's column argument while an
    # integer divisor is live exhausts ax/bx/cx and makes Turbo Basic spill
    # through di (`mov di,cx`). This is the minimal witnessed form of the
    # byte-89 gap shared by wild kinder/catalog/pfl/process.
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_dispill.exe"))) == (
        "10 A = SCREEN(3,SCREEN(4,1)) \\ 16\n20 PRINT A\n"
    )


def test_decode_t1_screen3():
    # INT ED sub 44 is SCREEN(row,col,color): the extra argument pushes the
    # row into cx while the column and color arrive in bx/ax. This additional
    # register pressure is what makes nested uses spill through di.
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_screen3.exe"))) == (
        "10 A = SCREEN(3,1,1)\n20 PRINT A\n"
    )


def test_decode_t1_locate5():
    # INT CE is the trailing cursor scan-line range of five-argument LOCATE;
    # start/stop arrive in bx/ax after the existing INT CF + INT D0 calls.
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_locate5.exe"))) == (
        '10 LOCATE 11,20,1,0,7\n20 PRINT "X"\n'
    )


def test_decode_t1_databig():
    # DATA shares the ordinary literal pool. Its 15-bit framed character
    # record can exceed 255 bytes, and unreferenced descriptors are the DATA
    # items rather than erased FRE(s$) operands. This also pins DATA and
    # payload-free DEFxxx entries sharing or occupying separate orphan
    # clusters in an active error-line table (wild metric.exe).
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_databig.exe")))
    assert src == open(
        os.path.join(_ROOT, "fixtures", "usercode", "t1_databig.bas")
    ).read()
    assert src.count("DATA ") == 4
    assert src.count("DEFSNG A-Z") == 3
    assert "60 ON ERROR GOTO 200" in src


def test_decode_t1_getstr():
    # INT EC sub 4C is binary GET$: file number comes from [0060], count is
    # in AX, and the following movsi/strassign names the string target.
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_getstr.exe"))) == (
        '10 OPEN "X" FOR BINARY AS #1\n'
        "20 A% = 4\n"
        "30 GET$ #1, A%, B$\n"
        "40 END\n"
    )


def test_decode_t1_closevar():
    # CLOSE #n where n is a variable, not a literal (wild metric.exe,
    # right after the orax/DO-loop gap): the file number reaches CLOSE's
    # dispatch via the standard FP-to-int bridge (fld/fistp/fwait/
    # movaxmem), leaving a Var in ax rather than a Lit. ir.Close.num now
    # accepts either -- a plain int (existing literal case, unchanged)
    # or an Expr, with render.py/c0.py each gaining a branch for the
    # latter.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_closevar.exe"))
    assert prog[2] == ir.Close(ir.Var("A"))
    assert emit0.emit(prog) == (
        '10 A = 1\n20 OPEN "X.DAT" FOR OUTPUT AS #1\n30 CLOSE #A\n40 END\n'
    )


def test_decode_t1_nestfor():
    # DO...LOOP WHILE wrapping a FOR...NEXT, ending a GOSUB'd routine
    # (wild metric.exe): the loop-back edge is the materialized test's
    # OWN trailing jmp (backward, landing on a real statement), not a
    # separate `jmps` elsewhere for _has_jmps_back to find -- a nested
    # FOR...NEXT leaves no such edge, since the FOR's own machinery owns
    # the last backward jump before this point. Mirror image of
    # _lift_do_tail's polarity: here the materialized jcc CAUSES the
    # exit and falling through (to the jmp) retries.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_nestfor.exe"))
    assert prog[9] == ir.Loop(
        "WHILE", ir.RelOp("<>", ir.Var("A"), ir.Lit(23))
    )
    assert emit0.emit(prog) == (
        "10 GOSUB 40\n20 PRINT A\n30 END\n40 A = 17\n50 DO\n"
        "60 FOR B = 3 TO 76\n70 C = B\n80 NEXT B\n90 A = A + 1\n"
        "100 LOOP WHILE A <> 23\n110 RETURN\n"
    )


def test_decode_t1_nestfor2():
    # Same shape as t1_nestfor but UNTIL (the other exit_jcc polarity) --
    # pinned separately since the inline-IF branch this new code sits
    # beside claims cc==0x75 unconditionally, so the ordering that keeps
    # UNTIL reachable here is itself the thing worth pinning.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_nestfor2.exe"))
    assert prog[9] == ir.Loop(
        "UNTIL", ir.RelOp("=", ir.Var("A"), ir.Lit(23))
    )
    assert emit0.emit(prog) == (
        "10 GOSUB 40\n20 PRINT A\n30 END\n40 A = 17\n50 DO\n"
        "60 FOR B = 3 TO 76\n70 C = B\n80 NEXT B\n90 A = A + 1\n"
        "100 LOOP UNTIL A = 23\n110 RETURN\n"
    )


def test_decode_t1_fileint():
    # INPUT# with INTEGER targets (inv87/invoice at 0x1389c): the numeric
    # read leaves the value on the x87 stack as usual, but an int slot is
    # stored through the fistp bridge (fistp 2C; fwait; movaxmem 2C;
    # movm_ax <slot>) -- fp_math's fistp assign branch popped the _FREAD
    # sentinel and fed it straight to ir.Assign instead of routing it to
    # _fread_target (the _READDATA analog got the same fix). The probe also
    # witnessed INT C3, PRINT#'s comma separator (console comma is C1):
    # `PRINT #1, 5, 7` compiles item;C3;item, previously unscanned.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_fileint.exe"))
    assert prog[4] == ir.InputFile(1, (ir.Var("A%"), ir.Var("B%")))
    assert prog[1] == ir.Print(
        (ir.Lit(5), ir.Lit(7)), newline=True, file=1, commas=(0, 1, 0)
    )
    assert emit0.emit(prog) == (
        '10 OPEN "O",#1,"T.DAT"\n'
        "20 PRINT #1, 5, 7\n"
        "30 CLOSE\n"
        '40 OPEN "I",#1,"T.DAT"\n'
        "50 INPUT #1, A%, B%\n"
        "60 CLOSE\n"
        "70 PRINT A% + B%\n"
        "80 END\n"
    )


def test_decode_t1_fprintblank():
    # Bare `PRINT #n,` (wild be.exe/styllist.exe): a blank-line flush to a
    # file channel with no items staged at all, so the B8/BA flush-vector
    # handler's "no pend_print, but want_file" branch previously just
    # raised. Emits ir.Print((), file=n), the file-channel sibling of the
    # existing bare-console-PRINT case just above it. Closes wild be.exe
    # fully; styllist.exe advances to a distinct gap.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_fprintblank.exe"))
    assert prog[1] == ir.Print((), file=1)
    assert emit0.emit(prog) == (
        '10 OPEN "T.DAT" FOR OUTPUT AS #1\n20 PRINT #1,\n30 CLOSE #1\n40 END\n'
    )


def test_decode_t1_fpcomma():
    # Leading zone-advance comma on a FILE-channel PRINT (`PRINT #1, , A`,
    # wild styllist.exe): the console PRINT already auto-creates an empty
    # pend_print for a leading comma (gap 52, t1_pcomma2), but the file
    # channel's C3 vector never got the same treatment -- it required
    # pend_print["items"] to be non-empty, which a leading comma can never
    # satisfy. Mirrors the console auto-create, staging file=pend_fnum.
    # Closes wild styllist.exe's blocker; advances to a distinct gap.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_fpcomma.exe"))
    assert prog[2] == ir.Print((ir.Var("A"),), file=1, commas=(1, 0))
    assert emit0.emit(prog) == (
        '10 OPEN "T.DAT" FOR OUTPUT AS #1\n20 A = 5\n30 PRINT #1, , A\n'
        "40 CLOSE #1\n50 END\n"
    )


def test_decode_t1_resumestart():
    # RESUME <line>, where <line> is the program's own FIRST statement
    # (wild styllist.exe): TB 1.0's E9-near-jump canonicalization tags ANY
    # jump landing on target == start+3 (the first statement's address) as
    # "run", the same tag a bare RUN's jump-to-start gets, since the bytes
    # are identical either way. resume_pre's tail now recognizes this
    # (RESUME can never trigger a genuine full-reset RUN, so it's always
    # the plain first-statement target). The jump distance has to exceed
    # short-jcc range to force the E9 form; a plain short probe never hits
    # this shape under either dialect. Closes wild styllist.exe fully.
    from tbx import decode0, emit0

    prog = decode0.decode_user_code(_exe("t1_resumestart.exe"))
    src = emit0.emit(prog)
    assert src.splitlines()[0] == "10 ON ERROR GOTO 900"
    assert src.splitlines()[-1] == "900 RESUME 10"


def test_decode_t1_addimm():
    # 01 06 = add [disp16], ax: the disp16 sibling of addm_ax_bp (t1_local1's
    # LOCAL combine-store) -- `X% = X% + <expr>` when the RHS isn't a bare
    # literal 1 (no INCR fast path applies), materializing the RHS into ax
    # first and folding the store back with ADD instead of a separate
    # load/add/MOV
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_addimm.exe")))
    assert src == "10 A% = 5\n20 A% = A% + 3\n30 PRINT A%\n40 END\n"


def test_decode_t1_fwd():
    # Nested SUBs, three shapes in one fixture: ff 76 d+2 / ff 76 d
    # (arg_push_fwd -- forwarding the enclosing SUB's by-ref far-pointer param
    # to a nested CALL, typed from the callee's signature), 26 01 04
    # (far_addm_ax_si -- compound-store add into a by-ref int param), and the
    # chained skip-jmp def-region layout for two consecutive SUB definitions.
    # Formal params sharing a bp offset across SUBs must not synthesize SHARED.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_fwd.exe"))
    assert prog[0] == ir.SubDef(
        "SUB1",
        ("A%",),
        (ir.Assign(ir.Var("A%"), ir.BinOp("+", ir.Var("A%"), ir.Lit(1))),),
    )
    assert prog[1] == ir.SubDef(
        "SUB2", ("A%",), (ir.CallStmt("SUB1", (ir.Var("A%"),)),)
    )
    assert emit0.emit(prog) == (
        "10 SUB SUB1(A%)\n  A% = A% + 1\nEND SUB\n"
        "20 SUB SUB2(A%)\n  CALL SUB1(A%)\nEND SUB\n"
        "30 B% = 5\n40 CALL SUB2(B%)\n50 PRINT B%\n60 END\n"
    )


def test_decode_t1_locidx():
    # FOR over a LOCAL int inside a SUB, whole bp-relative family: mov_bp_imm
    # init / cmp_bpi8 test / inc_bp step, plus movsi_bp (8b 76: LOCAL as array
    # index) and the NEAR string-element strassign terminal after addsi.
    # The literal-bound LOCAL FOR reserves two temp words in the frame right
    # after the loop var -- dropped from LOCAL, but the retf pop math keeps
    # the full zero-filled span (no phantom SUB param).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_locidx.exe"))
    sub = prog[0]
    assert isinstance(sub, ir.SubDef) and sub.params == ()
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n"
        "  DIM V0$(10)\n  LOCAL A%\n  FOR A% = 1 TO 5\n"
        '  V0$(A%) = "X"\n  NEXT A%\n  PRINT V0$(3)\nEND SUB\n'
        "20 CALL SUB1\n30 END\n"
    )


def test_decode_t1_loccmp():
    # 3b 46 = cmp ax,[bp+d8]: integer relational against a LOCAL int, plus
    # 03 46 = add ax,[bp+d8] (LOCAL folded LEFT into ax). The compiler
    # evaluates the source RHS into ax and compares the LOCAL as memory
    # (flags reversed vs cmpax_bx), so the IF form consumes its own jcc+jmp
    # with a mirrored negation map to keep the LOCAL spelled on the left --
    # the emitted skip-goto respell is byte-identical on recompile.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_loccmp.exe")))
    assert src == (
        "10 SUB SUB1\n"
        "  LOCAL A%, B%\n  A% = 3\n  B% = 9\n"
        '  IF A% <> 0 THEN 16\n  PRINT "Z"\n'
        '16 IF A% >= B% + 1 THEN 18\n  PRINT "W"\n'
        "18 PRINT A%\nEND SUB\n"
        "20 CALL SUB1\n30 END\n"
    )


def _names():
    # canonical rename order: A..Z, then AA, AB, ...
    import string

    for c in string.ascii_uppercase:
        yield c
    for c1 in string.ascii_uppercase:
        for c2 in string.ascii_uppercase:
            yield c1 + c2


def test_decode_t1_bandwide():
    # Gap 16, the general mechanism: the compiler stamps the ordinary-scalars
    # band descriptor (num_size, num_base, str_size, num_base+num_size,
    # n_static, grid_base, 0, num_base) into the init image, directly
    # followed by the static slot records -- the record run FLOATS past
    # variable-length init data, by more than one ARR_BLOCK when the scalar
    # band is wide (168 bytes here), which pushed it clean out of
    # find_statics's window AND let the greedy walk "solve" a wrong layout
    # whose phantom pooled double read past EOF. The stamp-anchored path
    # (layout.py) now solves these from the stamp itself, before the walk.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_bandwide.exe"))
    names = _names()
    lines = ["10 DIM V0(20)", "20 DIM V1(20)"]
    ln = 30
    for k in range(40):
        lines.append(f"{ln} {next(names)} = {k}.5")
        ln += 10
    fv, hv = next(names) + "%", next(names) + "%"
    lines += [
        f"{ln} FOR {fv} = 1 TO 6",
        f"{ln + 10} V0({fv}) = {fv}",
        f"{ln + 20} NEXT {fv}",
        f"{ln + 30} {hv} = V1(1)",
        f"{ln + 40} PRINT A, AN, {hv}",
        f"{ln + 50} END",
    ]
    assert ir.For(ir.Var(fv), ir.Lit(1), ir.Lit(6), ir.Lit(1)) in prog
    assert emit0.emit(prog) == "\n".join(lines) + "\n"


def test_decode_t1_bandstr():
    # Companion witness for the stamp path's STRING sub-band: string scalars
    # are SEGREGATED after the numerics (stamp str_size > 0, wild schart's
    # shape) regardless of source order -- the five string assignments here
    # are interleaved among the singles in the source, yet their descriptors
    # all sit in the trailing 20-byte string sub-band, and the decode maps
    # each back to its interleaved source position.
    from tbx import decode0, emit0

    prog = decode0.decode_user_code(_exe("t1_bandstr.exe"))
    names = _names()
    lines = ["10 DIM V0(20)", "20 DIM V1(20)"]
    ln = 30
    for k in range(30):
        lines.append(f"{ln} {next(names)} = {k}.5")
        ln += 10
        if k in (4, 9, 14, 19, 24):
            lines.append(f'{ln} {next(names)}$ = "X{k}"')
            ln += 10
    fv, hv = next(names) + "%", next(names) + "%"
    lines += [
        f"{ln} FOR {fv} = 1 TO 6",
        f"{ln + 10} V0({fv}) = {fv}",
        f"{ln + 20} NEXT {fv}",
        f"{ln + 30} {hv} = V1(1)",
        f"{ln + 40} PRINT A, F$, {hv}",
        f"{ln + 50} END",
    ]
    assert emit0.emit(prog) == "\n".join(lines) + "\n"


def test_decode_t1_dim4():
    # Rank-4 static array record (30 populated bytes, same cumulative-span
    # model as rank 3; surfaced by wild hfprop's DIM x(...,...,...,...)).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_dim4.exe"))
    assert prog[0] == ir.Dim("V0", (2, 3, 5, 4))
    assert emit0.emit(prog) == (
        "10 DIM V0(2,3,5,4)\n20 V0(1,2,3,4) = 7\n"
        "30 PRINT V0(1,2,3,4)\n40 END\n"
    )


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
    test_decode_t1_svaridx()
    test_decode_t1_run2()
    test_decode_t1_byref2()
    test_decode_t1_forstep()
    test_decode_t1_forstepn()
    test_decode_t1_forbig()
    test_decode_t1_for10arr()
    test_decode_t1_strch()
    test_decode_t1_lpusing()
    test_decode_t1_errcmp()
    test_decode_t1_imulpool()
    test_decode_t1_strgodo()
    test_decode_t1_ifgoto()
    test_decode_t1_addpool()
    test_decode_t1_pcomma2()
    test_decode_t1_bigjmp()
    test_decode_t1_blkgoto()
    test_decode_t1_miderr()
    test_decode_t1_strgoto()
    test_decode_t1_orchain()
    test_decode_t1_fileint()
    test_decode_t1_addimm()
    test_decode_t1_fwd()
    test_decode_t1_locidx()
    test_decode_t1_loccmp()
    test_decode_t1_bandwide()
    test_decode_t1_bandstr()
    test_decode_t1_dim4()
    print("ALL PASS")
