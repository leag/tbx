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
