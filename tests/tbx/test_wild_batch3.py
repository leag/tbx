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

    from conftest import wild_hits_bytes

    exe = wild_hits_bytes("banker.exe")
    prog = decode0.decode_user_code(exe)
    loops = [s for s in prog if isinstance(s, ir.For)]
    assert any(
        isinstance(s.limit, ir.BinOp)
        and s.limit.op == "-"
        and s.limit.lhs == ir.Lit(66)
        for s in loops
    )


def test_decode_long_single_and_double_for():
    # Long bodies use inverse-Jcc + near-JMP legs in the NEXT template.
    # DOUBLE steps test their sign word at step+6 rather than SINGLE's +2.
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_forlongfp.exe"))
    loops = [s for s in prog if isinstance(s, ir.For)]
    assert [s.var.name.endswith("#") for s in loops] == [False, True]
    assert all(s.step == ir.Lit(1) for s in loops)


def test_scan_wild_far_jump_group():
    # Wild binaries using EA far transfers.  The scanner must preserve their
    # rebased target instead of stopping at the raw x86 byte; later decoder
    # failures are separate, file-specific gaps.
    #
    # Every one of these is a $SEGMENT program, and the zero-offset EA that
    # used to be read as "the fixed runtime handoff" is really the metacommand
    # closing one code segment and continuing in the next (`segjmp`, see
    # scan.py). Following it multiplies the jmpf counts here because most of
    # each program lived past that point and was previously never scanned at
    # all -- elec87 goes 5 -> 21, mf 8 -> 151.
    from tbx import decode0

    from conftest import wild_hits_bytes

    cases = (  # name, jmpf, segjmp
        ("elec87.exe", 21, 1),
        ("electron.exe", 21, 1),
        ("mcmurphy.exe", 0, 1),
        ("mf.exe", 151, 1),
        ("swbb.exe", 16, 2),
        ("wb.exe", 3, 1),
    )
    for name, count, segs in cases:
        exe = wild_hits_bytes(name)
        start, dialect = decode0.find_prologue(exe)
        ops = decode0._scan(exe, start, dialect, set())
        assert sum(op[1] == "jmpf" for op in ops) == count, name
        assert sum(op[1] == "segjmp" for op in ops) == segs, name
        assert ops[-1][1] == "epilogue", name


def test_scan_wild_sabpcv3_clears_its_inline_subs():
    # sabpcv3.exe was in the group above with zero jmpf ops because the scan
    # stopped at its $SEGMENT transition. Following that, and then reading the
    # inline SUBs the metacommand moved (whose $INLINE lists open with a proc
    # prologue), carries it all the way into ordinary compiled SUB bodies --
    # and then relaying an array parameter onward carries it further still, to
    # an unrelated template.
    import pytest

    from tbx import decode0

    from conftest import wild_hits_bytes

    exe = wild_hits_bytes("sabpcv3.exe")
    start, dialect = decode0.find_prologue(exe)
    with pytest.raises(ValueError, match=r"unhandled byte 51 at 0xd30b"):
        decode0._scan(exe, start, dialect, set())


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


def test_decode_t1_cmpfarif():
    # The IF-form sibling of t1_cmpfar: the same `cmp ax,es:[si]` compare
    # consumed by a jcc + skip-jmp instead of the movax-FFFF value template
    # (wild tbd73.exe, TBWINDOW `SUB Openwin`'s `IF shadow < 1 THEN ... ELSE`).
    # Flags are rhs-vs-lhs, so the skip relop is the source "<" mirrored to
    # ">=", and the param stays on the LEFT -- respelling it `1 > A%` would
    # put the param in ax and recompile to different bytes.
    from tbx import decode0, emit0

    for stem in ("t1_cmpfarif.exe", "v10_t1_cmpfarif.exe"):
        src = emit0.emit(decode0.decode_user_code(_exe(stem)))
        assert src == (
            "10 SUB SUB1(A%)\n"
            "  LOCAL B%\n"
            "  IF A% >= 1 THEN 15\n"
            "  B% = 5\n"
            "  GOTO 16\n"
            "15 B% = 7\n"
            "16 PRINT B%\n"
            "END SUB\n"
            "20 C% = 1\n30 CALL SUB1(C%)\n40 END\n"
        ), stem


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


def test_decode_t1_byreflong():
    # By-ref LONG (`&`) SUB param, the m32 sibling of t1_byref1's INTEGER
    # family: FILD onto the FP stack for PRINT/read (far_fild_si32), FSTP
    # writing the FP-stack top back into the param (far_fstp_si32), and a
    # mixed-type IF compare against the param (far_icomp_si32, the far/
    # by-ref sibling of the computed-array-element icomp_si32) -- all via
    # the same `les si,[bp+N]` by-ref addressing as t1_byref1, just the
    # ESC DB/DF x87 opcodes instead of a plain register op. Wild bmaster.exe/
    # ifi.exe.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_byreflong.exe")))
    assert src == (
        "10 SUB SUB1(A&)\n"
        "  PRINT A&\n  A& = 999\n"
        '  IF A& <> 999 THEN 15\n  PRINT "YES"\n15 PRINT "DONE"\n'
        "END SUB\n"
        "20 B& = 123456\n30 CALL SUB1(B&)\n40 PRINT B&\n50 END\n"
    )


def test_decode_t1_localdbl():
    # DOUBLE-precision LOCAL variable (`LOCAL X#`): fld_bp64/fstp_bp64/
    # fold_bp64 are the m64 siblings of fld_bp/fstp_bp/fold_bp's SINGLE
    # forms -- same first-touch retyping convention, just over FOUR
    # zero-filled words instead of two. Wild filepatc.exe.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_localdbl.exe")))
    assert src == (
        "10 SUB SUB1\n  LOCAL A#\n  A# = 1.5#\n  PRINT A#\n"
        "  A# = A# + 1\n  PRINT A#\nEND SUB\n"
        "20 CALL SUB1\n30 END\n"
    )


def test_decode_t1_localdblcmp():
    # DOUBLE LOCAL compare (fcomp_bp64), the m64 sibling of fcomp_bp.
    # Wild filepatc.exe.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_localdblcmp.exe")))
    assert src == (
        "10 SUB SUB1\n  LOCAL A#\n  A# = 1.5#\n"
        '  IF A# <= 1 THEN 15\n  PRINT "YES"\n15 PRINT "DONE"\n'
        "END SUB\n20 CALL SUB1\n30 END\n"
    )


def test_decode_t1_forvarlimneg():
    # Variable-limit integer FOR/NEXT with STEP -1: the NEXT test's JGE
    # (0x7D) descending condition, mirroring the literal-limit cmp_mi8
    # case's own wantcc/invcc split. Also the fixture for a real bug the
    # investigation surfaced: state.fors.append() for this FOR-header shape
    # never set "idx", so the NEXT-side dec_m STEP -1 patch-up (which reads
    # f["idx"] to rewrite the provisional Lit(1) step) crashed with a bare
    # KeyError instead of decoding or raising a clean ValueError. Wild
    # morcalc.exe.
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_forvarlimneg.exe"))
    loops = [s for s in prog if isinstance(s, ir.For)]
    assert loops == [ir.For(ir.Var("B%"), ir.Lit(5), ir.Var("A%"), ir.Lit(-1))]


def test_decode_t1_palettereset():
    # Bare PALETTE (INT ECh sub 86h, zero operands: reset to default
    # palette) -- distinct from PALETTE attr,color (sub 88h). Identified
    # from wild rsltest.exe (`7020 PALETTE`), oracle-verified byte-exact
    # via a dedicated probe.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_palettereset.exe"))
    assert prog[0] == ir.Palette(ir.Lit(1), ir.Lit(2))
    assert prog[1] == ir.Palette(None, None)
    assert emit0.emit(prog) == "10 PALETTE 1, 2\n20 PALETTE\n30 END\n"


def test_decode_t1_argrefonly():
    # A DGROUP scalar only ever touched via a by-ref CALL argument
    # (arg_push_ref), never a direct read/write anywhere in the program --
    # layout's evidence-gathering pass has no type signal for it at all,
    # so `state.loc()` used to raise unconditionally. Deferred, mirroring
    # arg_push_fwd's own "fwd"/"fwdpending" placeholder: the callee's own
    # param list supplies the type once known. This probe's callee (SUB2)
    # is defined AFTER the caller (SUB1) in source order, exercising the
    # forward-reference "argrefpending" path (_resolve_calls); wild
    # rsltest.exe (below) exercises the immediate-resolution path, where
    # the callee is already known.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_argrefonly.exe"))
    subs = {s.name: s for s in prog if isinstance(s, ir.SubDef)}
    assert subs["SUB1"].body == (ir.CallStmt("SUB2", (ir.Var("A%"),)),)
    assert emit0.emit(prog) == (
        "10 CALL SUB1\n20 END\n30 SUB SUB1\n  CALL SUB2(A%)\nEND SUB\n"
        "40 SUB SUB2(B%)\n  B% = B% + 1\n  PRINT B%\nEND SUB\n"
    )


def test_wild_rsltest_argref_advances():
    # rsltest.exe used to fail with "displacement 0x472 is neither scalar
    # nor array element" -- TBMENU.INC's MAKEMENU sub (dead code, never
    # called from TEST.BAS) relays its own SHARED globals (mrow%, mcol%,
    # mwidth%, mattr%, mhiattr%, mbrdrsel%, mshadow%, mzoom%) into
    # MAKEWINDOW purely by reference, so they have no other evidence
    # anywhere in the program. Confirms the wild file now advances past
    # that gap (MakeWindow, the callee, is already decoded by the time
    # this call is reached, so this exercises the immediate-resolution
    # path rather than test_decode_t1_argrefonly's forward-reference one).
    # It then stopped at 0xac2e, the tail jump of a block IF arm landing on
    # the code-less-line hooks ahead of an FP promote-to-scratch. The promote
    # commits no statement, but cleared `c.cur` anyway, so that hook's address
    # was dropped and the statement re-anchored on the next hook (fixed in
    # core.fstp64's fp64_bridge leg). It now reaches 0xae3a, which is a
    # different shape: a run of hooks immediately before `proc_ret`, i.e. a
    # jump to the SUB's own epilogue, which owns no statement. Same family as
    # help.exe -- see PLAN.md Part II's table.
    import pytest

    from tbx import decode0

    from conftest import wild_hits_bytes

    with pytest.raises(ValueError, match=r"jump target 0xae3a is not a statement start"):
        decode0.decode_user_code(wild_hits_bytes("rsltest.exe"))


def test_decode_t1_declnoend():
    # Main code that FALLS INTO the definition region -- no END closing it,
    # so the compiler's entry skip-jmp over the first SUB is preceded by an
    # ordinary statement instead of by END/proc_ret/fn_ret and is not at op
    # 0 either. None of the five older "glue, not a GOTO" sites matched it,
    # so the skip was decoded as a real user `GOTO`, silently inventing a
    # statement the source never had (byte-significant: the round trip
    # emitted both the invented GOTO and a fresh skip-jmp, ~33 bytes off in
    # both dialects). Found via wild rsltest.exe, whose DIM block precedes
    # a $INCLUDE'd TBWINDOW definition run. Both dialects verified
    # byte-exact.
    from tbx import decode0, emit0, ir

    for stem in ("t1_declnoend", "v10_t1_declnoend"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert not any(isinstance(s, ir.Goto) for s in prog), stem
        assert [type(s).__name__ for s in prog] == ["Assign", "SubDef", "Print"], stem
        assert emit0.emit(prog) == (
            '10 A% = 1\n20 SUB SUB1\n  PRINT "F"\nEND SUB\n30 PRINT A%\n'
        ), stem


def test_decode_t1_inlinebp():
    # A SUB ... INLINE whose $INLINE list opens with `push bp; mov bp,sp` was
    # refused by the rescue's proc-shape guard (added for wild CVT2TB.EXE,
    # whose real framed procedure ends in a legitimate `pop bp; retf` and so
    # satisfied the bare-CB terminator check). TB always APPENDS a bare far
    # RET to an inline body, so a list that already ends in its own retf
    # yields the doubled `CB CB` -- which no framed epilogue can produce
    # (`pop bp; retf` ends 5D CB) -- and that makes the proc-shaped body safe
    # to accept. Found via wild tbd73.exe/sabpcv3.exe. Byte-exact, both
    # dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_inlinebp", "v10_t1_inlinebp"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        assert len(sub.body) == 1 and isinstance(sub.body[0], ir.Inline), stem
        assert sub.body[0].data == bytes(
            (0x55, 0x8B, 0xEC, 0xC4, 0x7E, 0x0A, 0x5D, 0xCB)
        ), stem
        assert emit0.emit(prog) == (
            "10 A% = 1\n20 CALL SUB1\n30 END\n$SEGMENT\n40 SUB SUB1 INLINE\n"
            "  $INLINE &H55, &H8B, &HEC, &HC4, &H7E, &H0A, &H5D, &HCB\nEND SUB\n"
        ), stem


def test_decode_t1_erasesubcommon():
    # `ERASE` of a SUB-LOCAL static array in a program that also has COMMON
    # arrays (wild tbd73.exe: `SUB Showfile` does `DIM recarr$(5000)` --
    # a constant bound, so a compile-time static, and the SUB body has no
    # dim_begin at all -- then `ERASE recarr$` at TBD73.BAS:409).
    #
    # erase_static used to re-derive the array's index positionally,
    # `divmod(block - var_base, ARR_BLOCK)`, which assumes every slot record
    # sits at a plain grid stride from var_base. A COMMON band shifts that, so
    # the arithmetic missed and raised `ERASE of unknown static slot` -- even
    # though the whole-array CALL argument path resolves the very SAME operand
    # correctly through state.slot_info. Now ERASE uses that registry too.
    #
    # The COMMON declarations are load-bearing: without them the positional
    # arithmetic happens to land right and the fixture witnesses nothing.
    from tbx import decode0, emit0, ir

    for stem in ("t1_erasesubcommon", "v10_t1_erasesubcommon"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef) and s.name == "SUB1")
        assert ir.Erase("V0$") in sub.body, stem
        assert ir.CallStmt("SUB2", (ir.ArrayRef("V0$", ()), ir.Var("B"))) in sub.body, stem
        assert "  ERASE V0$\n" in emit0.emit(prog), stem


def test_decode_t1_erasestatic():
    # INT EC sub 38 is ERASE of a STATIC array -- gap 33, undiagnosed until
    # TBD73.BAS named it: `SUB Showfile` ends `ERASE recarr$` after
    # `DIM recarr$(5000)`, a LITERAL bound, where t1_erase's `DIM A(N)` is a
    # variable bound. Two runtime routines (sub 36 frees a dynamic heap block,
    # sub 38 re-initializes a static array in place), one source spelling: the
    # compiler picks the vector back from the DIM, so both lift to ir.Erase.
    # The op kinds stay distinct because only the dynamic form's movsi target
    # is a runtime slot block. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_erasestatic", "v10_t1_erasestatic"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert ir.Erase("V0$") in prog, stem
        assert emit0.emit(prog) == (
            '10 DIM V0$(10)\n20 V0$(1) = "X"\n30 ERASE V0$\n40 END\n'
        ), stem


def test_decode_t1_fwdinline():
    # Forwarding a by-ref parameter into a SUB ... INLINE. An inline SUB
    # declares no parameter list at all, yet TB passes it arguments -- the
    # $INLINE bytes read them off the stack themselves (TBWINDOW's Openbox
    # takes fifteen) -- so there is no callee signature to take the arg's type
    # from, and the enclosing SUB's own typing supplies it instead. The call
    # can precede every other use of that parameter, so the spelling is
    # reconciled at proc_ret once the frame's param types settle; otherwise
    # the header and the body name two different variables. Found via wild
    # tbd73.exe. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_fwdinline", "v10_t1_fwdinline"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        wrap = next(s for s in prog if isinstance(s, ir.SubDef) and s.params)
        assert wrap.params == ("A%",), stem
        assert wrap.body[0] == ir.CallStmt("SUB1", (ir.Var("A%"),)), stem
        assert emit0.emit(prog).endswith(
            "20 SUB SUB2(A%)\n  CALL SUB1(A%)\n  PRINT A%\nEND SUB\n"
            "30 B% = 3\n40 CALL SUB2(B%)\n50 END\n"
        ), stem


def test_decode_t1_twosublocal():
    # Two SUBs each declaring `LOCAL done, mloop, ans$, ans1$`. A LOCAL is named
    # from its FRAME offset, so locals at the same offset in different SUBs share
    # a name -- and `_scope_procs`, which synthesizes SHARED from "referenced in
    # more than one region", read each SUB's own locals as cross-region and
    # emitted a SHARED that REPEATED them. TB rejects that outright:
    # `Error 463: Duplicate variable declaration`. It already filtered the SUB's
    # own params and array formals for exactly this reason; locals were missed.
    #
    # Wild tbd73.exe, TBW73.INC:440 and 551 -- `Makevmenu` and `Makehmenu`
    # collide four ways, which blocked the WHOLE program's recompile once it
    # started decoding. Byte-exact, both dialects.
    from tbx import decode0, ir

    for stem in ("t1_twosublocal", "v10_t1_twosublocal"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        subs = [s for s in prog if isinstance(s, ir.SubDef)]
        assert len(subs) == 2, stem
        for sub in subs:
            loc = next(b for b in sub.body if isinstance(b, ir.Local))
            sh = [b for b in sub.body if isinstance(b, ir.Shared)]
            # the genuinely shared globals are still declared...
            assert sh and len(sh[0].names) >= 1, stem
            # ...and no name appears in both lists
            assert not (set(loc.names) & set(sh[0].names)), (
                f"{stem}: {sorted(set(loc.names) & set(sh[0].names))}"
            )


def test_decode_t1_ifblockselect():
    # A compound-condition BLOCK IF whose body is a SELECT CASE. `_inline_safe`
    # only rejected a nested IF, and only BEFORE the last statement, so this
    # decoded as an IfInline and emitted `IF c THEN SELECT CASE` -- which TB
    # rejects with `Error 470: Block/scanned statements not allowed here`. A
    # block-structured statement cannot render inline anywhere, including last.
    # The condition being compound is what left it exposed: round 35's
    # `block_ifs` discriminator only counts a plain RelOp.
    #
    # Also pins the empty-CASE-ELSE fix: `in_else` is set whenever the op after
    # the last arm's jmp is not another arm header, which includes landing on
    # the END SELECT -- so a two-arm SELECT gained a `CASE ELSE` with nothing
    # under it, and that alone was the entire 213-byte round-trip mismatch here.
    #
    # Wild tbd73.exe, TBW73.INC:510-514. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_ifblockselect", "v10_t1_ifblockselect"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        blk = sub.body[0]
        assert isinstance(blk, ir.IfBlock), f"{stem}: {type(blk).__name__}"
        sel = blk.arms[0][1][0]
        assert isinstance(sel, ir.SelectCase), stem
        assert len(sel.arms) == 2 and sel.case_else is None, stem
        src = emit0.emit(prog)
        assert "CASE ELSE" not in src, stem
        assert "THEN SELECT" not in src, stem


def test_decode_t1_ifgotobody():
    # A line-target IF must end its physical line. When one occurs before the
    # end of an enclosing compound IF's body, spelling the outer IF inline
    # produces `IF outer THEN ...: IF inner THEN line: trailing`, rejected by
    # Turbo Basic with Error 431. Wild inv87/invoice at emitted line 4360.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_ifgotobody.exe"))

    assert isinstance(prog[1], ir.IfBlock)
    assert isinstance(prog[1].arms[0][1][1], ir.IfGoto)
    assert emit0.emit(prog) == (
        "10 A% = 1\n"
        "20 IF A% = 1 OR A% = 2 THEN\n"
        '  PRINT "BEFORE"\n'
        "  IF A% = 1 THEN 40\n"
        '  PRINT "AFTER"\n'
        "END IF\n"
        '30 PRINT "OUTSIDE"\n'
        "40 END\n"
    )


def test_decode_t1_ifloopguard():
    # A conditional skip whose apparent body reaches LOOP is source-level
    # guard flow, not a block IF: folding it would put LOOP before END IF and
    # Turbo Basic rejects that with Error 441. Wild inv87/invoice and state.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_ifloopguard.exe"))

    assert isinstance(prog[3], ir.IfGoto)
    assert isinstance(prog[6], ir.Loop)
    assert emit0.emit(prog) == (
        "10 A% = 3\n"
        "20 DO\n"
        "30 INPUT A%\n"
        "40 IF A% >= 0 AND A% <= 2 THEN 80\n"
        "50 IF A% = 0 THEN 100\n"
        "60 BEEP\n"
        "70 LOOP\n"
        '80 PRINT "OK"\n'
        "90 END\n"
        "100 END\n"
    )


def test_decode_t1_gotobeforefor():
    # A GOTO to the address after an upcoming NEXT is not EXIT FOR: it lies
    # before that FOR's header. Exit folding must be scoped to the loop body.
    # Wild inv87/invoice emitted EXIT FOR before FOR (Error 438).
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_gotobeforefor.exe"))

    assert isinstance(prog[3], ir.Goto)
    assert isinstance(prog[4], ir.For)
    assert isinstance(prog[6], ir.NextStmt)


def test_decode_t1_dogotobody():
    # Three consecutive LOOP back-edges in a SUB: one targets an IF body and
    # two nested codeless DO headers share the second IF's address. External
    # GOTOs target both bodies. Loop headers must be placed after the target
    # IFs fold, and every closer's exit is the first non-LOOP operation.
    # Wild horses.exe at 0x848a/0x848c/0x848e.
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_dogotobody.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))

    assert [type(s) for s in sub.body] == [
        ir.IfGoto,
        ir.IfGoto,
        ir.ExitSub,
        ir.Do,
        ir.IfBlock,
        ir.Loop,
        ir.Do,
        ir.Do,
        ir.IfBlock,
        ir.Loop,
        ir.Loop,
    ]
    assert isinstance(sub.body[0].target, ir.BodyLine)
    assert isinstance(sub.body[1].target, ir.BodyLine)


def test_decode_t1_exloopsub():
    # `EXIT LOOP` inside a block IF inside a codeless DO, in a SUB. The IF's
    # region closes at the statement after END IF, so the loop body that
    # follows looks like an else-skip region -- but it ends in the LOOP that
    # closes a DO opened *before* the IF. An ELSE arm cannot hold that closer:
    # TB requires END IF first, which is Error 441. Wild ziptest.exe SUB4.
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_exloopsub.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))

    assert [type(s) for s in sub.body] == [
        ir.Assign,
        ir.Assign,
        ir.Assign,
        ir.Do,
        ir.IfBlock,
        ir.Assign,
        ir.Assign,
        ir.Assign,
        ir.Loop,
        ir.Locate,
    ]
    # The loop closer stays a sibling of the IF, and the exit keeps its name.
    guard = sub.body[4]
    assert guard.else_body is None
    assert any(isinstance(s, ir.ExitLoop) for s in guard.arms[0][1])


def test_decode_t1_exlooptop():
    # The same shape at top level rather than in a SUB, which reaches the
    # ELSE-region fold by a different route and was mis-folded even before the
    # deferred-fold drain existed. Same guard covers both.
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_exlooptop.exe"))

    assert [type(s) for s in prog] == [
        ir.Assign,
        ir.Assign,
        ir.Assign,
        ir.Do,
        ir.IfBlock,
        ir.Assign,
        ir.Assign,
        ir.Assign,
        ir.Loop,
        ir.Locate,
        ir.End,
    ]
    assert prog[4].else_body is None
    assert any(isinstance(s, ir.ExitLoop) for s in prog[4].arms[0][1])


def test_decode_t1_ifthenfncall():
    # A jump target landing on a statement whose FIRST op is `push bp` -- the
    # DEF FN call-staging opener (`push bp; sub sp,N; mov bp,sp`). Third opener
    # in this family after `sub_sp` and `arg_push_array_bp`
    # (test_decode_t1_ifbeforecall); all three return early, before core.py's
    # generic `state.cur = addr` fallback, so the statement was recorded at a
    # later op and the jump had no statement to land on.
    #
    # Wild tbd73.exe, TBD73.BAS:6-13 -- a five-arm `SELECT CASE FNCurdisplay`
    # followed by `msg1$ = STR$(FNCurvideo)`, so all five arm-end jumps land on
    # that statement's `push bp` (`jump target 0xd6a8 is not a statement
    # start`). THIS WAS THE LAST GAP: tbd73.exe decodes end to end with it.
    #
    # The fixture reduces the five converging jumps to one (an inline IF) and
    # keeps `FNCurvideo` verbatim from TBW73.INC:308-312, because the SELECT
    # CASE itself is separately mis-recovered as an IF/GOTO chain --
    # wild/probes/probe_selfpchain, which is the unreduced source shape.
    # Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_ifthenfncall", "v10_t1_ifthenfncall"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert isinstance(prog[0], ir.DefFn) and prog[0].is_block, stem
        # the inline IF's skip target IS the FN-call assignment
        assert prog[1] == ir.IfGoto(
            ir.RelOp("<>", ir.Var("A%"), ir.Lit(0)), 3
        ), stem
        assert prog[3] == ir.Assign(
            ir.Var("C$"), ir.Call("STR$", (ir.FnCall("FNFN1", ()),))
        ), stem
        assert "40 C$ = STR$(FNFN1)\n" in emit0.emit(prog), stem


def test_decode_t1_boolloopuntil():
    # `LOOP UNTIL <compound>` whose retry edge is the template's TRAILING JMP
    # rather than the combining jcc itself. Two polarities occur -- exactly the
    # pair `_lift_while` already distinguishes for a SIMPLE tail test -- and
    # which one the compiler picks is a matter of DISTANCE: a body within short-
    # jcc range gets `jcc <back>`, a longer one gets `jcc <exit>` + `jmp <back>`.
    # `_lift_bool_do_tail` only matched the first, so the second fell through to
    # `_lift_bool_tail` and was consumed as a compound IF.
    #
    # The failure mode was SILENT: no error, but the DO and LOOP statements
    # never materialized and the body's statements were left flat in the
    # enclosing block. This fixture's body is padded past 127 bytes precisely to
    # force the far form; the same program with a short body decodes correctly
    # either way, which is why the shape went unwitnessed.
    #
    # Wild tbd73.exe, TBW73.INC:727: `LOOP UNTIL (ans$ = CHR$(13)) OR
    # (ans$ = CHR$(27))` closes `SUB Makelmenu`'s ~1600-byte DO body. It
    # surfaced only indirectly, as `jump target 0xd49b is not a statement start`
    # raised by the IF on the line before it. Byte-exact, both dialects.
    from tbx import decode0, ir

    for stem in ("t1_boolloopuntil", "v10_t1_boolloopuntil"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert prog[1] == ir.Do(None), stem
        loop = prog[-3]
        assert loop == ir.Loop(
            "UNTIL",
            ir.LogOp(
                "OR",
                ir.Group(
                    ir.RelOp("=", ir.Var("A$"), ir.Call("CHR$", (ir.Lit(13),)))
                ),
                ir.Group(
                    ir.RelOp("=", ir.Var("A$"), ir.Call("CHR$", (ir.Lit(27),)))
                ),
            ),
        ), stem


def test_decode_t1_selarmblockif():
    # Block IFs INSIDE a SELECT CASE arm. An arm body is snapshotted at arm
    # close and never revisited by the top-level `_fold_if` pass -- exactly the
    # situation core.py's proc_ret already handles for a SUB body -- but arms
    # had no fold pass at all, so a block IF in an arm kept its skip-Goto as a
    # spurious statement and lost its ELSE. `select_case._fold_arm` runs the
    # fold with the arm's own end address as `bound`, since nested IFs that all
    # fall through to the end of the arm skip to the arm-close jmp, which is
    # glue rather than a statement.
    #
    # Wild tbd73.exe, TBW73.INC:658-670 (`SUB Makelmenu`, `CASE CHR$(80)`):
    # three nested block IFs, one with an ELSE, all ending at the arm, so three
    # skips converge on its trailing `jmp END SELECT` (`jump target 0xd0ba is
    # not a statement start`). Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_selarmblockif", "v10_t1_selarmblockif"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sel = next(
            b
            for s in prog
            if isinstance(s, ir.SubDef)
            for b in s.body
            if isinstance(b, ir.SelectCase)
        )
        arm = sel.arms[0].body
        # the arm holds ONE block IF, nested three deep, with no leftover Goto
        assert len(arm) == 1 and isinstance(arm[0], ir.IfBlock), stem
        assert not any(isinstance(b, ir.Goto) for b in arm), stem
        inner = arm[0].arms[0][1][1]  # IF C% > 2 THEN ...
        assert isinstance(inner, ir.IfBlock), stem
        deepest = inner.arms[0][1][1]  # IF A% <= B% THEN ... ELSE ...
        assert isinstance(deepest, ir.IfBlock), stem
        assert deepest.else_body == (ir.Assign(ir.Var("A%"), ir.Var("B%")),), stem
        assert emit0.emit(prog).startswith(
            "10 SUB SUB1(A%, B%, C%, D$)\n  SELECT CASE D$\n  CASE \"a\"\n"
            "    IF A% < B% THEN\n      INCR C%\n      IF C% > 2 THEN\n"
            "        DECR C%\n        IF A% <= B% THEN\n          PRINT \"u\"\n"
            "        ELSE\n          A% = B%\n        END IF\n      END IF\n"
            "    END IF\n  CASE ELSE\n    PRINT \"z\"\n  END SELECT\nEND SUB\n"
        ), stem


def test_decode_t1_iftailarm():
    # A single-line IF as the LAST statement of a SELECT CASE arm: its skip
    # lands on the arm's trailing `jmp END SELECT`, which is glue, so there is
    # nothing to name as a GOTO target -- the same situation as an IF closing a
    # procedure (test_decode_t1_iftaillast), extended to arm ends in
    # DecodeState.open_tail_if. `select_case` also has to drain pending inline-IF
    # bodies before folding the arm, because `select_case.step` runs BEFORE the
    # dispatch loop's own close point (DecodeState.close_ifs).
    #
    # Wild tbd73.exe, TBW73.INC:716 (`SUB Makelmenu`, closing `CASE CHR$(71)`):
    # `IF i <> numrecs THEN CALL Drawlist(...)` (`jump target 0xd367 is not a
    # statement start`). Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_iftailarm", "v10_t1_iftailarm"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sel = next(
            b
            for s in prog
            if isinstance(s, ir.SubDef)
            for b in s.body
            if isinstance(b, ir.SelectCase)
        )
        assert sel.arms[0].body == (
            ir.IfInline(
                ir.RelOp("<>", ir.Var("A%"), ir.Var("B%")),
                (ir.Print((ir.StrLit("x"),), True, None, None),),
            ),
        ), stem
        assert emit0.emit(prog).startswith(
            "10 SUB SUB1(A%, B%, C$)\n  SELECT CASE C$\n  CASE \"a\"\n"
            "    IF A% <> B% THEN PRINT \"x\"\n  CASE ELSE\n    PRINT \"z\"\n"
            "  END SELECT\nEND SUB\n"
        ), stem


def test_decode_t1_ifbeforecall():
    # An inline IF whose skip target is the CALL that follows it. A CALL's
    # argument-staging prologue opens the statement, but that family of ops
    # returns early -- before core.py's generic `state.cur = addr` fallback --
    # so the CallStmt was recorded at whichever later op happened to anchor it
    # and the IF's skip address belonged to no statement.
    #
    # TB picks the opener by argument count: `sub sp,N` reserves an outgoing
    # area when there are enough arguments (wild tbd73.exe, TBW73.INC:688-689 --
    # `IF recpos < 1 THEN recpos = 1` then `CALL Drawlist(...)` with five,
    # `jump target 0xd1af`), and otherwise the first push IS the first op --
    # here `arg_push_array_bp`, with two. Both anchor now; this fixture pins the
    # two-argument form and tbd73 witnessed the other. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_ifbeforecall", "v10_t1_ifbeforecall"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef) and len(s.params) == 3)
        assert sub.body[1] == ir.IfGoto(
            ir.RelOp(">=", ir.Var("D%"), ir.Lit(1)), ir.BodyLine(1, 4)
        ), stem
        assert isinstance(sub.body[3], ir.CallStmt), stem
        # the CALL is numbered at the skip target, i.e. it owns that address
        assert "24 CALL SUB1(C$(),B%)\n" in emit0.emit(prog), stem


def test_decode_t1_ifbeforecallref():
    # Two scalar by-reference arguments use arg_push_ref directly, with no
    # outgoing-area prologue. The first push therefore owns the CALL address.
    from tbx import decode0, emit0

    source = emit0.emit(decode0.decode_user_code(_exe("t1_ifbeforecallref.exe")))

    assert "30 IF A% = 0 THEN 50" in source
    assert "50 CALL SUB1(A%,B%)" in source


def test_decode_t1_iftaillast():
    # A single-line `IF cond THEN <stmt>` as the LAST statement of a SUB body.
    # The dispatch pair's false-skip lands on the epilogue, and the usual
    # `IF <negated> THEN <line>` normalization needs that skip address to BE a
    # statement -- which an epilogue never is, since END SUB carries no line
    # number. So the IF has to stay INLINE (DecodeState.open_tail_if); the
    # ifs-close loop fires on the epilogue address before the proc_ret handler
    # runs, so the body folds normally.
    #
    # Wild tbd73.exe, TBW73.INC:634: `IF numrecs - recpos + 1 < i THEN
    # barpos = j - 1` closes `SUB Drawlist` (`jump target 0xcdc4 is not a
    # statement start`). Two compare paths reach this shape and both had to be
    # handled: the by-ref param compare pinned here, and the generic/FP compare
    # in fp_dispatch -- the latter is what unblocked wild ziptest.exe end to end
    # (test_fp_local_for.py::test_ziptest_decodes_with_a_tail_if_closing_a_sub).
    # Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_iftaillast", "v10_t1_iftaillast"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        tail = sub.body[-1]
        # inline, NOT an IfGoto to an unnameable epilogue address
        assert isinstance(tail, ir.IfInline), f"{stem}: {type(tail).__name__}"
        assert tail.body == (
            ir.Assign(ir.Var("B%"), ir.BinOp("-", ir.Var("D"), ir.Lit(1))),
        ), stem
        # the by-ref param stays on the LEFT of the compare (orientation is
        # byte-significant); the relop is the SKIP map's negation
        assert tail.cond.op == ">" and tail.cond.lhs == ir.Var("C%"), stem
        assert emit0.emit(prog) == (
            "10 SUB SUB1(A%, B%, C%)\n  LOCAL D\n  FOR D = 1 TO A%\n"
            "  PRINT D\n  NEXT D\n"
            "  IF C% > 1 + (A% + (-B%)) THEN B% = D - 1\nEND SUB\n"
            "20 E% = 3\n30 F% = 1\n40 G% = 9\n50 CALL SUB1(E%,F%,G%)\n"
            "60 PRINT F%\n70 END\n"
        ), stem


def test_decode_t1_selarmtarget():
    # A jump target landing INSIDE a SELECT CASE arm. Folding an arm moves its
    # statements off the flat list and deletes their `state.addrs` entries, so
    # the addresses vanished with them -- the same loss `core.py` already guards
    # against at proc_ret for a SUB body. `_resolve_targets`'s `map_body`
    # already walks SelectCase arms and knows how to number them; it just never
    # had an address to work with.
    #
    # Wild tbd73.exe, TBW73.INC:486-487 inside `SELECT CASE ans1$ /
    # CASE CHR$(72)`: `IF curntpos < 1 THEN curntpos = itemcount` normalizes to
    # `IF curntpos >= 1 THEN <line>`, whose target is the WHILE header two
    # statements later in the SAME arm (`jump target 0xba9f is not a statement
    # start`). Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_selarmtarget", "v10_t1_selarmtarget"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        sel = next(b for b in sub.body if isinstance(b, ir.SelectCase))
        arm = sel.arms[0].body
        assert arm[1] == ir.IfGoto(
            ir.RelOp(">=", ir.Var("B%"), ir.Lit(1)), ir.BodyLine(0, 6)
        ), stem
        assert arm[3].kind == "WHILE", stem  # the DO WHILE it targets
        assert emit0.emit(prog) == (
            "10 SUB SUB1(A$, B%, C%)\n  SELECT CASE A$\n  CASE \"a\"\n"
            "    DECR B%\n    IF B% >= 1 THEN 16\n    B% = C%\n"
            "16 DO WHILE MID$(A$,B%,1) = \"0\"\n    DECR B%\n    LOOP\n"
            "  CASE ELSE\n    B% = 0\n  END SELECT\nEND SUB\n"
            "20 D$ = \"a\"\n30 E% = 2\n40 F% = 3\n50 CALL SUB1(D$,E%,F%)\n60 END\n"
        ), stem


def test_decode_t1_inlfwdwhile():
    # Respelling a SUB body's `Pxx` placeholders (the SUB ... INLINE forwarding
    # of test_decode_t1_fwdinline above) REBUILDS every statement that mentions
    # a parameter -- and `stmt_addr`, which places BodyLine jump targets inside
    # a SUB body, is keyed on `id(stmt)`. So a respelled statement that is ALSO
    # a jump target lost its address and failed to resolve. The same identity
    # hazard `_resolve_calls` documents, except the node genuinely changes
    # here, so the address must be MOVED rather than the rebuild avoided.
    #
    # Wild tbd73.exe: `SUB Makevmenu` forwards `item$()` to `SUB Sprint
    # INLINE`, so its whole body is respelled -- including the
    # `WHILE MID$(liveitem$,curntpos,1) <> "1"` header (TBW73.INC:444), which
    # is the merge point of the single-line nested IF/ELSE on the line before
    # it (`jump target 0xb192 is not a statement start`). Byte-exact, both
    # dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_inlfwdwhile", "v10_t1_inlfwdwhile"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        wrap = next(s for s in prog if isinstance(s, ir.SubDef) and s.params)
        assert wrap.params == ("A$", "B%", "C%"), stem
        # the DO WHILE header is body phys 7 -- both the outer IF's false-skip
        # and the ELSE arm's skip resolve to it
        assert wrap.body[1] == ir.IfGoto(
            ir.RelOp("<>", ir.Var("B%"), ir.Lit(0)), ir.BodyLine(1, 7)
        ), stem
        assert wrap.body[4] == ir.Goto(ir.BodyLine(1, 7)), stem
        assert wrap.body[6].kind == "WHILE", stem
        assert emit0.emit(prog).endswith(
            "20 SUB SUB2(A$, B%, C%)\n  CALL SUB1(A$)\n"
            "  IF B% <> 0 THEN 27\n  IF C% <> 0 THEN 26\n"
            "  B% = 1\n  GOTO 27\n26 B% = C%\n"
            '27 DO WHILE MID$(A$,B%,1) <> "1"\n  INCR B%\n  LOOP\n'
            "  PRINT B%\nEND SUB\n"
            '30 D$ = "001"\n40 E% = 0\n50 F% = 2\n'
            "60 CALL SUB2(D$,E%,F%)\n70 END\n"
        ), stem


def test_decode_t1_exitsublocstr():
    # EXIT SUB out of a SUB that declares LOCAL strings. Their descriptors are
    # freed in the epilogue, as a run of `arg_ref <disp>; str_temp_free` pairs
    # ahead of the proc_ret (the shape t1_localstr/t1_locstrafterfor already
    # witness) -- and since an EXIT SUB jumps to the FIRST pair rather than to
    # the proc_ret, the frame's exit address has to name the run's start. With
    # only the proc_ret recognized, the EXIT SUB decoded as a plain Goto to an
    # address no statement owns.
    #
    # Wild tbd73.exe, TBW73.INC:452: `EXIT SUB` inside
    # `IF curntpos > itemcount THEN ... END IF` in `SUB Makevmenu`, whose two
    # LOCAL strings `ans$, ans1$` start the epilogue six bytes early
    # (`jump target 0xc2cc is not a statement start`). Byte-exact, both
    # dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_exitsublocstr", "v10_t1_exitsublocstr"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        blk = next(b for b in sub.body if isinstance(b, ir.IfBlock))
        # the EXIT SUB survives as ExitSub inside the block, not as a Goto
        assert blk.arms[0][1][-1] == ir.ExitSub(), stem
        assert not any(isinstance(b, ir.Goto) for b in blk.arms[0][1]), stem
        assert emit0.emit(prog) == (
            "10 SUB SUB1(A%, B%)\n  LOCAL C$\n  C$ = \"x\"\n"
            "  IF A% > B% THEN\n    A% = 0\n    EXIT SUB\n  END IF\n"
            "  PRINT C$; A%\nEND SUB\n"
            "20 D% = 5\n30 E% = 2\n40 CALL SUB1(D%,E%)\n50 END\n"
        ), stem


def test_decode_t1_selelsetarget():
    # A jump target reachable ONLY through a SELECT CASE arm. `_jump_targets`
    # recursed into IfInline bodies but not into IfBlock arms/ELSE or
    # SelectCase arms/CASE ELSE, so it under-delivered on its own "anywhere in
    # the statement tree" contract -- and since `targets` is what promotes an
    # inline-safe IfInline to a block (_fold_if's second leg), the enclosing IF
    # stayed inline and its interior never became addressable.
    #
    # Wild tbd73.exe, TBW73.INC:476-483: the compound
    # `IF ans1$ = CHR$(72) OR ... THEN` block holds two SELECT CASEs, and the
    # inline `IF flon THEN CALL Sprint(...)` ending the FIRST one's CASE ELSE
    # skips forward to the SECOND one's header -- so that address appears
    # nowhere except inside a CASE ELSE (`jump target 0xba64 is not a statement
    # start`). The compound condition matters: a plain RelOp would have been
    # promoted anyway by the block_ifs leg. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_selelsetarget", "v10_t1_selelsetarget"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        # the compound IF is a BLOCK, not an IfInline, and holds both SELECTs
        blk = sub.body[0]
        assert isinstance(blk, ir.IfBlock), f"{stem}: {type(blk).__name__}"
        arm = blk.arms[0][1]
        assert sum(isinstance(b, ir.SelectCase) for b in arm) == 2, stem
        # The CASE ELSE's trailing inline IF used to survive as a conditional
        # GOTO, which forced the second SELECT to be numbered so the skip had
        # something to name. It now folds into the arm as the single-line IF
        # the source actually spells (`IF C% > 2 THEN PRINT "flon"`, see the
        # .bas), so nothing targets the second SELECT and it is unnumbered.
        # Still byte-exact in both dialects.
        assert "\n20 SELECT CASE B$\n" not in emit0.emit(prog), stem
        assert '      IF C% > 2 THEN PRINT "flon"\n' in emit0.emit(prog), stem


def test_decode_t1_fnlitresult():
    # A block DEF FN whose result store is a LITERAL: `FNBar% = 7` compiles to
    # `mov word [bp+0], 7`, the SAME op and cell as the prologue's result-slot
    # init `mov word [bp+0], 0`. Only POSITION separates them -- the prologue's
    # own write is what marks the block form, and a literal-zero result
    # (`FNCurdisplay = 0`) makes the immediate useless as a discriminator.
    #
    # Every bp+0 literal store used to be swallowed as that marker, so the
    # assignment vanished AND the FN lost its `%` (the suffix rides the `int`
    # flag the result store sets -- t1_fnintcall's gap 2). It decoded with no
    # error, silently wrong: `DEF FNFN1` with an EMPTY body. t1_fnintarith's
    # result is COMPUTED (movm_ax_bp), which is why it never showed this.
    #
    # Wild tbd73.exe: TBW73.INC's `DEF FNCurdisplay` assigns its result five
    # times, every one a literal.
    from tbx import decode0, emit0, ir

    for stem in ("t1_fnlitresult", "v10_t1_fnlitresult"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        fn = next(s for s in prog if isinstance(s, ir.DefFn))
        assert fn.name == "FNFN1%" and fn.is_block, stem
        assert fn.body == (ir.FnResult(ir.Lit(7)),), stem
        assert emit0.emit(prog) == (
            "10 DEF FNFN1%\n  FNFN1% = 7\nEND DEF\n"
            "20 SUB SUB1\n  A% = FNFN1% - 7\n  PRINT A%\nEND SUB\n"
            "30 CALL SUB1\n40 END\n"
        ), stem


def test_nested_fn_result_renders_the_fn_name():
    # emit0 substituted the DEF FN's name only for a FnResult at the body's TOP
    # level; a nested one fell through to unparse_stmt, whose FnResult fallback
    # is the placeholder `FN = ...` -- not valid Turbo Basic. Nested results
    # only became reachable once literal result stores stopped being swallowed
    # (see above); wild tbd73.exe's DEF FNCurdisplay assigns its result inside
    # five levels of block IF.
    from tbx import emit0, ir

    prog = [
        ir.DefFn(
            "FNX%",
            (),
            (
                ir.IfInline(
                    ir.RelOp("=", ir.Var("A%"), ir.Lit(1)),
                    (ir.FnResult(ir.Lit(4)), ir.ExitDef()),
                ),
                ir.FnResult(ir.Lit(0)),
            ),
            True,
        ),
        ir.End(),
    ]
    src = emit0.emit(prog)
    assert "FNX% = 4" in src and "FN = 4" not in src
    assert "FNX% = 0" in src


def test_decode_t1_fnintarith():
    # t1_fnintcall's sibling, and TWO gaps in one shape.
    #
    # 1. The caller's `mov ax,[bp+0]` result read was keyed on the fn_call
    #    being the IMMEDIATELY preceding op. When the result feeds a binary
    #    operator, the OTHER operand was evaluated before the call and is
    #    banked into bx right after it, so a `movbxax` sits between and the
    #    key missed: `[bp+0] outside the open LOCAL frame`. Worse, with a DEF
    #    FN frame open instead of a SUB frame the same shape did not raise at
    #    all -- loc_local fell through to its DEF-FN-param branch and returned
    #    P00%, a SILENT mis-decode (wild tbd73.exe, three sites at 0xa5xx).
    # 2. A ZERO-ARG DEF FN is declared without a parameter list and called
    #    WITHOUT parens; TB rejects `FNFN1%()` outright, so the emitted source
    #    did not even recompile. No corpus fixture had ever called a zero-arg
    #    DEF FN, so nothing witnessed it.
    #
    # Wild tbd73.exe: TBWINDOW's `IF FNCurvideo <> 7 THEN` (TBW73.INC:339).
    # The witness uses arithmetic rather than that IF because the compare form
    # is still blocked by two unrelated open gaps -- see PLAN.md round 28.
    from tbx import decode0, emit0, ir

    for stem in ("t1_fnintarith", "v10_t1_fnintarith"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        fn = next(s for s in prog if isinstance(s, ir.DefFn))
        assert fn.name == "FNFN1%" and fn.params == (), stem
        assert emit0.emit(prog) == (
            "10 DEF FNFN1%\n  FNFN1% = A% AND 15\nEND DEF\n"
            "20 SUB SUB1\n  B% = FNFN1% - 7\n  PRINT B%\nEND SUB\n"
            "30 A% = 7\n40 CALL SUB1\n50 END\n"
        ), stem


def test_decode_t1_fnintcall():
    # An INTEGER-valued DEF FN called from inside a SUB body. Two gaps in one
    # shape: the caller reads the result with `mov ax,[bp+0]` (the integer
    # sibling of every existing fixture's `fld_bp 0`), which was only accepted
    # when no frame was open -- but mov_bp_sp has repointed BP at the staging
    # frame, so keying on the preceding fn_call is what lets the call happen
    # inside a SUB at all. And the FN's own `%` was dropped: an unsuffixed
    # name is SINGLE to TB, so the recompile widened the result and every
    # reference to it (32 bytes). Found via wild tbd73.exe, whose TBWINDOW
    # SUBs call FNAttr() under DEFINT a-z. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_fnintcall", "v10_t1_fnintcall"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        fn = next(s for s in prog if isinstance(s, ir.DefFn))
        assert fn.name == "FNFN1%", stem
        assert emit0.emit(prog) == (
            "10 DEF FNFN1%(A%)\n  FNFN1% = A% + 1\nEND DEF\n"
            "20 SUB SUB1\n  B% = FNFN1%(2)\n  PRINT B%\nEND SUB\n"
            "30 CALL SUB1\n40 END\n"
        ), stem


def test_decode_t1_inlinethendef():
    # A chained declaration skip-jmp landing on a block DEF FN: a DEF FN has
    # no proc_enter of its own, so the chain's next-op test (proc_enter /
    # inline_sub / opaque_helper) missed it, main_start stopped advancing, and
    # the DEF FN never auto-opened. Its `mov [bp+0],0` result-slot zero-fill
    # is the marker; safe to accept because `addr == main_start` already pins
    # the jmp to exactly where the previous hop landed. Found via wild
    # tbd73.exe, whose TBWINDOW DEF FN run follows its inline SUBs.
    # Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_inlinethendef", "v10_t1_inlinethendef"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        fn = next(s for s in prog if isinstance(s, ir.DefFn))
        assert fn.is_block and fn.name == "FNFN1", stem
        assert emit0.emit(prog).endswith(
            "60 DEF FNFN1(B)\n  LOCAL C\n  C = B + 1\n  FNFN1 = C\nEND DEF\n"
        ), stem


def test_decode_t1_commonarrstatic():
    # The ORDINARY region past the COMMON band is not scalars-only: an
    # ordinary STATIC array's own 0x36 slot sits there first, ahead of the
    # scalars. On the non-COMMON path the static count falls out of the gap
    # between var_base and the first runtime block; here the statics come
    # AFTER the blocks, so they are read off the image once ds is known.
    # Found via wild tbd73.exe. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_commonarrstatic", "v10_t1_commonarrstatic"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert [s.name for s in prog if isinstance(s, ir.Dim)] == ["V0", "V1"], stem
        assert ir.Common(("V1(1)",)) in prog, stem

    for stem in ("t1_commonarrsubstatic", "v10_t1_commonarrsubstatic"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert ir.Common(("V1(1)",)) in prog, stem
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        assert any(isinstance(b, ir.Dim) and b.name == "V0$" for b in sub.body), stem
        assert emit0.emit(prog).endswith(
            '60 SUB SUB1\n  DIM V0$(50)\n  V0$(1) = "X"\n  PRINT V0$(1)\nEND SUB\n'
        ), stem


def test_decode_t1_erasepre():
    # ERASE reached BEFORE the array's own DIM in address order -- ordinary
    # when the ERASE sits on an earlier line, and in SUB bodies, which the
    # compiler emits ahead of the main code that DIMs. The slot is a known
    # runtime block either way, so it is named off the grid rather than
    # requiring r_arrs to have seen the DIM. Wild rs.exe. Byte-exact, both
    # dialects.
    from tbx import decode0, ir

    for stem in ("t1_erasepre", "v10_t1_erasepre"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert any(s == ir.Erase("V0") for s in _flat(prog)), stem


def _flat(stmts):
    for s in stmts:
        yield s
        for f in ("body", "arms", "else_body"):
            v = getattr(s, f, None)
            if isinstance(v, tuple):
                for x in v:
                    if isinstance(x, tuple):
                        for y in x:
                            if isinstance(y, tuple):
                                yield from _flat(y)
                    elif hasattr(x, "__dataclass_fields__"):
                        yield from _flat((x,))


def test_decode_t1_arrfwd():
    # Forwarding a whole-array PARAMETER onward as a whole-array CALL argument
    # (`mov ax,ss; mov ds,ax; mov si,bp; add si,d8; INT D4`): the descriptor
    # lives in the caller's frame, not DGROUP, so DS points at the stack
    # segment for the push and is restored right after. Found via wild
    # tbd73.exe, whose TBW73.INC relays item$(1) through Makehmenu.
    # Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_arrfwd", "v10_t1_arrfwd"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        one = next(s for s in prog if isinstance(s, ir.SubDef) and s.name == "SUB1")
        assert one.params == ("A(1)",), stem
        assert one.body == (ir.CallStmt("SUB2", (ir.ArrayRef("A", ()),)),), stem
        assert emit0.emit(prog).endswith(
            "50 SUB SUB1(A(1))\n  CALL SUB2(A())\nEND SUB\n"
            "60 SUB SUB2(A(1))\n  PRINT A(1)\nEND SUB\n"
        ), stem


def test_relayed_string_array_param_stays_loud():
    # A relay carries no element-type evidence -- the SUB never touches an
    # element -- so its P-name is unsuffixed. That is right only when the
    # callee's parameter is untyped too; for a STRING array the header we
    # would emit contradicts the callee's and TB rejects the source outright
    # (probe_arrfwd's emitted form does not recompile). Refuse rather than
    # emit something that cannot compile.
    import pytest

    from tbx import decode0

    exe = open(
        os.path.join(_ROOT, "..", "wild", "probes", "probe_arrfwd.exe"), "rb"
    ).read()
    with pytest.raises(ValueError, match=r"relayed array parameter P06"):
        decode0.decode_user_code(exe)


def test_decode_t1_inlinedata():
    # An inline SUB carrying trailing data inside its own body -- TBWINDOW's
    # Getftblptr keeps the frame table in $INLINE lines between its own code
    # and its END SUB, so the compiler emits one uninterrupted blob and the
    # SUB/data boundary is not in the bytes at all. It does not need to be:
    # TB appends the terminating CB itself, so re-emitting the whole blob as
    # one $INLINE list recompiles byte-identically. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_inlinedata", "v10_t1_inlinedata"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        assert sub.body[0].data == bytes(
            (0x55, 0x8B, 0xEC, 0xC4, 0x7E, 0x0A, 0x5D, 0xCB,
             0xDA, 0xBF, 0xC0, 0xD9, 0xB3, 0xC4)
        ), stem
        assert emit0.emit(prog).endswith(
            "40 SUB SUB1 INLINE\n  $INLINE &H55, &H8B, &HEC, &HC4, &H7E, &H0A, "
            "&H5D, &HCB, &HDA, &HBF, &HC0, &HD9, &HB3, &HC4\nEND SUB\n"
        ), stem


def test_decode_t1_segment():
    # $SEGMENT closes the current code segment and continues the program in
    # the next one, which the compiler reaches with a far jump to that
    # segment's offset 0. That EA was read as the fixed runtime handoff and
    # ENDED the scan, so everything the metacommand moved -- in TBWINDOW,
    # every SUB -- was silently dropped and the CALL into it mis-resolved to
    # a GOSUB. The scan now follows it, far_call/fn_call fold the segment
    # word into their target (0 for every single-segment program, so a no-op
    # elsewhere), and the metacommand rides out as a metastatement. Found via
    # wild tbd73.exe. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_segment", "v10_t1_segment"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert prog[1] == ir.CallStmt("SUB1", ()), stem
        assert any(isinstance(s, ir.SubDef) for s in prog), stem
        assert (3, "$SEGMENT") in prog.metas, stem
        assert emit0.emit(prog) == (
            "10 A% = 1\n20 CALL SUB1\n30 END\n$SEGMENT\n40 SUB SUB1\n"
            '  PRINT "F"\nEND SUB\n'
        ), stem


def test_decode_t1_commonarr():
    # A COMMON'd array's 0x36 descriptor block sits in the CHAIN-persistent
    # COMMON band at DS:0110, BELOW var_base, so the layout solver's "runtime
    # blocks follow the statics at var_base" arithmetic went negative and it
    # refused the whole image. COMMON itself compiles to no ops at all, so the
    # band position is the only evidence the declaration existed: it is
    # synthesized back with the array's rank, after the DIM (TB compiles
    # DIM-then-COMMON and COMMON-then-DIM two bytes apart), and the array
    # declares with a plain DIM rather than DIM DYNAMIC. Found via wild
    # tbd73.exe (TBWINDOW 7.3 COMMONs eleven DIMmed arrays). Byte-exact, both
    # dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_commonarr", "v10_t1_commonarr"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert isinstance(prog[0], ir.Dim) and not prog[0].dynamic, stem
        assert prog[1] == ir.Common(("V0(1)",)), stem
        assert emit0.emit(prog) == (
            "10 DIM V0(10)\n20 COMMON V0(1)\n30 V0(1) = 5\n40 PRINT V0(1)\n50 END\n"
        ), stem

    prog = decode0.decode_user_code(_exe("t1_commonarr2.exe"))
    assert prog[1] == ir.Common(("V0(1)", "V1(1)"))


def test_decode_t1_commonarrmix():
    # The COMMON band runs on past the descriptor blocks into the COMMON
    # SCALARS, then aligns to 16 and carries a 16-byte stamp before the
    # ORDINARY band begins at stamp+0x10 (`COMMON A(1), C%` puts C% at 0x146,
    # right after the single block, stamp at 0x150, ordinary band empty at
    # 0x160). Those band scalars ARE the COMMON declarations -- emitting them
    # as ordinary variables recompiles ~16 bytes differently. Byte-exact, both
    # dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_commonarrmix", "v10_t1_commonarrmix"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        assert prog[1] == ir.Common(("V0(1)", "A%")), stem
        assert emit0.emit(prog) == (
            "10 DIM V0(10)\n20 COMMON V0(1), A%\n30 V0(1) = 5\n40 A% = 7\n"
            "50 PRINT V0(1); A%\n60 END\n"
        ), stem


def test_decode_t1_fwdcalltgt():
    # _resolve_calls preserves the `is` identity of every UNCHANGED statement
    # so nested jump targets survive -- but a statement it DOES rebuild (here
    # the forward CALL whose ("addr", n) placeholder becomes a real SUB name)
    # left its stmt_addr entry keyed to the discarded object, orphaning the
    # address as surely as a fold would. A body line that both CALLs a
    # later-defined SUB and is itself a jump target could therefore never
    # resolve. Found via wild rsltest.exe. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_fwdcalltgt", "v10_t1_fwdcalltgt"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        one = next(s for s in prog if isinstance(s, ir.SubDef) and s.name == "SUB1")
        jump = next(s for s in one.body if isinstance(s, ir.IfGoto))
        assert isinstance(jump.target, ir.BodyLine), stem
        assert emit0.emit(prog) == (
            "10 CALL SUB1\n20 END\n30 SUB SUB1\n  A% = 1\n  IF A% = 1 THEN 34\n"
            '  A% = 2\n34 CALL SUB2\nEND SUB\n40 SUB SUB2\n  PRINT "T"\nEND SUB\n'
        ), stem


def test_decode_t1_dblhook():
    # A code-less source line (END IF) under event trapping still gets its own
    # per-statement CC hook, so two trap_hooks pile up ahead of the next real
    # statement. The decoder stamps that statement with the FIRST hook, but the
    # compiler's block-IF arm tails jump to the LAST -- which matched no
    # statement, so the fold never happened and the else-skip Goto survived
    # into _resolve_targets. Jump targets landing inside a hook run are now
    # normalized onto the run's first hook (every hook in a run precedes the
    # same statement). The SUB variant additionally needed the body to get the
    # _fold_if pass the top level always ran, and map_body to account ELSEIF/
    # ELSE arms exactly. Found via wild rsltest.exe. Byte-exact, both dialects.
    from tbx import decode0, emit0, ir

    for stem in ("t1_dblhook", "v10_t1_dblhook"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        blk = next(s for s in prog if isinstance(s, ir.IfBlock))
        assert len(blk.arms) == 2 and blk.else_body is not None, stem
        assert emit0.emit(prog) == (
            "10 ON TIMER(1) GOSUB 70\n20 TIMER ON\n30 A = 1\n"
            "40 IF A > 1 THEN\n  B% = 1\nELSEIF A > 0 THEN\n  B% = 2\n"
            "ELSE\n  B% = 3\nEND IF\n50 PRINT B%\n60 END\n70 RETURN\n"
        ), stem

    for stem in ("t1_dblhooksub", "v10_t1_dblhooksub"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        blk = next(s for s in sub.body if isinstance(s, ir.IfBlock))
        assert len(blk.arms) == 2 and blk.else_body is not None, stem
        assert not any(isinstance(s, ir.Goto) for s in sub.body), stem
        assert emit0.emit(prog) == (
            "10 ON TIMER(1) GOSUB 50\n20 TIMER ON\n30 CALL SUB1\n40 END\n"
            "50 RETURN\n60 SUB SUB1\n  A = 1\n  IF A > 1 THEN\n    B% = 1\n"
            "  ELSEIF A > 0 THEN\n    B% = 2\n  ELSE\n    B% = 3\n  END IF\n"
            "  PRINT B%\nEND SUB\n"
        ), stem


def test_decode_t1_scgoto():
    # A GOTO landing on a numbered line past a multi-arm SELECT CASE
    # (with CASE ELSE) inside a SUB body: _resolve_targets' map_body only
    # ever recursed accurately through a single-arm, ELSE-less IfBlock
    # ("fully accounted": header + recursed body + END IF); a SelectCase
    # sets a "multi" flag and keeps a placeholder line count instead,
    # raising if a LATER target actually needs to resolve past it.
    # emit0.py's own SelectCase rendering is fully deterministic (1 +
    # per-arm(1 + body) + [1 + case_else body] + 1), so map_body now
    # recurses through it the same way. Found via wild rsltest.exe
    # (TBMENU.INC's `select case ans$ ... end select` followed by `if
    # curntpos% > itemcount% then curntpos% = 1`, itself a jump target).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_scgoto.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    goto = sub.body[1]
    assert isinstance(goto, ir.Goto) and isinstance(goto.target, ir.BodyLine)
    assert emit0.emit(prog) == (
        "10 CALL SUB1\n20 END\n30 SUB SUB1\n"
        '  A$ = "X"\n  GOTO 41\n  SELECT CASE A$\n  CASE "A"\n'
        '    PRINT "A"\n  CASE "B"\n    PRINT "B"\n  CASE ELSE\n'
        '    PRINT "ELSE"\n  END SELECT\n41 PRINT "AFTER"\nEND SUB\n'
    )


def test_decode_t1_scgotone():
    # Same as test_decode_t1_scgoto but without CASE ELSE, exercising
    # that branch of the new recursion independently.
    from tbx import decode0, emit0

    prog = decode0.decode_user_code(_exe("t1_scgotone.exe"))
    assert emit0.emit(prog) == (
        "10 CALL SUB1\n20 END\n30 SUB SUB1\n"
        '  A$ = "X"\n  GOTO 39\n  SELECT CASE A$\n  CASE "A"\n'
        '    PRINT "A"\n  CASE "B"\n    PRINT "B"\n  END SELECT\n'
        '39 PRINT "AFTER"\nEND SUB\n'
    )


def test_decode_t1_movaxmpool():
    # movax_m (a plain scalar-load op) was missing the pooled-int-literal
    # fallback its siblings addax_m/subax_m/imul_m already have: `3724 \
    # A%` (a pooled literal as the LEFT operand of an integer divide, wild
    # rsltest.exe) raised unconditionally instead of falling back to
    # state.pool_lit() the same way those do.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_movaxmpool.exe"))
    assert prog[1] == ir.Assign(
        ir.Var("B%"), ir.BinOp("\\", ir.Lit(3724), ir.Var("A%"))
    )
    assert emit0.emit(prog) == (
        "10 A% = 2\n20 B% = 3724 \\ A%\n30 PRINT B%\n40 END\n"
    )


def test_decode_t1_peekand():
    # A bare-value (uncompared) compound-AND first term: `PEEK(&H410) AND
    # &H40 = 48` -- Turbo Basic's relational-over-AND precedence parses
    # this as `PEEK(&H410) AND (&H40 = 48)`, a genuine bitwise AND (not a
    # short-circuit LOGICAL and) of PEEK's raw byte with a materialized
    # comparison. TB's AND/OR operate on raw integer values, so a bare
    # value never gets the usual movax-FFFF materialization a comparison
    # does; only the SECOND term (the comparison) does, and PEEK's own
    # short-circuit ("if 0, the AND result is already known, skip
    # evaluating the comparison entirely") reaches straight past it.
    # Found via wild rsltest.exe (TEST.BAS line 159, video-adapter
    # detection via the BIOS equipment byte).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_peekand.exe"))
    blk = next(s for s in prog if isinstance(s, ir.IfBlock))
    cond, _ = blk.arms[0]
    assert cond == ir.LogOp(
        "AND",
        ir.Call("PEEK", (ir.Lit(1040),)),
        ir.RelOp("=", ir.Lit(64), ir.Lit(48)),
    )
    assert emit0.emit(prog) == (
        "10 IF PEEK(1040) AND 64 = 48 THEN\n"
        '  A$ = "B & N"\nELSE\n  A$ = "COLOR"\nEND IF\n'
        "20 PRINT A$\n30 END\n"
    )


def test_decode_t1_selcasechr():
    # SELECT CASE on a STRING selector under active event trapping, with a
    # multi-guard arm mixing computed CHR$(n) guards and a bare string
    # literal: `CASE CHR$(88), CHR$(89), "Z"`. Three compounding gaps, all
    # found via wild rsltest.exe (TBMENU.INC's `select case ans$ / case
    # chr$(72),chr$(75),"-","8","4" / ...`):
    #   (1) the string-entry gate's lookahead sanity check didn't tolerate
    #       an event-trapping poll hook landing between `movsi [temp];
    #       strassign` and the first arm header;
    #   (2) no shape at all recognized a COMPUTED (CHR$) guard, only a
    #       bare variable/pooled-literal one (movsi val;rt...);
    #   (3) the bare form's own arm-continuation logic unconditionally
    #       called _begin_body, silently discarding every guard after the
    #       first in a comma list instead of continuing to test them --
    #       fixed by mirroring the numeric arm's own cc==0x75(JNE, non-
    #       final)/cc==0x74(JE, final) split, the only reliable signal
    #       (structural position alone can't tell them apart: both land
    #       on the very next op when the compiler lays guards out
    #       contiguously).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_selcasechr.exe"))
    sc = next(s for s in prog if isinstance(s, ir.SelectCase))
    assert sc.arms[0].guards == (
        ir.CaseValue(ir.Call("CHR$", (ir.Lit(88),))),
        ir.CaseValue(ir.Call("CHR$", (ir.Lit(89),))),
        ir.CaseValue(ir.StrLit("Z")),
    )
    assert emit0.emit(prog) == (
        "10 ON TIMER(1) GOSUB 60\n20 TIMER ON\n30 A$ = \"Y\"\n"
        "40 SELECT CASE A$\n"
        'CASE CHR$(88), CHR$(89), "Z"\n  PRINT "MATCH"\n'
        'CASE ELSE\n  PRINT "NOMATCH"\nEND SELECT\n'
        "50 END\n60 RETURN\n"
    )


def test_decode_t1_whileinstat():
    # A HEAD-test WHILE loop whose condition is a bare value with no
    # materialization prefix (WHILE <function call>, not WHILE <compare>):
    # `fn_ax0;notax;orax;jcc;jmp` with no leading `movax 0FFFF;jcc;incax`
    # template for _lift_while to key off. Under active event trapping (an
    # ON TIMER trap, matching wild rsltest.exe's ON TIMER-driven benchmark
    # loop) a poll hook precedes the condition's own first op and stamps
    # state.cur onto ITSELF, not onto the following op the way trace-hook
    # stripping does elsewhere -- so the loop-back jmps's real target
    # lands one op past state.cur. Found via wild rsltest.exe (TBMENU.INC's
    # dead-code MAKEMENU: `WHILE NOT INSTAT` / `WEND`, an empty-body
    # busy-wait poll).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_whileinstat.exe"))
    loops = [s for s in prog if isinstance(s, (ir.Do, ir.Loop))]
    assert loops == [
        ir.Do("WHILE", ir.Not(ir.Nullary("INSTAT"))),
        ir.Loop(None, None),
    ]
    assert emit0.emit(prog) == (
        "10 ON TIMER(1) GOSUB 70\n20 TIMER ON\n"
        "30 DO WHILE NOT INSTAT\n40 LOOP\n50 PRINT \"DONE\"\n60 END\n"
        "70 RETURN\n"
    )


def test_decode_t1_arrbyrefidx():
    # A computed-index element of a NEAR/STATIC array, passed BY REFERENCE
    # to an ordinary far-called SUB: needs an explicit ES:SI far pointer
    # (movdx <relocated DS segment>; movesdx) even though the array itself
    # is near -- the computed-index sibling of core.py's own constant-index
    # `movsi d; movdx blk; movesdx; arg_push_arr` handling, which doesn't
    # validate the movdx segment value either. Found via wild rsltest.exe
    # (TBMENU.INC's dead-code MAKEMENU passing ITEM$(mloop%), an implicitly
    # auto-dimensioned 11-element STATIC string array, into QPRINTC).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_arrbyrefidx.exe"))
    calls = [s for s in prog if isinstance(s, ir.CallStmt)]
    assert calls == [
        ir.CallStmt("SUB1", (ir.ArrayRef("V0%", (ir.Var("A%"),)),))
    ]
    assert emit0.emit(prog) == (
        "10 DIM V0%(5)\n20 V0%(2) = 42\n30 A% = 2\n"
        "40 CALL SUB1(V0%(A%))\n50 END\n60 SUB SUB1(B%)\n"
        "  B% = B% + 1\nEND SUB\n"
    )


def test_wild_baby_event_hook_loops_decode():
    """Event-hook-prefixed loop targets normalize to their semantic start."""
    from tbx import decode0, emit0, ir

    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("baby.exe"))
    src = emit0.emit(prog)
    assert any(isinstance(s, ir.Loop) for s in prog)
    assert "INKEY$" in src


def test_wild_cvt2tb_opaque_helper_advances():
    # A twelfth framed helper (BODY_12, wild CVT2TB.EXE): a small,
    # program-specific directory-search primitive (AH=4Eh DOS Find
    # First, INT 21h) wrapped in the same framing/epilogue convention as
    # the rest of the family -- unlike BODY_11 (a known third-party
    # library, TBWINDOW), this one is unique to this one program, which
    # the fingerprint mechanism handles identically either way.
    import pytest

    from tbx import decode0

    from conftest import wild_hits_bytes

    with pytest.raises(ValueError, match=r"\[bp\+6\] outside the open LOCAL frame"):
        decode0.decode_user_code(wild_hits_bytes("CVT2TB.EXE"))


def test_wild_phone_opaque_helper_advances():
    # An eleventh framed helper (BODY_11, wild phone.exe): same overall
    # framing/epilogue as the BODY..BODY_10 family, but much larger
    # (1740 bytes) -- its own CALL leads into an embedded box-drawing
    # character DATA table before real code resumes near the end. Exact
    # byte-fingerprint match; size doesn't change the recognition
    # mechanism. phone.exe's NEXT blocker (right after this helper) is a
    # chain of jmp-to-jmp thunks landing on further helper-shaped code --
    # a genuinely different, unfamiliar trampoline/overlay structure not
    # attempted here; only this one confirmed closure is tested.
    import pytest

    from tbx import decode0

    from conftest import wild_hits_bytes

    with pytest.raises(ValueError, match=r"unhandled byte 33 at 0xa9ae"):
        decode0.decode_user_code(wild_hits_bytes("phone.exe"))


def test_wild_filepatc_opaque_helpers_advance():
    # Two more framed far-procedure helpers (BODY_9/BODY_10, wild
    # filepatc.exe), sitting back-to-back right after the already-
    # calibrated BODY..BODY_8 family (all from wild resume.exe): same
    # push-bp/push-ds/push-es framing and CGA-adjacent bp-relative param
    # convention, but each ends directly `pop bp; retf` with no INT3
    # padding byte, so neither is paired with a "_V10" transform the way
    # BODY_3..8 are -- only these exact two shapes are witnessed. Like
    # the other opaque-helper closures, this is coverage-only recovery
    # (fingerprint match, not a byte pattern with an oracle-verifiable
    # source spelling), so it's tested as a wild-witness advance.
    import pytest

    from tbx import decode0

    from conftest import wild_hits_bytes

    with pytest.raises(
        ValueError,
        match=r"displacement 0x1054 is neither scalar nor array element",
    ):
        decode0.decode_user_code(wild_hits_bytes("filepatc.exe"))


def test_wild_mf_compound_if_far_exit_advances():
    # A compound-IF's second term closing dispatch pair can end in a FAR
    # `jmpf` (EA, 5 bytes) instead of the near `jmp` (E9, 3 bytes) when the
    # exit target crosses segments -- the same op-kind breadth `direct_bool`
    # already accepts for its own dispatch-tail jmp, extended to
    # `_lift_bool_tail`'s tail-shape check. Like the OTHER established
    # `jmpf` closures in this campaign (PLAN.md, "Far JMP (EA) runtime-
    # revision group"), the oracle's local toolchain doesn't reproduce
    # segment-crossing jumps, so this is a wild-only witness, not an
    # oracle-verified fixture.
    import pytest

    from tbx import decode0

    from conftest import wild_hits_bytes

    # The runtime-grid layout now resolves; this advances mf.exe to its next
    # independent string-descriptor recovery gap.
    with pytest.raises(
        ValueError, match=r"bad string descriptor at \[0x05a0\]: 0x01b8"
    ):
        decode0.decode_user_code(wild_hits_bytes("mf.exe"))


def test_decode_t1_forvarlimfar():
    # Variable-limit integer FOR/NEXT whose body is beyond short-jump
    # range: the NEXT test uses the inverse signed condition + JMP instead
    # of a direct JLE to body (the same indirect form the literal-limit
    # cmp_mi8 case already handles). Wild pwinst.exe.
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_forvarlimfar.exe"))
    loops = [s for s in prog if isinstance(s, ir.For)]
    assert loops == [ir.For(ir.Var("B%"), ir.Lit(1), ir.Var("A%"), ir.Lit(1))]
    assert any(isinstance(s, ir.NextStmt) and s.var == ir.Var("B%") for s in prog)


def test_decode_t1_midvarstart():
    # `MID$(A$, N%) = B$` -- the start position is a variable expression,
    # not just a literal: state.ax already holds whatever computed it
    # (movax_m etc.) by the time the midassign op fires. Wild pwinst.exe.
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_midvarstart.exe"))
    assert (
        ir.MidAssign(ir.Var("A$"), ir.Var("C%"), ir.Var("B$")) in prog
    )


def test_decode_t1_inpfilearr():
    # `INPUT #n, A$(i,j), B%(i,j)` -- a computed-index numeric array element
    # as a LATER INPUT# target: the generic FP->int scratch bridge
    # (`fistp <scratch>; fwait; movaxmem <scratch>`) lands the read value in
    # ax, then the ordinary computed-element integer write (movm_ax_si)
    # consumes it, unlike the direct fstp_si path a lone numeric target
    # uses. Wild pfl.exe/pwinst.exe.
    from tbx import decode0, ir

    prog = decode0.decode_user_code(_exe("t1_inpfilearr.exe"))
    assert ir.InputFile(
        1,
        (
            ir.ArrayRef("V0$", (ir.Var("A%"), ir.Var("B%"))),
            ir.ArrayRef("V1%", (ir.Var("A%"), ir.Var("B%"))),
        ),
    ) in prog


def test_decode_t1_byrefdbl():
    # By-ref DOUBLE (`#`) SUB param, the m64 sibling of t1_byreflong's LONG
    # family: FLD/FSTP/FCOMP onto/from/against the FP stack via `les
    # si,[bp+N]` + ESC D9/DD by-ref addressing. Wild bmaster.exe/ifi.exe.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_byrefdbl.exe")))
    assert src == (
        "10 SUB SUB1(A#)\n"
        "  PRINT A#\n  A# = 1.5#\n"
        '  IF A# <> 1.5# THEN 15\n  PRINT "YES"\n15 PRINT "DONE"\n'
        "END SUB\n"
        "20 B# = 2.5#\n30 CALL SUB1(B#)\n40 PRINT B#\n50 END\n"
    )


def test_decode_t1_localincr():
    # `INCR X%` on a LOCAL scalar: a bare `inc [bp+d8]`, NOT byte-identical
    # to `X% = X% + 1` (which compiles to addm_ax_bp) the way the two
    # spellings are for a DGROUP scalar (t1_incr1) -- decodes as its own
    # `ir.Incr` node instead of normalizing to an Assign. Wild bmaster.exe/
    # ifi.exe.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_localincr.exe"))
    sub = prog[0]
    assert sub.body[2] == ir.Incr(ir.Var("A%"))
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n  LOCAL A%\n  A% = 5\n  INCR A%\n  PRINT A%\nEND SUB\n"
        "20 CALL SUB1\n30 END\n"
    )


def test_decode_t1_localdecr():
    # `DECR X%` on a LOCAL scalar: the decrement sibling of t1_localincr's
    # bare `inc [bp+d8]`, same LOCAL-only non-identity with `X% = X% - 1`.
    # Wild horses.exe.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_localdecr.exe"))
    sub = prog[0]
    assert sub.body[2] == ir.Decr(ir.Var("A%"))
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n  LOCAL A%\n  A% = 5\n  DECR A%\n  PRINT A%\nEND SUB\n"
        "20 CALL SUB1\n30 END\n"
    )


def test_decode_t1_byrefincr():
    # `INCR A%` on a by-ref INTEGER SUB param: the far/by-ref sibling of
    # t1_localincr's LOCAL case, same bare-INC-vs-addm_ax_si non-identity.
    # Wild bmaster.exe/ifi.exe.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_byrefincr.exe"))
    sub = prog[0]
    assert sub.body[0] == ir.Incr(ir.Var("A%"))
    assert emit0.emit(prog) == (
        "10 SUB SUB1(A%)\n  INCR A%\n  PRINT A%\nEND SUB\n"
        "20 B% = 5\n30 CALL SUB1(B%)\n40 END\n"
    )


def test_decode_t1_byrefdecr():
    # `DECR A%` on a by-ref INTEGER SUB param: the descending mirror of
    # t1_byrefincr just above. `dec es:[si]` had only its FOR-NEXT STEP -1
    # leg -- the bare-statement leg was explicitly left fail-loud as
    # unwitnessed. Wild tbd73.exe supplies the witness: TBWINDOW
    # `SUB Makevmenu`, `CASE CHR$(72) : DECR curntpos`.
    from tbx import decode0, emit0, ir

    for stem in ("t1_byrefdecr.exe", "v10_t1_byrefdecr.exe"):
        prog = decode0.decode_user_code(_exe(stem))
        sub = prog[0]
        assert sub.body[0] == ir.Decr(ir.Var("A%")), stem
        assert emit0.emit(prog) == (
            "10 SUB SUB1(A%)\n  DECR A%\n  PRINT A%\nEND SUB\n"
            "20 B% = 5\n30 CALL SUB1(B%)\n40 END\n"
        ), stem


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


def test_decode_t1_nestelse():
    # A nested block IF/ELSE inside another block IF. `_fold_body`, which folds
    # a nested body, had NO ELSE leg -- its docstring said "bodies carry no
    # Goto-else marker", true only while nested ELSE was unwitnessed. So the
    # ELSE arm was LOST: the else-skip Goto survived as a spurious statement and
    # the ELSE body was hoisted to a sibling of the IF:
    #
    #   IF A = 2 THEN / B = 1 / GOTO 30 / END IF / B = 2      (wrong)
    #
    # `_fold_body` now delegates to `_fold_if` when a nested else-skip marker is
    # actually present, so there is one implementation of the ELSE
    # reconstruction. The skip lands on the ENCLOSING structure's merge point,
    # outside this body, which is what `_fold_if`'s `bound` parameter is for.
    #
    # Wild tbd73.exe: TBW73.INC's DEF FNCurdisplay nests block IF/ELSE four
    # deep and showed exactly this shape at every level.
    from tbx import decode0, emit0, ir

    for stem in ("t1_nestelse", "v10_t1_nestelse"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        outer = next(s for s in prog if isinstance(s, ir.IfBlock))
        inner = outer.arms[0][1][0]
        assert isinstance(inner, ir.IfBlock), stem
        assert inner.else_body == (
            ir.Assign(ir.Var("B"), ir.Lit(2)),
        ), stem  # the ELSE arm, not a hoisted sibling
        src = emit0.emit(prog)
        assert "GOTO" not in src, stem  # no surviving else-skip
        assert src == (
            "10 A = 1\n"
            "20 IF A = 1 THEN\n"
            "  IF A = 2 THEN\n    B = 1\n  ELSE\n    B = 2\n  END IF\n"
            "END IF\n"
            "30 PRINT B\n40 END\n"
        ), stem


def test_block_if_is_distinguished_from_inline_if():
    # Block vs inline IF is BYTE-SIGNIFICANT, not a spelling choice: a block IF
    # compiles its condition through the movax-FFFF MATERIALIZATION template,
    # an inline `IF <simple> THEN <stmt>` through a bare dispatch pair. Measured
    # on the oracle: the two spellings of one two-statement body differ in 71
    # bytes, and emitting the block form inline loses 16 -- which is why
    # zz_bif1/zz_bif4 used to FAIL their own verify_fixture round trip.
    #
    # `_lift_while` only ever sees the materialization template, so a SIMPLE
    # relop arriving there is positive evidence of a block IF. Compound
    # conditions materialize either way, so IfInline(cond=LogOp/BinOp/Group)
    # stays legitimate -- only the plain-RelOp rows are block evidence.
    from tbx import decode0, emit0, ir

    # simple cond, two-statement body: block, NOT `IF A = 1 THEN B = 2: C = 3`
    prog = decode0.decode_user_code(_exe("zz_bif1.exe"))
    blk = next(s for s in prog if isinstance(s, ir.IfBlock))
    assert blk.arms[0][0] == ir.RelOp("=", ir.Var("A"), ir.Lit(1))
    assert blk.else_body is None
    assert "IF A = 1 THEN\n  B = 2\n  C = 3\nEND IF" in emit0.emit(prog)

    # the same leg applies to a NESTED body IF (_fold_body), zz_bif4's inner one
    src = emit0.emit(decode0.decode_user_code(_exe("zz_bif4.exe")))
    assert "  IF A = 2 THEN\n    B = 5\n  END IF" in src

    # ...and an inline IF whose condition never materialized stays inline
    src = emit0.emit(decode0.decode_user_code(_exe("zz_sub7.exe")))
    assert "IF A < 0 THEN EXIT SUB" in src


def test_decode_t1_fnblockif():
    # A block IF inside a block DEF FN body. `fn_ret` never ran the `_fold_if`
    # pass that proc_ret runs for SUB bodies and the top level runs for main
    # code, so a DEF FN body's IfInlines stayed inline -- byte-wrong once the
    # block/inline distinction is honoured (see the test above). Wild tbd73.exe:
    # TBW73.INC's DEF FNCurdisplay is five levels of nested block IF.
    from tbx import decode0, emit0, ir

    for stem in ("t1_fnblockif", "v10_t1_fnblockif"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        fn = next(s for s in prog if isinstance(s, ir.DefFn))
        assert isinstance(fn.body[0], ir.IfBlock), stem
        assert emit0.emit(prog) == (
            "10 DEF FNFN1%\n"
            "  IF A% = 1 THEN\n    FNFN1% = 4\n    EXIT DEF\n  END IF\n"
            "  FNFN1% = 0\n"
            "END DEF\n"
            "20 A% = 1\n30 PRINT FNFN1%\n40 END\n"
        ), stem


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


def test_decode_t1_blkgotoelse():
    # The same jump-into-a-block-interior as t1_blkgoto, but the block has an
    # ELSE. `_resolve_targets` used to map a block IF's interior only when the
    # block had exactly one arm and no ELSE, so the target never entered the
    # index and finalization raised `jump target ... is not a statement start`
    # -- wild secure.exe, target 0x82fe, owned by arm 0's fourth statement.
    # An ELSE changes nothing about how emit0 numbers the arm's own lines.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_blkgotoelse.exe")))
    assert src == (
        '10 A$ = "X"\n'
        '20 IF A$ <> "Q" THEN\n'
        '  PRINT "A"\n'
        '22 PRINT "B"\n'
        "ELSE\n"
        '  PRINT "C"\n'
        "END IF\n"
        '30 IF A$ = "X" THEN 50\n'
        "40 END\n"
        '50 A$ = "Q"\n'
        "60 GOTO 22\n"
    )


def test_decode_t1_blkgotoelif():
    # An ELSEIF arm's interior is addressable on the same terms, and pins the
    # physical-line accounting the fix shares with the nested case: the target
    # is in the SECOND arm, so its `BodyLine` phys has to count arm 0's header
    # line, arm 0's body, and the ELSEIF header before reaching it.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_blkgotoelif.exe")))
    assert src == (
        '10 A$ = "X"\n'
        '20 IF A$ = "Q" THEN\n'
        '  PRINT "A"\n'
        'ELSEIF A$ = "X" THEN\n'
        '  PRINT "B"\n'
        '24 PRINT "C"\n'
        "ELSE\n"
        '  PRINT "D"\n'
        "END IF\n"
        '30 IF A$ = "X" THEN 50\n'
        "40 END\n"
        '50 A$ = "Q"\n'
        "60 GOTO 24\n"
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


def test_decode_t1_lineinparr():
    # `LINE INPUT #n` into a VARIABLE-INDEXED string array element
    # (wild tbd73.exe, TBD73.BAS:394 `LINE INPUT #1,recarr$(rec)`).
    # t1_lineinf's consumer is a fixed `movsi; strassign` pair, but a computed
    # index puts its whole shl/addsi chain between the read and the store, so
    # the store is what names the target -- exactly the case the PROMPT form of
    # LINE INPUT already handled (wild cal87.exe) and the `#n` form did not.
    # The file number has to ride through the staged state or the rebuilt
    # statement loses its `#1`.
    from tbx import decode0, emit0, ir

    for stem in ("t1_lineinparr", "v10_t1_lineinparr"):
        prog = decode0.decode_user_code(_exe(f"{stem}.exe"))
        li = next(s for s in prog if isinstance(s, ir.LineInput))
        assert li == ir.LineInput(None, ir.ArrayRef("V0$", (ir.Var("B"),)), 1), stem
        assert "LINE INPUT #1, V0$(B)" in emit0.emit(prog), stem


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
    # individual bytes. How many bytes ride on one $INLINE source line has no
    # byte-level representation (confirmed byte-exact both ways), but the LINE
    # LENGTH does matter: a long enough line trips TB's editor limit and the
    # program will not compile, so the emitter wraps at 14 per line -- the
    # original source's own convention. Here that means two lines.
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
        "&HE6, &H61, &HB9, &H40, &H01\n"
        "  $INLINE &HE2, &HFE, &H4A, &H74, &H02, &HEB, &HF2\n"
        "END SUB\n20 CALL SUB1\n30 END\n"
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
    # or an Expr, with render.py gaining a branch for the
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


def test_decode_t1_resumefar():
    # RESUME <line> uses an EA ptr16:16 tail when its target is inside a
    # relocated $SEGMENT rather than at that segment's offset zero. Besides
    # accepting jmpf as the far sibling of jmps/jmp, this proves the scanner
    # includes segment*16 when mapping the target back to the file image.
    # Calibrated by t1_resumefar and witnessed by wild wb.exe.
    from tbx import decode0, emit0

    prog = decode0.decode_user_code(_exe("t1_resumefar.exe"))
    src = emit0.emit(prog)

    assert "40 RESUME 60" in src
    assert '$SEGMENT\n50 PRINT "BEFORE"\n60 PRINT "RECOVERED"' in src


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


def test_decode_t1_dim4v():
    # Rank-4 static array accessed at a COMPUTED (variable) index, all four
    # subscripts: the far-IDX register machine's addsiax/imul_m chain only
    # recognized span1 (jspan, blk+0x0C) and span2 (kspan, blk+0x12) --
    # missing span3 (blk+0x18) and the third combine level (si=lspan +
    # ax=kspan -> kl; si=kl + ax=jspan -> jkl) needed for a 4th dimension.
    # t1_dim4 (constant indices) never exercises this chain at all --
    # those compile through the movsi-disp16 path (gap 15), not shl-si/
    # imul_m (wild hfprop.exe, probe q_dim4var).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_dim4v.exe"))
    assign = next(
        s for s in prog if isinstance(s, ir.Assign) and isinstance(s.target, ir.ArrayRef)
    )
    assert assign.target == ir.ArrayRef(
        "V0", (ir.Var("A%"), ir.Var("B%"), ir.Var("C%"), ir.Var("D%"))
    )
    assert emit0.emit(prog) == (
        "10 DIM V0(2,3,5,4)\n20 A% = 1\n30 B% = 2\n40 C% = 3\n50 D% = 4\n"
        "60 V0(A%,B%,C%,D%) = 7\n70 PRINT V0(A%,B%,C%,D%)\n80 END\n"
    )


def test_decode_t1_imulsi():
    # `imul word [si]` with NO es: prefix (wild grdscn.exe/ziptest.exe):
    # multiplicative fold of a computed static int-array element, the DS
    # sibling of far_imulax_si (which is es:[si]-prefixed and reserved for
    # by-ref SUB params). mem = the array ref (left operand), same
    # orientation as addax_si. When the SECOND factor is itself a computed
    # array element needing its own index math (e.g. a 2-D array), TB
    # round-trips the first factor through bx (movbxax/movrr) across that
    # computation -- already-generic ops, so no extra handling was needed.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_imulsi.exe")))
    assert "130 D% = D% + V0%(A%) * V1%(A%,A%)" in src


def test_decode_t1_localforstepm1():
    # Integer FOR over a LOCAL var with a literal STEP -1: `dec [bp+d8]`
    # at the NEXT -- the bp-relative sibling of dec_m, gated exactly like
    # inc_bp (consumed silently only inside a matching open FOR; a bare
    # DEC via this opcode outside a FOR is a SEPARATE, unwitnessed shape
    # -- see t1_localsub1 below for how bare LOCAL DECR actually compiles,
    # wild horses.exe).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_localforstepm1.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    for_stmt = next(s for s in sub.body if isinstance(s, ir.For))
    assert for_stmt == ir.For(ir.Var("A%"), ir.Lit(5), ir.Lit(1), ir.Lit(-1))
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n  LOCAL A%\n  FOR A% = 5 TO 1 STEP -1\n"
        "  PRINT A%\n  NEXT A%\nEND SUB\n20 CALL SUB1\n30 END\n"
    )


def test_decode_t1_localsingle():
    # SINGLE-precision LOCAL variable (`LOCAL X!`): fld_bp/fstp_bp had NO
    # case at all for state.proc_frame is not None (only fn_frame's DEF FN
    # params/result and a "main frame: FN-call staging" fallback that
    # silently no-ops fld_bp, dropping the value) -- a genuinely
    # unimplemented feature, not a missing byte pattern (documented
    # earlier this campaign against ziptest.exe, never landed). Spans TWO
    # consecutive 2-byte words of the LOCAL zero-fill range; the first
    # word's phantom int name gets its suffix corrected to '!' on first
    # touch and the second word is dropped entirely -- one FP variable,
    # not two ints. Surfaced chasing wild resume.exe's own FP-typed LOCAL.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_localsingle.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    assert ir.Local(("A",)) in sub.body
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n  LOCAL A\n  A = 1.5#\n  A = A + 1\n"
        "  PRINT A\nEND SUB\n20 CALL SUB1\n30 END\n"
    )


def test_decode_t1_localsub1():
    # Bare LOCAL DECR (`X% = X% - 1`, outside any FOR): `sub [bp+d8], ax`
    # -- the subtraction sibling of the already-calibrated addm_ax_bp
    # (bare LOCAL INCR uses `add [bp+d8], ax`, t1_local1). Surfaced
    # chasing wild horses.exe's next gap after t1_localforstepm1 above.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_localsub1.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    assert ir.Assign(ir.Var("A%"), ir.BinOp("-", ir.Var("A%"), ir.Lit(1))) in sub.body
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n  LOCAL A%\n  A% = A% - 1\n  PRINT A%\nEND SUB\n"
        "20 CALL SUB1\n30 CALL SUB1\n40 END\n"
    )


def test_decode_t1_localvarstep():
    # Computed (variable) STEP FOR over a LOCAL (wild ziptest.exe): the
    # LOCAL-frame mirror of t1_forvarstep, using movax_bp/movm_ax_bp/
    # mov_bp_imm/cmp_bpi8 throughout instead of the DGROUP movax_m/movm_ax/
    # cmpm_ax family -- vdisp and loc_local's L-names already disambiguate
    # the two frames uniformly (same as the literal-step LOCAL FOR). The
    # header reserves a [limit-temp, step-temp] word pair as the LAST two
    # words of the LOCAL span (here only the step-temp is actually read,
    # since the limit is a literal) -- unlike the literal-step case's
    # temps, the step-temp IS read again at NEXT, so it can't be dropped
    # from the LOCAL name table until the SUB body is fully decoded.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_localvarstep.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    assert ir.Local(("B%", "C%", "D%")) in sub.body
    for_stmt = next(s for s in sub.body if isinstance(s, ir.For))
    assert for_stmt == ir.For(ir.Var("B%"), ir.Lit(1), ir.Lit(10), ir.Var("D%"))
    src = emit0.emit(prog)
    assert "LOCAL B%, C%, D%" in src
    assert "FOR B% = 1 TO 10 STEP D%" in src


def test_decode_t1_forstepm1():
    # Literal STEP -1: TB special-cases both +1 and -1 to a bare INC/DEC at
    # the NEXT (inc_m / dec_m) instead of the generic addm_i8 fast path any
    # OTHER literal step uses (t1_forstepn covers -10) -- dec_m's FOR-frame
    # branch previously fail-loud raised, assuming this shape unwitnessed.
    # Same placeholder-patch as addm_i8: the header folds a provisional
    # Lit(1) step before the NEXT-side DEC confirms it's actually -1
    # (wild bill.exe, closed fully by this fixture + the COLOR-cell
    # runtime-revision-shift alias).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_forstepm1.exe"))
    assert prog[0] == ir.For(ir.Var("A%"), ir.Lit(10), ir.Lit(1), ir.Lit(-1))
    assert emit0.emit(prog) == (
        "10 FOR A% = 10 TO 1 STEP -1\n20 PRINT A%\n30 NEXT A%\n40 END\n"
    )


def test_decode_t1_forvarinit():
    # Computed (variable) FOR INIT: `FOR I% = N% TO 23` compiles the same
    # header shape as a literal-init FOR (assign; jmp test; ... cmp_mi8 ...)
    # but via movm_ax instead of movm_imm, since the init value is whatever
    # expression was in ax -- the header recognizer required a Lit init,
    # rejecting this shape outright even though nothing downstream actually
    # needs it to be one (wild tamstart.exe, closed fully by this fixture).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_forvarinit.exe"))
    assert prog[1] == ir.For(ir.Var("B%"), ir.Var("A%"), ir.Lit(23), ir.Lit(1))
    assert emit0.emit(prog) == (
        "10 A% = 5\n20 FOR B% = A% TO 23\n30 PRINT B%\n40 NEXT B%\n50 END\n"
    )


def test_decode_t1_fwdcall():
    # CALL to a SUB defined LATER in the file (address-ascending scan
    # order): proc_names has no entry yet at that point, since it's only
    # populated once the callee's OWN proc_ret has been processed (wild
    # process.exe, whose SUBs call each other in both directions). Staged
    # as a ("addr", n) placeholder, resolved once every SUB has been
    # decoded -- and since a CallStmt can nest inside ANOTHER SUB's body
    # (one SUB calling another), the resolution has to walk the same
    # nested shapes _resolve_targets's own fix() recurses into, not just
    # the top level (caught by an early version of this fix that only
    # scanned state.stmts directly).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_fwdcall.exe"))
    sub1 = next(s for s in prog if isinstance(s, ir.SubDef) and s.name == "SUB1")
    assert ir.CallStmt("SUB2", ()) in sub1.body
    assert emit0.emit(prog) == (
        "10 SUB SUB1(A%)\n  PRINT A%\n  CALL SUB2\nEND SUB\n"
        "20 SUB SUB2\n  PRINT \"IN SUB2\"\nEND SUB\n"
        "30 B% = 5\n40 CALL SUB1(B%)\n50 END\n"
    )


def test_decode_t1_licomp():
    # ESC DA modrm=1C (mod=0,reg=3,rm=4): a computed-index LONG (`&`) array
    # element compared against an FP-stack value (`IF A&(J%) > 5 THEN`) --
    # the [si] sibling of icomp's disp16 scalar form, missing from the
    # [si] kind table (wild bmaster.exe/ifi.exe, both at the identical
    # offset 0x8fdd -- near-duplicate binaries).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_licomp.exe"))
    ifgoto = next(s for s in prog if isinstance(s, ir.IfGoto))
    assert ifgoto.cond == ir.RelOp(
        "<=", ir.ArrayRef("V0&", (ir.Var("B%"),)), ir.Lit(5)
    )
    assert emit0.emit(prog) == (
        "10 DIM V0&(5)\n20 FOR A% = 1 TO 5\n"
        "30 V0&(A%) = A% * 1000000\n40 NEXT A%\n50 B% = 3\n"
        "60 IF V0&(B%) <= 5 THEN 80\n70 PRINT \"Y\"\n80 END\n"
    )


def test_decode_t1_icomp32():
    # ESC DA modrm=1E (mod=0,reg=3,rm=6, [disp16]): a plain LONG (`&`)
    # SCALAR variable compared against an FP-stack value (`IF X& > 5.5
    # THEN`) -- the disp16 sibling of icomp_si32's [si] (computed-index
    # array) form, missing from the disp16 kind table alongside icomp
    # (the m16 int version). Wild stat.exe.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_icomp32.exe"))
    ifgoto = next(s for s in prog if isinstance(s, ir.IfGoto))
    assert ifgoto.cond == ir.RelOp("<=", ir.Var("A&"), ir.DblLit(5.5))
    assert emit0.emit(prog) == (
        "10 A& = 100000\n20 IF A& <= 5.5# THEN 40\n30 PRINT \"Y\"\n40 END\n"
    )


def test_decode_t1_locforvarlim():
    # Integer FOR over a LOCAL var with a VARIABLE (non-literal) limit: the
    # bp-relative mirror of t1_fori's DGROUP `movax_m`/`cmpm_ax` pair, using
    # `movax_bp`/`cmpm_ax_bp` throughout (wild bmaster.exe/ifi.exe, once
    # past the t1_licomp gap above). The header reserves a [step-temp,
    # limit-temp] word pair right after the loop var, same as the
    # literal-limit LOCAL FOR case -- here the step-temp is unused (dropped
    # immediately) but the limit-temp IS read again at every iteration's
    # test, so it can't be dropped from the LOCAL name table until the SUB
    # body is fully decoded.
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_locforvarlim.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    assert ir.Local(("B%",)) in sub.body
    for_stmt = next(s for s in sub.body if isinstance(s, ir.For))
    assert for_stmt == ir.For(ir.Var("B%"), ir.Lit(1), ir.Var("A%"), ir.Lit(1))
    assert emit0.emit(prog) == (
        "10 SUB SUB1(A%)\n  LOCAL B%\n  FOR B% = 1 TO A%\n"
        "  PRINT B%\n  NEXT B%\nEND SUB\n20 CALL SUB1(5)\n30 END\n"
    )


def test_for_temps_retired_by_evidence_not_position():
    # A LOCAL FOR reserves two [step, limit] temp words that are NOT declared
    # LOCALs. A literal bound leaves no op referring to either, so they can
    # only be found positionally -- and the compiler puts them at the frame
    # TAIL, after every declared LOCAL, reusing one pair however many LOCAL
    # FORs the procedure has. The lift used to guess `loop_var + 2` / `+ 4`
    # and delete those words mid-walk, which silently removed a REAL local
    # whenever the loop var was not the last one declared. Retirement now
    # happens at proc_ret, walking back from the tail and stopping at the
    # first word the body actually touched.
    #
    # Both fixtures declare a LOCAL string AFTER the loop var, so `v + 2` is
    # that string's descriptor: the variable-limit form used to raise
    # `string BP push outside DEF FN` and the literal-bound form used to keep
    # the real temps as two phantom `LOCAL`s.
    from tbx import decode0, emit0, ir

    for stem, params, locals_ in (
        ("t1_locstrafterfor", ("A%",), ("B%", "C$")),
        ("t1_locstrafterforlit", (), ("A%", "B$")),
    ):
        for pfx in ("", "v10_"):
            prog = decode0.decode_user_code(_exe(f"{pfx}{stem}.exe"))
            sub = next(s for s in prog if isinstance(s, ir.SubDef))
            assert sub.params == params, (pfx, stem)
            # exactly the declared LOCALs: no deleted local, no phantom temp
            assert sub.body[0] == ir.Local(locals_), (pfx, stem)
            src = emit0.emit(prog)
            assert f"LOCAL {', '.join(locals_)}\n" in src, (pfx, stem)


def test_decode_t1_locforlong():
    # t1_locforvarlim's LONG-BODY sibling: once the body is past short-jump
    # range the NEXT test takes the inverse condition plus a JMP back
    # (`jg +3; e9 body`) instead of a direct `jle body`. The DGROUP
    # movax_m/cmpm_ax case already handled that indirect form; the
    # bp-relative one raised `int NEXT (var limit): expected JLE to body`.
    # Wild tbd73.exe: TBWINDOW `SUB Makevmenu`'s `FOR mloop = 1 TO itemcount`.
    from tbx import decode0, emit0, ir

    for stem in ("t1_locforlong.exe", "v10_t1_locforlong.exe"):
        prog = decode0.decode_user_code(_exe(stem))
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        for_stmt = next(s for s in sub.body if isinstance(s, ir.For))
        assert for_stmt == ir.For(
            ir.Var("B%"), ir.Lit(1), ir.Var("A%"), ir.Lit(1)
        ), stem
        assert isinstance(sub.body[-1], ir.NextStmt), stem
        assert sub.body[-1].var == ir.Var("B%"), stem
        src = emit0.emit(prog)
        assert src.count('PRINT "LINE') == 20, stem  # body must stay long
        assert src.endswith("END SUB\n20 C% = 3\n30 CALL SUB1(C%)\n40 END\n"), stem


def test_decode_t1_byrefforvar():
    # Integer FOR over a BY-REF INTEGER PARAMETER used directly as the loop
    # var, with a VARIABLE (non-literal) limit: the ES:[SI] mirror of
    # t1_locforvarlim just above -- `arg_ref P; les si,[bp+P]; cmp
    # es:[si],ax` at the test, `inc es:[si]` at the NEXT, new ops
    # far_cmpm_ax_si/far_inc_si. The loop var itself never occupies a
    # LOCAL slot (it's the parameter's own storage); only the
    # [step-temp, limit-temp] pair is reserved, same relationship
    # (limit-temp == step-temp + 2) as the pure-LOCAL case (wild
    # bmaster.exe/ifi.exe, once past the t1_locforvarlim gap above).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_byrefforvar.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    assert not any(isinstance(s, ir.Local) for s in sub.body)
    for_stmt = next(s for s in sub.body if isinstance(s, ir.For))
    assert for_stmt == ir.For(ir.Var("A%"), ir.Lit(1), ir.Var("B%"), ir.Lit(1))
    assert emit0.emit(prog) == (
        "10 SUB SUB1(A%, B%)\n  FOR A% = 1 TO B%\n"
        "  PRINT A%\n  NEXT A%\nEND SUB\n20 CALL SUB1(1,5)\n30 END\n"
    )


def test_decode_t1_byrefsub():
    # `N% = N% - <expr>` where N% is a by-ref INTEGER parameter: `sub
    # es:[si], ax` -- the subtraction sibling of the already-calibrated
    # far_addm_ax_si (compound-store add into a by-ref param). New op
    # far_subm_ax_si, consumed identically via BinOp("-", ...) instead of
    # ("+", ...) (wild bmaster.exe, surfaced chasing the byte-16 gap chain
    # further; a separate, still-open FOR-loop shape -- a by-ref param used
    # directly as a STEP -1 loop var -- was found in the same file but not
    # landed this session, see PLAN.md).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_byrefsub.exe"))
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    assert sub.body == (
        ir.Assign(ir.Var("A%"), ir.BinOp("-", ir.Var("A%"), ir.Lit(3))),
    )
    assert emit0.emit(prog) == (
        "10 SUB SUB1(A%)\n  A% = A% - 3\nEND SUB\n"
        "20 B% = 10\n30 CALL SUB1(B%)\n40 PRINT B%\n50 END\n"
    )


def test_decode_t1_localargcall():
    # CALL SUB2(A%) where A% is a LOCAL variable declared in the CALLING
    # sub: `push ss; mov ax,off; add ax,bp; push ax` -- the LOCAL-frame
    # sibling of arg_push_ref (DGROUP scalars: `push ds; mov ax,off; push
    # ax`, no `add ax,bp` needed since DGROUP disps are compile-time
    # absolute). New op arg_push_ref_bp, consumed identically to
    # arg_push_ref via loc_local instead of loc (wild bmaster.exe/ifi.exe/
    # resume.exe, all three sharing this exact "unhandled byte 16" gap).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_localargcall.exe"))
    sub2 = next(s for s in prog if isinstance(s, ir.SubDef) and s.name == "SUB2")
    assert ir.CallStmt("SUB1", (ir.Var("B%"),)) in sub2.body
    assert emit0.emit(prog) == (
        "10 SUB SUB1(A%)\n  A% = A% + 1\nEND SUB\n"
        "20 SUB SUB2\n  LOCAL B%\n  B% = 5\n  CALL SUB1(B%)\n"
        "  PRINT B%\nEND SUB\n30 CALL SUB2\n40 END\n"
    )


def test_decode_t1_fnlocal():
    # DEF FN body declaring its own LOCAL: `local_init`'s zero-fill was
    # previously hard-gated to `state.proc_frame` (SUB bodies only) and
    # `loc_local` only ever consulted it too, so a DEF FN's LOCAL raised
    # "LOCAL zero-fill outside a fresh SUB body" unconditionally. Also
    # exercises the auto-fn_frame-open generalization: this file's DEF FN
    # is reached via a per-definition trailing skip-jmp right after the
    # preceding proc_ret (mod trap_hook stamps), not one leading skip-jmp
    # over the whole def region, so `state.main_start` alone never used to
    # open it (wild resume.exe, probe_a).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_fnlocal.exe"))
    fn = next(s for s in prog if isinstance(s, ir.DefFn))
    assert fn.params == ("A",)
    assert ir.Local(("B%",)) in fn.body
    assert emit0.emit(prog) == (
        "10 DEF FNFN1(A)\n  LOCAL B%\n  B% = A + 1\n"
        "  FNFN1 = B% + 2\nEND DEF\n20 PRINT FNFN1(3)\n30 END\n"
    )


def test_decode_t1_fnlocalint():
    # DEF FN with two plain-INTEGER params (packed 2 bytes apiece right
    # after the result cell, NOT the 4-byte stride an FP/string param list
    # uses) plus a LOCAL: exercises loc_local's new fn_frame param
    # fallback (the touched bp-offset set IS the param list -- no fixed
    # stride assumed), the int-typed FN result store via movm_ax_bp 0, the
    # caller-side literal/computed int-arg staging (mov_bp_imm / movm_ax_bp
    # into state.fn_args), the caller-side integer-result reload
    # (movax_bp 0 popping the FnCall off state.stack), and the nested-call
    # sp_save_cell save/restore across push_bp/pop_bp (wild resume.exe,
    # probe_d).
    from tbx import decode0, emit0, ir

    prog = decode0.decode_user_code(_exe("t1_fnlocalint.exe"))
    fn = next(s for s in prog if isinstance(s, ir.DefFn))
    assert fn.params == ("A%", "B%")
    assert ir.Local(("C%",)) in fn.body
    assert emit0.emit(prog) == (
        "10 DEF FNFN1(A%, B%)\n  LOCAL C%\n  C% = A% * B%\n"
        "  IF C% <= 100 THEN 15\n  C% = C% + 1\n15 FNFN1 = C%\nEND DEF\n"
        "20 PRINT FNFN1(3,4)\n30 END\n"
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
    test_decode_t1_byreflong()
    test_decode_t1_localdbl()
    test_decode_t1_localdblcmp()
    test_decode_t1_forvarlimneg()
    test_decode_t1_palettereset()
    test_decode_t1_argrefonly()
    test_wild_rsltest_argref_advances()
    test_decode_t1_declnoend()
    test_decode_t1_dblhook()
    test_decode_t1_fwdcalltgt()
    test_decode_t1_inlinebp()
    test_decode_t1_erasestatic()
    test_decode_t1_fwdinline()
    test_decode_t1_inlfwdwhile()
    test_decode_t1_exitsublocstr()
    test_decode_t1_selelsetarget()
    test_decode_t1_selarmtarget()
    test_decode_t1_iftaillast()
    test_decode_t1_boolloopuntil()
    test_decode_t1_ifthenfncall()
    test_decode_t1_twosublocal()
    test_decode_t1_ifblockselect()
    test_decode_t1_selarmblockif()
    test_decode_t1_iftailarm()
    test_decode_t1_ifbeforecall()
    test_decode_t1_fnintcall()
    test_decode_t1_inlinethendef()
    test_decode_t1_commonarrstatic()
    test_decode_t1_erasepre()
    test_decode_t1_arrfwd()
    test_relayed_string_array_param_stays_loud()
    test_decode_t1_inlinedata()
    test_decode_t1_segment()
    test_decode_t1_commonarr()
    test_decode_t1_commonarrmix()
    test_decode_t1_scgoto()
    test_decode_t1_scgotone()
    test_decode_t1_movaxmpool()
    test_decode_t1_peekand()
    test_decode_t1_selcasechr()
    test_decode_t1_whileinstat()
    test_decode_t1_arrbyrefidx()
    test_wild_cvt2tb_opaque_helper_advances()
    test_wild_phone_opaque_helper_advances()
    test_wild_filepatc_opaque_helpers_advance()
    test_wild_mf_compound_if_far_exit_advances()
    test_decode_t1_forvarlimfar()
    test_decode_t1_midvarstart()
    test_decode_t1_inpfilearr()
    test_decode_t1_byrefdbl()
    test_decode_t1_localincr()
    test_decode_t1_localdecr()
    test_decode_t1_byrefincr()
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
    test_decode_t1_dim4v()
    test_decode_t1_imulsi()
    test_decode_t1_localforstepm1()
    test_decode_t1_localsingle()
    test_decode_t1_localsub1()
    test_decode_t1_localvarstep()
    test_decode_t1_forstepm1()
    test_decode_t1_forvarinit()
    test_decode_t1_fwdcall()
    test_decode_t1_licomp()
    test_decode_t1_icomp32()
    test_decode_t1_locforvarlim()
    test_decode_t1_byrefforvar()
    test_decode_t1_byrefsub()
    test_decode_t1_localargcall()
    test_decode_t1_fnlocal()
    test_decode_t1_fnlocalint()
    print("ALL PASS")
