"""Compound IF conditions (AND/OR) + intrinsics."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = [
    "t1_and",
    "t1_or",
    "t1_fn",
    "t1_erase",
    "t1_boolwh",
    "t1_booluntil",
    "t1_and3",
    "t1_mixedbool",
    "t1_mixedbool2",
    "t1_mixedbool3",
    "t1_orofands",
]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_compound_first_term_matches_wrapped_near_target():
    from tbx.decode0.matchers import match_bool_term1, match_loose_for_header

    # `electron.exe` reaches this ordinary AND template in a later 64 KiB
    # code window.  The scanner's canonical near-jump target is the same
    # 16-bit offset in the first window, so this comparison must be modular.
    ops = [
        (0x1EEB7, "movax", 0xFFFF),
        (0x1EEBA, "jcc", 0x72, 0x1EEBD),
        (0x1EEBC, "incax"),
        (0x1EEBD, "orax"),
        (0x1EEC1, "jcc", 0x75, 0x1EEC6),
        (0x1EEC3, "jmp", 0xEEDA),
        (0x1EED2, "movax", 0xFFFF),
        (0x1EED5, "jcc", 0x72, 0x1EED8),
        (0x1EED7, "incax"),
        (0x1EED8, "andaxbx"),
    ]
    typed = match_bool_term1(ops, 0)
    assert typed is not None
    assert typed.operator == "AND"
    assert typed.deferred is False
    # The recognized template is the six-operation header, whatever the
    # applier goes on to fold.
    assert (typed.start, typed.stop, typed.consumed) == (0, 6, 6)
    assert typed.short_circuit == 0xEEDA

    # The same program's SINGLE FOR header jumps to its negative comparison
    # branch at the canonical offset; its scanned second branch is 64 KiB
    # later.  This remains the distinctive loose-FOR template.
    for_ops = [
        (0x1DB8D, "testw", 978, 0x8000),
        (0x1DB95, "jcc", 0x74, 0x1DB9A),
        (0x1DB97, "jmp", 0xDBAD),
        (0x1DB9A, "fld", 980),
        (0x1DB9F, "fcomp", 996),
        (0x1DBA4, "fstsw"),
        (0x1DBA8, "jcc", 0x73, 0x1DB5E),
        (0x1DBAA, "jmp", 0xDBBD),
        (0x1DBAD, "fld", 980),
        (0x1DBB2, "fcomp", 996),
        (0x1DBB7, "fstsw"),
        (0x1DBBB, "jcc", 0x76, 0x1DB5E),
    ]
    stmts = [
        ir.Assign(ir.Var("V03D4"), ir.Lit(0)),
        ir.Assign(ir.Var("V03D0"), ir.Lit(1)),
        ir.Assign(ir.Var("V03E4"), ir.Lit(2)),
    ]
    loose = match_loose_for_header(
        for_ops, 0, stmts, lambda v: int(v.name[1:], 16)
    )
    assert loose is not None
    assert (loose.limit, loose.step, loose.var) == (980, 976, 996)


def test_decode_string_nested_and_or_group():
    from tbx import decode0, emit0

    exe = open(
        os.path.join(
            _ROOT, "..", "wild", "probes", "probe_string_nested_and_or_block.exe"
        ),
        "rb",
    ).read()
    assert emit0.emit(decode0.decode_user_code(exe)) == (
        '10 A$ = "A"\n'
        '20 B$ = "B"\n'
        '30 C$ = "C"\n'
        '40 IF A$ = "A" AND ((B$ = "B") OR (C$ = "C")) THEN PRINT "YES": PRINT "OK"\n'
        "50 END\n"
    )


def test_decode_int_string_nested_and_or_group():
    from tbx import decode0, emit0

    exe = open(
        os.path.join(
            _ROOT, "..", "wild", "probes", "probe_int_string_nested_and_or_block.exe"
        ),
        "rb",
    ).read()
    assert emit0.emit(decode0.decode_user_code(exe)) == (
        "10 A% = 0\n"
        '20 B$ = "B"\n'
        '30 C$ = "C"\n'
        '40 IF A% = 0 AND ((B$ = "B") OR (C$ = "C")) THEN PRINT "YES": PRINT "OK"\n'
        "50 END\n"
    )


def test_decode_t1_and():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    want = [
        ir.Input(None, V("A")),
        ir.Input(None, V("B")),
        ir.IfGoto(
            ir.LogOp("AND", ir.RelOp(">", V("A"), L(1)), ir.RelOp("<", V("B"), L(5))), 5
        ),
        ir.Print(L(0)),
        ir.Goto(6),
        ir.Print(L(1)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_and.exe")) == want


def test_decode_t1_or():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    want = [
        ir.Input(None, V("A")),
        ir.IfGoto(
            ir.LogOp("OR", ir.RelOp("<", V("A"), L(0)), ir.RelOp(">", V("A"), L(9))), 4
        ),
        ir.Print(L(0)),
        ir.Goto(5),
        ir.Print(L(1)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_or.exe")) == want


def test_decode_t1_fn():
    from tbx import decode0

    V = ir.Var
    x = V("A")
    want = [
        ir.Input(None, x),
        ir.Assign(V("B"), ir.Call("ABS", (x,))),
        ir.Assign(V("C"), ir.Call("SQR", (x,))),
        ir.Assign(V("D"), ir.Call("INT", (x,))),
        ir.Assign(V("E"), ir.Call("SGN", (x,))),
        ir.Print(
            ir.BinOp("+", ir.BinOp("+", ir.BinOp("+", V("B"), V("C")), V("D")), V("E"))
        ),  # parens are source-faithful
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_fn.exe")) == want


def test_decode_t1_erase():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    n = V("A")
    want = [
        ir.Input(None, n),
        ir.Dim("V0", (n,)),
        ir.Assign(ir.ArrayRef("V0", (L(1),)), L(2)),
        ir.Erase("V0"),
        ir.Dim("V0", (n,)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_erase.exe")) == want


def test_decode_t1_boolstrgroup():
    # A BARE VALUE as the left operand of an ungrouped outer AND whose right
    # operand is a parenthesized group of STRING compares:
    # `IF F% AND (A$ = CHR$(75) OR A$ = CHR$(77)) THEN`. Wild tbd73.exe's
    # TBWINDOW `SUB Makevmenu` (TBW73.INC:510).
    #
    # `or ax,ax` self-tests the bare value without destroying it, so the group
    # protocol (bank in bx, park in cx across the group, fold with andaxbx) is
    # the SAME one t1_nestedbool already drives via direct_bool_gate -- there
    # the left operand is a folded group (`oraxbx`) instead of a bare value.
    # Previously `materialization template mismatch`.
    #
    # Per-term parens are emitted because the source's own single level of
    # parens around the group is byte-identical either way (oracle-checked).
    from tbx import decode0, emit0

    for stem in ("t1_boolstrgroup.exe", "v10_t1_boolstrgroup.exe"):
        src = emit0.emit(decode0.decode_user_code(_exe(stem)))
        assert src == (
            '10 A$ = "K"\n20 B% = -1\n'
            '30 IF B% AND ((A$ = CHR$(75)) OR (A$ = CHR$(77))) THEN PRINT "YES"\n'
            "40 END\n"
        ), stem


def test_decode_t1_boolstrord():
    # The ORDERING rows of the same shape. strcmp's flags are FORWARD, so a
    # materialized string relational needs _JCC_RELOP_STR_TRUE, not
    # _JCC_RELOP_TRUE's FP-reversed unsigned rows -- the two maps agree only on
    # `=`/`<>`, so this fixture (and not t1_boolstrgroup) is what pins the four
    # ordering rows. With the wrong map every one of them decodes mirrored,
    # which still recompiles to a valid program, just not the source's.
    from tbx import decode0, emit0

    for stem in ("t1_boolstrord.exe", "v10_t1_boolstrord.exe"):
        src = emit0.emit(decode0.decode_user_code(_exe(stem)))
        assert "((A$ < CHR$(75)) OR (A$ > CHR$(77)))" in src, stem
        assert "((A$ <= CHR$(75)) OR (A$ >= CHR$(77)))" in src, stem


def test_decode_t1_and3():
    # 3+-term compound chain: each MID segment materializes its term, folds
    # with `and ax,bx` (`or ax,bx`), and its dispatch jmp short-circuits into
    # the NEXT segment's fold template (comb addr +2 AND / +0 OR) instead of
    # exiting -- _lift_bool_tail folds the condition and keeps the compound
    # open until the final segment's jmp exits the chain. Left-associative:
    # LogOp(AND, LogOp(AND, t1, t2), t3).
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    prog = decode0.decode_user_code(_exe("t1_and3.exe"))
    assert prog[3] == ir.IfGoto(
        ir.LogOp(
            "AND",
            ir.LogOp(
                "AND", ir.RelOp(">", V("A"), L(1)), ir.RelOp("<", V("B"), L(5))
            ),
            ir.RelOp("=", V("C"), L(2)),
        ),
        5,
    )


def test_decode_t1_mixedbool():
    # Combinator SWITCH mid-chain: `A AND B OR C` = `(A AND B) OR C` (wild
    # state.exe/state87.exe): AND binds tighter than OR (standard
    # precedence, confirmed by probing the OR-then-AND mirror shape --
    # see t1_mixedbool2 -- which produces a genuinely different tree, NOT
    # "equal precedence, left-associative" as this comment once claimed).
    # This fixture's own shape happens to coincide with a flat left-fold
    # regardless, since AND already appears leftmost with nothing after
    # the trailing OR to compete with it. Same byte shape as t1_and3 but
    # the THIRD term's fold uses the OTHER combinator (orax instead of
    # andaxbx) -- _lift_bool_tail's mid-segment lookahead now tries both
    # combinators, since the same-comb-only check silently finalized as
    # a 2-term chain and orphaned the third term's bytes, producing an
    # IfGoto whose target landed inside its own compiled statement.
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    prog = decode0.decode_user_code(_exe("t1_mixedbool.exe"))
    assert prog[3] == ir.IfGoto(
        ir.LogOp(
            "OR",
            ir.LogOp(
                "AND",
                ir.RelOp("=", V("A$"), ir.StrLit("L")),
                ir.RelOp("=", V("B"), L(15)),
            ),
            ir.RelOp("=", V("C"), L(1)),
        ),
        6,
    )


def test_decode_t1_mixedbool2():
    # Combinator SWITCH where the FIRST term defers to a multi-term inner
    # GROUP: `A OR B AND C` = `A OR (B AND C)` (wild wb.exe/grdscn.exe/
    # mcmurphy.exe). Unlike t1_mixedbool's single-trailing-term switch, B
    # and C must resolve as their OWN 2-term chain (a fresh
    # _match_bool_term1 entry point at B) before folding with A -- A's own
    # short-circuit lands on (B AND C)'s convergence point, not on B
    # directly. Distinguishing signal: another `movax 0FFFFh`
    # materialization sits strictly between A's fold and the match (B's own
    # self-test), unlike a direct single-term combine.
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    prog = decode0.decode_user_code(_exe("t1_mixedbool2.exe"))
    assert prog[3] == ir.IfGoto(
        ir.LogOp(
            "OR",
            ir.RelOp("=", V("A$"), ir.StrLit("L")),
            ir.LogOp(
                "AND",
                ir.RelOp("=", V("B"), L(15)),
                ir.RelOp("=", V("C"), L(1)),
            ),
        ),
        6,
    )


def test_decode_t1_mixedbool3():
    # Left-associative CASCADE of GROUPS: `A AND B OR C AND D OR E AND F`
    # = `((A AND B) OR (C AND D)) OR (E AND F)` (wild mcmurphy.exe). Each
    # deferred group folds into the enclosing accumulator as soon as it
    # resolves (rather than stacking nested defers), exactly like every
    # other left-fold in this file, just one level up: a cascade of
    # 2-term GROUPS instead of a cascade of plain terms.
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    prog = decode0.decode_user_code(_exe("t1_mixedbool3.exe"))
    assert prog[6] == ir.IfGoto(
        ir.LogOp(
            "OR",
            ir.LogOp(
                "OR",
                ir.LogOp(
                    "AND",
                    ir.RelOp("=", V("A"), L(1)),
                    ir.RelOp("=", V("B"), L(2)),
                ),
                ir.LogOp(
                    "AND",
                    ir.RelOp("=", V("C"), L(3)),
                    ir.RelOp("=", V("D"), L(4)),
                ),
            ),
            ir.LogOp(
                "AND",
                ir.RelOp("=", V("E"), L(5)),
                ir.RelOp("=", V("F"), L(6)),
            ),
        ),
        9,
    )


def test_decode_t1_or3():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    prog = decode0.decode_user_code(_exe("t1_or3.exe"))
    assert prog[1] == ir.IfGoto(
        ir.LogOp(
            "OR",
            ir.LogOp(
                "OR", ir.RelOp("<", V("A"), L(0)), ir.RelOp(">", V("A"), L(9))
            ),
            ir.RelOp("=", V("A"), L(5)),
        ),
        3,
    )


def test_decode_t1_boolwh():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    want = [
        ir.Do(None, None),
        ir.Input(None, V("A")),
        ir.Loop(
            "WHILE",
            ir.LogOp("OR", ir.RelOp("<", V("A"), L(0)), ir.RelOp(">", V("A"), L(1))),
        ),
        ir.Print((V("A"),)),
    ]
    assert decode0.decode_user_code(_exe("t1_boolwh.exe")) == want


def test_decode_t1_booluntil():
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    want = [
        ir.Do(None, None),
        ir.Input(None, V("A")),
        ir.Loop(
            "UNTIL",
            ir.LogOp("AND", ir.RelOp(">=", V("A"), L(0)), ir.RelOp("<=", V("A"), L(1))),
        ),
        ir.Print((V("A"),)),
    ]
    assert decode0.decode_user_code(_exe("t1_booluntil.exe")) == want


def test_decode_t1_orofands():
    # Explicitly parenthesized `(A AND B) OR (C AND D)` (wild bmaster.exe/
    # ifi.exe): each AND-group's own first term never gets the usual
    # self-test dispatch pair (`or ax,ax`) -- TB folds the whole group as a
    # plain VALUE (materialize -> movbxax -> materialize -> andaxbx) and
    # reuses the SECOND group's own trailing jcc/jmp as the shared decision
    # point for the entire OR. The explicit parens are byte-significant
    # (dropping them recompiles a different, self-tested template), so each
    # group round-trips through an `ir.Group`.
    from tbx import decode0

    L, V = ir.Lit, ir.Var
    prog = decode0.decode_user_code(_exe("t1_orofands.exe"))
    assert prog[0].body[0] == ir.IfInline(
        ir.LogOp(
            "OR",
            ir.Group(
                ir.LogOp(
                    "AND",
                    ir.RelOp("=", V("A%"), L(0)),
                    ir.RelOp("=", V("B$"), ir.StrLit("X")),
                )
            ),
            ir.Group(
                ir.LogOp(
                    "AND",
                    ir.RelOp("=", V("C%"), L(1)),
                    ir.RelOp("=", V("D$"), ir.StrLit("Y")),
                )
            ),
        ),
        (ir.Print((ir.StrLit("YES"),), True, None, None),),
    )


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_compound_if():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_and.exe"))) == (
        "10 INPUT A\n"
        "20 INPUT B\n"
        "30 IF A > 1 AND B < 5 THEN 60\n"
        "40 PRINT 0\n"
        "50 GOTO 70\n"
        "60 PRINT 1\n"
        "70 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_or.exe"))) == (
        "10 INPUT A\n"
        "20 IF A < 0 OR A > 9 THEN 50\n"
        "30 PRINT 0\n"
        "40 GOTO 60\n"
        "50 PRINT 1\n"
        "60 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_fn.exe"))) == (
        "10 INPUT A\n"
        "20 B = ABS(A)\n"
        "30 C = SQR(A)\n"
        "40 D = INT(A)\n"
        "50 E = SGN(A)\n"
        "60 PRINT B + C + D + E\n"
        "70 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_and()
    test_decode_t1_or()
    test_decode_t1_fn()
    test_decode_t1_erase()
    test_dialect_invariant()
    test_emit_compound_if()
    print("ALL PASS")
