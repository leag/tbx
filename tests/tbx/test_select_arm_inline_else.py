"""A single-line IF/ELSE inside a CASE arm has to fold into the arm.

A simple condition canonicalizes to `IfGoto`, so at top level
`IF B% = 0 THEN B% = 64 ELSE B% = B% - 1` decodes to a conditional GOTO, the
THEN statements, an else-skip GOTO and the ELSE statements -- four statements
that emit as numbered lines and recompile byte-for-byte.

Inside a CASE arm that spelling has nowhere to land. The else-skip targets the
arm's own end, which is the arm-close jmp and owns no statement, so the address
never resolves: `jump target 0x873e is not a statement start`. `_fold_if`
handles the same convergence for a BLOCK if (t1_selarmblockif) but only matches
an `ir.IfInline`, and this shape never became one.

Folding to a block IF is not an option -- the block spelling of a simple
condition compiles to different bytes (16 more here, oracle-checked), so the
fold has to reproduce the single-line form, ELSE included.

Wild: 13 programs fail with this signature, the largest bucket in the corpus.
"""

from pathlib import Path

from tbx import decode0, emit0, ir

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _prog(stem):
    return decode0.decode_user_code((_CORPUS / f"{stem}.exe").read_bytes())


def test_the_arm_holds_one_inline_if_with_an_else():
    prog = _prog("t1_selarmifelse")
    select = next(s for s in prog if isinstance(s, ir.SelectCase))
    assert len(select.arms) == 2
    for arm in select.arms:
        assert len(arm.body) == 1, f"arm did not fold: {arm.body}"
        inline = arm.body[0]
        assert isinstance(inline, ir.IfInline)
        assert inline.else_body, "the ELSE arm was dropped"
    # The IfGoto's condition is negated back into the source's own sense.
    first = select.arms[0].body[0]
    assert first.cond == ir.RelOp("=", ir.Var("B%"), ir.Lit(0))


def test_it_emits_the_single_line_form():
    assert emit0.emit(_prog("t1_selarmifelse")) == (
        "10 A% = 1\n"
        "20 SELECT CASE A%\n"
        "CASE 1\n"
        "  IF B% = 0 THEN B% = 64 ELSE B% = B% - 1\n"
        "CASE 2\n"
        "  IF B% = 64 THEN B% = 0 ELSE B% = B% + 1\n"
        "END SELECT\n"
        "30 PRINT B%\n"
        "40 END\n"
    )


def test_top_level_spelling_is_untouched():
    # Outside an arm the numbered-GOTO form is legal and byte-exact, so the
    # fold must not reach it: t1_ifgoto keeps its conditional GOTO.
    prog = _prog("t1_ifgoto")
    assert any(isinstance(s, ir.IfGoto) for s in prog)
