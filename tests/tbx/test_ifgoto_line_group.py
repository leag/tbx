"""A statement sharing a line with an `IF ... THEN <line>` is its ELSE clause.

Turbo Basic rejects `IF c THEN 80: E$ = "Y"` (Error 431, End-of-line expected):
after a line-number THEN target the line is finished. So when the error-trap line
table puts further statements on the same original line as an `IfGoto`, the only
source that can have produced them is an ELSE clause -- the fall-through path.
Witnessed on wild vhfprop.exe, which has 28 such lines.
"""

from tbx import emit0, ir
from tbx.decode0.meta import Program


def _prog(stmts, lines):
    p = Program(stmts)
    p.lines = list(lines)
    return p


def _cond(name):
    return ir.RelOp("<>", ir.Var(name + "$"), ir.StrLit("y"))


def test_trailing_statement_becomes_else():
    #  74 IF E$ <> "y" THEN 80 ELSE E$ = "Y"
    #  80 END
    prog = _prog(
        [
            ir.IfGoto(_cond("E"), 2),
            ir.Assign(ir.Var("E$"), ir.StrLit("Y")),
            ir.End(),
        ],
        [74, 74, 80],
    )
    text = emit0.emit(prog)
    assert '74 IF E$ <> "y" THEN 80 ELSE E$ = "Y"\n' in text
    assert "THEN 80:" not in text


def test_statements_before_and_after_the_if():
    # 300 CLS: IF G$ <> "y" THEN 301 ELSE PRINT: PRINT
    prog = _prog(
        [
            ir.Cls(),
            ir.IfGoto(_cond("G"), 4),
            ir.Print(()),
            ir.Print(()),
            ir.End(),
        ],
        [300, 300, 300, 300, 301],
    )
    text = emit0.emit(prog)
    assert '300 CLS: IF G$ <> "y" THEN 301 ELSE PRINT: PRINT\n' in text


def test_nested_block_shape_becomes_inline_on_same_physical_line():
    prog = _prog(
        [
            ir.IfGoto(_cond("A"), 3),
            ir.Assign(ir.Var("Z$"), ir.StrLit("Y")),
            ir.IfBlock(
                ((ir.LogOp("OR", _cond("Z"), _cond("Q")), (ir.End(),)),),
                (ir.Goto(0),),
            ),
            ir.End(),
        ],
        [133, 133, 133, 134],
    )
    prog.expanded_line_table = True

    text = emit0.emit(prog)

    assert (
        '133 IF A$ <> "y" THEN 134 ELSE Z$ = "Y": '
        'IF Z$ <> "y" OR Q$ <> "y" THEN END ELSE GOTO 133\n'
    ) in text
    assert "\n ELSE\n" not in text


def test_else_skip_sequence_becomes_inline_on_same_physical_line():
    prog = _prog(
        [
            ir.Locate(ir.Lit(24), ir.Lit(1)),
            ir.IfGoto(ir.RelOp("<>", ir.Var("Z$"), ir.StrLit("6")), 4),
            ir.Assign(ir.Var("A"), ir.Lit(64)),
            ir.Goto(5),
            ir.Assign(ir.Var("A"), ir.Lit(31)),
            ir.End(),
        ],
        [700, 700, 700, 700, 700, 705],
    )
    prog.expanded_line_table = True

    text = emit0.emit(prog)

    assert (
        '700 LOCATE 24,1: IF Z$ = "6" THEN A = 64 ELSE A = 31\n'
    ) in text
    assert "GOTO 700" not in text
