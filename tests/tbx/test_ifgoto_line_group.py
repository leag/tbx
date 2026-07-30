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
