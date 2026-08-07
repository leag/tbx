"""emit0.emit's optional line_starts out-param: the authoritative mapping
from a top-level statement index to the 0-based line it renders to.
"""

from tbx import emit0, ir


def test_line_starts_matches_one_statement_per_line():
    stmts = [
        ir.Print((ir.StrLit("A"),)),
        ir.Print((ir.StrLit("B"),)),
        ir.End(),
    ]

    line_starts: list[int] = []
    source = emit0.emit(stmts, line_starts=line_starts)

    assert source.splitlines() == ['10 PRINT "A"', '20 PRINT "B"', "30 END"]
    assert line_starts == [0, 1, 2]


def test_line_starts_groups_statements_sharing_one_line():
    class _Statements(list):
        lines = (10, 10, 20)

    stmts = _Statements(
        [
            ir.Assign(ir.Var("A"), ir.Lit(1)),
            ir.Assign(ir.Var("B"), ir.Lit(2)),
            ir.End(),
        ]
    )

    line_starts: list[int] = []
    source = emit0.emit(stmts, line_starts=line_starts)

    lines = source.splitlines()
    assert len(lines) == 2  # "10 A=1:B=2" and "20 END"
    # Both statements sharing line 10 point at the same rendered line.
    assert line_starts[0] == line_starts[1] == 0
    assert line_starts[2] == 1


def test_line_starts_is_none_by_default_and_does_not_affect_output():
    stmts = [ir.Print((ir.StrLit("HI"),)), ir.End()]

    assert emit0.emit(stmts) == emit0.emit(stmts, line_starts=None)
