from tbx import ir
from tbx.decode0.lift import _apply_exit_folds


def test_exit_loop_fold_requires_an_enclosing_do():
    stmts = [ir.Goto(("addr", 100)), ir.Goto(("addr", 200))]
    addrs = [10, 20]

    _apply_exit_folds(stmts, addrs, [(ir.ExitLoop(), 300, 100)])

    assert stmts[0] == ir.Goto(("addr", 100))


def test_exit_loop_fold_rewrites_inside_do():
    stmts = [ir.Do(None), ir.Goto(("addr", 100)), ir.Loop(None), ir.Goto(("addr", 200))]
    addrs = [10, 20, 30, 300]

    _apply_exit_folds(stmts, addrs, [(ir.ExitLoop(), 30, 100)])

    assert stmts[1] == ir.ExitLoop()
