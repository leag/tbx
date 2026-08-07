import pytest

from tbx import emit0, ir


def test_emit_rejects_exit_loop_without_do():
    with pytest.raises(ValueError, match="EXIT LOOP without an enclosing DO"):
        emit0.emit([ir.ExitLoop()])


def test_emit_accepts_exit_loop_inside_inline_if_and_do():
    source = emit0.emit(
        [
            ir.Do(None),
            ir.IfInline(ir.RelOp("=", ir.Lit(1), ir.Lit(1)), (ir.ExitLoop(),)),
            ir.Loop(None),
        ]
    )
    assert "EXIT LOOP" in source
