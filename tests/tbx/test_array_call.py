"""Whole-array CALL arguments passed by runtime vector D4."""

from pathlib import Path

import pytest

from tbx import c0, decode0, ir

_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "path",
    [
        "wild/probes/arrayparam6.exe",
        "wild/hits/zip.exe",
    ],
)
def test_d4_whole_array_argument_shape(path):
    data = (_ROOT / path).read_bytes()
    _, dialect = decode0.find_prologue(data)
    i = next(
        i
        for i in range(len(data) - 1)
        if data[i] == 0xCD and dialect.canon_vec(data[i + 1]) == 0xD4
    )
    assert data[i - 3] == 0xBE  # mov si,<array slot>
    assert data[i + 2] == 0x9A  # far CALL immediately consumes the descriptor


def test_numeric_array_parameter_decodes_completely():
    prog = decode0.decode_user_code(
        (_ROOT / "wild/probes/arrayparam6.exe").read_bytes()
    )
    assert prog[2] == ir.CallStmt("SUB1", (ir.ArrayRef("V0", ()),))
    assert prog[4] == ir.SubDef(
        "SUB1",
        ("A(1)",),
        (ir.Print((ir.ArrayRef("A", (ir.Lit(1),)),)),),
    )


def test_zip_string_array_parameter_decodes_completely():
    prog = decode0.decode_user_code((_ROOT / "wild/hits/zip.exe").read_bytes())
    sub = prog[-1]
    assert isinstance(sub, ir.SubDef)
    assert sub.name == "SUB30"
    assert sub.params == ("M$(1)",)
    assert any(
        isinstance(s, ir.IfInline)
        and isinstance(s.cond, ir.LogOp)
        and isinstance(s.cond.lhs, ir.RelOp)
        and s.cond.lhs.lhs == ir.ArrayRef("M$", (ir.Lit(1),))
        for s in sub.body
    )


def test_whole_array_ir_spelling_and_c0_refusal():
    arg = ir.ArrayRef("A", ())
    assert ir.unparse(arg) == "A()"
    prog = [
        ir.SubDef("SUB1", ("B",), ()),
        ir.CallStmt("SUB1", (arg,)),
        ir.End(),
    ]
    with pytest.raises(ValueError, match="whole-array SUB argument"):
        c0.emit_c(prog)

    prog = [ir.SubDef("SUB1", ("A(1)",), ()), ir.End()]
    with pytest.raises(ValueError, match="whole-array SUB parameter"):
        c0.emit_c(prog)
