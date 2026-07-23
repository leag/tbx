"""Whole-array CALL arguments passed by runtime vector D4."""

from pathlib import Path

import pytest

from tbx import c0, decode0, ir

_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("path", "next_gap"),
    [
        ("wild/probes/arrayparam6.exe", "unhandled byte 2b"),
        ("wild/hits/zip.exe", "unhandled byte b0"),
    ],
)
def test_d4_whole_array_argument_advances(path, next_gap):
    data = (_ROOT / path).read_bytes()
    _, dialect = decode0.find_prologue(data)
    i = next(
        i
        for i in range(len(data) - 1)
        if data[i] == 0xCD and dialect.canon_vec(data[i + 1]) == 0xD4
    )
    assert data[i - 3] == 0xBE  # mov si,<array slot>
    assert data[i + 2] == 0x9A  # far CALL immediately consumes the descriptor
    with pytest.raises(ValueError, match=next_gap):
        decode0.decode_user_code(data)


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
