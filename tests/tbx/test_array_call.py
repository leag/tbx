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
    p = _ROOT / path
    if not p.is_file():
        pytest.skip(f"{path} not present (gitignored, local-only corpus)")
    data = p.read_bytes()
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
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("zip.exe"))
    sub = prog[-1]
    assert isinstance(sub, ir.SubDef)
    assert sub.name == "SUB30"
    assert sub.params == ("M$(1)",)
    # A block IF/ELSE, not an IfInline + trailing GOTO: SUB bodies now get the
    # same _fold_if pass the top level has always run (t1_dblhooksub), and both
    # spellings compile identically, so the block form is the canonical one.
    assert any(
        isinstance(s, ir.IfBlock)
        and isinstance(s.arms[0][0], ir.LogOp)
        and isinstance(s.arms[0][0].lhs, ir.RelOp)
        and s.arms[0][0].lhs.lhs == ir.ArrayRef("M$", (ir.Lit(1),))
        and s.else_body is not None
        for s in sub.body
    )


def test_string_array_parameter_element_passed_by_reference():
    # An array PARAMETER's element read as a string AND passed by reference:
    # `arg_push_arr` is a bare ES:SI pointer push, byte-identical for every
    # element type, so it carries no type evidence. The suffix derivation used
    # to fall through to "" (SINGLE) there and collide with the `$` the
    # earlier far_spush had established for the same param
    # (`inconsistent array-parameter type`). Wild tbd73.exe: TBWINDOW
    # `SUB Makevmenu`'s `CALL Sprint(..., LEN(item$(mloop)) \ 2,
    # item$(mloop), ...)` does both in ONE statement.
    from tbx import emit0

    for stem in ("t1_arrparmref.exe", "v10_t1_arrparmref.exe"):
        prog = decode0.decode_user_code(
            (_ROOT / "tests/fixtures/corpus" / stem).read_bytes()
        )
        sub = prog[5]
        assert isinstance(sub, ir.SubDef) and sub.params == ("B$(1)",), stem
        # both accesses resolve to the SAME string-typed element
        assert sub.body[1] == ir.Print(
            (ir.Call("LEN", (ir.ArrayRef("B$", (ir.Var("A%"),)),)),)
        ), stem
        assert sub.body[2] == ir.CallStmt(
            "SUB2", (ir.ArrayRef("B$", (ir.Var("A%"),)),)
        ), stem
        assert "CALL SUB2(B$(A%))" in emit0.emit(prog), stem


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
