"""Whole-array CALL arguments passed by runtime vector D4."""

from pathlib import Path

import pytest

from tbx import decode0, ir

_ROOT = Path(__file__).resolve().parents[2]


def test_array_parameter_type_resolved_from_a_later_access():
    # `arg_push_arr` (passing a computed element by reference) and
    # `arg_push_array_bp` (relaying the whole array onward) BOTH carry no
    # element-type evidence -- they are bare pointer/descriptor pushes,
    # byte-identical for every element type. When one of them is the FIRST
    # thing a SUB does with its array parameter, defaulting the type to SINGLE
    # collides with the real type later in the body. The type is found by
    # looking ahead for an access that does witness it.
    #
    # Both shapes come from wild tbd73.exe's TBWINDOW `SUB Makehmenu`, which
    # forwards item$() onward AND indexes it.
    from tbx import emit0

    # by-ref element push first, string read after
    for pfx in ("", "v10_"):
        prog = decode0.decode_user_code(
            (_ROOT / "tests/fixtures/corpus" / f"{pfx}t1_arrparmfwdfirst.exe").read_bytes()
        )
        sub = prog[5]
        assert isinstance(sub, ir.SubDef) and sub.params == ("B$(1)",), pfx
        assert sub.body[1] == ir.CallStmt(
            "SUB2", (ir.ArrayRef("B$", (ir.Var("A%"),)),)
        ), pfx

    # whole-array RELAY first, element read after. The relay's own spelling
    # must pick up the suffix too: `B$()` and `B()` are different variables and
    # recompile to different bytes. Previously a raw KeyError on 'lo_off',
    # because the relay registered the descriptor without an index base.
    for pfx in ("", "v10_"):
        prog = decode0.decode_user_code(
            (_ROOT / "tests/fixtures/corpus" / f"{pfx}t1_arrparmrelayidx.exe").read_bytes()
        )
        sub = prog[5]
        assert isinstance(sub, ir.SubDef) and sub.params == ("B$(1)",), pfx
        assert sub.body[1] == ir.CallStmt("SUB2", (ir.ArrayRef("B$", ()),)), pfx
        assert "CALL SUB2(B$())" in emit0.emit(prog), pfx


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


@pytest.mark.parametrize(
    ("stem", "params", "header"),
    [
        # array FIRST + one scalar: the minimal mixed signature
        ("t1_arrparmmix", ("A$(1)", "B%"), "SUB SUB1(A$(1), B%)"),
        # array LAST -- the case that proves the frame walk reads each
        # descriptor's own witnessed offset instead of assuming arrays lead
        ("t1_arrparmmixlast", ("A%", "B$(1)"), "SUB SUB1(A%, B$(1))"),
        # several scalars, so the 0x3C-vs-4 byte arithmetic is exercised past
        # n=1 -- the shape TBWINDOW's Makevmenu(item$(1), + 9 scalars) uses
        ("t1_arrparmmixmany", ("A$(1)", "B%", "C%", "D%"), "SUB SUB1(A$(1), B%, C%, D%)"),
    ],
)
def test_mixed_scalar_array_sub_signature(stem, params, header):
    # A whole-array param arrives as a 0x3C rank-1 descriptor copied by
    # runtime vector D4, an ordinary param as a 4-byte by-ref slot -- and a
    # signature may MIX them. The retf pop count only gives the TOTAL, so the
    # split comes from each descriptor's own start offset (witnessed by its
    # `moves_bp`) walked from bp+6 upward in reverse source order.
    # Previously `unsupported array-parameter frame`.
    from tbx import emit0

    for pfx in ("", "v10_"):
        prog = decode0.decode_user_code(
            (_ROOT / "tests/fixtures/corpus" / f"{pfx}{stem}.exe").read_bytes()
        )
        sub = next(s for s in prog if isinstance(s, ir.SubDef))
        assert sub.params == params, (pfx, stem)
        assert header in emit0.emit(prog), (pfx, stem)


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


def test_whole_array_ir_spelling():
    arg = ir.ArrayRef("A", ())
    assert ir.unparse(arg) == "A()"
    assert arg == ir.ArrayRef("A", ())
