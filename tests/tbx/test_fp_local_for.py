"""SINGLE LOCAL variables and BP-relative variable-STEP FOR templates."""

from pathlib import Path

import pytest

from tbx import decode0, ir
from tbx.decode0 import scan

_ROOT = Path(__file__).resolve().parents[2]


def test_scan_testw_bp_is_exact():
    ops = []
    data = bytes.fromhex("f7 46 18 00 80")
    assert scan._scan_direct(data, 0, data[0], decode0.TB11, ops, 0) == 5
    assert ops == [(0, "testw_bp", 0x18, 0x8000)]


@pytest.mark.parametrize(
    ("stem", "exc", "next_gap"),
    [
        ("cleanup.exe", ValueError, "jump target 0xe9be is not a statement start"),
        ("crossref.exe", ValueError, "displacement 0x324 is neither scalar nor array element"),
        ("reformat.exe", ValueError, "jump target 0xed49 is not a statement start"),
    ],
)
def test_fp_local_for_advances_wild_program(stem, exc, next_gap):
    from conftest import wild_hits_bytes

    data = wild_hits_bytes(stem)
    with pytest.raises(exc, match=next_gap):
        decode0.decode_user_code(data)


@pytest.mark.parametrize("stem", ["t1_fnlocalarrstr", "v10_t1_fnlocalarrstr"])
def test_mixed_def_fn_for_storage(stem):
    program = decode0.decode_user_code(
        (_ROOT / "tests" / "fixtures" / "corpus" / f"{stem}.exe").read_bytes()
    )
    fn = program[0]
    assert isinstance(fn, ir.DefFn)
    assert [stmt for stmt in fn.body if isinstance(stmt, ir.For)] == [
        ir.For(ir.Var("G"), ir.Lit(0), ir.Lit(2), ir.Var("B")),
        ir.For(ir.Var("E"), ir.Lit(1), ir.Var("D%"), ir.Var("F")),
    ]


def test_ziptest_decodes_with_a_tail_if_closing_a_sub():
    # ziptest.exe used to stop at `jump target 0x9ff7 is not a statement start`
    # and now decodes end to end. The gap was a single-line IF as the LAST
    # statement of a SUB: its false-skip lands on the epilogue, which is not a
    # statement and never can be (END SUB carries no line number), so the
    # `IF <negated> THEN <line>` normalization had nothing to name. Such an IF
    # stays inline instead -- DecodeState.open_tail_if.
    #
    # This file witnesses the generic-compare path (an FP compare through
    # fp_dispatch's _JCC_RELOP); corpus t1_iftaillast witnesses the by-ref
    # param compare path that wild tbd73.exe needed. Both had to be handled.
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("ziptest.exe"))
    tails = [
        s.body[-1]
        for s in prog
        if isinstance(s, ir.SubDef) and s.body and isinstance(s.body[-1], ir.IfInline)
    ]
    assert tails == [
        ir.IfInline(
            ir.RelOp(
                ">",
                ir.BinOp("*", ir.DblLit(0.017), ir.Var("AI")),
                ir.BinOp("-", ir.Var("AG"), ir.Var("AH")),
            ),
            (ir.CallStmt("SUB4", (ir.Var("AJ$"),)),),
        )
    ]


@pytest.mark.parametrize("stem", ["t1_fnforward", "v10_t1_fnforward"])
def test_forward_block_fn_call(stem):
    program = decode0.decode_user_code(
        (_ROOT / "tests" / "fixtures" / "corpus" / f"{stem}.exe").read_bytes()
    )
    assert program[0] == ir.Print(
        (ir.FnCall("FNFN1", (ir.Lit(3),)),), newline=True
    )
