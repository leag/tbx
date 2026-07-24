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
        ("cleanup.exe", ValueError, "LOCAL zero-fill outside a fresh SUB/DEF FN body at 0xd0ca"),
        ("crossref.exe", ValueError, "unhandled INT EC sub 38 at 0x11a63"),
        ("reformat.exe", ValueError, "LOCAL zero-fill outside a fresh SUB/DEF FN body at 0xd455"),
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


def test_ziptest_advances_to_forward_fn_resolution_gap():
    from conftest import wild_hits_bytes

    data = wild_hits_bytes("ziptest.exe")
    with pytest.raises(ValueError, match="jump target 0x9ff7 is not a statement start"):
        decode0.decode_user_code(data)


@pytest.mark.parametrize("stem", ["t1_fnforward", "v10_t1_fnforward"])
def test_forward_block_fn_call(stem):
    program = decode0.decode_user_code(
        (_ROOT / "tests" / "fixtures" / "corpus" / f"{stem}.exe").read_bytes()
    )
    assert program[0] == ir.Print(
        (ir.FnCall("FNFN1", (ir.Lit(3),)),), newline=True
    )
