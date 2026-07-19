"""TB 1.0 dialect tests: the same source compiled by Turbo Basic 1.0 must
decode to the SAME typed IR as the 1.1 build -- the calibration transfers
modulo the dialect table."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = [
    "tier0_trivial",
    "tier1_expr",
    "t1_for",
    "t1_print",
    "t1_int",
    "t1_arr1",
    "t1_sstat",
    "t1_run2",
    "t1_byref2",
    "t1_forstep",
    "t1_forstepn",
    "t1_forbig",
    "t1_addimm",
    "t1_for10arr",
    "t1_fwd",
    "t1_locidx",
    "t1_loccmp",
    "t1_bandwide",
    "t1_bandstr",
    "t1_dim4",
    "t1_strch",
    "t1_svaridx",
    "t1_addpool",
    "t1_ifgoto",
    "t1_errcmp",
    "t1_fileint",
    "t1_imulpool",
    "t1_miderr",
    "t1_orchain",
    "t1_andchain",
    "t1_dataorph",
    "t1_dimorph",
    "t1_color3",
    "t1_nestif2",
    "t1_gotoerr",
    "t1_doerr",
    "t1_arrwrite",
    "t1_arrread",
    "t1_arrcmp",
    "t1_subm",
    "t1_arrswap",
    "t1_arrswapf",
    "t1_openfor",
    "t1_pcomma2",
    "t1_strgodo",
    "t1_strgoto",
    "t1_bigjmp",
    "t1_blkgoto",
    "t1_lpusing",
]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_find_prologue_dialects():
    from tbx import decode0

    s11, d11 = decode0.find_prologue(_exe("tier0_trivial.exe"))
    s10, d10 = decode0.find_prologue(_exe("v10_tier0_trivial.exe"))
    assert d11.name == "1.1" and d10.name == "1.0"
    assert s11 == 0x8700 and s10 == 0x70B0


def test_decode_v10_trivial():
    from tbx import decode0

    want = [ir.Assign(ir.Var("A"), ir.Lit(1)), ir.End()]
    assert decode0.decode_user_code(_exe("v10_tier0_trivial.exe")) == want


def test_dialect_invariant_ir():
    from tbx import decode0

    for name in PAIRS:
        got11 = decode0.decode_user_code(_exe(f"{name}.exe"))
        got10 = decode0.decode_user_code(_exe(f"v10_{name}.exe"))
        assert got10 == got11, f"{name}: 1.0 IR != 1.1 IR"


if __name__ == "__main__":
    test_find_prologue_dialects()
    test_decode_v10_trivial()
    test_dialect_invariant_ir()
    print("ALL PASS")
