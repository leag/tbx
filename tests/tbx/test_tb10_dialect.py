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
