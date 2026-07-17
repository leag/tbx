"""Compiler-flag fixtures.

Each f<code>_ fixture is compiled with one IDE Options-menu toggle ON
(fkb=Keyboard break, fbd=Bounds, fov=Overflow, fst=Stack test, f87=8087
required). Decode must detect the toggle from the flags mask byte at
prologue-0x73 and emit source IDENTICAL to what the unflagged program
decodes to -- the toggle has no TB source form, so it rides on
Program.toggles (a carrying comment would not be byte-invisible under K/O,
so nothing is emitted).

Flagged fixtures carry no `.bas` golden, so the golden sweep skips them;
these tests pin their decode directly.
"""

import os

from tbx import decode0, emit0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


# (flagged fixture, toggles, expected recovered source)
CASES = [
    (
        "fst_t1_gosub.exe",
        "S",
        "10 A = 1\n20 GOSUB 50\n30 A = 3\n40 END\n50 B = 2\n60 RETURN\n",
    ),
    ("f87_t1_beep.exe", "8", "10 BEEP\n20 END\n"),
    (  # FP add via the 9B D8+n alias; non-aliased source, so gate-clean
        "f87_t1_arr1.exe",
        "8",
        "10 DIM V0(10)\n20 V0(1) = 5\n30 V0(2) = V0(1) + 1\n40 A = V0(2)\n50 END\n",
    ),
    ("fkb_t1_beep.exe", "K", "10 BEEP\n20 END\n"),
    ("fkb_t1_and.exe", "K", None),
    ("fov_t1_and.exe", "O", None),
    (  # 0xCE (INTO) after an integer ADD fold under Overflow: no source
        # spelling, skipped mid-expression without disturbing statement
        # grouping
        "fov_t1_ovfadd.exe",
        "O",
        "10 A% = 30000\n20 B% = 30000\n30 C% = A% + B%\n40 PRINT C%\n50 END\n",
    ),
    (
        "v10_fov_t1_ovfadd.exe",
        "O",
        "10 A% = 30000\n20 B% = 30000\n30 C% = A% + B%\n40 PRINT C%\n50 END\n",
    ),
    (
        "fbd_t1_arr1.exe",
        "B",
        "10 DIM V0(10)\n20 V0(1) = 5\n30 V0(2) = V0(1) + 1\n40 A = V0(2)\n50 END\n",
    ),
    ("fbd_t1_arr2.exe", "B", None),
    (  # 1-D numeric variable index under Bounds (bchk0/bchk_base/bchk_idx)
        "fbd_t1_arrv.exe",
        "B",
        "10 DIM V0(10)\n20 A = 3\n30 V0(A) = 2\n40 B = V0(A) + V0(1)\n50 END\n",
    ),
    (  # runtime-DIM array, variable index under Bounds
        "fbd_t1_dimv.exe",
        "B",
        "10 INPUT A\n20 DIM V0(A)\n30 V0(1) = 2\n40 PRINT V0(1)\n50 END\n",
    ),
    ("fbd_t1_sarr.exe", "B", None),  # string-array variable index (bchk covers it)
    ("fbd_t1_dimm.exe", "B", None),  # 2-D variable index (bchk_span, F3.5)
    ("v10_fkb_t1_beep.exe", "K", "10 BEEP\n20 END\n"),
]


def test_flagged_fixtures_detect_and_decode():
    for flagged, tog, expect in CASES:
        prog = decode0.decode_user_code(_exe(flagged))
        assert getattr(prog, "toggles", "") == tog, flagged
        src = emit0.emit(prog)
        assert "$TOGGLES" not in src and "'" not in src.split("\n")[0], flagged
        if expect is not None:
            assert src == expect, flagged


def test_default_corpus_reads_no_toggles():
    for f in ("t1_beep.exe", "t1_and.exe", "t1_gosub.exe", "v10_t1_beep.exe"):
        assert getattr(decode0.decode_user_code(_exe(f)), "toggles", "") == ""


def test_toggle_names():
    assert decode0.toggle_names("K") == "Keyboard break"
    assert decode0.toggle_names("BO") == "Bounds, Overflow"


def test_stack_test_scan_vocabulary():
    """cd 8a <i32 start-rel> lifts as the GOSUB near call; cd 8b as RETURN."""
    exe = _exe("fst_t1_gosub.exe")
    start, dia = decode0.find_prologue(exe)
    ops = decode0._scan(exe, start, dia, set())
    kinds = [o[1] for o in ops]
    assert "call" in kinds and "ret" in kinds
    (call,) = [o for o in ops if o[1] == "call"]
    assert start < call[2] <= start + 0x100  # target resolves inside user code


def test_bounds_varindex_scan_vocabulary():
    """Variable-index access under Bounds inserts xor si,si (bchk0) + INT 91
    (bchk_base) and a checked INT 93 (bchk_idx) around the unchanged index math."""
    exe = _exe("fbd_t1_arrv.exe")
    start, dia = decode0.find_prologue(exe)
    kinds = [o[1] for o in decode0._scan(exe, start, dia, set())]
    assert "bchk0" in kinds and "bchk_base" in kinds and "bchk_idx" in kinds
    assert "addsi" in kinds and "shlsi" in kinds  # index math still present (F3.4)
    # 2-D adds the checked span-multiply bchk_span (F3.5)
    dimm = _exe("fbd_t1_dimm.exe")
    ds, dd = decode0.find_prologue(dimm)
    assert "bchk_span" in [o[1] for o in decode0._scan(dimm, ds, dd, set())]


def test_8087_scan_aliases_emulated_fp():
    """9B D8+n scans to the same FP op kinds the emulation INT 34h+n would.
    f87_t1_arr1's `V0(1) + 1` is FLD/FADD-mem/FSTP -- all via the 9B D8+n alias."""
    exe = _exe("f87_t1_arr1.exe")
    start, dia = decode0.find_prologue(exe)
    kinds = [o[1] for o in decode0._scan(exe, start, dia, set())]
    assert "fld" in kinds and "fold" in kinds and "fstp" in kinds
