"""COMMON: CHAIN-persistent scalars in their own DGROUP band at DS:0110.

The statement compiles to no ops -- only a pair of 16-byte band-descriptor
stamps in the init image, (num_size, num_base)(str_size, num_base+num_size)
(0, num_base)(0, num_base), one for the COMMON band and one for the ordinary
scalars (which become SEGREGATED, numerics first). The compiler is lossy
about the declaration: numeric/string interleaving, numeric width mixes of
equal total size, and splitting across statements all compile identically,
so the decoder emits one canonical statement (numerics as '%' fillers where
no reference types a slot, then strings) -- every shape verified byte-exact
through the oracle before promotion.
"""

import os
from tbx import decode0, emit0, ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_common1():
    # authored `COMMON A$, B%, C#` normalizes: the unreferenced numeric space
    # (B% + C# = 10 bytes) fills as five '%' ints, the string moves last
    prog = decode0.decode_user_code(_exe("t1_common1.exe"))
    assert prog[0] == ir.Common(("A%", "B%", "C%", "D%", "E%", "F$"))
    src = emit0.emit(prog)
    assert src == (
        "10 COMMON A%, B%, C%, D%, E%, F$\n"
        '20 G$ = "HI"\n30 H% = 7\n40 PRINT G$; H%\n50 END\n'
    )


def test_decode_t1_common2():
    # three COMMON strings + two ordinary strings: stamps sit between the
    # bands (com at align16(com_end), ord right after)
    src = emit0.emit(decode0.decode_user_code(_exe("t1_common2.exe")))
    assert src == (
        "10 COMMON A$, B$, C$\n"
        '20 D$ = "HI"\n30 E$ = "YO"\n40 PRINT D$; E$\n50 END\n'
    )


def test_decode_t1_common3():
    # 10-string COMMON with NO ordinary scalars: the stamps shift down a
    # paragraph and stamp1 overlays the band's own tail cells, so extraction
    # must match stamps by shape, never position
    src = emit0.emit(decode0.decode_user_code(_exe("t1_common3.exe")))
    assert src == (
        "10 COMMON A$, B$, C$, D$, E$, F$, G$, H$, I$, J$\n"
        '20 J$ = "HI"\n30 PRINT J$\n40 END\n'
    )


def test_decode_v10_t1_common2():
    # TB 1.0 emits the same stamp encoding (same .bas as t1_common2)
    assert emit0.emit(decode0.decode_user_code(_exe("v10_t1_common2.exe"))) == (
        emit0.emit(decode0.decode_user_code(_exe("t1_common2.exe")))
    )


if __name__ == "__main__":
    test_decode_t1_common1()
    test_decode_t1_common2()
    test_decode_t1_common3()
    test_decode_v10_t1_common2()
    print("ALL PASS")
