"""CLS / LOCATE / COLOR."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_scr():
    from tbx import decode0

    L = ir.Lit
    want = [
        ir.Cls(),
        ir.Locate(L(3), L(5)),
        ir.Color(fg=L(1)),
        ir.Locate(L(10), L(20)),
        ir.Color(fg=L(7), bg=L(0)),
        ir.Print(ir.StrLit("HI")),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_scr.exe")) == want


def test_decode_t1_scr2():
    from tbx import decode0

    L = ir.Lit
    want = [
        ir.Locate(L(3), L(5), L(1)),
        ir.Locate(L(4), L(6), L(0)),
        ir.Color(bg=L(2)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_scr2.exe")) == want


def test_dialect_invariant():
    from tbx import decode0

    for name in ("t1_scr", "t1_scr2"):
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_screen():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_scr.exe"))) == (
        "10 CLS\n20 LOCATE 3,5\n30 COLOR 1\n40 LOCATE 10,20\n50 COLOR 7,0\n"
        '60 PRINT "HI"\n70 END\n'
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_scr2.exe"))) == (
        "10 LOCATE 3,5,1\n20 LOCATE 4,6,0\n30 COLOR ,2\n40 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_scr()
    test_decode_t1_scr2()
    test_dialect_invariant()
    test_emit_screen()
    print("ALL PASS")
