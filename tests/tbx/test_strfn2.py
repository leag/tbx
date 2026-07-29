"""COMMAND$ / INPUT$ / STRING$(n, s$) -- the INT EE string-intrinsic subs
02/10/12/24, the top gaps in the PC-SIG wild scan after SCREEN."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_cmd():
    # EE sub 02: zero-arg, result pushed (witnessed t1_cmd)
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_cmd.exe"))
    assert prog[0] == ir.Assign(ir.Var("A$"), ir.Nullary("COMMAND$"))


def test_decode_t1_inp5():
    # EE sub 10: keyboard INPUT$(n), n in ax; sub 12: file INPUT$(n, f),
    # n shuttled to bx, f in ax (witnessed t1_inp5)
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_inp5.exe"))
    assert prog[4] == ir.Assign(
        ir.Var("A$"), ir.Call("INPUT$", (L(3), L(2)))
    )
    assert prog[6] == ir.Assign(ir.Var("B$"), ir.Call("INPUT$", (L(1),)))


def test_decode_t1_strs2():
    # EE sub 24: STRING$(n, s$) with n in ax and s$ on the string stack --
    # the character-code form stays sub 22 (witnessed t1_strs2)
    from tbx import decode0

    L = ir.Lit
    prog = decode0.decode_user_code(_exe("t1_strs2.exe"))
    assert prog[0] == ir.Assign(
        ir.Var("A$"), ir.Call("STRING$", (L(5), ir.StrLit("-")))
    )
    assert prog[1] == ir.Assign(ir.Var("B$"), ir.Call("STRING$", (L(6), L(42))))
    assert prog[2] == ir.Assign(
        ir.Var("C$"), ir.Call("STRING$", (L(4), ir.Var("A$")))
    )


def test_emit_strfn2():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_strs2.exe"))) == (
        '10 A$ = STRING$(5,"-")\n20 B$ = STRING$(6,42)\n30 C$ = STRING$(4,A$)\n'
        "40 PRINT A$; B$; C$\n50 END\n"
    )


if __name__ == "__main__":
    test_decode_t1_cmd()
    test_decode_t1_inp5()
    test_decode_t1_strs2()
    test_emit_strfn2()
    print("ALL PASS")
