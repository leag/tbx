"""Output formatting -- PRINT variants/USING, KILL/PLAY."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_pr2", "t1_kill", "t1_play"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_pr2():
    from tbx import decode0

    S, V = ir.StrLit, ir.Var
    a = V("A")
    want = [
        ir.Input(None, a),
        ir.Print((S("A"), a, S("B"))),
        ir.Print((S("X"),), newline=False),
        ir.PrintUsing(S("##.##"), (a,)),
        ir.PrintUsing(S("#.# #.#"), (a, a)),
        ir.Open(S("O"), 1, S("R.TXT")),
        ir.Print((a,), file=1),
        ir.PrintUsing(S("##.##"), (a, a), file=1),
        ir.Close(1),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_pr2.exe")) == want


def test_decode_t1_kill():
    from tbx import decode0

    want = [ir.Kill(ir.StrLit("X.DAT")), ir.End()]
    assert decode0.decode_user_code(_exe("t1_kill.exe")) == want


def test_decode_t1_play():
    from tbx import decode0

    want = [ir.Play(ir.StrLit("O5G8.G8.G8...")), ir.End()]
    assert decode0.decode_user_code(_exe("t1_play.exe")) == want


def test_print_single_item_normalization():
    # legacy single-expr ctor == one-item tuple form (backward compat)
    assert ir.Print(ir.Lit(1)) == ir.Print((ir.Lit(1),))


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_print_using():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_pr2.exe"))) == (
        "10 INPUT A\n"
        '20 PRINT "A"; A; "B"\n'
        '30 PRINT "X";\n'
        '40 PRINT USING "##.##"; A\n'
        '50 PRINT USING "#.# #.#"; A; A\n'
        '60 OPEN "O",#1,"R.TXT"\n'
        "70 PRINT #1, A\n"
        '80 PRINT #1, USING "##.##"; A; A\n'
        "90 CLOSE #1\n"
        "100 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_kill.exe"))) == (
        '10 KILL "X.DAT"\n20 END\n'
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_play.exe"))) == (
        '10 PLAY "O5G8.G8.G8..."\n20 END\n'
    )


if __name__ == "__main__":
    test_decode_t1_pr2()
    test_decode_t1_kill()
    test_decode_t1_play()
    test_print_single_item_normalization()
    test_dialect_invariant()
    test_emit_print_using()
    print("ALL PASS")
