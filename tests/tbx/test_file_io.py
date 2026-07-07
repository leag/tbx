"""OPEN / INPUT# / CLOSE."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = ["t1_file", "t1_file2"]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_decode_t1_file():
    from tbx import decode0

    want = [
        ir.Open(ir.StrLit("I"), 1, ir.StrLit("X.DAT")),
        ir.InputFile(1, (ir.Var("A"),)),
        ir.InputFile(1, (ir.Var("B$"),)),
        ir.Close(1),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_file.exe")) == want


def test_decode_t1_file2():
    from tbx import decode0

    want = [
        ir.LineInput(None, ir.Var("A$")),
        ir.Open(ir.StrLit("I"), 2, ir.Var("A$")),
        ir.InputFile(2, (ir.Var("B"), ir.Var("C"))),
        ir.Close(2),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_file2.exe")) == want


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_file_io():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_file.exe"))) == (
        '10 OPEN "I",#1,"X.DAT"\n20 INPUT #1, A\n30 INPUT #1, B$\n40 CLOSE #1\n50 END\n'
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_file2.exe"))) == (
        '10 LINE INPUT A$\n20 OPEN "I",#2,A$\n30 INPUT #2, B, C\n40 CLOSE #2\n50 END\n'
    )


if __name__ == "__main__":
    test_decode_t1_file()
    test_decode_t1_file2()
    test_dialect_invariant()
    test_emit_file_io()
    print("ALL PASS")
