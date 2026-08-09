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


def test_decode_t1_open2():
    # short-form OPEN's ax is the record length: 0x80 (the compiler default)
    # lifts to reclen=None, anything else was spelled -- witnessed t1_open2
    # (modes O/I/A default, R with reclen 64)
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_open2.exe"))
    assert prog[0] == ir.Open(ir.StrLit("O"), 1, ir.StrLit("A.TXT"))
    assert prog[8] == ir.Open(ir.StrLit("R"), 4, ir.StrLit("B.DAT"), ir.Lit(64))


def test_decode_get_with_omitted_record_number():
    from tbx import decode0, emit0

    program = decode0.decode_user_code(_exe("v10_t1_getbare.exe"))

    assert program[1] == ir.Get(1, None)
    assert emit0.emit(program).splitlines()[1] == "20 GET #1"


def test_constant_integer_array_read_is_not_a_pool_literal():
    from tbx import decode0, emit0

    program = decode0.decode_user_code(_exe("v10_t1_intarrconst.exe"))

    assert program[2] == ir.Print(
        (ir.ArrayRef("V0%", (ir.Lit(2),)),), newline=True
    )
    assert emit0.emit(program).splitlines()[2] == "30 PRINT V0%(2)"


def test_emit_random_open_with_explicit_record_length():
    from tbx import decode0, emit0

    program = decode0.decode_user_code(_exe("v10_t1_openrandomlen.exe"))

    assert program[1] == ir.Open(
        ir.StrLit("R"), 1, ir.Var("A$"), ir.Lit(215), for_as=True
    )
    assert emit0.emit(program).splitlines()[1] == (
        "20 OPEN A$ FOR RANDOM AS #1 LEN = 215"
    )


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
    test_decode_t1_open2()
    test_dialect_invariant()
    test_emit_file_io()
    print("ALL PASS")
