"""Four-byte STRING variables declared with LOCAL inside a SUB."""

from pathlib import Path

import pytest

from tbx import decode0, emit0, ir

_ROOT = Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "fixtures" / "corpus"


@pytest.mark.parametrize("stem", ["t1_localstr", "v10_t1_localstr"])
def test_string_local_ir_and_emission(stem):
    program = decode0.decode_user_code((_CORPUS / f"{stem}.exe").read_bytes())
    sub = program[2]

    assert sub == ir.SubDef(
        "SUB1",
        (),
        (
            ir.Local(("A$",)),
            ir.Assign(ir.Var("A$"), ir.StrLit("X")),
            ir.Print((ir.Var("A$"),), newline=True),
        ),
    )
    assert emit0.emit(program) == (
        "10 CALL SUB1\n20 END\n30 SUB SUB1\n"
        '  LOCAL A$\n  A$ = "X"\n  PRINT A$\nEND SUB\n'
    )


@pytest.mark.parametrize("stem", ["t1_fnlocalarrstr", "v10_t1_fnlocalarrstr"])
def test_string_local_in_block_def_fn(stem):
    program = decode0.decode_user_code((_CORPUS / f"{stem}.exe").read_bytes())
    fn = program[0]
    assert isinstance(fn, ir.DefFn)
    assert fn.body[0] == ir.Local(("V0$()", "B", "C$", "D%", "E", "F"))
    assert ir.Input(None, ir.Var("D%")) in fn.body
    assert ir.Dim("V0$", (ir.Var("D%"),)) in fn.body
    assert ir.Assign(ir.Var("C$"), ir.Call("UCASE$", (ir.Var("C$"),))) in fn.body
    assert ir.Erase("V0$") in fn.body


@pytest.mark.parametrize(
    ("stem", "exc", "next_gap"),
    [
        # advanced past `string BP push outside DEF FN at 0x9279` once the
        # variable-limit LOCAL FOR stopped deleting the local at loop_var+2
        # from the frame table (t1_locstrafterfor)
        ("bmaster.exe", ValueError, "forwarded arg to unknown callee params at 0x9391"),
        ("ifi.exe", ValueError, "unhandled INT 8c at 0x19bd2"),
        ("cleanup.exe", ValueError, "jump target 0xe9be is not a statement start"),
        ("reformat.exe", ValueError, "jump target 0xed49 is not a statement start"),
    ],
)
def test_string_local_witnesses_advance(stem, exc, next_gap):
    from conftest import wild_hits_bytes

    with pytest.raises(exc, match=next_gap):
        decode0.decode_user_code(wild_hits_bytes(stem))
