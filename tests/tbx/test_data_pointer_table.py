"""Small DATA pointer-table recovery."""

from pathlib import Path

from tbx import decode0, emit0, ir

_ROOT = Path(__file__).resolve().parents[2]


def test_shared_and_repeated_data_items_are_recovered_in_source_order():
    exe = (
        _ROOT / "tests" / "fixtures" / "corpus" / "t1_datasharedlit.exe"
    ).read_bytes()

    program = decode0.decode_user_code(exe)

    assert program[0] == ir.Data(
        (
            ir.DataItem("P", True),
            ir.DataItem("D", True),
            ir.DataItem("0", False),
        )
    )
    assert emit0.emit(program).startswith('10 DATA "P","D",0\n')
