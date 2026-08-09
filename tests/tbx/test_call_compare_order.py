from pathlib import Path

from tbx import decode0, emit0


_ROOT = Path(__file__).resolve().parents[2]


def test_fcompp_call_operand_keeps_its_source_order():
    exe = (_ROOT / "tests/fixtures/corpus/t1_poscmp.exe").read_bytes()
    assert emit0.emit(decode0.decode_user_code(exe)) == (
        "10 A = 31\n"
        "20 IF POS(0) > A THEN 40\n"
        '30 PRINT "MATCH"\n'
        "40 END\n"
    )
