"""WIDTH #filenum,cols runtime form (canonical INT EC sub F0)."""

from pathlib import Path

import pytest

from tbx import decode0, emit0, ir

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


@pytest.mark.parametrize("stem", ["t1_widthfile", "v10_t1_widthfile"])
def test_width_file_ir_and_emission(stem):
    program = decode0.decode_user_code((_CORPUS / f"{stem}.exe").read_bytes())
    assert list(program) == [ir.Width(ir.Lit(80), file=1), ir.End()]
    assert emit0.emit(program) == "10 WIDTH #1,80\n20 END\n"
