"""Source-relative `$INLINE "file"` provenance and bundle assets."""

from pathlib import Path

import pytest

from tbx import decode0, emit0, ir

_ROOT = Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "fixtures" / "corpus"


def test_external_inline_filename_and_payload_are_recovered():
    payload = (_CORPUS / "T1FILE.BIN").read_bytes()
    program = decode0.decode_user_code((_CORPUS / "t1_inlinefile.exe").read_bytes())

    assert program[0] == ir.SubDef("SUB1", (), (ir.Inline(payload),))
    assert program.inline_files == (("T1FILE.BIN", payload),)

    # Plain text output remains self-contained when there is nowhere to write
    # a companion binary. A bundle restores the source-significant file form.
    assert '$INLINE "T1FILE.BIN"' not in emit0.emit(program)
    bundle = emit0.emit_split(program)
    assert '  $INLINE "T1FILE.BIN"\n' in bundle.root
    assert "$INLINE &H" not in bundle.root
    assert bundle.assets == (("T1FILE.BIN", payload),)


def test_inline_asset_order_mismatch_fails_loud():
    program = decode0.Program(
        [ir.SubDef("SUB1", (), (ir.Inline(b"ABC"),))]
    )
    program.inline_files = (("WRONG.BIN", b"XYZ"),)

    with pytest.raises(ValueError, match="does not match rendered procedure body"):
        emit0.emit_split(program)
