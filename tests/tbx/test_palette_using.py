"""PALETTE USING's EC/8A dispatch and ES:SI array-element shapes."""

from pathlib import Path

from tbx import decode0, emit0, ir

_ROOT = Path(__file__).resolve().parents[2]
_PROBES = _ROOT / "wild" / "probes"


def _decode(name: str):
    return decode0.decode_user_code((_PROBES / name).read_bytes())


def test_palette_using_static_constant_element():
    # mov si,<element>; mov dx,<array segment>; mov es,dx; EC/8A.
    prog = _decode("probe_paletteusing_static.exe")
    assert prog[1] == ir.PaletteUsing(ir.ArrayRef("V0%", (ir.Lit(0),)))
    assert emit0.emit(prog) == (
        "10 DIM V0%(20)\n"
        "20 PALETTE USING V0%(0)\n"
        "30 END\n"
    )


def test_palette_using_dynamic_constant_element():
    # mov es,[array block]; xor si,si; EC/8A.
    prog = _decode("probe_paletteusing.exe")
    assert prog[1] == ir.PaletteUsing(ir.ArrayRef("V0%", (ir.Lit(0),)))
    assert emit0.emit(prog) == (
        "10 DIM DYNAMIC V0%(20)\n"
        "20 PALETTE USING V0%(0)\n"
        "30 END\n"
    )


def test_palette_using_dynamic_variable_element():
    # mov si,[index]; shl si,1; mov es,[array block]; EC/8A.
    prog = _decode("probe_paletteusing_var.exe")
    assert prog[2] == ir.PaletteUsing(ir.ArrayRef("V0%", (ir.Var("A%"),)))
    assert emit0.emit(prog) == (
        "10 A% = 0\n"
        "20 DIM DYNAMIC V0%(20)\n"
        "30 PALETTE USING V0%(A%)\n"
        "40 END\n"
    )
