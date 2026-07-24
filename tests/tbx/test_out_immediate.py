"""Byte-constant OUT optimization in wild zip.exe's tone procedures."""

from tbx import decode0, ir
from tbx.decode0 import scan


def test_scan_out_immediate_is_atomic():
    ops = []
    data = bytes.fromhex("b0 74 e6 43")
    assert scan._scan_direct2(data, 0, data[0], ops) == 4
    assert ops == [(0, "out_imm", 0x43, 0x74)]

    # Neither half independently joins the vocabulary.
    assert scan._scan_direct2(bytes.fromhex("b0 74 90 90"), 0, 0xB0, []) is None


def test_zip_decodes_all_immediate_out_procedures():
    from conftest import wild_hits_bytes

    data = wild_hits_bytes("zip.exe")
    prog = decode0.decode_user_code(data)
    outs = [
        s
        for sub in prog
        if isinstance(sub, ir.SubDef)
        for s in sub.body
        if isinstance(s, ir.Out)
    ]
    assert len(outs) == 78
    assert outs[:3] == [
        ir.Out(ir.Lit(67), ir.Lit(116)),
        ir.Out(ir.Lit(65), ir.Lit(18)),
        ir.Out(ir.Lit(65), ir.Lit(0)),
    ]


def test_out_immediate_ir_spelling():
    assert ir.unparse_stmt(ir.Out(ir.Lit(0x43), ir.Lit(0x74))) == "OUT 67, 116"
