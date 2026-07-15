"""Rank-3 arrays: slot records, constant-index recovery, runtime DIM,
variable-index legs, and the bare-chain popop orientation.

The record grows 6 bytes per dimension past the first: per-dim lo/hi with a
CUMULATIVE element span between dims (span1 = ext1, span2 = span1*ext2,
count = span2*ext3 -- t1_dim3). The variable-index access chains a third
leg through the span2 cell at block+0x12 (t1_dim3v). Both fixtures are
byte-exact verified through the oracle.
"""

import os

from tbx import decode0, emit0, ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _decode(name):
    exe = open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()
    return decode0.decode_user_code(exe)


def test_static_rank3_record_and_constant_indices():
    prog = _decode("t1_dim3.exe")
    assert prog[0] == ir.Dim("V0", (2, 3, 4))
    # column-major recovery: r = (i1-lo1) + (i2-lo2)*span1 + (i3-lo3)*span2
    assert prog[1] == ir.Assign(
        ir.ArrayRef("V0", (ir.Lit(1), ir.Lit(2), ir.Lit(3))), ir.Lit(7)
    )
    assert prog[2] == ir.Assign(
        ir.ArrayRef("V0", (ir.Lit(2), ir.Lit(3), ir.Lit(4))), ir.Lit(9)
    )


def test_runtime_rank3_dim_and_variable_indices():
    prog = _decode("t1_dim3v.exe")
    src = emit0.emit(prog)
    assert "20 DIM V0(2,A,3)\n" in src
    # the loop body: three-leg far index, and the bare + chain keeps its
    # source operand order without parens (a grouped operand would flip
    # TB to right-first evaluation -- byte-significant)
    assert "60 V0(B,C,D) = B * 100 + C * 10 + D\n" in src


def test_popop_grouped_operands_keep_r_first():
    # the grouped shape still decodes R-first (tier1_expr2's witness)
    prog = _decode("tier1_expr2.exe")
    src = emit0.emit(prog)
    assert "80 H = (A - B) * (C + D)\n" in src
