"""Wild zip.exe's tone procedures are $INLINE machine code, not OUT statements.

This file used to assert the opposite. It pinned an `out_imm` op reading
`mov al,imm8; out imm8,al` as a byte-constant OUT that Turbo Basic had folded
-- a mapping with no compiled fixture, refuted by probe: `OUT 67, 116` (zip's
own operands) emits the general mov-AX / mov-DX / OUT-DX form at top level and
inside a SUB alike, and TB has no statement that compiles to E4-E7 at all.

The bodies are `SUB name INLINE` + `$INLINE`, which round-trips byte-exactly;
decoding them as OUT cost zip.exe 592 bytes and ziptest.exe 224. Ledger
RO-OUT-IMM-FOLD; fixture t1_inlineport is the shape in miniature.
"""

import os

from tbx import decode0, ir
from tbx.decode0 import scan

_CORPUS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "corpus"
)


def test_mov_al_out_imm_is_not_in_the_vocabulary():
    # Neither half, and not the pair: these bytes must reach the inline rescue.
    assert scan._scan_direct2(bytes.fromhex("b0 74 e6 43"), 0, 0xB0, []) is None
    assert scan._scan_direct2(bytes.fromhex("b0 74 90 90"), 0, 0xB0, []) is None


def test_port_immediate_only_rules_a_body_in():
    body = bytes.fromhex("55 8b ec b0 74 e6 43 5d")
    assert scan._has_port_immediate(body, 0, len(body))
    # A framed body with no port instruction stays ambiguous, so the caller
    # keeps declining it -- that is what holds CVT2TB.EXE and phone.exe loud.
    plain = bytes.fromhex("55 8b ec 8b 46 06 5d")
    assert not scan._has_port_immediate(plain, 0, len(plain))


def test_zip_tone_procedures_decode_as_inline():
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("zip.exe"))
    subs = [s for s in prog if isinstance(s, ir.SubDef)]
    inline = [b for s in subs for b in s.body if isinstance(b, ir.Inline)]
    assert len(inline) == 26
    assert not [b for s in subs for b in s.body if isinstance(b, ir.Out)]
    # The list carries its own bp frame; TB appends the terminating CB.
    assert inline[0].data == bytes.fromhex("558becb074e643b012e641b000e6415d")


def test_ziptest_tone_procedures_decode_as_inline():
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("ziptest.exe"))
    subs = [s for s in prog if isinstance(s, ir.SubDef)]
    assert len([b for s in subs for b in s.body if isinstance(b, ir.Inline)]) == 23
    assert not [b for s in subs for b in s.body if isinstance(b, ir.Out)]


def test_a_real_out_statement_still_decodes():
    # t1_out.bas is `OUT 888, 1`: the general form, untouched by any of this.
    with open(os.path.join(_CORPUS, "t1_out.exe"), "rb") as handle:
        prog = decode0.decode_user_code(handle.read())
    assert ir.Out(ir.Lit(888), ir.Lit(1)) in tuple(prog)
