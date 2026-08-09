"""A near jump's rel16 is relative to CS, not to the entry point.

A program whose code outgrows 64KB has more than one code segment, and the
later ones do not begin a multiple of 64KB from the entry point. Normalizing
every jump against the entry point sent each jump in those segments 64KB
backwards into unrelated early code -- wild rs.exe emitted
`IF BM$ = "N" ... THEN 490` for what is really `THEN 20670`, the next prompt.

Single-segment programs (every fixture, most wild files) are unaffected: the
window is the entry point, exactly as before.
"""

import struct

import pytest

from tbx import decode0
from tbx.decode0 import scan


def _jmp(exe, p, start, cs=None):
    ops = []
    assert scan._scan_direct(exe, p, exe[p], decode0.TB11, ops, start, cs) == p + 3
    (op,) = ops
    assert op[1] == "jmp"
    return op[2]


def _image(size, p, rel):
    exe = bytearray(b"\x90" * size)
    exe[p] = 0xE9
    struct.pack_into("<h", exe, p + 1, rel)
    return bytes(exe)


def test_a_near_jump_inside_one_segment_is_linear():
    start, p = 0x8C50, 0x18B4B
    exe = _image(0x1E800, p, 0x230)

    assert _jmp(exe, p, start, 0x17C40) == p + 3 + 0x230


def test_a_forward_jump_encoded_as_a_negative_rel_wraps_within_its_segment():
    # The t1_bigjmp / inv87.exe shape: a GOTO far enough forward that rel16
    # goes negative. It wraps around the segment it is in, which for a
    # single-segment program is the entry point.
    start, p = 0x9EF0, 0xA100
    exe = _image(0x1E800, p, -0x2000)

    assert _jmp(exe, p, start) == p + 3 - 0x2000 + 0x10000


def test_the_entry_point_is_the_window_when_no_segment_is_given():
    start, p = 0x9EF0, 0xA100
    exe = _image(0x1E800, p, -0x2000)

    assert _jmp(exe, p, start, None) == _jmp(exe, p, start, start)


@pytest.mark.parametrize(
    ("stem", "statements"), [("rs.exe", 2328), ("dirmain1.exe", 4876)]
)
def test_a_multi_segment_wild_program_decodes_end_to_end(stem, statements):
    # Both outgrow 64KB of code. dirmain1.exe used to stop at
    # `unhandled op cmp_mi8` -- a NEXT whose loop head the mis-normalized
    # jump had placed 64KB away -- and now decodes completely.
    from conftest import wild_hits_bytes

    program = decode0.decode_user_code(wild_hits_bytes(stem))

    assert len(program) == statements


def test_a_single_segment_wild_program_is_unchanged():
    from conftest import wild_hits_bytes

    assert len(decode0.decode_user_code(wild_hits_bytes("inv87.exe"))) == 2790
