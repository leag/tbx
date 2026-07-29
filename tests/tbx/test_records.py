"""Direct unit tests for decode0's fixed-shape record parsers.

The fixture corpus exercises every record through full decodes; these tests
pin the record layouts themselves (slot records, DATA pool tail structures,
string descriptors, the allocation table, the SWAP template) so a layout
regression fails with a pointed message instead of a corpus-wide decode diff.
"""

import struct

import pytest

from tbx import decode0, ir


def test_static_slot_rank1():
    rec = struct.pack("<9H", 0x0123, 0x0104, 11, 4, 0, 10, 0, 0, 0)
    a = decode0._parse_static_slot(rec, 0)
    assert a is not None
    assert a["rank"] == 1 and a["count"] == 11 and a["lo"] == [0] and a["hi"] == [10]
    assert a["base"] == 0x0123 << 4 and not a["str"] and not a["long"] and not a["int"]


def test_static_slot_rank2_string():
    # 2-D string array DIM (1 TO 3, 0 TO 4): span 3, count 15, esz 4, type 0x0A
    rec = struct.pack("<9H", 0x0200, 0x020A, 15, 4, 1, 3, 3, 0, 4)
    a = decode0._parse_static_slot(rec, 0)
    assert a is not None
    assert a["rank"] == 2 and a["str"] and a["lo"] == [1, 0] and a["hi"] == [3, 4]


def test_static_slot_rejects_bad_extents():
    # count disagrees with hi-lo+1 -> not a slot record
    rec = struct.pack("<9H", 0x0123, 0x0104, 12, 4, 0, 10, 0, 0, 0)
    assert decode0._parse_static_slot(rec, 0) is None


def test_rt_slot():
    bare = struct.pack("<9H", 0, 0x0104, 0, 4, 0, 0, 0, 0, 0)
    assert decode0._is_rt_slot(bare, 0)
    assert not decode0._is_rt_slot(struct.pack("<9H", 1, 0x0104, 0, 4, *[0] * 5), 0)


def test_str_lit():
    exe = struct.pack("<HH", 0x8003, 0x0000) + b"ABC"
    assert decode0._str_lit(exe, 0, 0, 4) == ir.StrLit("ABC")
    with pytest.raises(ValueError, match="bad string descriptor"):
        decode0._str_lit(struct.pack("<HH", 0x0003, 0) + b"ABC", 0, 0, 4)


def test_data_pool():
    # Two DATA items, source order ["1", "FOO"]: the framed text buffer holds
    # them concatenated in REVERSE statement order ("FOO" then "1"), split by
    # the `<len:u8> 80 <off16>` descriptor table behind its len==0 sentinel.
    base = 0x0100
    sentinel = bytes([0x00, 0x80]) + struct.pack("<H", base)
    descs = bytes([3, 0x80]) + struct.pack("<H", base)  # "FOO" at buffer +0
    descs += bytes([1, 0x80]) + struct.pack("<H", base + 3)  # "1" at buffer +3
    text = b"FOO1"
    frame = bytes([len(text), 0x80, 0, 0, 0, 0]) + text + bytes([len(text), 0x80])
    exe = b"\x90" * 8 + sentinel + descs + frame + b"\x00"
    assert decode0._read_data_pool(exe) == [
        ir.DataItem("1", False),
        ir.DataItem("FOO", True),
    ]
    assert decode0._read_data_pool(b"\x90" * 32) == []  # no pool


def test_meta_stmts():
    # Allocation table at start-0x40: [sound, 0, 0x20, sound] then the stack
    # paragraph count at start-0x34. Defaults 0x10/0x40 are byte-invisible.
    start = 0x40
    exe = bytearray(start + 3)
    exe[0:8] = struct.pack("<4H", 0x20, 0, 0x20, 0x20)
    exe[12:14] = struct.pack("<H", 0x80)
    assert decode0._meta_stmts(bytes(exe), start) == ("$SOUND 64", "$STACK 2048")
    exe[0:8] = struct.pack("<4H", 0x10, 0, 0x20, 0x10)
    exe[12:14] = struct.pack("<H", 0x40)
    assert decode0._meta_stmts(bytes(exe), start) == ()  # both defaults
    exe[2:4] = struct.pack("<H", 1)  # g0 != 0: not the known table shape
    assert decode0._meta_stmts(bytes(exe), start) == ()


def test_try_swap():
    def mov_xchg_mov(a, b):
        return (
            b"\x8b\x06"
            + struct.pack("<H", a)
            + b"\x87\x06"
            + struct.pack("<H", b)
            + b"\x89\x06"
            + struct.pack("<H", a)
        )

    good = mov_xchg_mov(0x0120, 0x0124) + mov_xchg_mov(0x0122, 0x0126)
    assert decode0._try_swap(good, 0) == (0x0120, 0x0124)
    # second triple not on the +2 halves -> plain mov/xchg run, not a SWAP
    bad = mov_xchg_mov(0x0120, 0x0124) + mov_xchg_mov(0x0130, 0x0134)
    assert decode0._try_swap(bad, 0) is None
    assert decode0._try_swap(good[:23], 0) is None  # truncated


def test_try_inline_rescue():
    # SUB ... INLINE: the body has NO proc-enter framing, and TB
    # auto-appends a bare far RET (CB) after it (t1_inline/q_shriek).
    exe = bytearray(30)
    exe[10] = 0xBA  # first inline byte -- anything but 0x55 (push bp)
    exe[19] = 0xCB  # target-1: a bare CB right before the jmp's target
    ops = [(7, "jmp", 20)]
    assert decode0._try_inline_rescue(bytes(exe), ops) == 20
    assert ops == [(7, "jmp", 20), (10, "inline_sub", bytes(exe[10:19]))]

    # False-positive guard (wild CVT2TB.EXE): a genuine `push bp; mov
    # bp,sp; ...; pop bp; retf` procedure -- either mov-bp,sp encoding --
    # legitimately ends in 5D CB, which also satisfies "byte before the
    # target is CB". Must NOT be rescued; it's real proc-enter-shaped
    # code the ordinary scan should keep failing loud on, not $INLINE.
    for enc in (b"\x8b\xec", b"\x89\xe5"):
        exe2 = bytearray(30)
        exe2[10] = 0x55
        exe2[11:13] = enc
        exe2[18] = 0x5D
        exe2[19] = 0xCB
        ops2 = [(7, "jmp", 20)]
        assert decode0._try_inline_rescue(bytes(exe2), ops2) is None
        assert ops2 == [(7, "jmp", 20)]  # unchanged

    # Exact framed helpers are classified before normal scanning, rather than
    # being smuggled through this failure-driven INLINE rescue.
    helper = decode0._OPAQUE_HELPER_BODY
    from tbx.decode0 import opaque_helpers
    from tbx.decode0.opaque import find_opaque_helpers

    image = b"\x00" * 7 + b"\xe9" + len(helper).to_bytes(2, "little") + helper + b"\x00"
    spec = opaque_helpers.OpaqueHelperSpec(helper, (0x1E,))
    assert find_opaque_helpers(image, 0, (spec,)) == {
        10: (10 + len(helper), helper, (0x1E,))
    }

    # Turbo Basic 1.0 omits the INT3 immediately before RETF in graphics
    # helper variants 3-8 (wild bmaster/ifi). Each exact v1.0 body remains
    # eligible for the same full-fingerprint rescue.
    for helper10 in (
        opaque_helpers._OPAQUE_HELPER_BODY_3_V10,
        opaque_helpers._OPAQUE_HELPER_BODY_4_V10,
        opaque_helpers._OPAQUE_HELPER_BODY_5_V10,
        opaque_helpers._OPAQUE_HELPER_BODY_6_V10,
        opaque_helpers._OPAQUE_HELPER_BODY_7_V10,
        opaque_helpers._OPAQUE_HELPER_BODY_8_V10,
    ):
        image = b"\x00" * 7 + b"\xe9" + len(helper10).to_bytes(2, "little") + helper10
        spec = opaque_helpers.OpaqueHelperSpec(helper10, (0x1E,))
        assert find_opaque_helpers(image, 0, (spec,)) == {
            10: (10 + len(helper10), helper10, (0x1E,))
        }


def test_scan_nop_padding():
    from tbx.decode0.scan import _scan_direct

    ops = []
    assert _scan_direct(b"\x90", 0, 0x90, None, ops, 0) == 1
    assert ops == [(0, "nop")]


def test_string_selector_cleanup_runtime_alias():
    from tbx.decode0.scan import _scan_direct2

    body = bytes.fromhex(
        "31 d2 31 f6 87 16 5c 00 87 36 5e 00 cd cc"
    )
    ops = []
    assert _scan_direct2(body, 0, body[0], ops) == len(body)
    assert ops == [(0, "str_free_temp")]


def test_integer_divide_memory_template():
    from tbx.decode0.scan import _scan_direct2

    exe = bytes.fromhex("f7 3e 54 10")
    ops = []
    assert _scan_direct2(exe, 0, exe[0], ops) == 4
    assert ops == [(0, "idiv_m", 0x1054)]


def test_tb10_cvl_vector_alias():
    from tbx.decode0.dialect import TB10
    from tbx.decode0.scan import _scan_int

    ops = []
    vec = TB10.canon_vec(0xA9)
    assert _scan_int(b"\xcd\xa9", 0, set(), TB10, ops, 0, vec) == 2
    assert ops == [(0, "str2num", "CVL")]


def test_scan_instr_with_start_dispatch():
    from tbx import ir
    from tbx.decode0.core import DecodeState, fp_dispatch
    from tbx.decode0.dialect import TB11
    from tbx.decode0.scan import _scan_int

    ops = []
    assert _scan_int(b"\xcd\xed\x1e", 0, set(), TB11, ops, 0, 0xED) == 3
    assert ops == [(0, "instr3")]

    state = DecodeState(
        ax=ir.Lit(2), k=0, sstack=[ir.Var("A$"), ir.StrLit("C")]
    )
    fp_dispatch(state, ops[0], 0, "instr3")
    assert state.ax == ir.Call(
        "INSTR", (ir.Lit(2), ir.Var("A$"), ir.StrLit("C"))
    )
    assert state.sstack == []
