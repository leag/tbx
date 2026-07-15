"""DATA constant-pool recovery from the EXE tail structures."""

from __future__ import annotations
import struct
from typing import Any

from tbx import ir


def _data_find_frame(exe: bytes):
    """Backward scan from EOF for the DATA framed text buffer
    `<L> 80 00 00 00 00 <L bytes> <L> 80`. Returns (frame_start, L) or None."""
    if len(exe) < 8:
        return None
    for f in range(len(exe) - 8, -1, -1):
        if exe[f + 1] != 0x80 or exe[f + 2 : f + 6] != b"\x00\x00\x00\x00":
            continue
        l = exe[f]
        if l == 0 or f + 6 + l + 1 >= len(exe):
            continue
        if exe[f + 6 + l] == l and exe[f + 6 + l + 1] == 0x80:
            return f, l
    return None


def _data_find_sentinel(exe: bytes, frame: int):
    """Backward scan from the frame for the descriptor sentinel `00 80 <off16> 00`
    immediately followed by a real entry (tag 0x80, len != 0)."""
    for s in range(frame - 4, -1, -1):
        if (
            exe[s] == 0x00
            and exe[s + 1] == 0x80
            and exe[s + 5] == 0x80
            and exe[s + 4] != 0x00
        ):
            return s
    return None


def _read_data_pool(exe: bytes) -> list[ir.DataItem]:
    """Recover the DATA constant pool into items in
    source order. The pool is two contiguous tail structures: a framed text buffer
    holding every item's verbatim text concatenated in REVERSE statement order, and
    a `<len:u8> 80 <off16>` descriptor table (leading len==0 sentinel). Items are
    split by the descriptor lengths/offsets and reversed to source order. Each item
    is a string literal iff its text is not a number. Empty list if no pool."""
    fr = _data_find_frame(exe)
    if fr is None:
        return []
    f, l = fr
    text = exe[f + 6 : f + 6 + l]
    s = _data_find_sentinel(exe, f)
    if s is None:
        raise ValueError("DATA descriptor sentinel not found")
    base = struct.unpack_from("<H", exe, s + 2)[0]
    items: list[ir.DataItem] = []
    p = s + 4
    while True:
        if p + 4 > len(exe):
            raise ValueError("DATA descriptor table runs past EOF")
        length, tag = exe[p], exe[p + 1]
        if tag != 0x80 or length == 0:
            break
        off = struct.unpack_from("<H", exe, p + 2)[0]
        start = off - base
        if start < 0:
            raise ValueError("DATA item offset below buffer base")
        end = start + length
        if end > l:
            raise ValueError("DATA item runs past buffer end")
        s_text = text[start:end].decode("latin-1")
        try:
            float(s_text)
            is_str = False
        except ValueError:
            is_str = True
        items.append(ir.DataItem(s_text, is_str))
        if end == l:
            break
        p += 4
    items.reverse()  # buffer order is reverse statement order
    return items


def _parse_static_slot(exe: bytes, pos: int) -> dict[str, Any] | None:
    """Parse a populated static slot record at file `pos`:
    +0 base-para, +2 04|rank, +4 count, +6 type (04 single / 0A string), then
    per dimension `lo/hi` with a CUMULATIVE element span between dims --
    rank 1: +8/+A lo1/hi1 (12 bytes); rank 2: ... +C span1, +E/+10 lo2/hi2
    (18 bytes); rank 3: ... +12 span2, +14/+16 lo3/hi3 (24 bytes, witnessed
    t1_dim3: span1 = ext1, span2 = span1*ext2, count = span2*ext3).
    None if the bytes don't validate."""
    para, rt, count, esz = struct.unpack_from("<4H", exe, pos)
    # Type byte: 0x00 = integer (esz 2, witnessed t1_getput), 0x02 = long integer,
    # 0x04 = single, 0x06 = double, 0x0A = string; element size 2 (int),
    # 4 (single/long/string desc) or 8 (double).
    if (
        rt >> 8 not in (1, 2, 3)
        or rt & 0xFF not in (0x00, 0x02, 0x04, 0x06, 0x0A)
        or esz not in (2, 4, 8)
        or count <= 1
        or para == 0
    ):
        return None
    rank = rt >> 8
    lo, hi, spans = [], [], []
    p, span = pos + 8, 1
    for d in range(rank):
        lo_d, hi_d = struct.unpack_from("<2H", exe, p)
        if hi_d < lo_d:
            return None
        lo.append(lo_d)
        hi.append(hi_d)
        p += 4
        if d < rank - 1:
            (span_d,) = struct.unpack_from("<H", exe, p)
            if span_d != span * (hi_d - lo_d + 1):
                return None
            spans.append(span_d)
            span = span_d
            p += 2
    if count != span * (hi[-1] - lo[-1] + 1):
        return None
    return {
        "name": None,
        "rank": rank,
        "str": rt & 0xFF == 0x0A,
        "count": count,
        "lo": lo,
        "hi": hi,
        "span": spans[0] if spans else count,  # rank-2 compat: span1
        "spans": spans,  # cumulative spans, one per dim after the first
        "base": para << 4,
        "esz": esz,
        "long": rt & 0xFF == 0x02,  # pre-seed; confirmed in _layout finish
        "int": rt & 0xFF == 0x00,
    }


def _is_rt_slot(exe: bytes, pos: int) -> bool:
    """A runtime slot record stores only (rank<<8)|type and esz at file time."""
    para, rt, count, esz = struct.unpack_from("<4H", exe, pos)
    return (
        para == 0
        and count == 0
        and esz in (2, 4, 8)
        and rt >> 8 in (1, 2, 3)
        and rt & 0xFF in (0x00, 0x02, 0x04, 0x06, 0x0A)
    )
