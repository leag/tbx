"""Byte-faithful float literal formatting.

Turbo Basic targets the x87, so pooled FP singles are IEEE-754 (not GW-BASIC's
MBF). Each formatter renders the shortest decimal text whose encoding
round-trips to the original bit pattern.
"""

from __future__ import annotations
import struct as _struct


def f32_dec(b: bytes) -> float:
    """Decode a pooled FP single literal (little-endian IEEE-754 single)."""
    return _struct.unpack("<f", b[:4])[0]


def f32_enc(v: float) -> bytes:
    """Encode to an IEEE-754 single, round-to-nearest-even (= the x87/TB parser)."""
    return _struct.pack("<f", v)


def _fmt_float(v: float) -> str:
    """Shortest decimal text whose IEEE-single encoding round-trips to v's.
    TB types bare decimal literals as DOUBLE (qword pool loads) and 0/1/small
    ints as FLDZ/FLD1/FILD -- the '!' suffix is what makes a literal a pooled
    single, so every float Lit carries it."""
    if v == int(v) and abs(v) < 1e9:
        return str(int(v)) + "!"
    enc = f32_enc(v)
    for p in range(1, 10):
        txt = f"{v:.{p}g}"
        if f32_enc(float(txt)) == enc:
            txt = txt.upper().replace("E+0", "E+").replace("E-0", "E-")
            return txt + "!"
    return repr(v) + "!"


def _fmt_g64(v: float, p: int) -> str:
    """`%.{p}g` for f64: p significant digits, trailing
    zeros stripped, exponent signed with at least two digits."""
    return f"{v:.{max(p, 1)}g}"


def fmt_double(v: float) -> str:
    """Shortest decimal text whose f64 encoding round-trips to v's, '#'-suffixed.
    Integer fast path when v is an exact integer in (-1e15, 1e15)."""
    if v == int(v) and abs(v) < 1e15:
        return f"{int(v)}#"
    enc = _struct.pack("<d", v)
    for p in range(1, 18):
        txt = _fmt_g64(v, p)
        if _struct.pack("<d", float(txt)) == enc:
            return txt.upper().replace("E+0", "E+").replace("E-0", "E-") + "#"
    return f"{v}#"


def fmt_plain(v: float) -> str:
    """Render an implicit-single literal as a plain decimal with NO suffix (a `!`
    would not be byte-faithful: TB re-pools `!` literals as f32)."""
    if v == int(v) and abs(v) < 1e15:
        return str(int(v))
    enc = _struct.pack("<d", v)
    for p in range(1, 18):
        txt = _fmt_g64(v, p)
        if _struct.pack("<d", float(txt)) == enc:
            return txt.upper().replace("E+0", "E+").replace("E-0", "E-")
    return str(v)
