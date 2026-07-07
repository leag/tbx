"""Dialect detection: the per-compiler-version INT numbering and prologue scan."""

from __future__ import annotations
import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class Dialect:
    """Per-compiler-version INT numbering. Canonical numbering = TB 1.1;
    _scan canonicalizes 1.0's numbers at decode time so everything downstream
    (build pass, layout, IR, emitter) is version-blind. The shifts are
    systematic: 1.0 EC subs sit 2 below canonical from sub 0x30 up (witnessed
    30/4C/62/98/9A/E6; 1A/22 unshifted), and 1.0 service vectors 6 below
    canonical within [0x40, 0xEC) (witnessed 81/93/96/9A/B2/B5/B8/C9/CA; FP
    INTs 34-3D and EC itself unshifted). Canonicalize before matching -- raw
    numbers are ambiguous across versions (e.g. 1.0's print-eval 0xB8 = 1.1's
    print-flush 0xB8).

    The +2 sub shift is per-dispatch-table: each INT vector's sub table has
    its OWN 1.0->1.1 insertion point, so `canon_sub` takes the canonical floor
    at/above which the shift applies. EC (statements) inserts at canonical
    0x26 -- 1.1 added defseg_set there (TB 1.0 compiles DEF SEG = n INLINE as
    `mov [001C], imm`, no EC sub at all, and bare DEF SEG as `mov [001C], ds`
    in both dialects; witnessed v10_t1_defseg) -- so the shift floor is DELAY
    at canonical 0x28 (1.0 raw 26/28, v10_t1_delay); COLOR 0x22 and DATE$-set
    0x24 are unshifted. Like fpow below, raw EC 0x26 in 1.0 is unambiguously
    the shifted delay_init. ED (ax-returning intrinsics) inserts higher, at
    canonical 0x3C: 1.0 PEN 0x2E/PLAY 0x30/PMAP 0x32/POS 0x38 are unshifted,
    REG 0x3C/SCREEN 0x42/STICK 0x48/STRIG 0x4A shift +2. fpow (ED 0x3A) is
    1.1-only -- TB 1.0 encodes `^` without an ED sub -- so raw ED 0x3A is
    unambiguously 1.0's shifted REG. EE (string intrinsics) inserts at/above
    0x2C, but every witnessed EE sub is low (highest UCASE$ 0x28, unshifted in
    1.0), so its true floor is unconstrained; default 0x2C is a no-op for all
    of them."""

    name: str
    prologue: bytes
    sub_shift: int  # canonical EC sub = actual + sub_shift (above 0x2E)
    vec_shift: int  # canonical vector = actual + vec_shift (in range)

    def canon_sub(self, sub: int, canon_floor: int = 0x2C) -> int:
        return sub + self.sub_shift if sub >= canon_floor - self.sub_shift else sub

    def canon_vec(self, vec: int) -> int:
        return vec + self.vec_shift if 0x40 <= vec < 0xEC - self.vec_shift else vec


TB11 = Dialect("1.1", b"\xcd\xec\xba", 0, 0)
TB10 = Dialect("1.0", b"\xcd\xec\xb8", 2, 6)
DIALECTS = (TB11, TB10)


def find_prologue(exe: bytes) -> tuple[int, Dialect]:
    """Locate the program-start prologue and identify the compiler dialect from it.

    Earliest match wins, not first dialect tried: TB 1.0 encodes RESUME as raw EC sub
    0xBA (canonical BC), so `cd ec ba` -- the 1.1 signature -- occurs INSIDE 1.0 user
    code (v10_t1_resumel). The true prologue always precedes user code, so the lowest
    offset of either signature is the prologue."""
    cands = [(i, dia) for dia in DIALECTS if (i := exe.find(dia.prologue)) >= 0]
    if cands:
        return min(cands, key=lambda t: t[0])
    raise ValueError("TB program prologue (cd ec ba / cd ec b8) not found")


def _try_swap(exe: bytes, p: int):
    """Inline SWAP template (witnessed t1_swap): returns (a_disp, b_disp) or None."""
    if p + 24 > len(exe):
        return None
    for off, opc in (
        (0, 0x8B),
        (4, 0x87),
        (8, 0x89),
        (12, 0x8B),
        (16, 0x87),
        (20, 0x89),
    ):
        if exe[p + off] != opc or exe[p + off + 1] != 0x06:
            return None

    def d(i):
        return struct.unpack_from("<H", exe, p + i)[0]

    d0, d1, d2, d3, d4, d5 = d(2), d(6), d(10), d(14), d(18), d(22)
    if d2 == d0 and d5 == d3 and d3 == (d0 + 2) & 0xFFFF and d4 == (d1 + 2) & 0xFFFF:
        return (d0, d1)
    return None
