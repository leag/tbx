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

# Every Turbo Basic EXE starts at `mov cs:[00b2], ds` -- the linked runtime's
# own startup stub, ahead of any user code.  Measured across the 1220 MZ files
# in the fixture corpus and the wild set: 1220 of them begin with these three
# bytes and nothing else does.
TB_ENTRY_STUB = b"\x2e\x8c\x1e"


def _entry_offset(exe: bytes) -> int | None:
    """File offset of the MZ entry point, or None if there is no MZ header."""
    if len(exe) < 0x20 or exe[:2] != b"MZ":
        return None
    (hdrpar,) = struct.unpack_from("<H", exe, 8)
    ip, cs = struct.unpack_from("<HH", exe, 20)
    return hdrpar * 16 + cs * 16 + ip


def _not_a_plain_tb_image(exe: bytes) -> str | None:
    """Why this MZ file cannot be a plain Turbo Basic EXE, or None if it can.

    A content search for `cd ec b8` / `cd ec ba` finds those bytes wherever
    they occur, including inside COMPRESSED data, and then decoding starts on
    whatever follows and dies with a meaningless `unhandled byte`.  Wild
    brotheru.exe is LZEXE-compressed and its only match is a coincidence in
    the packed payload; wild pcdcfile.exe declares cs:ip = fff0:0100, an entry
    point 0x100020 bytes into a 119901-byte file.  Neither is a decoder gap,
    and reporting them as one puts them in the wild-corpus failure tally as
    though the byte vocabulary were missing something.
    """
    entry = _entry_offset(exe)
    if entry is None:
        return None  # not an MZ image at all; leave the old path to judge
    if exe[0x1C:0x20] == b"LZ91":
        return "LZEXE-compressed (unpack it first)"
    if entry + 3 > len(exe):
        return f"MZ entry point {entry:#x} is past the {len(exe):#x}-byte image"
    if exe[entry : entry + 3] != TB_ENTRY_STUB:
        return (
            f"MZ entry point {entry:#x} is not the Turbo Basic startup stub "
            f"({exe[entry:entry + 3].hex(' ')}, expected "
            f"{TB_ENTRY_STUB.hex(' ')})"
        )
    return None


def find_prologue(exe: bytes) -> tuple[int, Dialect]:
    """Locate the program-start prologue and identify the compiler dialect from it.

    Earliest match wins, not first dialect tried: TB 1.0 encodes RESUME as raw EC sub
    0xBA (canonical BC), so `cd ec ba` -- the 1.1 signature -- occurs INSIDE 1.0 user
    code (v10_t1_resumel). The true prologue always precedes user code, so the lowest
    offset of either signature is the prologue."""
    # MZ self-extractors and archives can carry an embedded TB-looking byte
    # sequence in their overlay.  Restrict recognition to the declared DOS
    # image; otherwise an appended ZIP payload is misclassified as TB 1.0.
    image_end = len(exe)
    if len(exe) >= 0x1C and exe[:2] == b"MZ":
        cblp, cp = struct.unpack_from("<HH", exe, 2)
        if cp:
            image_end = min(
                len(exe), cp * 512 - (512 - cblp if cblp else 0)
            )
    cands = [
        (i, dia)
        for dia in DIALECTS
        if (i := exe.find(dia.prologue, 0, image_end)) >= 0
    ]
    if cands:
        # A match inside compressed or protected payload is not a prologue;
        # check the entry stub before trusting one (see _not_a_plain_tb_image).
        if (why := _not_a_plain_tb_image(exe)) is not None:
            raise ValueError(f"not a plain Turbo Basic EXE: {why}")
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
