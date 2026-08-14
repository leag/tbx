"""Turbo Basic compiler signatures and dialect normalization."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CompilerProfile:
    """Version-specific encodings normalized to the Turbo Basic 1.1 ABI."""

    name: str
    prologue: bytes
    sub_shift: int
    vector_shift: int

    def canonical_sub(self, dispatcher: int, sub: int) -> int:
        floors = {0xEC: 0x28, 0xED: 0x3C, 0xEE: 0x2C}
        floor = floors[dispatcher]
        return sub + self.sub_shift if sub >= floor - self.sub_shift else sub

    def canonical_vector(self, vector: int) -> int:
        upper = 0xEC - self.vector_shift
        return vector + self.vector_shift if 0x40 <= vector < upper else vector


TB11 = CompilerProfile("1.1", b"\xcd\xec\xba", 0, 0)
TB10 = CompilerProfile("1.0", b"\xcd\xec\xb8", 2, 6)
PROFILES = (TB11, TB10)
PROLOGUES = {profile.prologue: profile.name for profile in PROFILES}
PROCEDURE_ENTER = b"\x55\x8b\xec"
PROCEDURE_RETURN = b"\x5d\xcb"
PROCEDURE_RETURN_POP = b"\x5d\xca"

# Direct-memory types carried by Turbo Basic's emulated x87 escape vectors.
# The analyzer consumes these as profile signatures; it does not infer widths
# from the referenced bytes.
FP_TRANSFER_TYPES = {
    0x35: "float",
    0x37: "long",
    0x39: "double",
    0x3B: "integer",
}
FP_ARITHMETIC_TYPES = {0x34: "float", 0x36: "long", 0x38: "double"}


def profile_for(dialect: str | None) -> CompilerProfile | None:
    return next((profile for profile in PROFILES if profile.name == dialect), None)


# Canonical INT EC dispatcher names. Some entries are complete source statements;
# others name runtime phases whose semantic fact passes still have to combine them.
EC_DISPATCH_NAMES = {
    0x00: "BEEP",
    0x14: "CLEAR",
    0x16: "CLOSE_ALL",
    0x18: "CLOSE",
    0x1A: "CLS",
    0x22: "COLOR",
    0x26: "DEF_SEG",
    0x28: "DELAY_INIT",
    0x2A: "DELAY_POLL",
    0x2C: "DIM_BEGIN",
    0x2E: "DIM_END",
    0x30: "DRAW",
    0x32: "END",
    0x36: "ERASE",
    0x38: "ERASE_STATIC",
    0x42: "FILES",
    0x44: "FILES",
    0x4E: "INPUT",
    0x60: "KILL",
    0x64: "LINE_INPUT",
    0x66: "LINE_INPUT_FILE",
    0x82: "OPEN",
    0x84: "PAINT",
    0x86: "PALETTE_RESET",
    0x88: "PALETTE",
    0x8A: "PALETTE_USING",
    0x9A: "READ_NUMBER",
    0x9C: "READ_STRING",
    0x9E: "INPUT_FILE_NUMBER",
    0xA0: "INPUT_FILE_STRING",
    0xA2: "POKE",
    0xA4: "PSET",
    0xB2: "DATA_NUMBER",
    0xB4: "DATA_STRING",
    0xB8: "RESET",
    0xE8: "EPILOGUE",
    0xEA: "VIEW",
    0xF2: "WINDOW",
}
