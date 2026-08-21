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
    defseg_cell: int
    inline_defseg_set: bool

    def canonical_sub(self, dispatcher: int, sub: int) -> int:
        floors = {0xEC: 0x28, 0xED: 0x3C, 0xEE: 0x2C}
        floor = floors[dispatcher]
        return sub + self.sub_shift if sub >= floor - self.sub_shift else sub

    def canonical_vector(self, vector: int) -> int:
        upper = 0xEC - self.vector_shift
        return vector + self.vector_shift if 0x40 <= vector < upper else vector

    def is_run_jump(self, opcode: int, target: int, code_start: int) -> bool:
        """Whether one direct jump is this compiler's bare RUN spelling."""

        if self.name == "1.0":
            return opcode == 0xE9 and target == code_start + 3
        return target == code_start


TB11 = CompilerProfile("1.1", b"\xcd\xec\xba", 0, 0, 0x1C, False)
TB10 = CompilerProfile("1.0", b"\xcd\xec\xb8", 2, 6, 0x1C, True)
PROFILES = (TB11, TB10)
PROLOGUES = {profile.prologue: profile.name for profile in PROFILES}
PROCEDURE_ENTER = b"\x55\x8b\xec"
PROCEDURE_RETURN = b"\x5d\xcb"
PROCEDURE_RETURN_POP = b"\x5d\xca"
RETURN_TO_VECTOR = 0x8C
TRACE_VECTOR = 0x97
CHECKED_GOSUB_VECTOR = 0x8A
CHECKED_RETURN_VECTOR = 0x8B

# Direct-memory types carried by Turbo Basic's emulated x87 escape vectors.
# The analyzer consumes these as profile signatures; it does not infer widths
# from the referenced bytes.
FP_TRANSFER_TYPES = {
    0x35: "float",
    0x37: "long",
    0x39: "double",
    0x3B: "integer",
}
FP_ARITHMETIC_TYPES = {
    0x34: "float",
    0x36: "long",
    0x38: "double",
    0x3A: "integer",
}

TRANSCEND_FUNCTIONS = {
    0x00: "SIN",
    0x02: "COS",
    0x04: "TAN",
    0x06: "ATN",
    0x08: "LOG",
    0x0C: "LOG10",
    0x0E: "EXP",
}


def profile_for(dialect: str | None) -> CompilerProfile | None:
    return next((profile for profile in PROFILES if profile.name == dialect), None)


# Complete source statements carried by one canonical INT EC dispatch. The
# tuple after the source name contains operands fixed by the selected subcode;
# expression and register operands are recovered by separate passes.
EC_SOURCE_STATEMENTS = {
    0x00: ("BEEP", ()),
    0x04: ("BLOAD", ()),
    0x06: ("BLOAD", ()),
    0x08: ("BSAVE", ()),
    0x0A: ("CALL_ABSOLUTE", ()),
    0x0C: ("CALL_INTERRUPT", ()),
    0x0E: ("CHAIN", ()),
    0x10: ("CHDIR", ()),
    0x12: ("CIRCLE", ()),
    0x14: ("CLEAR", ()),
    0x16: ("CLOSE", ()),
    0x18: ("CLOSE", ()),
    0x1A: ("CLS", ()),
    0x1C: ("TRAP_CTL", ("COM", "OFF")),
    0x1E: ("TRAP_CTL", ("COM", "STOP")),
    0x20: ("TRAP_CTL", ("COM", "ON")),
    0x22: ("COLOR", ()),
    0x24: ("DATE_TIME_SET", ("DATE$",)),
    0x26: ("DEF_SEG", ()),
    0x30: ("DRAW", ()),
    0x32: ("END", ()),
    0x34: ("ENVIRON", ()),
    0x36: ("ERASE", ()),
    0x38: ("ERASE", ()),
    0x3C: ("ERROR_STMT", ()),
    0x42: ("FILES", ()),
    0x44: ("FILES", ()),
    0x46: ("GET", ()),
    0x48: ("GET", ()),
    0x4A: ("GET_GFX", ()),
    0x4C: ("GET_STRING", ()),
    0x4E: ("INPUT", ()),
    0x50: ("IOCTL", ()),
    0x52: ("KEY", (False,)),
    0x54: ("KEY", (True,)),
    0x56: ("KEY_LIST", ()),
    0x58: ("KEY_DEF", ()),
    0x5A: ("TRAP_CTL", ("KEY", "OFF")),
    0x5C: ("TRAP_CTL", ("KEY", "STOP")),
    0x5E: ("TRAP_CTL", ("KEY", "ON")),
    0x60: ("KILL", ()),
    0x62: ("LINE_STMT", ()),
    0x64: ("LINE_INPUT", ()),
    0x66: ("LINE_INPUT", ()),
    0x6A: ("MKDIR", ()),
    0x6C: ("MTIMER", ()),
    0x6E: ("NAME", ()),
    0x70: ("ON_ERROR", ()),
    0x72: ("ON_GOSUB", ()),
    0x74: ("ON_GOTO", ()),
    0x76: ("ON_TRAP", ("COM",)),
    0x78: ("ON_TRAP", ("KEY",)),
    0x7A: ("ON_TRAP", ("PEN",)),
    0x7C: ("ON_TRAP", ("PLAY",)),
    0x80: ("ON_TRAP", ("TIMER",)),
    0x82: ("OPEN", ()),
    0x84: ("PAINT", ()),
    0x86: ("PALETTE", ()),
    0x88: ("PALETTE", ()),
    0x8A: ("PALETTE", ()),
    0x8C: ("TRAP_CTL", ("PEN", "OFF")),
    0x8E: ("TRAP_CTL", ("PEN", "STOP")),
    0x90: ("TRAP_CTL", ("PEN", "ON")),
    0x92: ("TRAP_CTL", ("PLAY", "OFF")),
    0x94: ("TRAP_CTL", ("PLAY", "STOP")),
    0x96: ("TRAP_CTL", ("PLAY", "ON")),
    0x98: ("PLAY", ()),
    0xA2: ("POKE", ()),
    0xA4: ("PSET", ()),
    0xA8: ("PUT", ()),
    0xAA: ("PUT_GFX", ()),
    0xAC: ("PUT_STRING", ()),
    0xB0: ("RANDOMIZE", ()),
    0xB6: ("REG_SET", ()),
    0xB8: ("RESET", ()),
    0xC2: ("RMDIR", ()),
    0xC4: ("RUN", ()),
    0xC6: ("SCREEN", ()),
    0xCA: ("SEEK", ()),
    0xCE: ("SHELL", ()),
    0xD0: ("SOUND", ()),
    0xD8: ("TRAP_CTL", ("STRIG", "OFF")),
    0xDA: ("TRAP_CTL", ("STRIG", "ON")),
    0xDC: ("PAINT", ()),
    0xE0: ("DATE_TIME_SET", ("TIME$",)),
    0xE2: ("TRAP_CTL", ("TIMER", "OFF")),
    0xE4: ("TRAP_CTL", ("TIMER", "STOP")),
    0xE6: ("TRAP_CTL", ("TIMER", "ON")),
    0xEA: ("VIEW", ()),
    0xEC: ("WIDTH", ()),
    0xEE: ("WIDTH", ()),
    0xF0: ("WIDTH", ()),
    0xF2: ("WINDOW", ()),
}

# Every known dispatcher name remains evidence, including phases that must be
# combined before they can become source statements.
EC_DISPATCH_NAMES = {
    sub: source[0] for sub, source in EC_SOURCE_STATEMENTS.items()
} | {
    0x04: "BLOAD_DEFAULT",
    0x16: "CLOSE_ALL",
    0x28: "DELAY_INIT",
    0x2A: "DELAY_POLL",
    0x2C: "DIM_BEGIN",
    0x2E: "DIM_END",
    0x38: "ERASE_STATIC",
    0x3A: "LOCAL_ARRAY_FREE",
    0x3E: "FIELD_BEGIN",
    0x40: "FIELD_ITEM",
    0x42: "FILES_BARE",
    0x66: "LINE_INPUT_FILE",
    0x70: "ON_ERROR",
    0x72: "ON_GOSUB",
    0x74: "ON_GOTO",
    0x76: "ON_COM",
    0x78: "ON_KEY",
    0x7A: "ON_PEN",
    0x7C: "ON_PLAY",
    0x80: "ON_TIMER",
    0x86: "PALETTE_RESET",
    0x8A: "PALETTE_USING",
    0x9A: "READ_NUMBER",
    0x9C: "READ_STRING",
    0x9E: "INPUT_FILE_NUMBER",
    0xA0: "INPUT_FILE_STRING",
    0xB2: "DATA_NUMBER",
    0xB4: "DATA_STRING",
    0xBC: "RESUME_BEGIN",
    0xBE: "RESUME_BARE",
    0xC0: "RESUME_NEXT",
    0xDC: "PAINT_TILE",
    0xE8: "EPILOGUE",
    0xEE: "WIDTH_DEVICE",
    0xF0: "WIDTH_FILE",
    0xF4: "WRITE_ITEM",
    0xF8: "WRITE_SEPARATOR",
    0xFA: "WRITE_FILE_NUMBER",
    0xFC: "WRITE_FILE_STRING",
    0xFE: "WRITE_FILE_SEPARATOR",
}
EC_RELATIVE_TARGET_SUBS = frozenset({0x70, 0x76, 0x78, 0x7A, 0x7C, 0x80})
EC_TARGET_TABLE_SUBS = frozenset({0x72, 0x74})

# Inline payloads that are part of one dispatcher instruction. Values are
# ``struct`` formats; decoding the whole signature prevents payload bytes from
# becoming unrelated x86 evidence during recursive discovery.
EC_INLINE_PAYLOAD_FORMATS = {
    0x12: "<B",    # CIRCLE option tag
    0x22: "<B",    # COLOR option tag
    0x4A: "<B",    # graphics GET option tag
    0x4E: "<HH",   # INPUT destination and flags
    0x62: "<B",    # LINE option tag
    0x64: "<HB",   # LINE INPUT destination and flags
    0x84: "<B",    # PAINT option tag
    0xA4: "<B",    # PSET option tag
    0xAA: "<B",    # graphics PUT option tag
    0xC6: "<B",    # SCREEN option tag
    0xDC: "<B",    # tiled PAINT option tag
    0xEA: "<B",    # VIEW option tag
    0xF2: "<B",    # WINDOW option tag
}
