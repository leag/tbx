"""Tiny 16-bit instruction decoder used for code discovery.

It only needs boundaries, branch targets, and a small semantic vocabulary.
Anything else remains a sized structural instruction or one opaque byte.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from typing import Any, Callable

from tbd.ir import Operation
from tbd.profile import (
    CHECKED_GOSUB_VECTOR,
    CHECKED_RETURN_VECTOR,
    EC_DISPATCH_NAMES,
    EC_INLINE_PAYLOAD_FORMATS,
    EC_RELATIVE_TARGET_SUBS,
    EC_TARGET_TABLE_SUBS,
    PROCEDURE_ENTER,
    PROCEDURE_RETURN,
    PROCEDURE_RETURN_POP,
    PROLOGUES,
    RETURN_TO_VECTOR,
    TRACE_VECTOR,
    profile_for,
)

_JCC = (
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
)
_REGS = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")
_ALU = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
_SEGMENT_PUSH = {0x06: "es", 0x0E: "cs", 0x16: "ss", 0x1E: "ds"}
_SEGMENT_POP = {0x07: "es", 0x17: "ss", 0x1F: "ds"}
_STRING_OPS = {
    0xA4: "movs", 0xA5: "movs", 0xA6: "cmps", 0xA7: "cmps",
    0xAA: "stos", 0xAB: "stos", 0xAC: "lods", 0xAD: "lods",
    0xAE: "scas", 0xAF: "scas",
}
_SIMPLE = {
    0x90: "nop", 0x98: "cbw", 0x99: "cwd", 0x9B: "wait",
    0x9C: "pushf", 0x9D: "popf", 0xC3: "ret", 0xCB: "retf",
    0xCC: "int3", 0xCE: "into", 0xCF: "iret", 0xEC: "in_al_dx",
    0xED: "in_ax_dx", 0xEE: "out_dx_al", 0xEF: "out_dx_ax",
    0xF4: "hlt", 0xF5: "cmc", 0xF8: "clc", 0xF9: "stc",
    0xFA: "cli", 0xFB: "sti", 0xFC: "cld", 0xFD: "std",
}
_MODRM = {
    *range(0x00, 0x04), *range(0x08, 0x0C), *range(0x10, 0x14),
    *range(0x18, 0x1C), *range(0x20, 0x24), *range(0x28, 0x2C),
    *range(0x30, 0x34), *range(0x38, 0x3C), 0x62, 0x63,
    *range(0x80, 0x90), 0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7,
    *range(0xD0, 0xD4), *range(0xD8, 0xE0), 0xF6, 0xF7, 0xFE, 0xFF,
}
_PREFIXES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
Decoder = Callable[[bytes, int, int, int, str | None], Operation | None]


def decode_instruction(
    exe: bytes, offset: int, stop: int, code_start: int, dialect: str | None
) -> Operation:
    """Decode one instruction without raising on an unknown opcode."""

    marker = exe[offset : offset + 3]
    if offset == code_start and marker in PROLOGUES:
        return _op(exe, offset, 3, "tb.prologue", (PROLOGUES[marker],), "signature")
    for decoder in _DECODERS:
        if operation := decoder(exe, offset, stop, code_start, dialect):
            return operation
    return _op(exe, offset, 1, "opaque.byte", (exe[offset],), "opaque")


def _decode_interrupt(
    exe: bytes, offset: int, stop: int, code_start: int, dialect: str | None
) -> Operation | None:
    if exe[offset] != 0xCD or offset + 1 >= stop:
        return None
    vector = exe[offset + 1]
    if vector in (0xEC, 0xED, 0xEE) and offset + 2 < stop:
        return _decode_tb_dispatch(exe, offset, stop, code_start, vector, dialect)
    if 0x34 <= vector <= 0x3D and offset + 2 < stop:
        size = min(stop - offset, 2 + _modrm_size(exe, offset + 2, stop))
        return _op(exe, offset, size, "tb.fp", (vector, exe[offset + 2]), "signature")
    canonical = _canonical_vector(vector, dialect)
    if dialect is not None and canonical == CHECKED_GOSUB_VECTOR:
        if offset + 6 > stop:
            return _op(
                exe,
                offset,
                2,
                "tb.checked_call_truncated",
                (6,),
                "structural",
            )
        relative = struct.unpack_from("<i", exe, offset + 2)[0]
        target = code_start + relative
        kind = (
            "tb.checked_gosub"
            if code_start <= target < stop
            else "tb.checked_call_runtime"
        )
        return _op(exe, offset, 6, kind, (target,), "signature")
    if dialect is not None and canonical == CHECKED_RETURN_VECTOR:
        return _op(exe, offset, 2, "tb.checked_return", (), "signature")
    if dialect is not None and canonical == TRACE_VECTOR and offset + 4 <= stop:
        return _op(
            exe,
            offset,
            4,
            "tb.trace",
            (_word(exe, offset + 2),),
            "signature",
        )
    if canonical == RETURN_TO_VECTOR:
        targeted = _decode_targeted_return(exe, offset, stop, code_start)
        if targeted is not None:
            return targeted
    kind = "tb.runtime" if canonical >= 0x80 else "x86.int"
    confidence = "signature" if canonical >= 0x80 else "structural"
    return _op(exe, offset, 2, kind, (canonical,), confidence)


def _decode_targeted_return(
    exe: bytes, offset: int, stop: int, code_start: int
) -> Operation | None:
    branch = exe[offset + 2] if offset + 2 < stop else None
    if branch == 0xE9 and offset + 5 <= stop:
        relative = struct.unpack_from("<h", exe, offset + 3)[0]
        target = code_start + ((offset + 5 + relative - code_start) & 0xFFFF)
        size = 5
    elif branch == 0xEB and offset + 4 <= stop:
        target = offset + 4 + _signed8(exe[offset + 3])
        size = 4
    elif branch == 0xEA and offset + 7 <= stop:
        far_offset, segment = struct.unpack_from("<HH", exe, offset + 3)
        target = code_start + segment * 16 + far_offset
        size = 7
    else:
        return None
    return _op(exe, offset, size, "tb.return_to", (target,), "signature")


def _decode_tb_dispatch(
    exe: bytes,
    offset: int,
    stop: int,
    code_start: int,
    vector: int,
    dialect: str | None,
) -> Operation:
    sub = _canonical_sub(vector, exe[offset + 2], dialect)
    if vector == 0xEC:
        name = EC_DISPATCH_NAMES.get(sub, f"SUB_{sub:02X}")
        kind = "tb.epilogue" if sub == 0xE8 else "tb.statement"
        if sub in EC_RELATIVE_TARGET_SUBS:
            if offset + 7 > stop:
                return _op(
                    exe,
                    offset,
                    3,
                    "tb.dispatch_truncated",
                    (name, sub, 7),
                    "structural",
                )
            relative = struct.unpack_from("<i", exe, offset + 3)[0]
            target = None if sub == 0x70 and relative == -1 else code_start + relative
            return _op(exe, offset, 7, kind, (name, sub, target), "signature")
        if sub in EC_TARGET_TABLE_SUBS:
            if offset + 5 > stop:
                return _truncated_dispatch(exe, offset, name, sub, 5)
            count = _word(exe, offset + 3)
            size = 5 + count * 4
            if offset + size > stop:
                return _truncated_dispatch(exe, offset, name, sub, size)
            targets = tuple(
                code_start + struct.unpack_from("<I", exe, offset + 5 + index * 4)[0]
                for index in range(count)
            )
            return _op(exe, offset, size, kind, (name, sub, *targets), "signature")
        if payload_format := EC_INLINE_PAYLOAD_FORMATS.get(sub):
            payload_size = struct.calcsize(payload_format)
            size = 3 + payload_size
            if offset + size > stop:
                return _truncated_dispatch(exe, offset, name, sub, size)
            payload = struct.unpack_from(payload_format, exe, offset + 3)
            return _op(exe, offset, size, kind, (name, sub, *payload), "signature")
        return _op(exe, offset, 3, kind, (name, sub), "signature")
    family = "numeric" if vector == 0xED else "string"
    return _op(exe, offset, 3, "tb.function", (family, sub), "signature")


def _truncated_dispatch(
    exe: bytes, offset: int, name: str, sub: int, expected_size: int
) -> Operation:
    return _op(
        exe,
        offset,
        3,
        "tb.dispatch_truncated",
        (name, sub, expected_size),
        "structural",
    )


def _decode_near_branch(
    exe: bytes, offset: int, stop: int, code_start: int, dialect: str | None
) -> Operation | None:
    byte = exe[offset]
    if 0x70 <= byte <= 0x7F and offset + 1 < stop:
        target = offset + 2 + _signed8(exe[offset + 1])
        return _op(exe, offset, 2, f"x86.{_JCC[byte - 0x70]}", (target,))
    if byte == 0xEB and offset + 1 < stop:
        target = offset + 2 + _signed8(exe[offset + 1])
        if _is_run_jump(byte, target, code_start, dialect):
            return _op(exe, offset, 2, "tb.run", (target,), "signature")
        return _op(exe, offset, 2, "x86.jmp", (target,))
    if byte in (0xE8, 0xE9) and offset + 2 < stop:
        relative = struct.unpack_from("<h", exe, offset + 1)[0]
        target = code_start + ((offset + 3 + relative - code_start) & 0xFFFF)
        kind = "x86.call" if byte == 0xE8 else "x86.jmp"
        if byte == 0xE9 and _is_run_jump(byte, target, code_start, dialect):
            return _op(exe, offset, 3, "tb.run", (target,), "signature")
        return _op(exe, offset, 3, kind, (target,))
    if 0xE0 <= byte <= 0xE3 and offset + 1 < stop:
        names = ("loopne", "loope", "loop", "jcxz")
        target = offset + 2 + _signed8(exe[offset + 1])
        return _op(exe, offset, 2, f"x86.{names[byte - 0xE0]}", (target,))
    return None


def _is_run_jump(
    opcode: int, target: int, code_start: int, dialect: str | None
) -> bool:
    profile = profile_for(dialect)
    return (
        profile.is_run_jump(opcode, target, code_start)
        if profile is not None
        else False
    )


def _decode_far_branch(
    exe: bytes, offset: int, stop: int, code_start: int, _dialect: str | None
) -> Operation | None:
    byte = exe[offset]
    if byte not in (0x9A, 0xEA) or offset + 4 >= stop:
        return None
    far_offset, segment = struct.unpack_from("<HH", exe, offset + 1)
    if byte == 0xEA and far_offset == segment == 0:
        return _op(exe, offset, 5, "tb.epilogue", (), "signature")
    target = code_start + segment * 16 + far_offset
    kind = "x86.call_far" if byte == 0x9A else "x86.jmp_far"
    return _op(exe, offset, 5, kind, (target, segment, far_offset))


def _decode_procedure_control(
    exe: bytes, offset: int, stop: int, _start: int, _dialect: str | None
) -> Operation | None:
    if exe.startswith(PROCEDURE_ENTER, offset, stop):
        return _op(exe, offset, len(PROCEDURE_ENTER), "tb.proc_enter", confidence="signature")
    if exe.startswith(PROCEDURE_RETURN, offset, stop):
        return _op(
            exe,
            offset,
            len(PROCEDURE_RETURN),
            "tb.proc_return",
            (0,),
            "signature",
        )
    size = len(PROCEDURE_RETURN_POP) + 2
    if exe.startswith(PROCEDURE_RETURN_POP, offset, stop) and offset + size <= stop:
        return _op(
            exe,
            offset,
            size,
            "tb.proc_return",
            (_word(exe, offset + len(PROCEDURE_RETURN_POP)),),
            "signature",
        )
    return None


def _decode_profile_direct(
    exe: bytes, offset: int, stop: int, _start: int, dialect: str | None
) -> Operation | None:
    profile = profile_for(dialect)
    if profile is None:
        return None
    if (
        offset + 4 <= stop
        and exe[offset : offset + 2] == b"\x8c\x1e"
        and _word(exe, offset + 2) == profile.defseg_cell
    ):
        return _op(exe, offset, 4, "tb.defseg_reset", confidence="signature")
    if (
        profile.inline_defseg_set
        and offset + 6 <= stop
        and exe[offset : offset + 2] == b"\xc7\x06"
        and _word(exe, offset + 2) == profile.defseg_cell
    ):
        return _op(
            exe,
            offset,
            6,
            "tb.defseg_set",
            (_word(exe, offset + 4),),
            "signature",
        )
    return None


def _decode_register(
    exe: bytes, offset: int, stop: int, _start: int, _dialect: str | None
) -> Operation | None:
    byte = exe[offset]
    if 0xB8 <= byte <= 0xBF and offset + 2 < stop:
        value = struct.unpack_from("<H", exe, offset + 1)[0]
        return _op(exe, offset, 3, "x86.mov_imm", (_REGS[byte - 0xB8], value))
    for first, kind in ((0x50, "push"), (0x58, "pop"), (0x40, "inc"), (0x48, "dec")):
        if first <= byte < first + 8:
            return _op(exe, offset, 1, f"x86.{kind}", (_REGS[byte - first],))
    if 0x91 <= byte <= 0x97:
        return _op(exe, offset, 1, "x86.xchg", ("ax", _REGS[byte - 0x90]))
    for table, kind in ((_SEGMENT_PUSH, "push"), (_SEGMENT_POP, "pop")):
        if segment := table.get(byte):
            return _op(exe, offset, 1, f"x86.{kind}", (segment,))
    return None


def _decode_stack_immediate(
    exe: bytes, offset: int, stop: int, _start: int, _dialect: str | None
) -> Operation | None:
    byte = exe[offset]
    if byte in (0x68, 0x6A):
        size = 3 if byte == 0x68 else 2
        if offset + size <= stop:
            value = _word(exe, offset + 1) if size == 3 else _signed8(exe[offset + 1])
            return _op(exe, offset, size, "x86.push_imm", (value,))
    return None


def _decode_alu_immediate(
    exe: bytes, offset: int, stop: int, _start: int, _dialect: str | None
) -> Operation | None:
    byte = exe[offset]
    if byte < 0x40 and byte & 7 in (4, 5):
        size = 2 if byte & 1 == 0 else 3
        if offset + size <= stop:
            value = exe[offset + 1] if size == 2 else _word(exe, offset + 1)
            return _op(exe, offset, size, f"x86.{_ALU[byte >> 3]}_imm", (value,))
    return None


def _decode_accumulator_memory(
    exe: bytes, offset: int, stop: int, _start: int, _dialect: str | None
) -> Operation | None:
    byte = exe[offset]
    if 0xA0 <= byte <= 0xA3 and offset + 2 < stop:
        direction = "store" if byte & 2 else "load"
        return _op(exe, offset, 3, "x86.mov_acc_mem", (_word(exe, offset + 1), direction))
    return None


def _decode_fixed(
    exe: bytes, offset: int, stop: int, _start: int, _dialect: str | None
) -> Operation | None:
    byte = exe[offset]
    if family := _STRING_OPS.get(byte):
        return _op(exe, offset, 1, f"x86.{family}", ("word" if byte & 1 else "byte",))
    if name := _SIMPLE.get(byte):
        return _op(exe, offset, 1, f"x86.{name}")
    if byte in (0xC2, 0xCA) and offset + 2 < stop:
        kind = "x86.retf" if byte == 0xCA else "x86.ret"
        return _op(exe, offset, 3, kind, (_word(exe, offset + 1),))
    return None


def _decode_modrm(
    exe: bytes, offset: int, stop: int, _start: int, _dialect: str | None
) -> Operation | None:
    prefix_end = offset
    while prefix_end < stop and exe[prefix_end] in _PREFIXES and prefix_end - offset < 4:
        prefix_end += 1
    if prefix_end + 1 >= stop or exe[prefix_end] not in _MODRM:
        return None
    opcode = exe[prefix_end]
    length = prefix_end - offset + 1 + _modrm_size(exe, prefix_end + 1, stop)
    reg = (exe[prefix_end + 1] >> 3) & 7
    length = min(length + _immediate_size(opcode, reg), stop - offset)
    return _op(exe, offset, length, _modrm_kind(opcode))


def _modrm_kind(opcode: int) -> str:
    if opcode < 0x40:
        return f"x86.{_ALU[opcode >> 3]}"
    if opcode in (0x88, 0x89, 0x8A, 0x8B, 0xC6, 0xC7):
        return "x86.mov"
    return f"x86.op_{opcode:02x}"


def _canonical_sub(vector: int, sub: int, dialect: str | None) -> int:
    profile = profile_for(dialect)
    return profile.canonical_sub(vector, sub) if profile is not None else sub


def _canonical_vector(vector: int, dialect: str | None) -> int:
    profile = profile_for(dialect)
    return profile.canonical_vector(vector) if profile is not None else vector


def _modrm_size(exe: bytes, offset: int, stop: int) -> int:
    modrm = exe[offset]
    mod, rm = modrm >> 6, modrm & 7
    displacement = 2 if mod == 0 and rm == 6 else (1 if mod == 1 else (2 if mod == 2 else 0))
    return min(1 + displacement, stop - offset)


def _immediate_size(opcode: int, reg: int) -> int:
    if opcode in (0x80, 0x82, 0x83, 0xC0, 0xC1, 0xC6):
        return 1
    if opcode in (0x81, 0xC7):
        return 2
    if opcode in (0xF6, 0xF7) and reg == 0:
        return 1 if opcode == 0xF6 else 2
    return 0


def _op(
    exe: bytes,
    offset: int,
    size: int,
    kind: str,
    operands: Iterable[Any] = (),
    confidence: str = "structural",
) -> Operation:
    raw = exe[offset : offset + size].hex(" ")
    return Operation(offset, size, kind, tuple(operands), raw, confidence)


def _signed8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _word(exe: bytes, offset: int) -> int:
    return struct.unpack_from("<H", exe, offset)[0]


_DECODERS: tuple[Decoder, ...] = (
    _decode_interrupt,
    _decode_near_branch,
    _decode_far_branch,
    _decode_procedure_control,
    _decode_profile_direct,
    _decode_register,
    _decode_stack_immediate,
    _decode_alu_immediate,
    _decode_accumulator_memory,
    _decode_fixed,
    _decode_modrm,
)
