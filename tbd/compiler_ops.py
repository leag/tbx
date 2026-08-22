"""Compiler-template operations translated from immutable evidence.

The names intentionally mirror the calibrated operation vocabulary used by
the reference decoder.  This module contains no ``tbx`` import: it translates
``tbd`` instructions so small fact passes can port proven template matchers
instead of rediscovering byte patterns independently.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from tbd.ir import Operation


@dataclass(frozen=True)
class CompilerOp:
    """One normalized operation consumed by compiler-template passes."""

    offset: int
    end: int
    kind: str
    args: tuple[object, ...] = ()


def translate_operations(instructions: tuple[Operation, ...]) -> tuple[CompilerOp, ...]:
    """Translate recognized instructions into the calibrated template vocabulary."""

    result = []
    for instruction in instructions:
        translated = _translate(instruction)
        if translated is not None:
            result.append(translated)
    return tuple(result)


def operation_indexes(
    operations: tuple[CompilerOp, ...],
) -> tuple[dict[int, int], dict[int, CompilerOp]]:
    """Return stable address-to-index and address-to-operation views."""

    return (
        {operation.offset: index for index, operation in enumerate(operations)},
        {operation.offset: operation for operation in operations},
    )


def _translate(instruction: Operation) -> CompilerOp | None:
    raw = bytes.fromhex(instruction.raw)
    if instruction.kind == "x86.mov_imm" and len(instruction.operands) == 2:
        register, value = instruction.operands
        if register in {"si", "dx"}:
            return _op(instruction, f"mov{register}", value)
        if register == "ax":
            return _op(instruction, "movax", value)
    if raw == b"\x8e\xc2":
        return _op(instruction, "movesdx")
    if raw == b"\x8e\xda":
        return _op(instruction, "movdsdx")
    if raw == b"\x89\xc6":
        return _op(instruction, "movsiax")
    if raw == b"\x89\xc3":
        return _op(instruction, "movbxax")
    if raw == b"\x8b\xd8":
        return _op(instruction, "movbxax")
    if raw == b"\x89\xd8":
        return _op(instruction, "movaxbx")
    if raw == b"\x89\xf3":
        return _op(instruction, "movbxsi")
    if raw == b"\x03\xf0":
        return _op(instruction, "addsiax")
    if raw == b"\x09\xc0":
        return _op(instruction, "orax")
    if instruction.kind == "x86.inc" and instruction.operands == ("ax",):
        return _op(instruction, "incax")
    if raw == b"\xd1\xe6":
        return _op(instruction, "shlsi")
    if len(raw) == 4 and raw[:2] == b"\x81\xc6":
        return _op(instruction, "addsi", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x8e\x06":
        return _op(instruction, "moves_m", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x8e\x1e":
        return _op(instruction, "movds_m", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x8c\x1e":
        return _op(instruction, "movm_ds", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x8c\x06":
        return _op(instruction, "movm_es", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x8b\x36":
        return _op(instruction, "movsim", _u16(raw, 2))
    if instruction.kind == "tb.statement" and instruction.operands:
        dim_kind = {"DIM_BEGIN": "dim_begin", "DIM_END": "dim_end"}.get(
            instruction.operands[0]
        )
        if dim_kind is not None:
            return _op(instruction, dim_kind)
    if instruction.kind == "x86.jmp" and len(instruction.operands) == 1:
        return _op(instruction, "jmp", instruction.operands[0])
    if instruction.kind.startswith("x86.j") and raw and 0x70 <= raw[0] <= 0x7F:
        return _op(instruction, "jcc", raw[0], instruction.operands[0])
    if instruction.kind == "tb.runtime" and instruction.operands == (0x99,):
        return _op(instruction, "fstsw")
    if instruction.kind == "tb.runtime" and instruction.operands == (0xA0,):
        return _op(instruction, "strassign")
    if instruction.kind == "tb.runtime" and instruction.operands == (0xA1,):
        return _op(instruction, "far_strassign")
    if instruction.kind == "tb.runtime" and instruction.operands in {
        (0x9C,),
        (0x9D,),
    }:
        return _op(instruction, "spush")
    if instruction.kind == "tb.fwait":
        return _op(instruction, "fwait")
    if (
        instruction.kind == "x86.mov_acc_mem"
        and len(instruction.operands) == 2
    ):
        direction = instruction.operands[1]
        if direction == "load":
            return _op(instruction, "movaxmem", instruction.operands[0])
        if direction == "store":
            return _op(instruction, "movmem_ax", instruction.operands[0])
    if instruction.kind in {"tb.fp", "tb.fp_far"}:
        return _fp_operation(instruction, raw)
    return _integer_operation(instruction, raw)


def _integer_operation(instruction: Operation, raw: bytes) -> CompilerOp | None:
    direct = _direct_integer_operation(instruction, raw)
    if direct is not None:
        return direct
    if raw == b"\x0b\xc0":
        return _op(instruction, "orax_self")
    if len(raw) >= 4 and raw[:2] == b"\xf7\x06":
        return _op(
            instruction,
            "testw",
            _u16(raw, 2),
            _u16(raw, 4),
        )
    if len(raw) in {5, 6} and raw[:2] in {b"\xf7\x46", b"\xf7\x86"}:
        displacement = _bp_displacement(raw)
        return _op(instruction, "testw_bp", displacement, _u16(raw, len(raw) - 2))
    return None


def _direct_integer_operation(
    instruction: Operation, raw: bytes
) -> CompilerOp | None:
    if len(raw) == 4 and raw[:2] == b"\x8b\x06":
        return _op(instruction, "movax_m", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x89\x06":
        return _op(instruction, "movm_ax", _u16(raw, 2))
    if len(raw) == 6 and raw[:2] == b"\xc7\x06":
        return _op(instruction, "movm_imm", _u16(raw, 2), _u16(raw, 4))
    if len(raw) == 4 and raw[:2] == b"\x39\x06":
        return _op(instruction, "cmpm_ax", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x3b\x06":
        return _op(instruction, "cmpax_m", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x01\x06":
        return _op(instruction, "addm_ax", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\x2b\x06":
        return _op(instruction, "subax_m", _u16(raw, 2))
    if len(raw) == 4 and raw[:2] == b"\xf7\x2e":
        return _op(instruction, "imul_m", _u16(raw, 2))
    if raw == b"\x89\x04":
        return _op(instruction, "movm_ax_si")
    if raw == b"\x26\x89\x04":
        return _op(instruction, "far_movm_ax_si")
    if raw == b"\x8b\x04":
        return _op(instruction, "movax_si")
    if raw == b"\x03\x04":
        return _op(instruction, "addax_si")
    if raw == b"\x2b\x04":
        return _op(instruction, "subax_si")
    if raw == b"\x3b\x04":
        return _op(instruction, "cmpax_si")
    if raw == b"\xf7\x2c":
        return _op(instruction, "imul_si")
    if raw == b"\x26\x8b\x04":
        return _op(instruction, "far_movax_si")
    exchange = {
        b"\x26\x8b\x07": "far_movax_bx",
        b"\x87\x04": "xchgsi",
        b"\x26\x89\x07": "far_movm_ax_bx",
        b"\x26\x8b\x47\x02": "far_movax_bx2",
        b"\x87\x44\x02": "xchgsi2",
        b"\x26\x89\x47\x02": "far_movm_ax_bx2",
        b"\x8b\x07": "movax_bx",
        b"\x26\x87\x04": "far_xchgsi",
        b"\x89\x07": "movm_ax_bx",
        b"\x8b\x47\x02": "movax_bx2",
        b"\x26\x87\x44\x02": "far_xchgsi2",
        b"\x89\x47\x02": "movm_ax_bx2",
        b"\x8b\x47\x04": "movax_bx4",
        b"\x26\x87\x44\x04": "far_xchgsi4",
        b"\x89\x47\x04": "movm_ax_bx4",
        b"\x8b\x47\x06": "movax_bx6",
        b"\x26\x87\x44\x06": "far_xchgsi6",
        b"\x89\x47\x06": "movm_ax_bx6",
    }.get(raw)
    if exchange is not None:
        return _op(instruction, exchange)
    if len(raw) == 4 and raw[:2] in {b"\xff\x06", b"\xff\x0e"}:
        kind = "inc_m" if raw[1] == 0x06 else "dec_m"
        return _op(instruction, kind, _u16(raw, 2))
    if len(raw) == 5 and raw[:2] in {b"\x83\x3e", b"\x83\x06"}:
        kind = "cmp_mi8" if raw[1] == 0x3E else "addm_i8"
        return _op(instruction, kind, _u16(raw, 2), struct.unpack_from("<b", raw, 4)[0])
    if len(raw) == 6 and raw[:2] in {b"\x81\x3e", b"\x81\x06"}:
        kind = "cmp_mi16" if raw[1] == 0x3E else "addm_i16"
        return _op(instruction, kind, _u16(raw, 2), struct.unpack_from("<h", raw, 4)[0])
    return _bp_integer_operation(instruction, raw)


def _bp_integer_operation(instruction: Operation, raw: bytes) -> CompilerOp | None:
    forms = {
        b"\x8b\x46": "movax_bp",
        b"\x8b\x86": "movax_bp",
        b"\x39\x46": "cmpm_ax_bp",
        b"\x39\x86": "cmpm_ax_bp",
        b"\x01\x46": "addm_ax_bp",
        b"\x01\x86": "addm_ax_bp",
    }
    kind = forms.get(raw[:2])
    if kind is not None:
        return _op(instruction, kind, _bp_displacement(raw))
    return None


def _fp_operation(instruction: Operation, raw: bytes) -> CompilerOp | None:
    if len(raw) < 3 or raw[0] != 0xCD:
        return None
    far = instruction.kind == "tb.fp_far"
    if far:
        escape = raw[2] if raw[1] == 0x3C else None
        modrm_index = 3
    else:
        escape = 0xD8 + raw[1] - 0x34 if 0x34 <= raw[1] <= 0x3B else None
        modrm_index = 2
    if escape is None:
        return None
    modrm = raw[modrm_index]
    register = (modrm >> 3) & 7
    base = {
        (0xD9, 0): "fld",
        (0xD9, 3): "fstp",
        (0xD8, 0): "fold",
        (0xD8, 3): "fcomp",
        (0xDD, 0): "fld64",
        (0xDD, 3): "fstp64",
        (0xDB, 0): "fild32",
        (0xDB, 3): "fistp32",
        (0xDF, 0): "fild",
        (0xDF, 3): "fistp",
        (0xDC, 0): "fold64",
        (0xDC, 3): "fcomp64",
    }.get((escape, register))
    if base is None:
        return None
    mode, rm = modrm >> 6, modrm & 7
    prefix = "far_" if far else ""
    if mode == 0 and rm == 4:
        return _op(instruction, prefix + _si_kind(base))
    address = _modrm_address(raw, modrm_index)
    if address is None:
        return None
    kind = f"{base}_bp" if _is_bp_modrm(modrm) else base
    args = ("+", address) if base in {"fold", "fold64"} else (address,)
    kind = prefix + kind
    return _op(instruction, kind, *args)


def _si_kind(base: str) -> str:
    suffix = ""
    if base.endswith("64"):
        base, suffix = base[:-2], "64"
    elif base.endswith("32"):
        base, suffix = base[:-2], "32"
    return f"{base}_si{suffix}"


def _modrm_address(raw: bytes, modrm_index: int) -> int | None:
    modrm = raw[modrm_index]
    mode, rm = modrm >> 6, modrm & 7
    displacement = modrm_index + 1
    if mode == 0 and rm == 6 and len(raw) == displacement + 2:
        return _u16(raw, displacement)
    if mode == 1 and rm == 6 and len(raw) == displacement + 1:
        return struct.unpack_from("<b", raw, displacement)[0]
    if mode == 2 and rm == 6 and len(raw) == displacement + 2:
        return struct.unpack_from("<h", raw, displacement)[0]
    return None


def _is_bp_modrm(modrm: int) -> bool:
    return modrm >> 6 in {1, 2} and modrm & 7 == 6


def _bp_displacement(raw: bytes) -> int:
    return (
        struct.unpack_from("<b", raw, 2)[0]
        if raw[1] & 0xC0 == 0x40
        else struct.unpack_from("<h", raw, 2)[0]
    )


def _u16(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<H", raw, offset)[0]


def _op(instruction: Operation, kind: str, *args: object) -> CompilerOp:
    return CompilerOp(instruction.offset, instruction.end, kind, tuple(args))
