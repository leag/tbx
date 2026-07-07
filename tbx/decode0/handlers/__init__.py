"""Opcode-family handlers for ``decode_user_code``'s dispatch loop.
Each handler takes the shared :class:`~tbx.decode0.core.DecodeState`
plus the current ``op``/``addr``/``kind`` and returns ``True`` when it consumed the
op -- the loop then advances ``state.k`` inside the handler and ``continue``s.

Families gather branches that are each owned by a single op ``kind`` (mutually
exclusive, order-independent per op), so consolidating their scattered branches
into one handler is behaviour-preserving. The families are grouped into themed
submodules; this package re-exports every handler so callers keep using
``handlers.<name>``.
"""

from __future__ import annotations

from tbx.decode0.handlers.dos_io import (
    filesystem,
    os_system,
    device_io,
    devwait,
    sound,
    timing,
    datetime,
    segments,
    bounds,
)
from tbx.decode0.handlers.fileio import (
    fileio,
    file_write,
    file_read,
    file_random,
    data_read,
    data_read2,
    write_ops,
)
from tbx.decode0.handlers.graphics import (
    graphics,
    graphics_box,
    console,
)
from tbx.decode0.handlers.arith import (
    int_alu,
    int_bitwise_m,
    int_bitwise_bx,
    fp_math,
    fp_bp,
    far_fp,
    stack_ops,
)
from tbx.decode0.handlers.control import (
    calls,
    cargs,
    runtime_call,
    on_control,
    errors_trap,
    string_ops,
    movax_family,
)

__all__ = [
    "bounds",
    "calls",
    "cargs",
    "console",
    "data_read",
    "data_read2",
    "datetime",
    "device_io",
    "devwait",
    "errors_trap",
    "far_fp",
    "file_random",
    "file_read",
    "file_write",
    "fileio",
    "filesystem",
    "fp_bp",
    "fp_math",
    "graphics",
    "graphics_box",
    "int_alu",
    "int_bitwise_bx",
    "int_bitwise_m",
    "movax_family",
    "on_control",
    "os_system",
    "runtime_call",
    "segments",
    "sound",
    "stack_ops",
    "string_ops",
    "timing",
    "write_ops",
]
