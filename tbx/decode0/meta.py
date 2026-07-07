"""Program container, compiler toggles and program-meta statements."""

from __future__ import annotations
import struct
from typing import Any

from tbx.decode0.const import _TOGGLE_BITS, _TOGGLE_NAMES


class Program(list[Any]):
    """Decoded statements. `lines[i]` holds statement i's ORIGINAL line number when
    the image embeds the error-trap line table (bare RESUME / RESUME NEXT / ERL need
    the erroring line at runtime); that table stores real line numbers, so canonical
    renumbering would change bytes (witnessed t1_onerr). None when the
    table is absent -- line numbers are then free and the emitter renumbers.
    `metas` holds synthesized metastatement source lines as (stmt_index, text)
    pairs -- $STACK/$SOUND from the allocation table at index 0, $EVENT ON/OFF at
    each CC-hook transition; the emitter inserts them unnumbered before the
    indexed statement."""

    lines: list[Any] | None = None
    metas: tuple[Any, ...] = ()
    toggles: str = ""  # IDE compiler toggles ON at compile time (harness hotkey
    # letters, menu order: '8'=8087, K=Keyboard break, B=Bounds, O=Overflow,
    # S=Stack test); detected from the flags mask, see _toggles
    hook_seq: tuple[
        int, ...
    ] = ()  # TRON: every trace-hook line, in address order (emit0 numbers)
    traced: tuple[int, ...] = ()  # TRON: statement indices inside a traced region
    # TRON: {stmt index -> traced physical-line count} for a mid-block TROFF
    trace_partial: dict[int, int]


def toggle_names(toggles: str) -> str:
    """Human-readable Options-menu names for a toggle letter string (CLI)."""
    return ", ".join(_TOGGLE_NAMES[t] for t in toggles)


def _toggles(exe: bytes, start: int) -> str:
    """Compiler toggles from the flags mask at prologue-0x73; '' = all defaults.
    Stamped unconditionally by the compiler, so detection is content-independent.
    Unknown low bits mean the byte isn't the known framework cell (possible in
    minimal synthetic fixtures) -- treated as unflagged, same as _meta_stmts'
    shape guard; a real flagged variant would fail its byte-exact gate loudly."""
    mask = exe[start - 0x73] if start >= 0x73 else 0
    if mask & 0x07:
        return ""
    return "".join(ch for bit, ch in _TOGGLE_BITS if mask & bit)


def _meta_stmts(exe: bytes, start: int) -> tuple[str, ...]:
    """Recover $SOUND/$STACK metastatements from the runtime allocation table, a
    paragraph-unit word table at a FIXED offset before the prologue (verified in
    both dialects): sound-buffer paras at start-0x40 (n notes = paras*2,
    default 0x10 = 32 notes; the size repeats at -0x3A and shifts the -0x36/-0x32
    bases, all regenerated on recompile) and stack paras at start-0x34 (bytes =
    paras*16, default 0x40 = 1024; $STACK 1024 is byte-invisible)."""
    if start < 0x40:
        return ()
    sound, g0, g1, sound2 = struct.unpack_from("<HHHH", exe, start - 0x40)
    stack = struct.unpack_from("<H", exe, start - 0x34)[0]
    if g0 != 0 or g1 != 0x20 or sound2 != sound:
        return ()  # not the known table shape (synthetic tier-0
    metas = []  # fixtures) -- a real variant that hid a $SOUND
    if sound != 0x10:  # or $STACK would fail its byte-exact gate
        metas.append(f"$SOUND {sound * 2}")
    if stack != 0x40:
        metas.append(f"$STACK {stack * 16}")
    return tuple(metas)
