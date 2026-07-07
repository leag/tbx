"""Raw x86 helpers for control-flow analysis of a compiled code region.

Provides:
  * JCC_RELOP / JCC -- conditional-jump mnemonic classification
  * jump_target     -- resolve a near jump/call to a full file offset
  * mnemonic        -- first token of a formatted instruction
  * decode_insns    -- linear 16-bit x86 decode of a byte range
"""

import re

from iced_x86 import Decoder, Formatter, FormatterSyntax

# Conditional-jump mnemonic -> relational operator on the compare that set the
# flags. Covers both unsigned (FP compare results reach the flags via
# FSTSW/SAHF: ZF=equal, CF=less-than) and signed integer forms.
JCC_RELOP = {
    "je": "=",
    "jz": "=",
    "jne": "<>",
    "jnz": "<>",
    "jb": "<",
    "jc": "<",
    "jnae": "<",
    "jbe": "<=",
    "jna": "<=",
    "ja": ">",
    "jnbe": ">",
    "jae": ">=",
    "jnb": ">=",
    "jnc": ">=",
    "jl": "<",
    "jnge": "<",
    "jle": "<=",
    "jng": "<=",
    "jg": ">",
    "jnle": ">",
    "jge": ">=",
    "jnl": ">=",
}
JCC = set(JCC_RELOP)
HEX = re.compile(r"([0-9A-Fa-f]+)h\b")


def jump_target(txt, src=None, code_range=None):
    """Resolve a near jump/call's target to a full file offset.

    Instructions are decoded in 16-bit mode, so the encoded target is an
    offset within the current 64KB code bank. With `src` known, the full
    offset is (src & ~0xFFFF) | target16.

    Programs with more than 64KB of code span multiple banks, and the
    compiler emits near jumps whose real target lies in the adjacent bank.
    When `code_range` (start, end) is given and the same-bank resolution
    falls outside it, the target is re-resolved into the other bank.
    """
    m = HEX.search(txt.split(None, 2)[-1]) if txt else None
    if not m:
        return None
    t16 = int(m.group(1), 16)
    if src is None:
        return t16
    same = (src & ~0xFFFF) | (t16 & 0xFFFF)
    if code_range is not None:
        start, end = code_range
        if not (start <= same <= end):
            other = same ^ 0x10000
            if start <= other <= end:
                return other
    return same


def mnemonic(txt):
    return txt.split(None, 1)[0] if txt else ""


def decode_insns(exe: bytes, start: int, end: int) -> list[tuple[int, str, str]]:
    """Linear 16-bit x86 decode of exe[start:end].

    Returns one (pos, 'x86', txt) tuple per decoded instruction, txt in NASM
    syntax. Undecodable bytes are skipped one at a time so the walk always
    makes progress.
    """
    pos, end = start, min(end, len(exe))
    fmt = Formatter(FormatterSyntax.NASM)
    lines = []
    while pos < end:
        dec = Decoder(16, exe[pos : pos + 16], ip=pos)
        if dec.can_decode:
            insn = dec.decode()
            if insn.is_invalid or insn.len == 0:
                pos += 1
            else:
                txt = fmt.format(insn)
                lines.append((pos, "x86", txt))
                pos += insn.len
        else:
            pos += 1
    return lines
