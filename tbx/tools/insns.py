"""Raw x86 helpers for control-flow analysis of a compiled code region.

Provides:
  * JCC_RELOP / JCC -- conditional-jump mnemonic classification
  * jump_target     -- resolve a near jump/call to a full file offset
  * mnemonic        -- first token of a formatted instruction
  * decode_insns    -- linear 16-bit x86 decode of a byte range
  * decode_flow     -- control-flow-directed 16-bit x86 decode of a byte range
"""

import bisect
import re

try:
    from iced_x86 import Decoder, FlowControl, Formatter, FormatterSyntax, OpKind
except ImportError as e:
    raise ImportError(
        "the disassembly debugging tools need the 'debug' extra: "
        "pip install 'tbx[debug]'"
    ) from e

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


# Flow-control kinds that transfer to a resolvable near address, added to
# the traversal worklist below. CALL is in both this set and
# _FALLTHROUGH_KINDS: a call both enters the callee and, on return,
# resumes at the next instruction.
_BRANCH_KINDS = {FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CONDITIONAL_BRANCH, FlowControl.CALL}

# Far jmp/call: x86 has no far conditional jump, so CONDITIONAL_BRANCH is
# deliberately not in this set (unlike _BRANCH_KINDS for near branches).
_FAR_BRANCH_KINDS = {FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CALL}

# Flow-control kinds after which straight-line execution continues at the
# next instruction. RETURN, INDIRECT_BRANCH (a computed jump whose target
# isn't known statically) and UNCONDITIONAL_BRANCH are deliberately
# excluded: nothing after them is reachable from this instruction alone.
_FALLTHROUGH_KINDS = {
    FlowControl.NEXT,
    FlowControl.CALL,
    FlowControl.INDIRECT_CALL,
    FlowControl.INTERRUPT,
    FlowControl.CONDITIONAL_BRANCH,
}


def decode_flow(
    exe: bytes, start: int, end: int, op_starts: list[int] | None = None
) -> list[tuple[int, str, str, int | None]]:
    """Control-flow-directed 16-bit x86 decode of exe[start:end].

    `decode_insns` sweeps byte-by-byte and has no notion of what's real
    code -- if the compiler places anything non-executable (a jump table,
    inline literal data) between two reachable instructions, the sweep
    decodes straight through it as if it were code, permanently losing
    alignment with the real instruction stream. There is no resync marker
    in x86, so every instruction after that point can come out wrong even
    though each one decodes "successfully".

    This instead starts at `start` and follows real control-flow edges --
    fallthrough, jump/branch targets, call targets -- so it only ever
    decodes bytes actually reachable as an instruction start. A target
    that lands inside a wrongly-swept instruction under the linear scan
    simply becomes its own correct entry here instead of vanishing into
    someone else's operand bytes. The tradeoff: an address reachable only
    through a computed/indirect jump (a dispatch table, `jmp bx`) can't be
    resolved statically and its far side won't appear -- that's a
    correctness bound of static disassembly generally, not something this
    walk can special-case away, and a gap in what's shown is preferable to
    guessing where it lands.

    A second, narrower gap this closes when `op_starts` is given (decode0's
    own recognized op-boundary positions for the same range, e.g. from
    `decode0._scan`): some runtime dispatches -- an `int` selecting a
    DIM-array descriptor, witnessed on tbd73.exe -- are followed by inline
    argument bytes the interrupt handler consumes and skips over at
    runtime, not further code. iced has no way to know this; decode0
    already does, since it recognized the whole thing as one op. Whenever
    an instruction starts exactly on a known op boundary and decode0's next
    op starts later than iced's own `pos + insn.len` would fall through to,
    that gap is exactly the inline argument tail -- fall through to
    decode0's boundary instead of into the middle of it.

    Far jmp/call targets (a `$SEGMENT` program's code split across more
    than one 64KB segment, tbd73.exe again) are resolved too, reusing
    decode0's own proven address math (`tbx.decode0.scan`'s far-call/
    far-jmp handling) rather than re-deriving DOS segment arithmetic here:
    the segment word is relative to `start`, so the file offset is
    `start + segment * 16 + offset`. An offset and segment both zero is
    decode0's "epilogue" sentinel (marks program end), not a real target.

    Returns one (pos, 'x86', txt, target) tuple per reached instruction,
    sorted by address; `target` is the resolved branch/call destination
    for control-flow instructions with a same-range target (near or far),
    else None (indirect branches and out-of-range targets).
    """
    end = min(end, len(exe))
    fmt = Formatter(FormatterSyntax.NASM)
    decoded: dict[int, tuple[str, int | None]] = {}
    worklist = [start]
    op_starts = sorted(op_starts) if op_starts else []
    op_start_set = set(op_starts)

    def next_op_boundary(pos: int) -> int | None:
        i = bisect.bisect_right(op_starts, pos)
        return op_starts[i] if i < len(op_starts) else None

    while worklist:
        pos = worklist.pop()
        if pos in decoded or not (start <= pos < end):
            continue
        dec = Decoder(16, exe[pos : pos + 16], ip=pos)
        if not dec.can_decode:
            continue
        insn = dec.decode()
        if insn.is_invalid or insn.len == 0:
            continue

        txt = fmt.format(insn)
        fc = insn.flow_control
        target = None
        if fc in _BRANCH_KINDS and insn.op0_kind == OpKind.NEAR_BRANCH16:
            # Resolved straight from iced's own decode of the operand, not
            # re-parsed out of the formatted text: NASM renders a target of
            # 0 as bare "0" with no "h" suffix, which `jump_target`'s
            # regex (built for the hex-with-suffix case everywhere else)
            # doesn't match.
            same = (pos & ~0xFFFF) | (insn.near_branch_target & 0xFFFF)
            if start <= same < end:
                target = same
            else:
                other = same ^ 0x10000
                if start <= other < end:
                    target = other
            if target is not None:
                worklist.append(target)
        elif fc in _FAR_BRANCH_KINDS and insn.op0_kind == OpKind.FAR_BRANCH16:
            off, seg = insn.far_branch16, insn.far_branch_selector
            if not (off == 0 and seg == 0):  # decode0's "epilogue" sentinel
                far_target = start + seg * 16 + off
                if start <= far_target < end:
                    target = far_target
                    worklist.append(far_target)
        if fc in _FALLTHROUGH_KINDS:
            fallthrough = pos + insn.len
            if pos in op_start_set:
                boundary = next_op_boundary(pos)
                if boundary is not None and boundary > fallthrough:
                    fallthrough = boundary
            worklist.append(fallthrough)

        decoded[pos] = (txt, target)

    return [(addr, "x86", text, target) for addr, (text, target) in sorted(decoded.items())]
