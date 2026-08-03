"""Instruction scan: walk the INT/ESC stream into the op list."""

from __future__ import annotations
import struct
from typing import Any

from tbx import ir
from tbx.decode0.const import (
    _AX0_SUBS,
    _AXARG_SUBS,
    _ED_STR_SUBS,
    _EE_STRFN_SUBS,
    _FNAX2_SUBS,
    _FNAX_SUBS,
    _FN_VECS,
    _FOLD_OPS,
    _FOLD_OPS_N,
    _FP0_SUBS,
    _POP_OPS,
    _POP_OPS_N,
    _PREC,
    _STR2NUM_VECS,
    _STRFN_VECS,
    _TABSPC_VECS,
    _TRANSCEND,
    _TRAP_CTL,
    _TRAP_GOSUB,
)
from tbx.decode0.dialect import Dialect, TB11, _try_swap
from tbx.decode0.opaque import find_opaque_helpers
from tbx.decode0.opaque_helpers import (
    OPAQUE_HELPERS,
)


def _scan_direct(exe, p, b, dia, ops, start) -> int | None:
    """Byte-dispatch family split out of _scan. Returns the new
    cursor when it decodes the op at ``p``, else None."""
    if b == 0x90:  # NOP padding around compiler templates
        ops.append((p, "nop"))
        return p + 1
    if b == 0xE9:  # jmp near rel16 (GOTO / FOR glue)
        rel = struct.unpack_from("<h", exe, p + 1)[0]
        # A GOTO spanning more than 32KB of code wraps around the 64KB code
        # segment (rel16 is signed): normalize the file-linear target back
        # into [start, start+64K) -- the mapping is linear, so the wrap is
        # exactly 0x10000 in file terms too (witnessed t1_bigjmp / wild
        # inv87.exe, an early GOTO +53KB encoded as a negative rel).
        target = start + ((p + 3 + rel - start) % 0x10000)
        # Some wild programs place a compiler/library data table between two
        # code regions and jump over it.  The ordinary operation stream is
        # linear, so without this guard it would try to decode the table as
        # instructions (nvg.exe has a 454-byte block containing 27% zero
        # bytes, followed by a real framed helper).  Keep this deliberately
        # conservative: only forward jumps over a substantial, predominantly
        # zero-filled gap whose target begins with a known code template are
        # treated as data skips.  User GOTO/loop jumps remain normal ops.
        if target > p + 35:
            gap = exe[p + 3 : target]
            if len(gap) >= 64 and gap.count(0) * 2 >= len(gap):
                lead = exe[target : target + 3]
                if lead in (b"\x55\x8b\xec", b"\x55\x89\xe5", b"\xe9"):
                    ops.append((p, "data_skip", target))
                    return target
        if dia.name == "1.0" and target == start + 3:
            # TB 1.0 RUN: ALWAYS a near jmp to the first statement (start+3),
            # even at short-jmp range (v10_t1_run: e9 fd ff, rel -3) -- a GOTO
            # there would compile short. 1.1 RUN jumps to the prologue instead.
            ops.append((p, "run"))
        elif target == start:
            # ...and that prologue jump only reached the short-jmp form's
            # `target == start` test while it stayed in rel8 range. A RUN far
            # enough from the entry compiles near and landed here as an
            # ordinary jmp to an address no statement owns, since the prologue
            # is not a statement (wild cleanup.exe, reformat.exe: `jump target
            # 0xa2b0 is not a statement start`). Fixture t1_runfar.
            ops.append((p, "run"))
        else:
            ops.append((p, "jmp", target))
        p += 3
        return p
    if 0x70 <= b <= 0x7F:  # Jcc rel8
        rel = struct.unpack_from("<b", exe, p + 1)[0]
        ops.append((p, "jcc", b, p + 2 + rel))
        p += 2
        return p
    if b == 0xF7 and exe[p + 1] == 0x06:  # test word [disp16], imm16 (FOR sign test)
        disp, imm = struct.unpack_from("<HH", exe, p + 2)
        ops.append((p, "testw", disp, imm))
        p += 6
        return p
    if b == 0xF7 and exe[p + 1] == 0x46:  # BP-relative SINGLE LOCAL
        disp, imm = struct.unpack_from("<bH", exe, p + 2)
        ops.append((p, "testw_bp", disp, imm))  # variable-STEP sign word
        p += 5  # (ziptest/cleanup/crossref/reformat)
        return p
    if b == 0xF7 and exe[p + 1] == 0x86:  # same sign-word test for a LOCAL
        disp, imm = struct.unpack_from("<HH", exe, p + 2)
        ops.append((p, "testw_bp", disp, imm))
        p += 6  # beyond disp8 range (wild cleanup/reformat)
        return p
    if b == 0xE8:  # call near rel16 (GOSUB); same 64KB wrap as jmp (t1_bigjmp)
        rel = struct.unpack_from("<h", exe, p + 1)[0]
        ops.append((p, "call", start + ((p + 3 + rel - start) % 0x10000)))
        p += 3
        return p
    if b == 0xEB:  # jmp short rel8
        rel = exe[p + 1] - 256 if exe[p + 1] >= 128 else exe[p + 1]
        target = p + 2 + rel
        if target == start:  # jump to entry = RUN
            ops.append((p, "run"))
        else:
            ops.append((p, "jmps", target))
        p += 2
        return p
    if b == 0xC3:  # ret near (RETURN)
        ops.append((p, "ret"))
        p += 1
        return p
    if b == 0xCC:  # event-trap statement hook (INT 3):
        ops.append((p, "trap_hook"))  # emitted before every statement when
        p += 1  # any trap statement is present
        return p
    if b == 0xCB:  # ret far (RETURN under event trapping)
        ops.append((p, "retf"))
        p += 1
        return p
    # --- procedures (SUB / DEF FN / CALL) ---
    if b == 0x55 and exe[p + 1] == 0x8B and exe[p + 2] == 0xEC:  # push bp; mov bp,sp
        ops.append((p, "proc_enter"))
        p += 3
        return p
    if b == 0x5D and exe[p + 1] == 0xCB:  # pop bp; retf
        ops.append((p, "proc_ret", 0))
        p += 2
        return p
    if b == 0x5D and exe[p + 1] == 0xCA:  # pop bp; retf N
        ops.append((p, "proc_ret", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if (
        b == 0x51  # push cx; push di; mov ax,ss; mov es,ax; mov cx,<n>;
        and exe[p + 1] == 0x57  # lea di,[bp+<disp16>]; xor ax,ax; cld; rep
        and exe[p + 2 : p + 6] == b"\x8c\xd0\x8e\xc0"  # stosw; pop di; pop cx --
        and exe[p + 6] == 0xB9  # LOCAL statement's zero-fill prologue, right
        and exe[p + 9 : p + 11] == b"\x8d\xbe"  # after proc_enter (witnessed
        and exe[p + 13 : p + 18] == b"\x31\xc0\xfc\xf3\xab"  # t1_local1)
        and exe[p + 18 : p + 20] == b"\x5f\x59"
    ):
        cnt = struct.unpack_from("<H", exe, p + 7)[0]
        disp = struct.unpack_from("<H", exe, p + 11)[0]
        ops.append((p, "local_init", cnt, disp))
        p += 20
        return p
    if (
        b == 0x51
        and exe[p + 1] == 0x57
        and exe[p + 2] == 0xB9
        and exe[p + 5] == 0xBF
        and exe[p + 8 : p + 11] == b"\xfc\xf3\xab"
        and exe[p + 11 : p + 13] == b"\x5f\x59"
    ):
        cnt = struct.unpack_from("<H", exe, p + 3)[0]
        disp = struct.unpack_from("<H", exe, p + 6)[0]
        ops.append((p, "local_init", cnt, disp))
        p += 13
        return p
    # Function/temp-frame glue: semantic-free SP/BP frame setup &
    # teardown around DEF FN call sites; matched AFTER the proc_enter/proc_ret
    # combined forms above. The lifter skips these.
    if b == 0x55:  # push bp
        ops.append((p, "push_bp"))
        p += 1
        return p
    if b == 0x51:  # helper frame glue: push cx
        ops.append((p, "push_cx"))
        p += 1
        return p
    if b == 0x06 and exe[p + 1] != 0x56:  # standalone push es frame glue
        ops.append((p, "push_es"))
        p += 1
        return p
    if b == 0x1C:  # standalone push ss helper glue
        ops.append((p, "push_ss"))
        p += 1
        return p
    if b == 0x1E and not (
        exe[p + 1] == 0xB8 and exe[p + 4] == 0x50
    ):  # push ds (standalone frame glue)
        ops.append((p, "push_ds"))
        p += 1
        return p
    if b == 0x5D:  # pop bp
        ops.append((p, "pop_bp"))
        p += 1
        return p
    if b == 0x8B and exe[p + 1] == 0xEC:  # mov bp,sp
        ops.append((p, "mov_bp_sp"))
        p += 2
        return p
    if b == 0x89 and exe[p + 1] == 0xE5:  # mov bp,sp (alternate encoding)
        ops.append((p, "mov_bp_sp"))
        p += 2
        return p
    if b == 0x9A:  # far call (proc entry; seg loader-relocated)
        off, seg = struct.unpack_from("<HH", exe, p + 1)
        ops.append(
            (p, "far_call", off + seg * 16 + start)
        )  # rebase segment-relative off to file offset. The segment word is 0
        # for every single-segment program (the whole corpus), so folding it in
        # is a no-op there; under $SEGMENT the callee lives in a later segment
        # and its offset restarts, so it is the only way to reach the right
        # byte (probe t1_segment; wild tbd73.exe).
        p += 5
        return p
    if b == 0xC4 and exe[p + 1] == 0x76:  # les si,[bp+off8]: by-ref param access
        ops.append((p, "arg_ref", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3
        return p
    if b == 0xC4 and exe[p + 1] == 0xB6:  # les si,[bp+off16]: same, wide disp
        ops.append((p, "arg_ref", struct.unpack_from("<h", exe, p + 2)[0]))
        p += 4  # (string DEF FN param temp free -- t1_fnstr)
        return p
    if (
        b == 0x1E and exe[p + 1] == 0xB8 and exe[p + 4] == 0x50
    ):  # push ds; mov ax,off; push ax
        ops.append((p, "arg_push_ref", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 5
        return p
    if (
        b == 0x16
        and exe[p + 1] == 0xB8
        and exe[p + 4] == 0x03
        and exe[p + 5] == 0xC5
        and exe[p + 6] in (0x50, 0xCE)
        and (exe[p + 6] == 0x50 or exe[p + 7] == 0x50)
    ):  # push ss; mov ax,off; add ax,bp; push ax: the LOCAL-frame sibling of
        # arg_push_ref -- forwards a LOCAL var's address as a by-ref CALL arg.
        # With Overflow checking enabled, `INTO` sits between ADD and PUSH
        # (wild CVT2TB.EXE); it has no source spelling and is handled here
        # rather than leaving a fake instruction boundary in the call setup.
        ops.append((p, "arg_push_ref_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 8 if exe[p + 6] == 0xCE else 7
        return p
    if (
        b == 0x8C
        and exe[p + 1] == 0xD0
        and exe[p + 2 : p + 4] == b"\x8e\xd8"
        and exe[p + 4 : p + 6] == b"\x8b\xf5"
        and exe[p + 6] == 0x83
        and exe[p + 7] == 0xC6
        and exe[p + 9] == 0xCD
        and exe[p + 10] in (0xD4, 0xCE)  # 1.1 vector / TB 1.0's shifted one
    ):  # mov ax,ss; mov ds,ax; mov si,bp; add si,d8; INT D4 -- forward a
        # whole-array PARAMETER as a whole-array CALL argument. The plain
        # `movsi <disp>; INT D4` form pushes a DGROUP array descriptor; a
        # received array param's descriptor lives in the caller's frame
        # instead, so DS has to point at the stack segment for the push (and
        # is restored right after by the `mov dx,imm; mov ds,dx` pair, which
        # already scans). Witnessed probe t1_arrfwd; wild tbd73.exe, whose
        # TBW73.INC relays `item$(1)` on through Makehmenu.
        ops.append((p, "arg_push_array_bp", exe[p + 8]))
        p += 11
        return p
    if (
        b == 0x8B
        and exe[p + 1] == 0xF5
        and exe[p + 2] == 0x83
        and exe[p + 3] == 0xC6
    ):  # mov si,bp; add si,d8; [into;] push ss; pop es: ES:SI = &LOCAL[d8]
        # -- the LOCAL-frame sibling of movsi's DGROUP-disp form, feeding
        # dim_begin/dim_end for a heap-allocated LOCAL DYNAMIC array
        # declared via `LOCAL A()` (probe q_localarr). An Overflow-toggle
        # INTO can land right after the `add si,d8` arithmetic, same as
        # elsewhere in this arithmetic-adjacent family (wild cleanup.exe).
        q = p + 5
        if exe[q] == 0xCE:
            q += 1
        if exe[q] == 0x16 and exe[q + 1] == 0x07:
            ops.append((p, "far_ref_bp", exe[p + 4]))
            p = q + 2
            return p
    if (
        b == 0x8B
        and exe[p + 1] == 0xF5
        and exe[p + 2] == 0x81
        and exe[p + 3] == 0xC6
    ):  # mov si,bp; add si,d16; [into;] push ss; pop es: the same LOCAL
        q = p + 6  # dynamic-array descriptor when its offset exceeds 127
        if exe[q] == 0xCE:
            q += 1
        if exe[q] == 0x16 and exe[q + 1] == 0x07:
            ops.append((p, "far_ref_bp", struct.unpack_from("<H", exe, p + 4)[0]))
            p = q + 2  # (wild cleanup.exe/reformat.exe)
            return p
    # Literal-arg staging glue (positions SI at a stack temp, saves/restores SP).
    if b == 0x89 and exe[p + 1] == 0x26:  # mov [disp],sp (save cleanup SP)
        ops.append((p, "mov_mem_sp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0xE6:  # mov si,sp
        ops.append((p, "mov_si_sp"))
        p += 2
        return p
    if b == 0x89 and exe[p + 1] == 0xF2:  # mov dx,si: preserve a LOCAL-array
        ops.append((p, "movrr", "dx", "si"))
        p += 2  # index across string-param staging (cleanup/reformat)
        return p
    if b == 0x89 and exe[p + 1] == 0xD6:  # mov si,dx: restore that index
        ops.append((p, "movrr", "si", "dx"))
        p += 2  # (cleanup/reformat)
        return p
    if b == 0x01 and exe[p + 1] == 0xE6:  # add si,sp
        ops.append((p, "add_si_sp"))
        p += 2
        return p
    if b == 0x83 and exe[p + 1] == 0xEC:  # sub sp,imm8 (allocate temps)
        ops.append((p, "sub_sp", exe[p + 2]))
        p += 3
        return p
    if b == 0x81 and exe[p + 1] == 0xEC:  # sub sp,imm16: the same call-temp
        ops.append((p, "sub_sp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # allocation when its size exceeds 127 (wild cleanup/reformat)
        return p
    if b == 0x83 and exe[p + 1] == 0xC4:  # add sp,imm8 (free temps)
        ops.append((p, "add_sp", exe[p + 2]))
        p += 3
        return p
    if (
        b == 0xFF
        and exe[p + 1] == 0x76
        and exe[p + 3] == 0xFF
        and exe[p + 4] == 0x76
        and exe[p + 2] == exe[p + 5] + 2
    ):  # push word [bp+d+2]; push word [bp+d]: forward the enclosing SUB's
        # by-ref param (a far seg:off pair in its frame) as a CALL argument
        ops.append((p, "arg_push_fwd", struct.unpack_from("<b", exe, p + 5)[0]))
        p += 6  # (witnessed q_fwd)
        return p
    if b == 0x16 and exe[p + 1] == 0x56:  # push ss; push si (push far temp ptr arg)
        ops.append((p, "arg_push_temp"))
        p += 2
        return p
    if (
        b == 0x06 and exe[p + 1] == 0x56
    ):  # push es; push si (push far array-elem ptr arg)
        ops.append((p, "arg_push_arr"))
        p += 2
        return p
    if b == 0x8B and exe[p + 1] == 0xDC:  # mov bx,sp (string-temp cleanup glue)
        ops.append((p, "mov_bx_sp"))
        p += 2
        return p
    if b == 0x36 and exe[p + 1] == 0xC4 and exe[p + 2] == 0x77:  # les si,[ss:bx]
        ops.append((p, "les_si_ss_bx"))
        p += 4
        return p
    if b == 0xB8:  # mov ax, imm16 (materialization)
        ops.append((p, "movax", struct.unpack_from("<H", exe, p + 1)[0]))
        p += 3
        return p
    if b == 0x40:  # inc ax (materialization)
        ops.append((p, "incax"))
        p += 1
        return p
    if b == 0xCE:  # into: Overflow-toggle check after arithmetic ('O' IDE
        ops.append((p, "into"))  # Options toggle; no operand, no source
        p += 1  # spelling (witnessed q_ovf)
        return p
    if (
        b == 0x81
        and exe[p + 1] == 0xFC  # cmp sp, imm16: Stack-test ('S') room check at
        and exe[p + 4 : p + 11] == b"\x73\x06\xb8\x07\x00\xcd\xec"  # CALL site:
        and dia.canon_sub(exe[p + 11], 0x28) == 0x3C  # jae skip / mov ax,7 /
    ):  # int EC 3C (raise error 7). Threshold varies with the callee frame;
        # semantic-free, recompiling with S regenerates it (witnessed q_stsub).
        ops.append((p, "stack_chk", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 12
        return p
    if b == 0x09 and exe[p + 1] == 0xC0:  # or ax, ax (materialization)
        ops.append((p, "orax"))
        p += 2
        return p
    if b == 0x23 and exe[p + 1] == 0xC3:  # and ax, bx (compound IF)
        ops.append((p, "andaxbx"))
        p += 2
        return p
    if b == 0xA1:  # mov ax, [imm16] (IDX% readback)
        ops.append((p, "movaxmem", struct.unpack_from("<H", exe, p + 1)[0]))
        p += 3
        return p
    if b == 0x89 and exe[p + 1] == 0xC6:  # mov si, ax (IDX% idiom)
        ops.append((p, "movsiax"))
        p += 2
        return p
    if b == 0x89 and exe[p + 1] == 0xC3:  # mov bx, ax (LOCATE row)
        ops.append((p, "movbxax"))
        p += 2
        return p
    if b == 0x8B and exe[p + 1] == 0xD8:  # mov bx, ax: opposite-direction encoding
        ops.append((p, "movbxax"))  # of the same instruction (SWAP of two array
        p += 2  # elements; probe q_arrswap)
        return p
    if b == 0xBA:  # mov dx, imm16 (relocated segment)
        ops.append((p, "movdx", struct.unpack_from("<H", exe, p + 1)[0]))
        p += 3
        return p
    if b == 0x8C and exe[p + 1] == 0xD8:  # mov ax, ds (VARSEG of a DGROUP var)
        ops.append((p, "movaxds"))
        p += 2
        return p
    if b == 0x8E and exe[p + 1] == 0xC2:  # mov es, dx (DIM bracket)
        ops.append((p, "movesdx"))
        p += 2
        return p
    if b == 0x8E and exe[p + 1] == 0xDA:  # mov ds, dx (reverse array SWAP restore)
        ops.append((p, "movdsdx"))
        p += 2
        return p
    if b == 0x8E and exe[p + 1] == 0x06:  # mov es, [disp16] (far array seg)
        ops.append((p, "moves_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x8E and exe[p + 1] == 0x46:  # mov es, [bp+d8]: the LOCAL-frame
        # sibling of moves_m -- loads a LOCAL DYNAMIC array's heap segment
        # from its handle cell (probe q_localarr)
        ops.append((p, "moves_bp", exe[p + 2]))
        p += 3
        return p
    if b == 0x8E and exe[p + 1] == 0x86:  # mov es,[bp+disp16]: the same
        ops.append((p, "moves_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # LOCAL DYNAMIC array beyond disp8 range (cleanup/reformat)
        return p
    if b == 0x8E and exe[p + 1] == 0x1E:  # mov ds, [disp16] (reverse array SWAP)
        ops.append((p, "movds_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x8C and exe[p + 1] == 0x06:  # mov [disp16], es (VARPTR$ pointer temp)
        ops.append((p, "movm_es", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0x36:  # mov [disp16], si (VARPTR$ pointer temp)
        ops.append((p, "movm_si", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x2B and exe[p + 1] == 0x06:  # sub ax, [disp16] (far IDX)
        ops.append((p, "subax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x03 and exe[p + 1] == 0xF0:  # add si, ax (far IDX)
        ops.append((p, "addsiax"))
        p += 2
        return p
    return None


def _scan_direct2_arithmetic(exe, p, b, ops) -> int | None:
    if b == 0x31 and exe[p + 1] == 0xC0:
        ops.append((p, "xorax"))
        return p + 2
    if b == 0x31 and exe[p + 1] == 0xF6:
        ops.append((p, "bchk0"))
        return p + 2
    if b == 0xD1 and exe[p + 1] == 0xE6:
        ops.append((p, "shlsi"))
        return p + 2
    if b == 0x81 and exe[p + 1] == 0xC6:
        ops.append((p, "addsi", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0xBE:
        ops.append((p, "movsi", struct.unpack_from("<H", exe, p + 1)[0]))
        return p + 3
    if b == 0x8B and exe[p + 1] == 0x06:
        ops.append((p, "movax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x03 and exe[p + 1] == 0x06:
        ops.append((p, "addax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x26 and exe[p + 1] == 0x03 and exe[p + 2] == 0x06:
        ops.append((p, "addax_m", struct.unpack_from("<H", exe, p + 3)[0]))
        return p + 5
    if b == 0x26 and exe[p + 1] == 0x8B and exe[p + 2] == 0x06:
        ops.append((p, "movax_m", struct.unpack_from("<H", exe, p + 3)[0]))
        return p + 5
    if b == 0x03 and exe[p + 1] == 0x86:
        ops.append((p, "addax_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0xF7 and exe[p + 1] == 0xD8:
        ops.append((p, "negax"))
        return p + 2
    if b == 0xF7 and exe[p + 1] == 0x2E:
        ops.append((p, "imul_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0xF7 and exe[p + 1] == 0x6E:
        ops.append((p, "imul_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    return None


def _scan_direct2_for_ops(exe, p, b, ops) -> int | None:
    if b == 0xFF and exe[p + 1] == 0x06:
        ops.append((p, "inc_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0xFF and exe[p + 1] == 0x46:
        ops.append((p, "inc_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0xFF and exe[p + 1] == 0x4E:
        ops.append((p, "dec_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0x83 and exe[p + 1] == 0x7E:
        bp_off, i8 = struct.unpack_from("<bb", exe, p + 2)
        ops.append((p, "cmp_bpi8", bp_off, i8))
        return p + 4
    if b == 0xFF and exe[p + 1] == 0x0E:
        ops.append((p, "dec_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x83 and exe[p + 1] == 0x3E:
        d16, i8 = struct.unpack_from("<Hb", exe, p + 2)
        ops.append((p, "cmp_mi8", d16, i8))
        return p + 5
    if b == 0x81 and exe[p + 1] == 0x3E:
        d16, i16 = struct.unpack_from("<Hh", exe, p + 2)
        ops.append((p, "cmp_mi16", d16, i16))
        return p + 6
    if b == 0x83 and exe[p + 1] == 0x06:
        d16, i8 = struct.unpack_from("<Hb", exe, p + 2)
        ops.append((p, "addm_i8", d16, i8))
        return p + 5
    return None


def _scan_direct2_integer_memory(exe, p, b, ops) -> int | None:
    if b == 0xC7 and exe[p + 1] == 0x06:
        d16, v16 = struct.unpack_from("<Hh", exe, p + 2)
        ops.append((p, "movm_imm", d16, v16))
        return p + 6
    if b == 0xC7 and exe[p + 1] == 0x46:
        bp_off, v16 = struct.unpack_from("<bh", exe, p + 2)
        ops.append((p, "mov_bp_imm", bp_off, v16))
        return p + 5
    if b == 0xC7 and exe[p + 1] == 0x86:
        bp_off, v16 = struct.unpack_from("<Hh", exe, p + 2)
        ops.append((p, "mov_bp_imm", bp_off, v16))
        return p + 6
    if b == 0x89 and exe[p + 1] == 0x06:
        ops.append((p, "movm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x89 and exe[p + 1] == 0x3E:
        ops.append((p, "spill_store", "di", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x8B and exe[p + 1] == 0x0E:
        ops.append((p, "spill_load", "cx", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x8B and exe[p + 1] == 0x3E:
        ops.append((p, "spill_load", "di", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x89 and exe[p + 1] == 0x04:
        ops.append((p, "movm_ax_si"))
        return p + 2
    if b == 0x36 and exe[p + 1 : p + 3] == b"\x89\x04":
        ops.append((p, "movm_ax_temp"))
        return p + 3
    if b == 0x36 and exe[p + 1 : p + 3] == b"\xc7\x04":
        ops.append((p, "movm_imm_temp", struct.unpack_from("<H", exe, p + 3)[0]))
        return p + 5
    if b == 0x01 and exe[p + 1] == 0x06:
        ops.append((p, "addm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x29 and exe[p + 1] == 0x06:
        ops.append((p, "subm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x89 and exe[p + 1] == 0x46:
        ops.append((p, "movm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0x89 and exe[p + 1] == 0x86:
        ops.append((p, "movm_ax_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x01 and exe[p + 1] == 0x46:
        ops.append((p, "addm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0x29 and exe[p + 1] == 0x46:
        ops.append((p, "subm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0xA3:
        ops.append((p, "movmem_ax", struct.unpack_from("<H", exe, p + 1)[0]))
        return p + 3
    if b == 0x8B and exe[p + 1] == 0x36:
        ops.append((p, "movsim", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x8B and exe[p + 1] == 0x76:
        ops.append((p, "movsi_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    return _scan_direct2_for_ops(exe, p, b, ops)


def _scan_direct2_register_ops(exe, p, b, ops) -> int | None:
    if b == 0x99:
        ops.append((p, "cwd"))
        return p + 1
    if b == 0xF7 and exe[p + 1] == 0xFB:
        ops.append((p, "idivbx"))
        return p + 2
    if b == 0xF7 and exe[p + 1] == 0x3E:
        ops.append((p, "idiv_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0xF7 and exe[p + 1] == 0xEB:
        ops.append((p, "imulbx"))
        return p + 2
    if b == 0xF7 and exe[p + 1] == 0xD0:
        ops.append((p, "notax"))
        return p + 2
    if b == 0xF7 and exe[p + 1] == 0xD2:
        ops.append((p, "notdx"))
        return p + 2
    if b == 0x8B and exe[p + 1] == 0xC2:
        ops.append((p, "movaxdx"))
        return p + 2
    if b == 0x8B and exe[p + 1] == 0x16:
        ops.append((p, "movdx_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x0B and exe[p + 1] == 0xC3:
        ops.append((p, "oraxbx"))
        return p + 2
    if b == 0x0B and exe[p + 1] == 0xC2:
        ops.append((p, "oraxdx"))
        return p + 2
    if b == 0x33 and exe[p + 1] == 0xC3:
        ops.append((p, "xoraxbx"))
        return p + 2
    if b == 0x03 and exe[p + 1] == 0xC3:
        ops.append((p, "addaxbx"))
        return p + 2
    if b == 0x2B and exe[p + 1] == 0xC3:
        ops.append((p, "subaxbx"))
        return p + 2
    if b == 0x23 and exe[p + 1] == 0x06:
        ops.append((p, "andax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x0B and exe[p + 1] == 0x06:
        ops.append((p, "orax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x33 and exe[p + 1] == 0x06:
        ops.append((p, "xorax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x3B and exe[p + 1] == 0x06:
        ops.append((p, "cmpax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x0B and exe[p + 1] == 0xC0:
        ops.append((p, "orax_self"))
        return p + 2
    return None


def _scan_direct2_io_ops(exe, p, b, ops) -> int | None:
    if b == 0x8B and exe[p + 1] == 0xD3:
        ops.append((p, "movdxbx"))
        return p + 2
    if b == 0x8B and exe[p + 1] == 0xD0:
        ops.append((p, "movdxax"))
        return p + 2
    if b == 0xEE:
        ops.append((p, "out"))
        return p + 1
    if b == 0xEC and exe[p + 1 : p + 5] == b"\x20\xd8\x74\xfb":
        ops.append((p, "wait_poll"))
        return p + 5
    if b == 0xEC and exe[p + 1 : p + 7] == b"\x30\xd8\x20\xc8\x74\xf9":
        ops.append((p, "wait_poll3"))
        return p + 7
    if b == 0xEC:
        ops.append((p, "in_al"))
        return p + 1
    if b == 0x30 and exe[p + 1] == 0xE4:
        ops.append((p, "xorah"))
        return p + 2
    return None


def _scan_direct2_local_ops(exe, p, b, ops) -> int | None:
    if b == 0x03 and exe[p + 1] == 0x46:
        ops.append((p, "addax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0x2B and exe[p + 1] == 0x46:
        ops.append((p, "subax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0x23 and exe[p + 1] == 0x46:
        ops.append((p, "andax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0x3B and exe[p + 1] == 0x46:
        ops.append((p, "cmpax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    if b == 0x3B and exe[p + 1] == 0x86:
        ops.append((p, "cmpax_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x3B and exe[p + 1] == 0xC3:
        ops.append((p, "cmpax_bx"))
        return p + 2
    if b == 0x39 and exe[p + 1] == 0x06:
        ops.append((p, "cmpm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        return p + 4
    if b == 0x39 and exe[p + 1] == 0x46:
        ops.append((p, "cmpm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        return p + 3
    return None


def _scan_direct2(exe, p, b, ops) -> int | None:
    """Byte-dispatch family split out of _scan. Returns the new
    cursor when it decodes the op at ``p``, else None."""
    if (
        b == 0x31
        and exe[p + 1] == 0xD2
        and exe[p + 2 : p + 4] == b"\x31\xf6"
        and exe[p + 4 : p + 6] == b"\x87\x16"
        and exe[p + 8 : p + 10] == b"\x87\x36"
        and exe[p + 12 : p + 14] in (b"\xcd\xd2", b"\xcd\xcc")
    ):  # string SELECT CASE selector-temp free; CC is a runtime-revision alias
        ops.append((p, "str_free_temp"))
        p += 14
        return p
    np = _scan_direct2_arithmetic(exe, p, b, ops)
    if np is not None:
        return np
    np = _scan_direct2_integer_memory(exe, p, b, ops)
    if np is not None:
        return np
    np = _scan_direct2_register_ops(exe, p, b, ops)
    if np is not None:
        return np
    np = _scan_direct2_io_ops(exe, p, b, ops)
    if np is not None:
        return np
    np = _scan_direct2_local_ops(exe, p, b, ops)
    if np is not None:
        return np
    # There is deliberately NO `mov al,imm8; out imm8,al` op here. It used to
    # be read as a byte-constant OUT that the compiler had folded, which is not
    # a thing Turbo Basic does: `OUT 67, 116` emits the general mov-AX / mov-DX
    # / OUT-DX form at top level and inside a SUB alike (probes
    # probe_out_const_toplevel / probe_out_const_in_sub), and the mapping never
    # had a compiled fixture. Those bytes are $INLINE machine code -- see
    # `_try_inline_rescue`, which now claims them -- and decoding them as an
    # OUT statement cost wild zip.exe 592 bytes and ziptest.exe 224 on the
    # round trip. Ledger RO-OUT-IMM-FOLD.
    if b == 0x8C and exe[p + 1] == 0x1E and exe[p + 2 : p + 4] == b"\x1c\x00":
        ops.append((p, "defseg"))  # mov [001C],ds: bare DEF SEG
        p += 4
        return p
    if b == 0x8C and exe[p + 1] == 0x1E:  # mov [disp16], ds: DS spill ahead of a
        ops.append((p, "movm_ds", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # near->far ES alias (SWAP of two array elements; probe q_arrswap)
        return p
    if b == 0x26 and exe[p + 1] == 0x3B and exe[p + 2] == 0x04:  # cmp ax, es:[si]:
        ops.append((p, "far_cmpax_si"))  # relational against a by-ref param
        p += 3  # (witnessed t1_cmpfar)
        return p
    if b == 0x26 and exe[p + 1] == 0x89 and exe[p + 2] == 0x06:
        # mov es:[disp16], ax: direct element store in a runtime array whose
        # segment is loaded from the allocator's current-array cell.  The
        # constant-bound `$DYNAMIC` form uses this topology (t1_dynconstnum);
        # it is deliberately separate from the indexed ES:[SI] family.
        ops.append((p, "far_movm_ax_disp", struct.unpack_from("<H", exe, p + 3)[0]))
        p += 5
        return p
    if b == 0x3B and exe[p + 1] == 0x04:  # cmp ax, [si]: relational against a
        ops.append((p, "cmpax_si"))  # computed static int-array element
        p += 2  # (wild number.exe)
        return p
    if b == 0x26 and exe[p + 1] == 0x03 and exe[p + 2] == 0x04:  # add ax, es:[si]:
        ops.append((p, "far_addax_si"))  # arithmetic fold of a by-ref int
        p += 3  # param, e.g. `N% + 1` (witnessed t1_local2)
        return p
    if b == 0x26 and exe[p + 1] == 0x2B and exe[p + 2] == 0x04:  # sub ax, es:[si]:
        ops.append((p, "far_subax_si"))  # subtractive fold of a by-ref int
        p += 3  # param, mem on the right like subax_m (wild bmaster.exe/ifi.exe)
        return p
    if b == 0x03 and exe[p + 1] == 0x04:  # add ax, [si]: arithmetic fold of a
        ops.append((p, "addax_si"))  # computed static int-array element
        p += 2  # e.g. `ARRAY%(i) + 1` (wild number.exe)
        return p
    if b == 0x2B and exe[p + 1] == 0x04:  # sub ax, [si]: subtractive fold of
        ops.append((p, "subax_si"))  # a computed static int-array element,
        p += 2  # mem on the right like subax_m (wild hebrew.exe)
        return p
    if b == 0x26 and exe[p + 1] == 0xF7 and exe[p + 2] == 0x2C:  # imul word es:[si]:
        ops.append((p, "far_imulax_si"))  # multiplicative fold of a by-ref
        p += 3  # int param, e.g. `A% * B%` (witnessed q_byref_imul)
        return p
    if b == 0xF7 and exe[p + 1] == 0x2C:  # imul word [si]: multiplicative fold
        ops.append((p, "imul_si"))  # of a computed static int-array element
        p += 2  # e.g. `ARRAY1%(k) * ARRAY2%(i,j)` (wild grdscn.exe, q_imulsi2)
        return p
    if b == 0x26 and exe[p + 1] == 0x8B and exe[p + 2] == 0x04:  # mov ax, es:[si]:
        ops.append((p, "far_movax_si"))  # plain read of a by-ref int param
        p += 3  # into ax, e.g. as an expression's first term (t1_byref1)
        return p
    if b == 0x26 and exe[p + 1] == 0x8B and exe[p + 2] == 0x34:
        ops.append((p, "far_movsi_si"))
        p += 3
        return p
    if b == 0x8B and exe[p + 1] == 0x04:  # mov ax, [si]: the read half of a
        ops.append((p, "movax_si"))  # computed static int-array element
        p += 2  # index chain (shl si/addsi), sibling of movm_ax_si's write
        return p  # (wild number.exe)
    if b == 0x26 and exe[p + 1] == 0x23 and exe[p + 2] == 0x04:  # and ax, es:[si]
        ops.append((p, "far_andax_si"))  # bitwise fold of a by-ref int param
        p += 3  # (t1_byref1)
        return p
    if b == 0x26 and exe[p + 1] == 0x0B and exe[p + 2] == 0x04:  # or ax, es:[si]
        ops.append((p, "far_orax_si"))  # bitwise OR fold of a by-ref int
        p += 3  # param, the OR sibling of far_andax_si (wild pwinst.exe)
        return p
    if b == 0x26 and exe[p + 1] == 0x01 and exe[p + 2] == 0x04:  # add es:[si], ax:
        ops.append((p, "far_addm_ax_si"))  # compound-store add into a by-ref
        p += 3  # int param, e.g. `A% = A% + 1` in the callee (witnessed q_fwd)
        return p
    if b == 0x26 and exe[p + 1] == 0x29 and exe[p + 2] == 0x04:  # sub es:[si], ax:
        ops.append((p, "far_subm_ax_si"))  # compound-store subtract into a
        p += 3  # by-ref int param, e.g. `A% = A% - <expr>` (wild bmaster.exe)
        return p
    if b == 0x26 and exe[p + 1] == 0x89 and exe[p + 2] == 0x04:  # mov es:[si], ax:
        ops.append((p, "far_movm_ax_si"))  # write ax into a by-ref int param
        p += 3  # (t1_byref1)
        return p
    if (
        b == 0x26 and exe[p + 1] == 0xC7 and exe[p + 2] == 0x04
    ):  # mov word es:[si], imm16: write a constant into a by-ref int param
        ops.append((p, "far_movm_imm_si", struct.unpack_from("<h", exe, p + 3)[0]))
        p += 5  # (t1_byref1)
        return p
    if b == 0x26 and exe[p + 1] == 0xFF and exe[p + 2] == 0x04:  # inc word es:[si]:
        ops.append((p, "far_inc_si"))  # FOR-NEXT increment of a by-ref int
        p += 3  # param used directly as the loop var (wild bmaster.exe/ifi.exe)
        return p
    if b == 0x26 and exe[p + 1] == 0xFF and exe[p + 2] == 0x0C:  # dec word es:[si]:
        ops.append((p, "far_dec_si"))  # descending sibling of far_inc_si, the
        p += 3  # STEP -1 FOR-NEXT decrement of a by-ref int loop var
        return p  # (wild bmaster.exe/ifi.exe)
    if b == 0x26 and exe[p + 1] == 0x39 and exe[p + 2] == 0x04:  # cmp es:[si], ax:
        ops.append((p, "far_cmpm_ax_si"))  # the far mem-first sibling of
        p += 3  # cmpm_ax/cmpm_ax_bp -- a by-ref int param's own FOR test with
        return p  # a VARIABLE limit (wild bmaster.exe/ifi.exe)
    if b == 0x8B and exe[p + 1] == 0x46:  # mov ax, [bp+disp8]: LOCAL int read
        ops.append((p, "movax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # (t1_byref1)
        return p
    if b == 0x8B and exe[p + 1] == 0x86:  # mov ax,[bp+disp16]: large LOCAL
        ops.append((p, "movax_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # read (wild cleanup/reformat)
        return p
    if b == 0x26 and exe[p + 1] == 0x8B and exe[p + 2] == 0x07:  # mov ax, es:[bx]:
        ops.append((p, "far_movax_bx"))  # SWAP-of-array-elements tail: read the
        p += 3  # first elem via a near-array's ES-aliased address (q_arrswap)
        return p
    if b == 0x8B and exe[p + 1] == 0x07:  # mov ax, [bx]: reverse SWAP tail
        ops.append((p, "movax_bx"))
        p += 2
        return p
    if b == 0x87 and exe[p + 1] == 0x04:  # xchg ax, [si]: SWAP-of-array-elements
        ops.append((p, "xchgsi"))  # tail, swap ax with the second (near) elem
        p += 2  # (q_arrswap)
        return p
    if b == 0x26 and exe[p + 1] == 0x87 and exe[p + 2] == 0x04:
        ops.append((p, "far_xchgsi"))
        p += 3
        return p
    if b == 0x89 and exe[p + 1] == 0x07:  # mov [bx], ax: reverse SWAP tail
        ops.append((p, "movm_ax_bx"))
        p += 2
        return p
    if b == 0x8B and exe[p + 1] == 0x47 and exe[p + 2] == 2:
        ops.append((p, "movax_bx2"))
        p += 3
        return p
    if b == 0x26 and exe[p + 1] == 0x87 and exe[p + 2] == 0x44 and exe[p + 3] == 2:
        ops.append((p, "far_xchgsi2"))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0x47 and exe[p + 2] == 2:
        ops.append((p, "movm_ax_bx2"))
        p += 3
        return p
    if b == 0x8B and exe[p + 1] == 0x47 and exe[p + 2] == 4:
        ops.append((p, "movax_bx4"))
        p += 3
        return p
    if b == 0x26 and exe[p + 1] == 0x87 and exe[p + 2] == 0x44 and exe[p + 3] == 4:
        ops.append((p, "far_xchgsi4"))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0x47 and exe[p + 2] == 4:
        ops.append((p, "movm_ax_bx4"))
        p += 3
        return p
    if b == 0x8B and exe[p + 1] == 0x47 and exe[p + 2] == 6:
        ops.append((p, "movax_bx6"))
        p += 3
        return p
    if b == 0x26 and exe[p + 1] == 0x87 and exe[p + 2] == 0x44 and exe[p + 3] == 6:
        ops.append((p, "far_xchgsi6"))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0x47 and exe[p + 2] == 6:
        ops.append((p, "movm_ax_bx6"))
        p += 3
        return p
    if b == 0x26 and exe[p + 1] == 0x89 and exe[p + 2] == 0x07:  # mov es:[bx], ax:
        ops.append((p, "far_movm_ax_bx"))  # SWAP-of-array-elements tail, store
        p += 3  # the swapped value back into the first (ES-aliased) elem
        return p  # (q_arrswap)
    if (
        b == 0x26 and exe[p + 1] == 0x8B and exe[p + 2] == 0x47 and exe[p + 3] == 2
    ):  # mov ax, es:[bx+2]: SWAP-of-array-elements tail, high word of a
        ops.append((p, "far_movax_bx2"))  # 4-byte (SINGLE) element -- second
        p += 4  # word-swap round after the low-word one (wild number.exe)
        return p
    if b == 0x87 and exe[p + 1] == 0x44 and exe[p + 2] == 2:  # xchg ax, [si+2]:
        ops.append((p, "xchgsi2"))  # high-word half of a 4-byte element swap
        p += 3  # (wild number.exe)
        return p
    if (
        b == 0x26 and exe[p + 1] == 0x89 and exe[p + 2] == 0x47 and exe[p + 3] == 2
    ):  # mov es:[bx+2], ax: high-word store, closing a 4-byte element swap
        ops.append((p, "far_movm_ax_bx2"))  # (wild number.exe)
        p += 4
        return p
    return None


def _scan_int(exe, p, commits, dia, ops, start, vec) -> int | None:
    """Byte-dispatch family split out of _scan. Returns the new
    cursor when it decodes the op at ``p``, else None."""
    if vec == 0x8A:  # stack-test GOSUB (toggle 'S', mask 0x08): a checked-call
        # Most builds stamp a signed i32 start-relative target.  Large wild
        # programs can cross the 64-KiB code window, where the same four bytes
        # are offset:segment words instead (the high word is the segment
        # paragraph).  Decode both forms; treating the latter as i32 creates
        # impossible Gosub targets such as 0xe989b00 (wild mcmurphy.exe).
        off = struct.unpack_from("<i", exe, p + 2)[0]
        target = start + off
        # The normal protocol carries a signed start-relative GOSUB target
        # (fst_t1_gosub and the KBOS probe). Multi-toggle builds also contain
        # runtime helper instances whose four payload bytes are not an offset
        # at all; their decoded target lands outside the user image (wild
        # mcmurphy.exe at 0xad21/0x10318). Preserve those helpers as source-less
        # operations instead of manufacturing an impossible GOSUB.
        if start <= target < len(exe):
            ops.append((p, "call", target))
        else:
            ops.append((p, "stack_call_runtime"))
        p += 6
        return p
    if vec == 0x8B:  # stack-test RETURN: `c3` ret becomes a checked-return
        # runtime vector, +1 byte per site (witnessed fst_t1_gosub).
        ops.append((p, "ret"))
        p += 2
        return p
    if vec == 0x91:  # Bounds (toggle 'B'): array-descriptor setup before a
        # checked variable index, `cd 91 <arr DGROUP slot base>`. Semantic-free
        # for decode -- the source subscript is unchanged; recompiling with
        # Bounds regenerates it (F3.4).
        ops.append((p, "bchk_base", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if vec == 0x92:  # Bounds checked span-multiply `cd 92 <arr base + 0x0C>`:
        # the 2-D row-major stride step, range-checking the dimension and
        # multiplying by the span -- the checked form of `imul_m`, shares its
        # lifter (F3.5). Operand is the span field, same as imul_m's.
        ops.append((p, "bchk_span", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if vec == 0x93:  # Bounds checked index `cd 93 <descriptor>`: range-checks
        # ax against the array bounds and loads it into si -- the checked
        # replacement for `mov si,ax`, so it lifts exactly like movsiax (F3.4).
        ops.append((p, "bchk_idx", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if vec == 0x94:  # Bounds descriptor setup for a SUB-local dynamic array:
        ops.append((p, "bchk_base_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # BP-relative sibling of DGROUP vector 91
        return p
    if vec == 0x96:  # checked index + SI transfer for that LOCAL descriptor
        ops.append((p, "bchk_idx_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # operand is descriptor base + 6 (cleanup/crossref/reformat)
        return p
    if vec == 0x97:  # TRON trace hook: CD 97 <lineno u16>,
        ops.append(
            (
                p,
                "trace_hook",  # emitted before every statement in a
                struct.unpack_from("<H", exe, p + 2)[0],
            )
        )  # TRON..TROFF region
        p += 4  # (canonical vec; raw 97 in TB 1.0 is
        return p  # far_spush -- canonicalizes to 9D)
    if vec == 0x99:  # FPU status -> CPU flags helper
        ops.append((p, "fstsw"))
        p += 2
        return p
    if vec == 0x8C and exe[p + 2] in (0xE9, 0xEB, 0xEA):
        # RETURN <line>: the runtime vector unwinds the active GOSUB/event
        # frame, then a near or far jump selects the requested line
        # (t1_returnline; wild baby/crossref/help/prtguide/readme and ifi).
        if exe[p + 2] == 0xE9:
            target = p + 5 + struct.unpack_from("<h", exe, p + 3)[0]
            size = 5
        elif exe[p + 2] == 0xEB:
            target = p + 4 + struct.unpack_from("<b", exe, p + 3)[0]
            size = 4
        else:
            off, seg = struct.unpack_from("<HH", exe, p + 3)
            target = start + seg * 16 + off
            size = 7
        ops.append((p, "return_to", target))
        p += size
        return p
    if vec == 0xCD:  # short-string constructor: builds a 1-char string desc
        ops.append((p, "shortstr"))  # from the packed (char<<8 | len=1) word
        p += 2  # just stored at the fixed scratch cell [002E] -- the
        return p  # compile-time-known mode keyword of `OPEN f$ FOR mode
        # AS #n` (OUTPUT/INPUT/APPEND/RANDOM/BINARY desugar to a 1-char
        # mode string this way; wild nvginst.exe et al., probe q_openfor)
    if vec == 0x3D:  # emulated FWAIT (IDX% idiom)
        ops.append((p, "fwait"))
        p += 2
        return p
    if vec in (
        0x9C,
        0xBE,
        0xB8,
        0xBB,  # PRINT/string-push runtime;
        0xBA,
        0xBD,
        0xC0,
        0xCA,
        0xCB,  # file/USING legs
        0xCC,  # USING string item (witnessed t1_using)
        0xC1,  # PRINT comma zone advance (witnessed t1_pcomma)
        0xC2,  # LPRINT comma zone advance (wild billadd/prtguide/rs)
        0xC3,  # PRINT# comma zone advance (witnessed t1_fileint)
        0xBC,
        0xB9,
        0xBF,  # LPRINT string item (witnessed t1_lpstr)
    ):  # LPRINT item / newline
        ops.append((p, "rt", vec))
        p += 2
        return p
    if vec in _TABSPC_VECS:  # TAB(ax)/SPC(ax) print item
        ops.append((p, "tabspc", vec))
        p += 2
        return p
    if vec == 0x9A:  # string compare (SELECT CASE string arm)
        ops.append((p, "strcmp"))
        p += 2
        return p
    if vec == 0x9B:  # string concat: pops two, pushes one
        ops.append((p, "strconcat"))
        p += 2
        return p
    if vec == 0xA0:  # string pop-assign to [si] desc
        ops.append((p, "strassign"))
        p += 2
        return p
    if vec == 0x9D:  # far string element push ES:[SI]
        ops.append((p, "far_spush"))
        p += 2
        return p
    if vec == 0x9E:  # push string at [bp+si]: DEF FN string param (t1_fnstr)
        ops.append((p, "spush_bp"))
        p += 2
        return p
    if vec == 0x9F:  # push a string FN call's result descriptor (t1_fnstr)
        ops.append((p, "fnres_spush"))
        p += 2
        return p
    if vec == 0xA2:  # pop string store to [bp+si]: FN result (si=0) or a
        ops.append((p, "strassign_bp"))  # staged string call arg (t1_fnstr)
        p += 2
        return p
    if vec == 0xA1:  # far string element assign
        ops.append((p, "far_strassign"))
        p += 2
        return p
    if vec == 0xA3:  # store string desc into a CALL-arg temp
        ops.append((p, "str_store_temp"))
        p += 2
        return p
    if vec == 0xD3:  # free a string CALL-arg temp after the call
        ops.append((p, "str_temp_free"))
        p += 2
        return p
    if vec == 0xD4:  # push a whole-array descriptor as a CALL argument
        ops.append((p, "arg_push_array"))
        p += 2
        return p
    if vec == 0xA4:  # LSET target$ = source$
        ops.append((p, "lset"))
        p += 2
        return p
    if vec == 0xA5:  # RSET target$ = source$
        ops.append((p, "rset"))
        p += 2
        return p
    if vec == 0xAE:  # MID$(target$, start) = source$
        ops.append((p, "midassign"))
        p += 2
        return p
    if vec == 0xAF:  # MID$(target$, start, len) = source$: start in bx and
        # len in ax, the same register convention the MID$ FUNCTION uses for
        # its own three arguments. Both dialects canonicalize to this vector
        # (TB 1.0 spells it raw AD).
        #
        # This was mapped to CVL in `_STR2NUM_VECS`, on the belief that it was
        # TB 1.0's raw A9 shifted -- which the shift arithmetic does not give
        # (A9 + 2 = AB), and TB 1.1 has no reason to reach a 1.0 spelling at
        # all. A compiled `MID$(A$, N%, 1) = " "` emits AF and a compiled
        # `CVL(A$)` emits A9, in 1.1 and 1.0 alike. The false mapping turned
        # every three-argument MID$ assignment into a CVL of its target with
        # the source string left stranded on the string stack (wild
        # cleanup.exe, reformat.exe, crossref.exe).
        ops.append((p, "midassign3"))
        p += 2
        return p
    if vec in _FN_VECS:  # runtime intrinsic: FP top -> result
        ops.append((p, "fn", _FN_VECS[vec]))
        p += 2
        return p
    if vec in _STR2NUM_VECS:  # string-arg numeric-result intrinsic
        ops.append((p, "str2num", _STR2NUM_VECS[vec]))
        p += 2
        return p
    if vec in _STRFN_VECS:  # string-result intrinsic
        ops.append((p, "strfn", _STRFN_VECS[vec]))
        p += 2
        return p
    if vec == 0xEE:  # string-result intrinsic dispatcher
        sub = dia.canon_sub(exe[p + 2])
        if sub not in _EE_STRFN_SUBS:
            raise ValueError(f"unhandled INT EE sub {sub:02x} at {p:#x}")
        ops.append((p, "strfn", _EE_STRFN_SUBS[sub]))
        p += 3
        return p
    if vec == 0xED:  # ax-returning intrinsic dispatcher
        sub = dia.canon_sub(exe[p + 2], 0x3C)  # ED inserts higher than EC (0x3C)
        if sub == 0x3A:  # ^ : FP-stack exponentiation fold
            ops.append((p, "fpow"))
            p += 3
            return p
        if sub == 0x02:  # CEIL: FP-stack unary intrinsic
            ops.append((p, "fn", "CEIL"))
            p += 3
            return p
        if sub == 0x14:  # FIX: FP-stack unary intrinsic
            ops.append((p, "fn", "FIX"))
            p += 3
            return p
        if sub == 0x40:  # RND(x): FP-stack unary intrinsic
            ops.append((p, "fn", "RND"))
            p += 3
            return p
        if sub == 0x18:  # FRE(n): n in ax, FP-stack result
            ops.append((p, "fn_axfp", "FRE"))
            p += 3
            return p
        if sub == 0x26:  # LOF(n): filenum in ax, FP-stack result (a file's
            ops.append((p, "fn_axfp", "LOF"))  # length can exceed 16 bits,
            p += 3  # unlike EOF's boolean; wild nvginst.exe, probe q_lof)
            return p
        if sub == 0x16:  # FRE(s$): string arg, FP result
            ops.append((p, "fre_str"))
            p += 3
            return p
        if sub == 0x32:  # PMAP(x, n): x FP stack, n ax; FP result
            ops.append((p, "pmap"))
            p += 3
            return p
        if sub in (0x4E, 0x20):  # UBOUND / LBOUND: array slot in bx,
            ops.append(
                (
                    p,
                    "fn_bound",  # dim in ax, es = relocated seg
                    "UBOUND" if sub == 0x4E else "LBOUND",
                )
            )
            p += 3
            return p
        if sub in _ED_STR_SUBS:  # LEN / INSTR: string -> ax result
            ops.append((p, "str2num", _ED_STR_SUBS[sub]))
            p += 3
            return p
        if sub == 0x1E:  # INSTR(start, haystack$, needle$): start in ax
            ops.append((p, "instr3"))
            p += 3
            return p
        if sub in _FNAX2_SUBS:  # two-FP-arg ax intrinsic (POINT)
            ops.append((p, "fn_ax2", _FNAX2_SUBS[sub]))
            p += 3
            return p
        if sub in _AXARG_SUBS:  # ax-arg, ax-returning (REG(n))
            ops.append((p, "fn_ax_ax", _AXARG_SUBS[sub]))
            p += 3
            return p
        if sub in _AX0_SUBS:  # zero-arg, ax-returning
            ops.append((p, "fn_ax0", _AX0_SUBS[sub]))
            p += 3
            return p
        if sub in _FP0_SUBS:  # zero-arg, FP-stack-returning
            ops.append((p, "fn_fp0", _FP0_SUBS[sub]))
            p += 3
            return p
        if sub == 0x42:  # SCREEN(row, col): row bx, col ax
            ops.append((p, "fn_screen"))
            p += 3
            return p
        if sub == 0x44:  # SCREEN(row, col, color): row cx, col bx, color ax
            ops.append((p, "fn_screen_color"))
            p += 3
            return p
        if sub not in _FNAX_SUBS:
            raise ValueError(f"unhandled INT ED sub {sub:02x} at {p:#x}")
        ops.append((p, "fn_ax", _FNAX_SUBS[sub]))
        p += 3
        return p
    if vec == 0x87:  # per-statement commit marker
        if commits is not None:  # (one per statement,
            commits.add(p)  # none after END; a comma-list DIM
        p += 2  # is ONE statement). Side-collected:
        return p  # templates assume op adjacency.
    if vec == 0x8F:  # CD 8F: DEF FN body terminator
        ops.append((p, "fn_ret"))
        p += 2
        return p
    if vec in (0x8D, 0x8E):  # value-returning FN call (single/multi-line)
        off, seg = struct.unpack_from(  # CD 8D <sub> <off16> <seg16>
            "<HH", exe, p + 3
        )
        ops.append(
            (p, "fn_call", off + seg * 16 + start)
        )  # seg-relative off rebased like far_call
        p += 7
        return p
    if vec == 0xCF:  # LOCATE row(bx),col(ax)
        ops.append((p, "locate"))
        p += 2
        return p
    if vec == 0xD0:  # LOCATE's cursor arg (ax)
        ops.append((p, "cursor"))
        p += 2
        return p
    if vec == 0xCE:  # LOCATE's cursor start/stop args (bx, ax)
        ops.append((p, "cursor_shape"))
        p += 2
        return p
    if (
        vec == 0x3C and exe[p + 2] == 0x59 and exe[p + 3] == 0x1C
    ):  # FSTP [ss:si]: stage literal arg
        ops.append((p, "fstp_temp"))
        p += 4
        return p
    if vec == 0x3E:  # transcendental dispatcher:
        sel = exe[p + 2]  # CD 3E <selector>, FP-stack unary
        if sel == 0x14:  # ^ : TB 1.0's exponentiation (TB 1.1 uses ED sub
            ops.append((p, "fpow"))  # 3A/fpow instead; same push order,
            p += 3  # same "fpow" op kind -- wild banker.exe/kinetics.exe,
            return p  # probe q_pow
        if sel not in _TRANSCEND:
            raise ValueError(f"unhandled INT 3E selector {sel:02x} at {p:#x}")
        ops.append((p, "fn", _TRANSCEND[sel]))
        p += 3
        return p
    return None


def _has_port_immediate(exe: bytes, start: int, end: int) -> bool:
    """Does [start, end) hold an instruction sequence the compiler cannot emit?

    The caller's `5D`-tail question is undecidable from shape alone: a framed
    procedure and a `$INLINE` list that happens to carry its own bp frame end
    in the same `5D CB`. What can decide it is CONTENT -- a body holding an
    instruction Turbo Basic has no way to generate was written by hand and
    reached the EXE through `$INLINE`, whatever its framing looks like.

    One such sequence is recognized today: `mov al,imm8; out imm8,al`
    (B0 xx E6 xx). Turbo Basic has no statement that compiles to an
    immediate-port OUT -- INP and OUT both route the port through DX and emit
    the register forms EC/EE whatever their operands, and `OUT 67, 116`, with
    both operands in byte range, still emits mov-AX / mov-DX / OUT-DX at top
    level and inside a SUB alike (probes probe_out_const_toplevel /
    probe_out_const_in_sub). Add further sequences here as they are witnessed
    and proved unreachable from source; each must earn its place with a probe
    showing the compiler emitting something else for every spelling that could
    plausibly produce it.

    Match whole instruction SEQUENCES, never a bare opcode-range test: these
    bodies are not disassembled, so any single-byte test reads operand and
    ModRM bytes as opcodes. Searching the E4-E7 port-I/O range was the first
    attempt and it accepted `89 E5` -- the alternate `mov bp,sp` encoding,
    sitting in the prologue of the very framed procedures this guard exists to
    reject.

    Deliberately narrow, and one-way. It only ever rules a body IN; a body it
    does not recognize stays fail-loud, which is what keeps an unexplained
    framed helper (wild CVT2TB.EXE, phone.exe) from being silently reprinted as
    machine code instead of being decoded.

    Witnessed by wild zip.exe and ziptest.exe, whose per-setting procedures are
    `$INLINE` lists that reprogram PIT counter 1 -- command byte 74h to port
    43h, then a 16-bit divisor to port 41h -- carrying their own bp frame, and
    by fixture t1_inlineport.
    """
    return any(
        exe[k] == 0xB0 and exe[k + 2] == 0xE6 for k in range(start, max(start, end - 3))
    )


def _try_inline_rescue(exe: bytes, ops: list[tuple[Any, ...]]) -> int | None:
    """After a scan failure, check whether we're stuck inside opaque code.

    The general case is a `SUB ... INLINE` body: the compiler copies
    $INLINE's byte list verbatim with no
    proc_enter framing at all, then auto-appends a bare far RET (CB) --
    Appendix C of the handbook, confirmed byte-for-byte via the oracle
    (probe q_shriek). The raw bytes are arbitrary and will often partially
    match real opcodes before finally failing outright (q_shriek: `BA 00
    07` legitimately scans as `mov dx,0700h` before `E4`, `IN AL,61h`, has
    no TB equivalent) -- so this only fires once the ordinary scan has
    already given up, keeping every other gap exactly as fail-loud as before.

    Finds the MOST RECENT `jmp` op; if every op scanned since sits before
    that jmp's target and the byte right before the target is a bare 0xCB,
    treats [jmp_end, target-1) as one opaque `inline_sub` blob, truncates
    the bogus partial-match ops back to just after the jmp, and returns the
    resume position (the jmp's target). Returns None (no rescue -- the
    original failure should propagate) otherwise. One fully fingerprinted
    every other proc-enter-shaped body remains a hard failure. Exact framed
    helpers are classified before normal scanning by ``find_opaque_helpers``."""
    for i in range(len(ops) - 1, -1, -1):
        if ops[i][1] != "jmp":
            continue
        target = ops[i][2]
        if not all(o[0] < target for o in ops[i + 1 :]):
            continue
        if exe[target - 1] != 0xCB:
            continue
        body_start = ops[i][0] + 3  # jmp is always `e9 rel16`, 3 bytes
        if exe[body_start] == 0x55 and exe[body_start + 1 : body_start + 3] in (
            b"\x8b\xec",
            b"\x89\xe5",
        ):  # push bp; mov bp,sp (either encoding): a genuine proc-enter
            j = target - 2
            while j > body_start and exe[j] == 0xCC:
                j -= 1  # event-trap poll hooks sit between the pop and the ret
            if (
                exe[j] == 0x5D
                and not (i and ops[i - 1][1] == "inline_sub")
                and not _has_port_immediate(exe, body_start, j)
            ):
                # `pop bp; [hooks;] retf` can be a complete third-party helper
                # rather than a user SUB. Treat the whole body as opaque.
                if False:
                    return None  # retained as documentation of the old guard
                # procedure, not $INLINE -- false positives witnessed in wild
                # CVT2TB.EXE (whose own unrelated gap-19 construct ends in a
                # legitimate 5D CB that also satisfies the bare-CB check above)
                # and, under event trapping where the epilogue is 5D CC CB, in
                # wild phone.exe's seven gap-19-family framed helpers.
                #
                # This tail is genuinely ambiguous and cannot be resolved from
                # the bytes: TB APPENDS the terminating CB, so a $INLINE list
                # ending in a bare `pop bp` (TBWINDOW's Openbox does exactly
                # that, leaning on the appended ret) produces the same 5D CB as
                # a framed epilogue. What does separate them is the chain: an
                # UNAMBIGUOUS inline body immediately before -- one whose own
                # tail is not 5D, so it needed no adjudication -- means the
                # declaration region is provably the user's, and the blobs its
                # skip-jmps bracket are theirs too. TBWINDOW seeds that chain
                # with Getftblptr, whose frame-table data ends C4 CB; phone.exe
                # and CVT2TB.EXE have no such seed, so they stay loud.
            # Anything else ending in the bare CB is an inline body that merely
            # OPENS with the prologue shape. TB appends that CB itself, so a
            # `$INLINE` list ending in its own `retf` gives `CB CB` and one
            # ending in data gives `<data> CB`; neither can be a framed
            # epilogue (`pop bp; retf N` ends with the immediate). Witnessed
            # t1_inlinebp / t1_inlinedata, whose lists are the `push bp; mov
            # bp,sp; les di,[bp+N]; pop bp; retf` shape TBWINDOW's Getftblptr
            # uses, the second with the frame-table data that follows it inside
            # the same SUB (wild tbd73.exe, confirmed against TBW73.INC).
        del ops[i + 1 :]
        ops.append((body_start, "inline_sub", exe[body_start : target - 1]))
        return target
    return None


def _scan_runtime_control(exe, p, sub, ops) -> int | None:
    if sub == 0x32:
        ops.append((p, "end"))
        return p + 3
    if sub == 0xE8:
        ops.append((p, "epilogue"))
        return -1
    if sub == 0x1A:
        ops.append((p, "cls"))
        return p + 3
    if sub == 0x14:
        ops.append((p, "clear"))
        return p + 3
    if sub == 0xA2:
        ops.append((p, "poke"))
        return p + 3
    if sub == 0x26:
        ops.append((p, "defseg_set"))
        return p + 3
    if sub == 0x86:
        ops.append((p, "palette_reset"))
        return p + 3
    if sub == 0x88:
        ops.append((p, "palette"))
        return p + 3
    if sub == 0x8A:
        ops.append((p, "palette_using"))
        return p + 3
    if sub == 0xEA:
        ops.append((p, "view", exe[p + 3]))
        return p + 4
    if sub == 0xF2:
        ops.append((p, "window", exe[p + 3]))
        return p + 4
    if sub == 0xA4:
        ops.append((p, "pset", exe[p + 3]))
        return p + 4
    if sub == 0x62:
        ops.append((p, "line", exe[p + 3]))
        return p + 4
    if sub == 0x12:
        ops.append((p, "circle", exe[p + 3]))
        return p + 4
    if sub == 0x84:
        ops.append((p, "paint", exe[p + 3]))
        return p + 4
    if sub == 0x30:
        ops.append((p, "draw"))
        return p + 3
    if sub == 0x22:
        ops.append((p, "color_commit", exe[p + 3]))
        return p + 4
    return None


def _scan_runtime_io(exe, p, sub, ops) -> int | None:
    if sub == 0x4E:
        d16, f16 = struct.unpack_from("<HH", exe, p + 3)
        ops.append((p, "input", d16, f16))
        return p + 7
    if sub == 0x9A:
        ops.append((p, "read_num"))
        return p + 3
    if sub == 0x9C:
        ops.append((p, "read_str"))
        return p + 3
    if sub == 0xB2:
        ops.append((p, "data_read_num"))
        return p + 3
    if sub == 0xB4:
        ops.append((p, "data_read_str"))
        return p + 3
    if sub == 0x64:
        d16 = struct.unpack_from("<H", exe, p + 3)[0]
        flags = exe[p + 5]
        if flags not in (0x40, 0xC0):
            raise ValueError(f"LINE INPUT trailing byte {flags:02x} at {p:#x}")
        ops.append((p, "line_input", d16, flags == 0xC0))
        return p + 6
    if sub == 0x66:
        ops.append((p, "line_input_file"))
        return p + 3
    if sub == 0x82:
        ops.append((p, "open"))
        return p + 3
    if sub == 0x9E:
        ops.append((p, "read_file_num"))
        return p + 3
    if sub == 0xA0:
        ops.append((p, "read_file_str"))
        return p + 3
    if sub == 0x18:
        ops.append((p, "close"))
        return p + 3
    if sub == 0x16:
        ops.append((p, "close_all"))
        return p + 3
    if sub == 0x2C:
        ops.append((p, "dim_begin"))
        return p + 3
    if sub == 0x2E:
        ops.append((p, "dim_end"))
        return p + 3
    if sub in (0x36, 0x38):
        ops.append((p, "erase" if sub == 0x36 else "erase_static"))
        return p + 3
    if sub == 0x3A:
        ops.append((p, "local_arr_free"))
        return p + 3
    return None


def _scan_runtime_files(p, sub, ops) -> int | None:
    names = {
        0x60: "kill",
        0xB8: "reset",
        0x44: "files",
        0x42: "files_bare",
        0x6E: "name",
        0x0E: "chain",
        0x10: "chdir",
        0x34: "environ",
        0x6A: "mkdir",
        0xC2: "rmdir",
        0xC4: "run_file",
        0xCE: "shell",
    }
    name = names.get(sub)
    if name is None:
        return None
    ops.append((p, name))
    return p + 3


def _scan_runtime_misc(exe, p, start, sub, ops) -> int | None:
    if sub in (0x74, 0x72):
        count = exe[p + 3] | (exe[p + 4] << 8)
        targets = [
            start + int.from_bytes(exe[p + 5 + i * 4 : p + 9 + i * 4], "little")
            for i in range(count)
        ]
        ops.append((p, "on_goto" if sub == 0x74 else "on_gosub", *targets))
        return p + 5 + count * 4
    names = {
        0x98: "play",
        0x00: "beep",
        0xB0: "randomize",
        0x28: "delay_init",
        0x2A: "delay_poll",
        0xD0: "sound",
        0xEC: "width",
        0xEE: "width_dev",
        0xF0: "width_file",
    }
    name = names.get(sub)
    if name is None:
        return None
    ops.append((p, name))
    return p + 3


def _scan_runtime_record_ops(exe, p, sub, ops) -> int | None:
    names = {
        0xF4: "write_item",
        0xF8: "write_sep",
        0xFA: "write_file_num",
        0xFC: "write_file_str",
        0xFE: "write_file_sep",
        0x48: "get",
        0x4C: "get_str",
        0xA8: "put",
        0xCA: "seek",
        0x06: "bload",
        0x04: "bload0",
        0x08: "bsave",
        0x3E: "field",
        0x40: "field_as",
    }
    if sub == 0xDC:
        ops.append((p, "paint_tile", exe[p + 3]))
        return p + 4
    name = names.get(sub)
    if name is None:
        return None
    ops.append((p, name))
    return p + 3


def _scan_runtime_events(exe, p, start, sub, ops) -> int | None:
    names = {0x54: "key_on", 0x58: "key_macro", 0x52: "key_off", 0x56: "key_list"}
    if sub in names:
        ops.append((p, names[sub]))
        return p + 3
    if sub == 0xC6:
        tag = exe[p + 3]
        if tag not in (0x02, 0x03, 0x08, 0x0C, 0x0E, 0x0F):
            raise ValueError(f"SCREEN bad tag at {p:#x}")
        ops.append((p, "screen", tag))
        return p + 4
    if sub == 0x70:
        off = struct.unpack_from("<i", exe, p + 3)[0]
        ops.append((p, "on_error", None if off == -1 else start + off))
        return p + 7
    names = {0x3C: "error_stmt", 0xBC: "resume_pre", 0xBE: "resume_bare", 0xC0: "resume_next"}
    if sub in names:
        ops.append((p, names[sub]))
        return p + 3
    if sub in _TRAP_GOSUB:
        off = struct.unpack_from("<i", exe, p + 3)[0]
        ops.append((p, "on_trap", sub, start + off))
        return p + 7
    if sub in _TRAP_CTL:
        ops.append((p, "trap_ctl", sub))
        return p + 3
    return None


def _scan_runtime_tail(exe, p, sub, ops) -> int | None:
    if sub in (0x4A, 0xAA):
        ops.append((p, "get_gfx" if sub == 0x4A else "put_gfx", exe[p + 3]))
        return p + 4
    names = {
        0x6C: "mtimer",
        0xB6: "reg_set",
        0x0C: "call_int",
        0x0A: "call_abs",
        0x24: "dateset",
        0xE0: "timeset",
        0x50: "ioctl",
        0xAC: "put_str",
    }
    name = names.get(sub)
    if name is None:
        return None
    ops.append((p, name))
    return p + 3


def _scan_esc_stack_ops(p, mo, esc, modrm, ops) -> int | None:
    names = {
        0xE8: "fld1",
        0xEE: "fldz",
        0xE0: "fchs",
        0xE1: "fabs",
        0xFA: "fsqrt",
        0xFC: "frndint",
    }
    if esc == 0xD9 and modrm in names:
        ops.append((p, names[modrm]))
        return mo + 1
    if esc == 0xDE and modrm == 0xD9:
        ops.append((p, "fcompp"))
        return mo + 1
    if esc == 0xDE and modrm in _POP_OPS_N:
        ops.append((p, "popop_n", _POP_OPS_N[modrm]))
        return mo + 1
    if esc == 0xDE and modrm in _POP_OPS:
        ops.append((p, "popop", _POP_OPS[modrm]))
        return mo + 1
    return None


def _scan_esc_si_ops(p, mo, esc, pre, reg, ops) -> int | None:
    kinds = {
        (0xD9, 0): "fld_si",
        (0xD9, 3): "fstp_si",
        (0xD8, 3): "fcomp_si",
        (0xDC, 3): "fcomp_si64",
        (0xDA, 3): "icomp_si32",
        (0xDD, 0): "fld_si64",
        (0xDD, 3): "fstp_si64",
        (0xDB, 0): "fild_si32",
        (0xDB, 3): "fstp_si32",
        (0xDF, 0): "fild_si",
        (0xDE, 1): "imulax_si",
        (0xDE, 3): "icomp_si",
    }
    kind = kinds.get((esc, reg))
    if kind:
        ops.append((p, pre + kind))
        return mo + 1
    folds = (
        (0xD8, _FOLD_OPS, "fold_si"),
        (0xDC, _FOLD_OPS, "fold64_si"),
        (0xDC, _FOLD_OPS_N, "fold_n64_si"),
        (0xD8, _FOLD_OPS_N, "fold_n_si"),
        (0xDE, _FOLD_OPS, "ifold_si"),
        (0xDE, _FOLD_OPS_N, "ifold_n_si"),
    )
    for opcode, table, name in folds:
        if esc == opcode and reg in table:
            ops.append((p, pre + name, table[reg]))
            return mo + 1
    return None


def _scan(
    exe: bytes, start: int, dia: Dialect = TB11, commits: set[int] | None = None
) -> list[tuple[Any, ...]]:
    """Pass 1 entry point: runs `_scan_pass`, rescuing explicitly recognized
    opaque bodies (see `_try_inline_rescue`) and resuming instead of failing."""
    p = start + 3
    ops: list[tuple[Any, ...]] = []
    opaque_helpers = find_opaque_helpers(exe, start, OPAQUE_HELPERS)
    while True:
        try:
            return _scan_pass(exe, start, dia, commits, ops, p, opaque_helpers)
        except ValueError:
            resume = _try_inline_rescue(exe, ops)
            if resume is None:
                raise
            p = resume


def _scan_pass(
    exe: bytes,
    start: int,
    dia: Dialect,
    commits: set[int] | None,
    ops: list[tuple[Any, ...]],
    p: int,
    opaque_helpers: dict[int, tuple[int, bytes, tuple[int, ...]]],
) -> list[tuple[Any, ...]]:
    """The actual linear decode, prologue to END. Each op is (addr, kind,
    *args); no DS knowledge needed. Raises on anything outside the
    calibrated vocabulary. `ops`/`p` are pre-seeded by `_scan` so a rescued
    SUB...INLINE body can resume a failed pass instead of restarting it."""
    while p + 1 < len(exe):
        if helper := opaque_helpers.get(p):
            target, body, param_offsets = helper
            ops.append((p, "opaque_helper", body, param_offsets))
            p = target
            continue
        b = exe[p]
        sw = _try_swap(exe, p)
        if sw is not None:
            ops.append((p, "swap", sw[0], sw[1]))
            p += 24
            continue
        np = _scan_direct(exe, p, b, dia, ops, start)
        if np is not None:
            p = np
            continue

        if b == 0x89 and (exe[p + 1] & 0xC0) == 0xC0:  # mov reg,reg: the far-index
            rm, rg = exe[p + 1] & 7, (exe[p + 1] >> 3) & 7  # spill protocol
            names = {0: "ax", 1: "cx", 3: "bx", 6: "si", 7: "di"}
            if rm in names and rg in names:
                ops.append((p, "movrr", names[rm], names[rg]))
                p += 2
                continue
        np = _scan_direct2(exe, p, b, ops)
        if np is not None:
            p = np
            continue

        if b == 0xEA:  # far JMP ptr16:16; segment-relative code target
            off, seg = struct.unpack_from("<HH", exe, p + 1)
            if off == 0 and seg == 0:
                # Fixed runtime handoff used by the legacy cleanup/event tail.
                ops.append((p, "epilogue"))
                return ops
            if off == 0:
                # $SEGMENT: the metacommand closes the current code segment and
                # continues the program in the next paragraph-aligned one, which
                # the compiler reaches with a far jump to its offset 0. Code, not
                # a handoff -- scanning has to follow it or everything the
                # metacommand moved (TBWINDOW puts every SUB there) is silently
                # dropped (probe t1_segment; wild tbd73.exe).
                ops.append((p, "segjmp", start + seg * 16, seg))
                p = start + seg * 16
                continue
            # Far jumps use the user-code origin plus the segment's paragraph
            # displacement. This is observable directly when a $SEGMENT
            # handoff names the same segment:
            # t1_resumefar's segment 2 begins at start+32, and wild wb.exe's
            # segment 2603 begins at start+2603*16.
            target = start + seg * 16 + off
            ops.append((p, "jmpf", target, seg, off))
            p += 5
            continue

        if b == 0x9B and 0xD8 <= exe[p + 1] <= 0xDF:
            # 8087-required codegen (toggle '8', mask 0x80): FWAIT + the real ESC
            # opcode in place of the emulation INT 34h+n, with identical modrm/
            # displacement bytes and identical length -- a
            # pure vocabulary alias onto the emulated-FP decode below. The far/
            # ES-override form (emulation INT 3C) is unwitnessed under 8087 and
            # still fails loudly.
            vec = 0x34 + (exe[p + 1] - 0xD8)
        elif b != 0xCD:
            raise ValueError(f"unhandled byte {b:02x} at {p:#x}")
        else:
            vec = exe[p + 1]
        if vec == 0xEC:  # runtime statement dispatch
            raw_sub = exe[p + 2]
            # A second TB 1.0 dispatch table (catalog.exe and the cal/night
            # family) places PUT # two slots earlier than the calibrated
            # v10 table.  The surrounding [0060] file-number setup and the
            # following record loop identify this as the existing PUT shape.
            sub = (
                0xA8
                if dia.name == "1.0" and raw_sub == 0xA4
                else dia.canon_sub(raw_sub, 0x28)
            )  # EC inserts at DELAY (v10_t1_delay)
            runtime = _scan_runtime_control(exe, p, sub, ops)
            if runtime is not None:
                if runtime == -1:
                    return ops
                p = runtime
                continue
            runtime = _scan_runtime_io(exe, p, sub, ops)
            if runtime is not None:
                p = runtime
                continue
            runtime = _scan_runtime_record_ops(exe, p, sub, ops)
            if runtime is not None:
                p = runtime
                continue
            runtime = _scan_runtime_events(exe, p, start, sub, ops)
            if runtime is not None:
                p = runtime
                continue
            runtime = _scan_runtime_tail(exe, p, sub, ops)
            if runtime is not None:
                p = runtime
                continue
            runtime = _scan_runtime_files(p, sub, ops)
            if runtime is not None:
                p = runtime
                continue
            runtime = _scan_runtime_misc(exe, p, start, sub, ops)
            if runtime is not None:
                p = runtime
                continue
            raise ValueError(f"unhandled INT EC sub {sub:02x} at {p:#x}")
        vec = dia.canon_vec(vec)
        np = _scan_int(exe, p, commits, dia, ops, start, vec)
        if np is not None:
            p = np
            continue

        far = vec == 0x3C  # INT 3C: ES-override prefix; the
        if far or 0x34 <= vec <= 0x3B:  # next byte is a raw ESC
            if far:
                esc = exe[p + 2]
                mo = p + 3  # modrm offset
                if not 0xD8 <= esc <= 0xDF:
                    # A few wild runtime revisions reuse INT 3C for a
                    # non-FP far helper selector.  The selector has no
                    # operand bytes; preserve it as opaque glue.
                    ops.append((p, "far_opaque", esc))
                    p += 3
                    continue
            else:
                esc = 0xD8 + (vec - 0x34)  # emulated x87: INT 34h+n == ESC D8h+n
                mo = p + 2
            pre = "far_" if far else ""
            modrm = exe[mo]
            mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
            np = _scan_esc_stack_ops(p, mo, esc, modrm, ops)
            if np is not None:
                p = np
                continue
            if mod == 0 and rm == 4:  # [si] operand (IDX% array access)
                np = _scan_esc_si_ops(p, mo, esc, pre, reg, ops)
                if np is not None:
                    p = np
                    continue
                raise ValueError(f"unhandled FP [si] op esc={esc:02x} modrm={modrm:02x} at {p:#x}")
            if mod == 0 and rm == 6:  # [disp16] operand
                disp = struct.unpack_from("<H", exe, mo + 1)[0]
                kind = {
                    (0xDF, 0): "fild",  # m16 const-pool literal push
                    (0xDF, 3): "fistp",  # m16 integer store (IDX% scratch)
                    (0xD9, 0): "fld",  # m32 scalar read
                    (0xD9, 3): "fstp",  # m32 scalar store (assignment)
                    (0xD8, 3): "fcomp",  # m32 compare (IF / loop tests)
                    (0xDE, 3): "icomp",  # m16 int compare: int var or pool
                    # literal vs. an FP-stack value (mixed-type IF/loop
                    # test, e.g. `IF X% > Y THEN`; wild grdscn.exe et al.,
                    # probe q_icomp)
                    (0xDA, 3): "icomp32",  # m32 long-int compare: a plain
                    # LONG (`&`) scalar var or pooled literal vs. an
                    # FP-stack value (`IF X& > 5.5 THEN`) -- the disp16
                    # sibling of icomp_si32's [si] form; wild stat.exe,
                    # probe q_icomp32
                    (0xDD, 0): "fld64",  # m64 load (SELECT CASE selector temp)
                    (0xDD, 3): "fstp64",  # m64 store (SELECT CASE selector temp)
                    (0xDC, 3): "fcomp64",  # m64 compare (SELECT CASE arm test)
                    (0xDB, 0): "fild32",  # m32 integer load
                    (0xDB, 3): "fistp32",  # m32 integer store
                }.get((esc, reg))
                if kind:
                    ops.append((p, pre + kind, disp))
                    p = mo + 3
                    continue
                if esc == 0xD8 and reg in _FOLD_OPS:  # fold var as LEFT operand
                    ops.append((p, pre + "fold", _FOLD_OPS[reg], disp))
                    p = mo + 3
                    continue
                if esc == 0xDE and reg in _FOLD_OPS:  # fold int var / pool literal LEFT
                    ops.append((p, pre + "ifold", _FOLD_OPS[reg], disp))
                    p = mo + 3
                    continue
                if esc == 0xD8 and reg in _FOLD_OPS_N:  # non-R: mem is RIGHT operand
                    ops.append((p, pre + "fold_n", _FOLD_OPS_N[reg], disp))
                    p = mo + 3
                    continue
                if esc == 0xDE and reg in _FOLD_OPS_N:
                    ops.append((p, pre + "ifold_n", _FOLD_OPS_N[reg], disp))
                    p = mo + 3
                    continue
                if esc == 0xDC and reg in _FOLD_OPS:  # m64 arithmetic, mem LEFT
                    ops.append((p, pre + "fold64", _FOLD_OPS[reg], disp))
                    p = mo + 3
                    continue
                if esc == 0xDC and reg in _FOLD_OPS_N:  # m64 non-R: mem RIGHT
                    ops.append((p, pre + "fold_n64", _FOLD_OPS_N[reg], disp))
                    p = mo + 3
                    continue
                if (
                    esc == 0xDA and reg in _FOLD_OPS
                ):  # m32 int arithmetic (long), mem LEFT.
                    # Only the R-form is modeled: the reversed form
                    # would need opposite orientation and no fixture exercises it.
                    ops.append((p, pre + "ifold32", _FOLD_OPS[reg], disp))
                    p = mo + 3
                    continue
            if mod == 1 and rm == 6:  # [bp+disp8]: DEF FN body / call-arg temp frame
                bp_off = struct.unpack_from("<b", exe, mo + 1)[
                    0
                ]  # signed displacement byte
                kind = {
                    (0xD9, 0): "fld_bp",
                    (0xD9, 3): "fstp_bp",
                    (0xD8, 3): "fcomp_bp",
                    (0xDF, 0): "fild_bp",  # LOCAL int read onto the FP stack
                    (0xDE, 3): "icomp_bp",  # LOCAL int compare (mixed-type
                    # IF/loop test against an FP-stack value; the bp-relative
                    # sibling of icomp/icomp_si32, wild bmaster.exe/ifi.exe)
                    (0xDD, 0): "fld_bp64",  # DOUBLE LOCAL read (the m64
                    (0xDD, 3): "fstp_bp64",  # sibling of fld_bp/fstp_bp's
                    (0xDC, 3): "fcomp_bp64",  # SINGLE m32 forms; fcomp_bp64
                    # is fcomp_bp's DOUBLE sibling too, wild filepatc.exe)
                }.get((esc, reg))  # (PRINT of a local int, witnessed t1_local1)
                if kind:
                    ops.append((p, pre + kind, bp_off))
                    p = mo + 2
                    continue
                if esc == 0xDE and reg in _FOLD_OPS:  # FIADD/FIMUL/FISUB/FIDIV
                    # m16 [bp+d8]:
                    # integer BP-frame operand folded as the left side of a
                    # floating expression (FIMUL: probe_fimul_bp; both: CVT2TB).
                    ops.append((p, pre + "ifold_bp", _FOLD_OPS[reg], bp_off))
                    p = mo + 2
                    continue
                if esc == 0xD8 and reg in _FOLD_OPS:
                    ops.append((p, pre + "fold_bp", _FOLD_OPS[reg], bp_off))
                    p = mo + 2
                    continue
                if esc == 0xD8 and reg in _FOLD_OPS_N:
                    ops.append((p, pre + "fold_n_bp", _FOLD_OPS_N[reg], bp_off))
                    p = mo + 2
                    continue
                if esc == 0xDC and reg in _FOLD_OPS:
                    # m64 arithmetic fold, LOCAL DOUBLE operand LEFT (the
                    # DOUBLE sibling of fold_bp's SINGLE m32 form, wild
                    # filepatc.exe).
                    ops.append((p, pre + "fold_bp64", _FOLD_OPS[reg], bp_off))
                    p = mo + 2
                    continue
                if esc == 0xDC and reg in _FOLD_OPS_N:
                    ops.append((p, pre + "fold_n_bp64", _FOLD_OPS_N[reg], bp_off))
                    p = mo + 2
                    continue
            if mod == 2 and rm == 6 and (esc, reg) in ((0xD9, 0), (0xD9, 3)):
                # fld/fstp dword [bp+disp16]: SINGLE LOCAL beyond the signed
                # disp8 range (both forms witnessed by cleanup.exe/reformat.exe).
                bp_off = struct.unpack_from("<H", exe, mo + 1)[0]
                kind = "fld_bp" if reg == 0 else "fstp_bp"
                ops.append((p, pre + kind, bp_off))
                p = mo + 3
                continue
            if mod == 2 and rm == 6 and (esc, reg) == (0xD8, 0):
                # fadd dword [bp+disp16]: large SINGLE LOCAL as the left
                # operand (wild cleanup.exe/reformat.exe).
                bp_off = struct.unpack_from("<H", exe, mo + 1)[0]
                ops.append((p, pre + "fold_bp", "+", bp_off))
                p = mo + 3
                continue
            if mod == 2 and rm == 6 and (esc, reg) == (0xD8, 3):
                # fcomp dword [bp+disp16]: compare against a large SINGLE
                # LOCAL (wild cleanup.exe/reformat.exe variable-step FOR).
                bp_off = struct.unpack_from("<H", exe, mo + 1)[0]
                ops.append((p, pre + "fcomp_bp", bp_off))
                p = mo + 3
                continue
            raise ValueError(
                f"unhandled FP op esc={esc:02x} modrm={modrm:02x} at {p:#x}"
            )
        raise ValueError(f"unhandled INT {vec:02x} at {p:#x}")
    raise ValueError("ran past end of image without the cleanup epilogue")


def _grp(x):
    """Wrap a compound in an explicit Group: parens are byte-significant --
    a parenthesized operand compiles pushed, a flat chain folds."""
    return ir.Group(x) if isinstance(x, (ir.BinOp, ir.Neg)) else x


def _rgrp(op: str, x):
    """Group `x` iff it cannot stand bare as the RIGHT operand of `op` (BinOp of
    lower/equal precedence, or a Neg)."""
    if isinstance(x, ir.Neg) or (isinstance(x, ir.BinOp) and _PREC[x.op] <= _PREC[op]):
        return ir.Group(x)
    return x


def _orient(op: str, mem, top):
    """Fold operand order. For `-`/`/` the R-form pins the mem
    operand as the textual LEFT (`A - B` = FLD B; FSUBR A); a lower/equal-precedence
    top needed parens in the source to evaluate first (`A / (B + C)`). For
    commutative `+`/`*` the mem operand is the textual LEFT when the top is a leaf
    (`A + B` = FLD B; FADD A) or a parenthesized group (`C * (A + B)` = eval group;
    FMUL C), and the textual RIGHT when the top is a flat-chain continuation
    (`A + B * C` = FLD C; FMUL B; FADD A): TB folds trailing leaves into the
    running expression, so the running expression stays on the left."""
    if isinstance(top, ir.BinOp) and _PREC[top.op] < _PREC[op]:
        return ir.BinOp(op, mem, ir.Group(top))  # group needed parens to be top
    if op in "+*" and isinstance(top, (ir.BinOp, ir.Neg)):
        return ir.BinOp(op, top, mem)  # flat chain, leaf folds right
    if op in "-/" and isinstance(top, ir.BinOp) and _PREC[top.op] == _PREC[op]:
        return ir.BinOp(op, mem, ir.Group(top))  # A - (B + C): parens required
    return ir.BinOp(op, mem, _grp(top) if isinstance(top, ir.Neg) else top)
