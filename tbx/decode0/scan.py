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


def _scan_direct(exe, p, b, dia, ops, start) -> int | None:
    """Byte-dispatch family split out of _scan. Returns the new
    cursor when it decodes the op at ``p``, else None."""
    if b == 0xE9:  # jmp near rel16 (GOTO / FOR glue)
        rel = struct.unpack_from("<h", exe, p + 1)[0]
        target = p + 3 + rel
        if dia.name == "1.0" and target == start + 3:
            # TB 1.0 RUN: ALWAYS a near jmp to the first statement (start+3),
            # even at short-jmp range (v10_t1_run: e9 fd ff, rel -3) -- a GOTO
            # there would compile short. 1.1 RUN jumps to the prologue instead.
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
    if b == 0xE8:  # call near rel16 (GOSUB)
        rel = struct.unpack_from("<h", exe, p + 1)[0]
        ops.append((p, "call", p + 3 + rel))
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
    # Function/temp-frame glue: semantic-free SP/BP frame setup &
    # teardown around DEF FN call sites; matched AFTER the proc_enter/proc_ret
    # combined forms above. The lifter skips these.
    if b == 0x55:  # push bp
        ops.append((p, "push_bp"))
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
    if b == 0x9A:  # far call (proc entry; seg loader-relocated)
        off = struct.unpack_from("<H", exe, p + 1)[0]
        ops.append(
            (p, "far_call", off + start)
        )  # rebase segment-relative off to file offset
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
    # Literal-arg staging glue (positions SI at a stack temp, saves/restores SP).
    if b == 0x89 and exe[p + 1] == 0x26:  # mov [disp],sp (save cleanup SP)
        ops.append((p, "mov_mem_sp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0xE6:  # mov si,sp
        ops.append((p, "mov_si_sp"))
        p += 2
        return p
    if b == 0x01 and exe[p + 1] == 0xE6:  # add si,sp
        ops.append((p, "add_si_sp"))
        p += 2
        return p
    if b == 0x83 and exe[p + 1] == 0xEC:  # sub sp,imm8 (allocate temps)
        ops.append((p, "sub_sp", exe[p + 2]))
        p += 3
        return p
    if b == 0x83 and exe[p + 1] == 0xC4:  # add sp,imm8 (free temps)
        ops.append((p, "add_sp", exe[p + 2]))
        p += 3
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
    if b == 0x8E and exe[p + 1] == 0x06:  # mov es, [disp16] (far array seg)
        ops.append((p, "moves_m", struct.unpack_from("<H", exe, p + 2)[0]))
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


def _scan_direct2(exe, p, b, ops) -> int | None:
    """Byte-dispatch family split out of _scan. Returns the new
    cursor when it decodes the op at ``p``, else None."""
    if (
        b == 0x31
        and exe[p + 1] == 0xD2
        and exe[p + 2 : p + 4] == b"\x31\xf6"
        and exe[p + 4 : p + 6] == b"\x87\x16"
        and exe[p + 8 : p + 10] == b"\x87\x36"
        and exe[p + 12 : p + 14] == b"\xcd\xd2"
    ):  # string SELECT CASE selector-temp free
        ops.append((p, "str_free_temp"))
        p += 14
        return p
    if b == 0x31 and exe[p + 1] == 0xC0:  # xor ax, ax (zero literal)
        ops.append((p, "xorax"))
        p += 2
        return p
    if b == 0x31 and exe[p + 1] == 0xF6:  # xor si,si: Bounds-check (toggle 'B')
        ops.append((p, "bchk0"))  # zeroes si before the checked index runs;
        p += 2  # semantic-free, the following bchk_idx sets si=ax (F3.4)
        return p
    if b == 0xD1 and exe[p + 1] == 0xE6:  # shl si, 1 (x2 = element size 4)
        ops.append((p, "shlsi"))
        p += 2
        return p
    if b == 0x81 and exe[p + 1] == 0xC6:  # add si, imm16 (array base)
        ops.append((p, "addsi", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0xBE:  # mov si, imm16 (string descriptor)
        ops.append((p, "movsi", struct.unpack_from("<H", exe, p + 1)[0]))
        p += 3
        return p
    if b == 0x8B and exe[p + 1] == 0x06:  # mov ax, [disp16] (int var load)
        ops.append((p, "movax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x03 and exe[p + 1] == 0x06:  # add ax, [disp16] (int left-fold)
        ops.append((p, "addax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0xF7 and exe[p + 1] == 0xD8:  # neg ax (int subtraction)
        ops.append((p, "negax"))
        p += 2
        return p
    if b == 0xF7 and exe[p + 1] == 0x2E:  # imul word [disp16]
        ops.append((p, "imul_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0xF7 and exe[p + 1] == 0x6E:  # imul word [bp+disp8]: LOCAL int
        ops.append((p, "imul_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # read as the right operand (witnessed t1_local2)
        return p
    if b == 0xC7 and exe[p + 1] == 0x06:  # mov word [disp16], imm16
        d16, v16 = struct.unpack_from("<Hh", exe, p + 2)
        ops.append((p, "movm_imm", d16, v16))
        p += 6
        return p
    if (
        b == 0xC7 and exe[p + 1] == 0x46
    ):  # mov word [bp+disp8], imm16 (DEF FN result init)
        bp_off, v16 = struct.unpack_from("<bh", exe, p + 2)
        ops.append((p, "mov_bp_imm", bp_off, v16))
        p += 5
        return p
    if b == 0x89 and exe[p + 1] == 0x06:  # mov [disp16], ax (int store)
        ops.append((p, "movm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0x46:  # mov [bp+disp8], ax: LOCAL int store
        ops.append((p, "movm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # (witnessed t1_local2)
        return p
    if b == 0x01 and exe[p + 1] == 0x46:  # add [bp+disp8], ax: LOCAL int
        ops.append((p, "addm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # combine-store, e.g. `X% = X% + 1` (witnessed t1_local1)
        return p
    if b == 0xA3:  # mov [imm16], ax (scratch bridge)
        ops.append((p, "movmem_ax", struct.unpack_from("<H", exe, p + 1)[0]))
        p += 3
        return p
    if b == 0x8B and exe[p + 1] == 0x36:  # mov si, [disp16] (loop var -> index)
        ops.append((p, "movsim", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0xFF and exe[p + 1] == 0x06:  # inc word [disp16]: the integer FOR
        ops.append((p, "inc_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # step, OR a bare `X = X + 1` (INCR) outside a loop (t1_incr1)
        return p
    if b == 0xFF and exe[p + 1] == 0x0E:  # dec word [disp16]: bare `X = X - 1`
        ops.append((p, "dec_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # (DECR, witnessed t1_decr1)
        return p
    if b == 0x83 and exe[p + 1] == 0x3E:  # cmp word [disp16], imm8 (int FOR test)
        d16, i8 = struct.unpack_from("<Hb", exe, p + 2)
        ops.append((p, "cmp_mi8", d16, i8))
        p += 5
        return p
    if b == 0x8B and exe[p + 1] == 0xD3:  # mov dx,bx (OUT port setup)
        ops.append((p, "movdxbx"))
        p += 2
        return p
    if b == 0x8B and exe[p + 1] == 0xD0:  # mov dx,ax (WAIT/INP port setup)
        ops.append((p, "movdxax"))
        p += 2
        return p
    if b == 0xEE:  # out dx,al (OUT statement terminal)
        ops.append((p, "out"))
        p += 1
        return p
    if b == 0xEC and exe[p + 1 : p + 5] == b"\x20\xd8\x74\xfb":
        ops.append((p, "wait_poll"))  # WAIT: in al,dx; and al,bl; jz back
        p += 5
        return p
    if b == 0xEC and exe[p + 1 : p + 7] == b"\x30\xd8\x20\xc8\x74\xf9":
        ops.append((p, "wait_poll3"))  # WAIT 3-arg: in; xor al,bl;
        p += 7  # and al,cl; jz back
        return p
    if b == 0xEC:  # in al,dx (INP intrinsic terminal)
        ops.append((p, "in_al"))
        p += 1
        return p
    if b == 0x30 and exe[p + 1] == 0xE4:  # xor ah,ah (INP result widen)
        ops.append((p, "xorah"))
        p += 2
        return p
    if b == 0x8C and exe[p + 1] == 0x1E and exe[p + 2 : p + 4] == b"\x1c\x00":
        ops.append((p, "defseg"))  # mov [001C],ds: bare DEF SEG
        p += 4
        return p
    if b == 0x99:  # cwd: sign-extend ax ahead of idiv
        ops.append((p, "cwd"))
        p += 1
        return p
    if b == 0xF7 and exe[p + 1] == 0xFB:  # idiv bx: ax \ bx -> ax (rem in dx)
        ops.append((p, "idivbx"))
        p += 2
        return p
    if b == 0xF7 and exe[p + 1] == 0xEB:  # imul bx (reg-reg combine)
        ops.append((p, "imulbx"))
        p += 2
        return p
    if b == 0xF7 and exe[p + 1] == 0xD0:  # not ax (unary NOT)
        ops.append((p, "notax"))
        p += 2
        return p
    if b == 0xF7 and exe[p + 1] == 0xD2:  # not dx (IMP left operand)
        ops.append((p, "notdx"))
        p += 2
        return p
    if b == 0x8B and exe[p + 1] == 0xC2:  # mov ax,dx: \ quotient -> MOD remainder
        ops.append((p, "movaxdx"))
        p += 2
        return p
    if b == 0x8B and exe[p + 1] == 0x16:  # mov dx, [disp16] (IMP left operand)
        ops.append((p, "movdx_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x0B and exe[p + 1] == 0xC3:  # or ax, bx (reg-reg combine)
        ops.append((p, "oraxbx"))
        p += 2
        return p
    if b == 0x0B and exe[p + 1] == 0xC2:  # or ax, dx (IMP combine)
        ops.append((p, "oraxdx"))
        p += 2
        return p
    if b == 0x33 and exe[p + 1] == 0xC3:  # xor ax, bx (reg-reg combine)
        ops.append((p, "xoraxbx"))
        p += 2
        return p
    if b == 0x03 and exe[p + 1] == 0xC3:  # add ax, bx (reg-reg combine)
        ops.append((p, "addaxbx"))
        p += 2
        return p
    if b == 0x2B and exe[p + 1] == 0xC3:  # sub ax, bx (reg-reg combine)
        ops.append((p, "subaxbx"))
        p += 2
        return p
    if b == 0x23 and exe[p + 1] == 0x06:  # and ax, [disp16] (int left-fold)
        ops.append((p, "andax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x0B and exe[p + 1] == 0x06:  # or ax, [disp16] (int left-fold)
        ops.append((p, "orax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x33 and exe[p + 1] == 0x06:  # xor ax, [disp16] (int left-fold)
        ops.append((p, "xorax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x3B and exe[p + 1] == 0x06:  # cmp ax, [disp16] (relational value)
        ops.append((p, "cmpax_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x3B and exe[p + 1] == 0xC3:  # cmp ax, bx: integer relational where
        ops.append((p, "cmpax_bx"))  # both sides are ax-computed -- source RHS
        p += 2  # evaluates first and shuttles to bx (witnessed t1_cmpax)
        return p
    if b == 0x39 and exe[p + 1] == 0x06:  # cmp [disp16], ax: the integer FOR
        ops.append((p, "cmpm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # test with a VARIABLE limit (witnessed t1_fori)
        return p
    if b == 0x26 and exe[p + 1] == 0x3B and exe[p + 2] == 0x04:  # cmp ax, es:[si]:
        ops.append((p, "far_cmpax_si"))  # relational against a by-ref param
        p += 3  # (witnessed t1_cmpfar)
        return p
    if b == 0x26 and exe[p + 1] == 0x03 and exe[p + 2] == 0x04:  # add ax, es:[si]:
        ops.append((p, "far_addax_si"))  # arithmetic fold of a by-ref int
        p += 3  # param, e.g. `N% + 1` (witnessed t1_local2)
        return p
    if b == 0x26 and exe[p + 1] == 0xF7 and exe[p + 2] == 0x2C:  # imul word es:[si]:
        ops.append((p, "far_imulax_si"))  # multiplicative fold of a by-ref
        p += 3  # int param, e.g. `A% * B%` (witnessed q_byref_imul)
        return p
    if b == 0x26 and exe[p + 1] == 0x8B and exe[p + 2] == 0x04:  # mov ax, es:[si]:
        ops.append((p, "far_movax_si"))  # plain read of a by-ref int param
        p += 3  # into ax, e.g. as an expression's first term (t1_byref1)
        return p
    if b == 0x26 and exe[p + 1] == 0x23 and exe[p + 2] == 0x04:  # and ax, es:[si]
        ops.append((p, "far_andax_si"))  # bitwise fold of a by-ref int param
        p += 3  # (t1_byref1)
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
    if b == 0x8B and exe[p + 1] == 0x46:  # mov ax, [bp+disp8]: LOCAL int read
        ops.append((p, "movax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # (t1_byref1)
        return p
    return None


def _scan_int(exe, p, commits, dia, ops, start, vec) -> int | None:
    """Byte-dispatch family split out of _scan. Returns the new
    cursor when it decodes the op at ``p``, else None."""
    if vec == 0x8A:  # stack-test GOSUB (toggle 'S', mask 0x08): a checked-call
        # runtime vector with an i32 start-relative target replaces the near
        # call, +3 bytes per site; lifts as plain "call".
        off = struct.unpack_from("<i", exe, p + 2)[0]
        ops.append((p, "call", start + off))
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
        off = struct.unpack_from("<H", exe, p + 3)[0]  # CD 8D <sub> <off16> <seg16>
        ops.append(
            (p, "fn_call", off + start)
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
    if (
        vec == 0x3C and exe[p + 2] == 0x59 and exe[p + 3] == 0x1C
    ):  # FSTP [ss:si]: stage literal arg
        ops.append((p, "fstp_temp"))
        p += 4
        return p
    if vec == 0x3E:  # transcendental dispatcher:
        sel = exe[p + 2]  # CD 3E <selector>, FP-stack unary
        if sel not in _TRANSCEND:
            raise ValueError(f"unhandled INT 3E selector {sel:02x} at {p:#x}")
        ops.append((p, "fn", _TRANSCEND[sel]))
        p += 3
        return p
    return None


def _scan(
    exe: bytes, start: int, dia: Dialect = TB11, commits: set[int] | None = None
) -> list[tuple[Any, ...]]:
    """Pass 1: pure instruction decode, prologue to END. Each op is (addr, kind, *args);
    no DS knowledge needed. Raises on anything outside the calibrated vocabulary."""
    p = start + 3
    ops: list[tuple[Any, ...]] = []
    while p + 1 < len(exe):
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
            names = {0: "ax", 1: "cx", 3: "bx", 6: "si"}
            if rm in names and rg in names:
                ops.append((p, "movrr", names[rm], names[rg]))
                p += 2
                continue
        np = _scan_direct2(exe, p, b, ops)
        if np is not None:
            p = np
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
            sub = dia.canon_sub(exe[p + 2], 0x28)  # EC inserts at DELAY (v10_t1_delay)
            if sub == 0x32:  # END (ordinary statement)
                ops.append((p, "end"))
                p += 3
                continue
            if sub == 0xE8:  # cleanup framework: end of user code
                ops.append((p, "epilogue"))
                return ops
            if sub == 0x1A:  # CLS
                ops.append((p, "cls"))
                p += 3
                continue
            if sub == 0x14:  # CLEAR (zero operand)
                ops.append((p, "clear"))
                p += 3
                continue
            if sub == 0xA2:  # POKE addr(FP), value(ax)
                ops.append((p, "poke"))
                p += 3
                continue
            if sub == 0x26:  # DEF SEG = <fp>
                ops.append((p, "defseg_set"))
                p += 3
                continue
            if sub == 0x88:  # PALETTE attr(bx), color(ax)
                ops.append((p, "palette"))
                p += 3
                continue
            if sub == 0xEA:  # VIEW commit (+ flag byte)
                ops.append((p, "view", exe[p + 3]))
                p += 4
                continue
            if sub == 0xF2:  # WINDOW commit (+ flag byte)
                ops.append((p, "window", exe[p + 3]))
                p += 4
                continue
            if sub == 0xA4:  # PSET/PRESET commit (+ flag byte)
                ops.append((p, "pset", exe[p + 3]))
                p += 4
                continue
            if sub == 0x62:  # LINE commit (+ flag byte)
                ops.append((p, "line", exe[p + 3]))
                p += 4
                continue
            if sub == 0x12:  # CIRCLE commit (+ flag byte)
                ops.append((p, "circle", exe[p + 3]))
                p += 4
                continue
            if sub == 0x84:  # PAINT commit (+ flag byte)
                ops.append((p, "paint", exe[p + 3]))
                p += 4
                continue
            if sub == 0x30:  # DRAW cmd$ (string operand)
                ops.append((p, "draw"))
                p += 3
                continue
            if sub == 0x22:  # COLOR commit + presence mask
                ops.append((p, "color_commit", exe[p + 3]))
                p += 4
                continue
            if sub == 0x4E:  # INPUT <prompt_desc> <flags>
                d16, f16 = struct.unpack_from("<HH", exe, p + 3)
                ops.append((p, "input", d16, f16))
                p += 7
                continue
            if sub == 0x9A:  # INPUT read: parse number -> FP push
                ops.append((p, "read_num"))
                p += 3
                continue
            if sub == 0x9C:  # INPUT read: line -> string stack
                ops.append((p, "read_str"))
                p += 3
                continue
            if sub == 0xB2:  # READ <numvar>: next DATA item -> FP push
                ops.append((p, "data_read_num"))
                p += 3
                continue
            if sub == 0xB4:  # READ <strvar>: next DATA item -> string stack
                ops.append((p, "data_read_str"))
                p += 3
                continue
            if sub == 0x64:  # LINE INPUT <prompt_desc> 40
                d16 = struct.unpack_from("<H", exe, p + 3)[0]
                if exe[p + 5] != 0x40:
                    raise ValueError(
                        f"LINE INPUT trailing byte {exe[p + 5]:02x} at {p:#x}"
                    )
                ops.append((p, "line_input", d16))
                p += 6
                continue
            if sub == 0x82:  # OPEN
                ops.append((p, "open"))
                p += 3
                continue
            if sub == 0x9E:  # INPUT# numeric read
                ops.append((p, "read_file_num"))
                p += 3
                continue
            if sub == 0xA0:  # INPUT# string read
                ops.append((p, "read_file_str"))
                p += 3
                continue
            if sub == 0x18:  # CLOSE #ax
                ops.append((p, "close"))
                p += 3
                continue
            if sub == 0x16:  # bare CLOSE: close all channels (witnessed t1_close)
                ops.append((p, "close_all"))
                p += 3
                continue
            if sub == 0x2C:  # runtime DIM: begin bracket
                ops.append((p, "dim_begin"))
                p += 3
                continue
            if sub == 0x2E:  # runtime DIM: allocate
                ops.append((p, "dim_end"))
                p += 3
                continue
            if sub == 0x36:  # ERASE (DIM-style prefix)
                ops.append((p, "erase"))
                p += 3
                continue
            if sub == 0x60:  # KILL file$
                ops.append((p, "kill"))
                p += 3
                continue
            if sub == 0xB8:  # RESET (close all files)
                ops.append((p, "reset"))
                p += 3
                continue
            if sub == 0x44:  # FILES f$ (pops spec string)
                ops.append((p, "files"))
                p += 3
                continue
            if sub == 0x6E:  # NAME a$ AS b$ (pops two strings)
                ops.append((p, "name"))
                p += 3
                continue
            if sub == 0x0E:  # CHAIN file$ (pops pushed string)
                ops.append((p, "chain"))
                p += 3
                continue
            if sub == 0x10:  # CHDIR p$ (pops pushed path)
                ops.append((p, "chdir"))
                p += 3
                continue
            if sub == 0x34:  # ENVIRON s$ (pops pushed var=value)
                ops.append((p, "environ"))
                p += 3
                continue
            if sub == 0x6A:  # MKDIR p$ (pops pushed path)
                ops.append((p, "mkdir"))
                p += 3
                continue
            if sub == 0xC2:  # RMDIR p$ (pops pushed path)
                ops.append((p, "rmdir"))
                p += 3
                continue
            if sub == 0xC4:  # RUN file$ (pops pushed name; distinct from bare
                # RUN's raw jmp -- loads and runs a different program)
                ops.append((p, "run_file"))
                p += 3
                continue
            if sub == 0xCE:  # SHELL cmd$ (pops pushed cmd; empty = bare)
                ops.append((p, "shell"))
                p += 3
                continue
            if sub in (0x74, 0x72):  # ON GOTO (74) / ON GOSUB (72)
                count = exe[p + 3] | (exe[p + 4] << 8)
                targets = []
                for i in range(count):
                    off = int.from_bytes(exe[p + 5 + i * 4 : p + 9 + i * 4], "little")
                    targets.append(start + off)  # start-relative → absolute
                name = "on_goto" if sub == 0x74 else "on_gosub"
                ops.append((p, name, *targets))
                p += 5 + count * 4
                continue
            if sub == 0x98:  # PLAY music$
                ops.append((p, "play"))
                p += 3
                continue
            if sub == 0x00:  # BEEP (zero operand)
                ops.append((p, "beep"))
                p += 3
                continue
            if sub == 0xB0:  # RANDOMIZE <expr>
                ops.append((p, "randomize"))
                p += 3
                continue
            if sub == 0x28:  # DELAY init (consumes FP count)
                ops.append((p, "delay_init"))
                p += 3
                continue
            if sub == 0x2A:  # DELAY poll-loop head
                ops.append((p, "delay_poll"))
                p += 3
                continue
            if sub == 0xD0:  # SOUND (ax freq + FP dur)
                ops.append((p, "sound"))
                p += 3
                continue
            if sub == 0xEC:  # WIDTH n (ax operand)
                ops.append((p, "width"))
                p += 3
                continue
            if sub == 0x54:  # KEY ON
                ops.append((p, "key_on"))
                p += 3
                continue
            if sub == 0x58:  # KEY n, s$: n in ax, macro on sstack (t1_key)
                ops.append((p, "key_macro"))
                p += 3
                continue
            if sub == 0x52:  # KEY OFF
                ops.append((p, "key_off"))
                p += 3
                continue
            if sub == 0xC6:  # SCREEN m[,b][,a][,v]: trailing presence mask
                # 08 mode / 04 burst / 02 apage / 01 vpage (t1_screenb/p)
                if p + 3 >= len(exe) or exe[p + 3] not in (0x08, 0x0C, 0x0E, 0x0F):
                    raise ValueError(f"SCREEN bad tag at {p:#x}")
                ops.append((p, "screen", exe[p + 3]))
                p += 4
                continue
            if sub == 0xF4:  # WRITE numeric item
                ops.append((p, "write_item"))
                p += 3
                continue
            if sub == 0xF8:  # WRITE comma separator
                ops.append((p, "write_sep"))
                p += 3
                continue
            if sub == 0xFA:  # WRITE# numeric item
                ops.append((p, "write_file_num"))
                p += 3
                continue
            if sub == 0xFC:  # WRITE# string item
                ops.append((p, "write_file_str"))
                p += 3
                continue
            if sub == 0xFE:  # WRITE# item separator
                ops.append((p, "write_file_sep"))
                p += 3
                continue
            if sub == 0x48:  # GET #n, rec
                ops.append((p, "get"))
                p += 3
                continue
            if sub == 0xA8:  # PUT #n, rec
                ops.append((p, "put"))
                p += 3
                continue
            if sub == 0xDC:  # PAINT tile variant: tile$ on sstack + flag byte
                ops.append((p, "paint_tile", exe[p + 3]))  # (witnessed t1_paintt)
                p += 4
                continue
            if sub == 0xCA:  # SEEK #n, pos
                ops.append((p, "seek"))
                p += 3
                continue
            if sub == 0x06:  # BLOAD f$, offset
                ops.append((p, "bload"))
                p += 3
                continue
            if sub == 0x08:  # BSAVE f$, offset, length
                ops.append((p, "bsave"))
                p += 3
                continue
            if sub == 0x3E:  # FIELD #n begin
                ops.append((p, "field"))
                p += 3
                continue
            if sub == 0x40:  # FIELD AS-entry
                ops.append((p, "field_as"))
                p += 3
                continue
            if sub == 0x70:  # ON ERROR GOTO (i32 start-rel; -1 = GOTO 0)
                off = struct.unpack_from("<i", exe, p + 3)[0]
                ops.append((p, "on_error", None if off == -1 else start + off))
                p += 7
                continue
            if sub == 0x3C:  # ERROR n (code in ax)
                ops.append((p, "error_stmt"))
                p += 3
                continue
            if sub == 0xBC:  # RESUME prefix (all three forms)
                ops.append((p, "resume_pre"))
                p += 3
                continue
            if sub == 0xBE:  # RESUME (bare) commit
                ops.append((p, "resume_bare"))
                p += 3
                continue
            if sub == 0xC0:  # RESUME NEXT commit
                ops.append((p, "resume_next"))
                p += 3
                continue
            if sub in _TRAP_GOSUB:  # ON <event>[(n)] GOSUB (i32 start-rel)
                off = struct.unpack_from("<i", exe, p + 3)[0]
                ops.append((p, "on_trap", sub, start + off))
                p += 7
                continue
            if sub in _TRAP_CTL:  # <event>[(n)] ON|OFF|STOP
                ops.append((p, "trap_ctl", sub))
                p += 3
                continue
            if sub == 0x56:  # KEY LIST (zero operand)
                ops.append((p, "key_list"))
                p += 3
                continue
            if sub == 0x4A:  # GET graphics blit (+ trail byte)
                ops.append((p, "get_gfx", exe[p + 3]))
                p += 4
                continue
            if sub == 0xAA:  # PUT graphics blit (+ action byte)
                ops.append((p, "put_gfx", exe[p + 3]))
                p += 4
                continue
            if sub == 0x6C:  # MTIMER (reset microtimer)
                ops.append((p, "mtimer"))
                p += 3
                continue
            if sub == 0xB6:  # REG index(ax), value(FP stack)
                ops.append((p, "reg_set"))
                p += 3
                continue
            if sub == 0x0C:  # CALL INTERRUPT n(ax)
                ops.append((p, "call_int"))
                p += 3
                continue
            if sub == 0x0A:  # CALL ABSOLUTE addr(FP stack)
                ops.append((p, "call_abs"))
                p += 3
                continue
            if sub == 0x24:  # DATE$ = s$ (pops string stack)
                ops.append((p, "dateset"))
                p += 3
                continue
            if sub == 0xE0:  # TIME$ = s$ (pops string stack)
                ops.append((p, "timeset"))
                p += 3
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
                    raise ValueError(f"bad far-FP ESC {esc:02x} at {p:#x}")
            else:
                esc = 0xD8 + (vec - 0x34)  # emulated x87: INT 34h+n == ESC D8h+n
                mo = p + 2
            pre = "far_" if far else ""
            modrm = exe[mo]
            mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
            if esc == 0xD9 and modrm == 0xE8:  # FLD1
                ops.append((p, "fld1"))
                p = mo + 1
                continue
            if esc == 0xD9 and modrm == 0xEE:  # FLDZ
                ops.append((p, "fldz"))
                p = mo + 1
                continue
            if esc == 0xD9 and modrm == 0xE0:  # FCHS
                ops.append((p, "fchs"))
                p = mo + 1
                continue
            if esc == 0xD9 and modrm == 0xE1:  # FABS (ABS intrinsic)
                ops.append((p, "fabs"))
                p = mo + 1
                continue
            if esc == 0xD9 and modrm == 0xFA:  # FSQRT (SQR intrinsic)
                ops.append((p, "fsqrt"))
                p = mo + 1
                continue
            if esc == 0xD9 and modrm == 0xFC:  # FRNDINT (CLNG intrinsic)
                ops.append((p, "frndint"))
                p = mo + 1
                continue
            if esc == 0xDE and modrm == 0xD9:  # FCOMPP: both sides FP-computed
                ops.append((p, "fcompp"))  # (witnessed t1_fcmp)
                p = mo + 1
                continue
            if esc == 0xDE and modrm in _POP_OPS_N:  # non-R FSUBP/FDIVP
                ops.append((p, "popop_n", _POP_OPS_N[modrm]))
                p = mo + 1
                continue
            if esc == 0xDE and modrm in _POP_OPS:  # FxxxP st(1),st
                ops.append((p, "popop", _POP_OPS[modrm]))
                p = mo + 1
                continue
            if mod == 0 and rm == 4:  # [si] operand (IDX% array access)
                kind = {
                    (0xD9, 0): "fld_si",
                    (0xD9, 3): "fstp_si",
                    (0xD8, 3): "fcomp_si",
                    (0xDC, 3): "fcomp_si64",  # m64 compare (double array elem)
                    (0xDD, 0): "fld_si64",
                    (0xDD, 3): "fstp_si64",
                    (0xDB, 0): "fild_si32",
                    (0xDB, 3): "fstp_si32",
                    (0xDF, 0): "fild_si",  # m16 int onto the FP stack, e.g. a
                }.get((esc, reg))  # by-ref int param for PRINT (t1_byref1)
                if kind:
                    ops.append((p, pre + kind))
                    p = mo + 1
                    continue
                if esc == 0xD8 and reg in _FOLD_OPS:
                    ops.append((p, pre + "fold_si", _FOLD_OPS[reg]))
                    p = mo + 1
                    continue
                if esc == 0xD8 and reg in _FOLD_OPS_N:
                    ops.append((p, pre + "fold_n_si", _FOLD_OPS_N[reg]))
                    p = mo + 1
                    continue
            if mod == 0 and rm == 6:  # [disp16] operand
                disp = struct.unpack_from("<H", exe, mo + 1)[0]
                kind = {
                    (0xDF, 0): "fild",  # m16 const-pool literal push
                    (0xDF, 3): "fistp",  # m16 integer store (IDX% scratch)
                    (0xD9, 0): "fld",  # m32 scalar read
                    (0xD9, 3): "fstp",  # m32 scalar store (assignment)
                    (0xD8, 3): "fcomp",  # m32 compare (IF / loop tests)
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
                }.get((esc, reg))  # (PRINT of a local int, witnessed t1_local1)
                if kind:
                    ops.append((p, pre + kind, bp_off))
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
