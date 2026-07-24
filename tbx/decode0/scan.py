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


# A compiler/library helper shared byte-for-byte by catalog.exe, filepatc.exe,
# morcalc.exe, process.exe and pw.exe.  It is a real framed far procedure, not
# source $INLINE, but its seven far-pointer arguments and direct port I/O make
# a source-level meaning impossible to infer safely from the corpus alone.
# Match the entire routine (including RETF), never merely its prologue, before
# allowing the coverage-only opaque-helper rescue.
_OPAQUE_HELPER_BODY = bytes.fromhex(
    """
    55 8b ec 06 1e 8b 16 00 00 c5 76 0a 8e 04 c5 76 06
    8b 3c c5 76 1a 8b 04 50 c5 76 0e 8b 04 c5 76 12 8b
    5c 02 03 d8 c5 76 1e 8b 0c c5 76 16 8b 74 02 03 f0
    58 d1 e7 fc 8e da 3d 00 00 74 25 ba da 03 ac 8b ee 8b
    f3 8a 24 43 8b f5 8b e8 b4 09 ec d0 d8 72 fb fa ec 22
    c4 74 fb 8b c5 ab fb e2 e1 eb 0e 90 ac 8b ee 8b f3 8a
    24 8b f5 43 ab e2 f3 1f 07 5d cb
    """
)
_OPAQUE_HELPER_BODY_2 = bytes.fromhex(
    """
    55 8b ec 1e 06 ba da 03 a1 00 00 8e c0 c5 76 1a 8b 04
    c5 76 1e 8b 0c c5 76 12 8b 5c 02 c5 76 0a 8e 1c 06 50
    c4 7e 0e 26 8b 05 03 d8 c4 7e 06 26 8b 35 c4 7e 16 26
    8b 7d 02 03 f8 58 07 d1 e6 fc 3d 00 00 74 23 b4 09 ec
    d0 d8 72 fb fa ec 22 c4 74 fb ad fb 26 88 05 8b ef 8b
    fb 26 88 25 8b fd 43 47 e2 e1 3b c0 74 11 ad 26 88 05
    8b ef 8b fb 26 88 25 8b fd 43 47 e2 ef 07 1f 5d cb
    """
)
# Six more framed far-procedure helpers, all sharing the family's exact
# "push bp; mov bp,sp; push ds; push es; ...; pop es; pop ds; pop bp;
# int3; retf" (55 8b ec 1e 06 ... 07 1f 5d cc cb) framing and CGA
# snow-avoidance retrace-wait idiom, witnessed together in wild
# resume.exe (placed back-to-back, each skipped by its own JMP).
# Identified exactly: these are six named $INLINE primitives from an
# early (Nov 1987-dated) TBWINDOW distribution -- QPRINT.BIN, QPRINTC.BIN,
# QFILL.BIN, QATTR.BIN, QSAVE.BIN, QREST.BIN respectively (BODY_3..BODY_8
# in that order), matched byte-for-byte (including the compiler-appended
# "int3; retf" tail) against the real .BIN files bundled with the wild
# find TEST420/RSLTEST 4.17 (wild/hits/rsltest.exe), whose TBWINDO.INC
# documents each routine's SUB and calling convention:
#   QPRINT(ROW%,COL%,STR$,ATTR%)                    -- BODY_3
#   QPRINTC(ROW%,COLL%,COLR%,STRDAT$,ATTR%)         -- BODY_4
#   QFILL(ROW%,COL%,ROWS%,COLS%,CHAR%,ATTR%)        -- BODY_5
#   QATTR(ROW%,COL%,ROWS%,COLS%,ATTR%)              -- BODY_6
#   QSAVE(ROW%,COL%,ROWS%,COLS%,SCRN%(??))          -- BODY_7
#   QREST(ROW%,COL%,ROWS%,COLS%,SCRN%(??))          -- BODY_8
# This is an earlier/simpler TBWINDOW packaging than BODY_11's monolithic
# TBWINDOW 5.0 (1988) blob -- six separate SUB...INLINE stubs rather than
# one big helper -- but the known calling convention still can't be
# recovered as literal source: $INLINE embeds the named .BIN file's bytes
# verbatim at compile time, so byte-exact recompilation would require that
# external file to exist alongside the recovered .bas, which tbx's
# decompiled text alone cannot reproduce. Coverage-only, same as the rest
# of this family.
_OPAQUE_HELPER_BODY_3 = bytes.fromhex(
    """
    55 8b ec 1e 06 c4 7e 0a 26 8b 0d 81 e1 ff 7f e3
    5b 51 8b 16 00 00 52 b4 0f cd 10 3c 07 75 08 bb
    00 b0 ba ba 03 eb 06 bb 00 b8 ba da 03 53 07 52
    33 db 8a dc c5 76 12 8b 04 48 f7 e3 d1 e0 c5 76
    0e 8b 1c 4b d1 e3 03 d8 8b fb c5 76 06 8b 1c c5
    76 0a 8b 74 02 5a 1f 59 fc fa ec a8 01 75 fb ec
    a8 01 74 fb a4 26 88 1d 47 e2 ef fb 07 1f 5d cc
    cb
    """
)
# TB 1.0 build of BODY_3: byte-identical except that the procedure epilogue
# ends directly in RETF rather than INT3; RETF (wild bmaster/ifi). Keep this
# as a full-body fingerprint, not a permissive suffix variant.
_OPAQUE_HELPER_BODY_3_V10 = _OPAQUE_HELPER_BODY_3[:-2] + b"\xcb"
_OPAQUE_HELPER_BODY_4 = bytes.fromhex(
    """
    55 8b ec 1e 06 c4 7e 0a 26 8b 0d 81 e1 ff 7f e3
    6a 51 8b 16 00 00 52 b4 0f cd 10 3c 07 75 08 bb
    00 b0 ba ba 03 eb 06 bb 00 b8 ba da 03 53 07 52
    33 db 8a dc c5 76 16 8b 04 48 f7 e3 d1 e0 c5 76
    12 8a 1c c5 76 0e 8a 3c 02 df 32 ff d1 eb d1 e9
    2b d9 4b d1 e3 03 d8 8b fb c5 76 06 8b 1c c5 76
    0a 8b 74 02 5a 1f 59 fc fa ec a8 01 75 fb ec a8
    01 74 fb a4 26 88 1d 47 e2 ef fb 07 1f 5d cc cb
    """
)
_OPAQUE_HELPER_BODY_4_V10 = _OPAQUE_HELPER_BODY_4[:-2] + b"\xcb"
_OPAQUE_HELPER_BODY_5 = bytes.fromhex(
    """
    55 8b ec 1e 06 b4 0f cd 10 3c 07 75 08 bb 00 b0
    ba ba 03 eb 06 bb 00 b8 ba da 03 53 07 c5 76 12
    8b 0c 51 52 33 db 8a dc c5 76 1a 8b 04 48 f7 e3
    d1 e0 c5 76 16 8b 1c 4b d1 e3 03 d8 8b fb c5 76
    0a 8b 04 8a d8 c5 76 06 8b 04 8a e0 fc c5 76 0e
    8b 34 5a 57 8b ce fa ec a8 01 75 fb ec a8 01 74
    fb 8a c3 ab e2 f1 fb 5f 59 49 e3 07 51 81 c7 a0
    00 eb e0 07 1f 5d cc cb
    """
)
_OPAQUE_HELPER_BODY_5_V10 = _OPAQUE_HELPER_BODY_5[:-2] + b"\xcb"
_OPAQUE_HELPER_BODY_6 = bytes.fromhex(
    """
    55 8b ec 1e 06 b4 0f cd 10 3c 07 75 08 bb 00 b0
    ba ba 03 eb 06 bb 00 b8 ba da 03 53 07 c5 76 0e
    8b 0c 51 52 33 db 8a dc c5 76 16 8b 04 48 f7 e3
    d1 e0 c5 76 12 8b 1c 4b d1 e3 03 d8 8b fb c5 76
    06 8b 1c fc c5 76 0a 8b 34 5a 57 fa 8b ce 47 ec
    a8 01 75 fb ec a8 01 74 fb 8a c3 aa e2 f0 fb 5f
    59 49 e3 07 51 81 c7 a0 00 eb df 07 1f 5d cc cb
    """
)
_OPAQUE_HELPER_BODY_6_V10 = _OPAQUE_HELPER_BODY_6[:-2] + b"\xcb"
_OPAQUE_HELPER_BODY_7 = bytes.fromhex(
    """
    55 8b ec 1e 06 b4 0f cd 10 3c 07 75 08 bb 00 b0
    ba ba 03 eb 06 bb 00 b8 ba da 03 53 1f c4 7e 0e
    26 8b 0d 51 52 33 db 8a dc c4 7e 16 26 8b 05 48
    f7 e3 d1 e0 c4 7e 12 26 8b 1d 4b d1 e3 03 d8 8b
    f3 c4 7e 0a 26 8b 1d c4 7e 06 fc 5a 56 fa 8b cb
    ec a8 01 75 fb ec a8 01 74 fb a5 e2 f3 fb 5e 59
    49 e3 07 51 81 c6 a0 00 eb e2 07 1f 5d cc cb
    """
)
_OPAQUE_HELPER_BODY_7_V10 = _OPAQUE_HELPER_BODY_7[:-2] + b"\xcb"
_OPAQUE_HELPER_BODY_8 = bytes.fromhex(
    """
    55 8b ec 1e 06 b4 0f cd 10 3c 07 75 08 bb 00 b0
    ba ba 03 eb 06 bb 00 b8 ba da 03 53 07 c5 76 0e
    8b 0c 51 52 33 db 8a dc c5 76 16 8b 04 48 f7 e3
    d1 e0 c5 76 12 8b 1c 4b d1 e3 03 d8 8b fb c5 76
    0a 8b 1c c5 76 06 fc 5a 57 fa 8b cb ec a8 01 75
    fb ec a8 01 74 fb a5 e2 f3 fb 5f 59 49 e3 07 51
    81 c7 a0 00 eb e2 07 1f 5d cc cb
    """
)
_OPAQUE_HELPER_BODY_8_V10 = _OPAQUE_HELPER_BODY_8[:-2] + b"\xcb"
# A ninth framed helper (wild filepatc.exe, TB 1.0): same push-bp/push-ds/
# push-es framing, bp-relative param reads, and CGA snow-avoidance
# vertical-retrace poll (`in al,dx; test al,1`) as the BODY/BODY_2..8
# family, but its own epilogue ends directly `pop bp; cld; retf` -- no
# INT3 padding byte before the far RET the way the resume.exe family's
# TB 1.1 builds do, so (unlike BODY_3..8) this is not paired with a
# separate "_V10" INT3-stripped transform: only this one exact shape is
# witnessed, and inventing an un-witnessed TB 1.1 padded variant would be
# a guess, not a fingerprint.
_OPAQUE_HELPER_BODY_9 = bytes.fromhex(
    """
    55 8b ec 1e 06 8b 76 0a ad 8b 76 16 8b 1c 8b 76
    06 8b 3c 8b 76 0e 8b 0c 8b 76 12 8b 34 8e c0 8e
    db fc 3b c3 75 0b 3b f7 77 07 03 f1 03 f9 4e 4f
    fd 8c d8 3d 00 b8 74 0c 8c c0 3d 00 b8 74 05 f3
    a4 eb 26 90 b4 05 cd 66 80 fb 00 74 f2 1e 33 c0
    8e d8 8b 16 63 04 83 c2 06 1f ec a8 01 75 fb fa
    ec a8 01 74 fb a4 fb e2 f1 07 1f 5d fc cb
    """
)
# A tenth helper, immediately adjacent to BODY_9 in filepatc.exe (its own
# JMP lands right after BODY_9's retf) -- a segment-selecting block-move
# dispatcher (picks a source/dest side via a small jump table, then
# rep movsb's), same push-bp/push-ds/push-es framing and direct
# `pop bp; retf` epilogue (no INT3 padding, matching BODY_9).
_OPAQUE_HELPER_BODY_10 = bytes.fromhex(
    """
    55 8b ec 1e 06 8b 76 06 8b 1c 8b 76 0a ad 8b 76
    0e 8b 14 50 33 f6 ad 8b 76 12 8b 0c 8b 74 02 80
    e5 7f 8e d8 58 e3 2d 51 8b ce 83 fb 00 75 0b 1e
    07 8e da 8b f0 8b f9 eb 12 90 83 fb 01 74 06 b8
    02 00 eb 16 90 8e c2 8b f8 8b f1 59 fc f3 a4 33
    c0 eb 08 90 b8 01 00 eb 02 90 59 07 1f 8b 76 16
    89 04 5d cb
    """
)
# An eleventh, much larger framed helper (wild phone.exe): identified by
# the user as TBWINDOW 5.0, (c) 1988 Richard D. Fothergill -- a
# commercial third-party TB window-management add-on library, not an
# in-house Borland runtime routine like BODY..BODY_10. Same overall
# push-bp/push-ds/push-es framing and "pop es; pop ds; pop bp; int3;
# retf" TB 1.1 epilogue as the rest of the family; its own CALL
# immediately leads into an embedded DATA table (box-drawing/CGA
# character codes, not instructions) before the real code resumes near
# the end -- consistent with a window-border character set. Exact
# byte-fingerprint match, same as every other opaque helper; size alone
# doesn't change the recognition mechanism. The jmp-to-jmp thunk chain
# immediately following this body (phone.exe's next blocker) is very
# plausibly TBWINDOW's own public-routine dispatch table, given a
# commercial library would need many stable entry points.
_OPAQUE_HELPER_BODY_11 = bytes.fromhex(
    """
    55 8b ec 1e 06 e8 4e 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    da bf c0 d9 b3 c4 c9 bb c8 bc ba cd d5 b8 d4 be
    b3 cd d6 b7 d3 bd ba c4 db db db db db db b0 b0
    b0 b0 b0 b0 b1 b1 b1 b1 b1 b1 b2 b2 b2 b2 b2 b2
    00 00 00 00 00 00 5b 0e 1f 33 c0 c4 7e 12 26 8b
    05 fe c8 e8 9e 04 8e c3 06 c4 7e 2a 26 8b 05 88
    07 c4 7e 26 26 8b 05 88 47 01 c4 7e 22 26 8b 05
    88 47 02 c4 7e 1e 26 8b 05 88 47 03 c4 7e 1a 26
    8b 05 b1 08 d3 e0 89 47 14 c4 7e 16 26 8b 05 d3
    e0 89 47 10 07 e8 e5 03 06 c4 7e 0e 26 8b 05 3d
    01 00 07 74 06 e8 46 01 e9 09 06 e8 03 00 e9 03
    06 8a 47 02 8a 4f 02 2a 0f d0 e9 2a c1 88 47 04
    88 47 06 8a 47 03 8a 4f 03 2a 4f 01 d0 e9 2a c1
    88 47 05 88 47 07 8a 47 07 fe c0 88 47 07 8a 47
    06 fe c0 88 47 06 8a 47 04 fe c8 88 47 04 8a 47
    05 fe c8 88 47 05 8a 27 8a 47 01 8a 6f 02 8a 4f
    03 8a 77 04 88 37 8a 77 06 88 77 02 8a 77 07 88
    77 03 8a 77 05 88 77 01 88 67 04 88 6f 06 88 47
    05 88 4f 07 b0 01 b4 01 b1 01 b5 01 b2 00 8a 37
    3a 77 04 75 03 e9 86 00 50 8a 07 fe c8 88 07 58
    8a 37 3a 77 04 74 77 50 8a 07 fe c8 88 07 58 8a
    37 3a 77 04 74 68 50 8a 07 fe c8 88 07 58 8a 77
    02 3a 77 06 74 63 50 8a 47 02 fe c0 88 47 02 58
    8a 77 02 3a 77 06 74 51 50 8a 47 02 fe c0 88 47
    02 58 8a 77 02 3a 77 06 74 3f 50 8a 47 02 fe c0
    88 47 02 58 8a 77 01 3a 77 05 74 38 50 8a 47 01
    fe c8 88 47 01 58 8a 77 03 3a 77 07 74 31 50 8a
    47 03 fe c0 88 47 03 58 e8 33 00 e9 70 ff 80 fa
    04 74 27 02 d4 b4 00 eb 95 80 fa 04 74 1c 02 d0
    b0 00 eb c0 80 fa 04 74 11 02 d5 b5 00 eb c7 80
    fa 04 74 06 02 d1 b1 00 eb ce e8 01 00 c3 50 53
    51 52 57 06 56 06 5f e8 21 03 8b ce 33 c0 8a 47
    01 f7 e1 51 32 ed 8a 0f d1 e1 03 c1 89 47 08 33
    c0 8a 47 01 59 f7 e1 51 8a 4f 02 d1 e1 03 c1 89
    47 0a 33 c0 8a 47 03 59 f7 e1 51 8a 0f d1 e1 03
    c1 89 47 0c 33 c0 8a 47 03 59 f7 e1 8a 4f 02 d1
    e1 03 c1 89 47 0e 53 ff 77 08 ff 77 0a ff 77 0c
    ff 77 0e ff 77 10 58 5b 53 8b df 8a 47 4b 5b e8
    35 04 53 8b df 8a 47 4a 5b 5b e8 2a 04 53 8b df
    8a 47 49 5b 5b e8 1f 04 53 8b df 8a 47 48 5b 5b
    e8 14 04 5b 33 c9 8a 4f 02 49 33 c0 8a 07 40 2b
    c8 41 53 8b 47 08 ff 77 10 8b d8 83 c3 02 58 53
    8b df 8a 47 4d 5b e8 ee 03 83 c3 02 e2 f8 5b 33
    c9 8a 4f 02 49 33 c0 8a 07 40 2b c8 41 53 8b 47
    0c ff 77 10 8b d8 83 c3 02 58 53 8b df 8a 47 4d
    5b e8 c3 03 83 c3 02 e2 f8 5b 33 c9 8a 4f 03 fe
    c9 33 c0 8a 47 01 fe c0 2b c8 53 8b 47 08 ff 77
    10 8b d8 58 53 8b df 8a 47 4c 5b 41 03 de e8 96
    03 e2 f9 5b 33 c9 8a 4f 03 fe c9 33 c0 8a 47 01
    fe c0 2b c8 53 8b 47 0a ff 77 10 8b d8 58 53 8b
    df 8a 47 4c 5b 41 03 de e8 6c 03 e2 f9 5b e8 08
    00 5e 07 5f 5a 59 5b 58 c3 53 89 6f 08 33 c9 33
    d2 8a 4f 01 83 c1 02 51 8a 0f 83 c1 02 51 8a 4f
    01 8a 57 03 2a d1 4a 52 8a 0f 8a 57 02 2a d1 4a
    52 b2 20 52 8b 47 14 8a d4 52 e8 d8 01 5b 8b 6f
    08 c3 56 57 50 53 51 52 06 c4 7e 0a 26 8b 05 3d
    01 00 73 03 e9 ed 00 3d 04 00 7e 03 e9 e5 00 53
    89 6f 08 33 d2 33 c9 8a 57 01 83 c2 02 52 a9 01
    00 74 66 8a 17 4a 52 8a 57 03 8a 4f 01 2b d1 42
    52 ba 02 00 52 3d 01 00 74 08 b2 08 52 e8 d8 01
    eb 09 b2 20 52 b2 00 52 e8 7a 01 5b 53 33 d2 33
    c9 8a 57 03 83 c2 02 52 8a 17 4a 52 ba 01 00 52
    8a 57 02 8a 0f 2b d1 42 52 c4 7e 0a 26 8b 05 3d
    01 00 74 0a ba 08 00 52 e8 9d 01 eb 73 90 b2 20
    52 b2 00 52 e8 3e 01 eb 67 8a 57 02 83 c2 02 52
    8a 57 03 8a 4f 01 2b d1 52 ba 02 00 52 3d 02 00
    74 08 b2 08 52 e8 70 01 eb 09 b2 20 52 b2 00 52
    e8 12 01 5b 53 33 d2 33 c9 8a 57 03 83 c2 02 52
    8a 17 83 c2 03 52 ba 01 00 52 8a 57 02 8a 0f 2b
    d1 42 52 c4 7e 0a 26 8b 05 3d 02 00 74 09 ba 08
    00 52 e8 33 01 eb 09 b2 20 52 b2 00 52 e8 d5 00
    5b 8b 6f 08 07 5a 59 5b 58 5f 5e c3 c3 56 57 50
    53 51 52 06 c4 7e 2e 26 8b 05 3d 00 00 74 5d 33
    d2 33 c9 8a 57 01 42 52 c4 7e 0a 26 8b 05 3d 00
    00 75 1b 8a 17 42 52 8a 57 03 8a 4f 01 2a d1 83
    c2 02 52 8a 57 02 8a 0f 2a d1 42 52 eb 26 a9 01
    00 74 06 8a 17 4a 52 eb 04 8a 17 42 52 8a 57 03
    8a 4f 01 2a d1 83 c2 03 52 8a 57 02 8a 0f 2a d1
    83 c2 03 52 c4 7e 06 06 57 e8 33 01 07 5a 59 5b
    58 5f 5e c3 56 57 50 53 51 52 06 b1 06 f6 e1 05
    18 00 03 c3 1e 07 8b f0 83 c3 48 8b fb fc b9 06
    00 f3 a4 07 5a 59 5b 58 5f 5e c3 50 53 51 1e b8
    40 00 50 1f 33 c0 a0 4a 00 d1 e0 8b f0 8a 16 49
    00 80 fa 07 75 05 b8 00 b0 eb 03 b8 00 b8 8e c0
    1f 59 5b 58 c3 55 8b ec 1e 06 e8 1e 01 53 07 8b
    4e 0a 51 52 33 db 8a dc 53 8b 46 0e 48 f7 e3 d1
    e0 8b 5e 0c 4b d1 e3 03 d8 8b fb 8b 46 06 8a d8
    8b 46 04 8a e0 8a c3 fc 8b 76 08 5b d1 e3 5a 57
    8b ce e8 05 01 ab e2 fa 5f 59 49 e3 05 51 03 fb
    eb ed 07 1f 5d c2 0c 00 55 8b ec 1e 06 e8 cb 00
    53 07 8b 4e 08 51 52 33 db 8a dc 53 8b 46 0c 48
    f7 e3 d1 e0 8b 5e 0a 4b d1 e3 03 d8 8b fb 8b 46
    04 fc 8b 76 06 5b d1 e3 5a 57 fa 8b ce e8 ba 00
    47 aa e2 f9 fb 5f 59 49 e3 05 51 03 fb eb ea 07
    1f 5d c2 0a 00 54 42 57 49 4e 44 4f 53 20 35 2e
    30 20 2f 20 43 6f 70 79 72 69 67 68 74 20 28 63
    29 20 31 39 38 38 20 62 79 20 52 69 63 68 61 72
    64 20 44 2e 20 46 6f 74 68 65 72 67 69 6c 6c 55
    8b ec 1e 06 e8 44 00 53 1f 8b 4e 0a 51 52 33 db
    8a dc 53 8b 46 0e 48 f7 e3 d1 e0 8b 5e 0c 4b d1
    e3 03 d8 8b f3 8b 46 08 c4 7e 04 fc 5b d1 e3 5a
    56 fa 8b c8 e8 33 00 a5 e2 fa fb 5e 59 49 e3 05
    51 03 f3 eb eb 07 1f 5d c2 0c 00 b8 40 00 50 1f
    8a 26 4a 00 a0 49 00 3c 07 75 08 bb 00 b0 ba ba
    03 eb 06 bb 00 b8 ba da 03 c3 50 ec d0 d8 72 fb
    ec d0 d8 73 fb 58 c3 06 5a 81 fa 00 b8 75 10 ba
    da 03 50 ec d0 d8 72 fb fa ec d0 d8 73 fb 58 26
    89 07 fb c3 e8 bb fc 07 1f 5d cc cb
    """
)
# A twelfth framed helper (wild CVT2TB.EXE): a small, program-specific
# directory-search primitive (`AH=4Eh` DOS Find First, INT 21h) wrapped
# in the SAME push-bp/mov-bp,sp (alternate `89 e5` encoding)/push-es/
# push-ds framing and bare-CB epilogue as the rest of this family --
# exact byte-fingerprint match, same recognition mechanism regardless
# of whether the routine is shared across files or (as here) unique to
# one program.
_OPAQUE_HELPER_BODY_12 = bytes.fromhex(
    "5589e5061ec47e06268b0d81e1ff7f83f9017f0431c0eb1b3e8b160000521f"
    "268b5502b44eb93700cd21730431c0eb03b8ffffc57e0a3e89051f075dcb"
)
_OPAQUE_HELPER_BODIES = (
    _OPAQUE_HELPER_BODY,
    _OPAQUE_HELPER_BODY_2,
    _OPAQUE_HELPER_BODY_3,
    _OPAQUE_HELPER_BODY_3_V10,
    _OPAQUE_HELPER_BODY_4,
    _OPAQUE_HELPER_BODY_4_V10,
    _OPAQUE_HELPER_BODY_5,
    _OPAQUE_HELPER_BODY_5_V10,
    _OPAQUE_HELPER_BODY_6,
    _OPAQUE_HELPER_BODY_6_V10,
    _OPAQUE_HELPER_BODY_7,
    _OPAQUE_HELPER_BODY_7_V10,
    _OPAQUE_HELPER_BODY_8,
    _OPAQUE_HELPER_BODY_8_V10,
    _OPAQUE_HELPER_BODY_9,
    _OPAQUE_HELPER_BODY_10,
    _OPAQUE_HELPER_BODY_11,
    _OPAQUE_HELPER_BODY_12,
)
_OPAQUE_HELPER_PARAM_OFFSETS = (0x1E, 0x1A, 0x16, 0x12, 0x0E, 0x0A, 0x06)


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
    # Function/temp-frame glue: semantic-free SP/BP frame setup &
    # teardown around DEF FN call sites; matched AFTER the proc_enter/proc_ret
    # combined forms above. The lifter skips these.
    if b == 0x55:  # push bp
        ops.append((p, "push_bp"))
        p += 1
        return p
    if b == 0x06 and exe[p + 1] != 0x56:  # standalone push es frame glue
        ops.append((p, "push_es"))
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
        and exe[p + 6] == 0x50
    ):  # push ss; mov ax,off; add ax,bp; push ax: the LOCAL-frame sibling of
        # arg_push_ref -- forwards a LOCAL var's address as a by-ref CALL
        # arg (wild bmaster.exe/ifi.exe/resume.exe, probe q_localargcall)
        ops.append((p, "arg_push_ref_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 7
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
    if b == 0xB0 and exe[p + 2] == 0xE6:
        # OUT with both operands in the byte range: Turbo Basic folds the
        # general mov-AX/mov-DX/OUT-DX sequence into MOV AL,value;
        # OUT port,AL. Keep the complete pair atomic so a stray MOV AL or
        # immediate-port OUT remains fail-loud (wild zip.exe's tone SUBs).
        ops.append((p, "out_imm", exe[p + 3], exe[p + 1]))
        p += 4
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
    if b == 0x03 and exe[p + 1] == 0x86:  # add ax,[bp+disp16]: large LOCAL
        ops.append((p, "addax_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # integer left-fold (wild cleanup/reformat)
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
    if b == 0xC7 and exe[p + 1] == 0x86:  # mov word [bp+disp16], imm16:
        bp_off, v16 = struct.unpack_from("<Hh", exe, p + 2)
        ops.append((p, "mov_bp_imm", bp_off, v16))
        p += 6  # LOCAL beyond disp8 range (wild cleanup/reformat)
        return p
    if b == 0x89 and exe[p + 1] == 0x06:  # mov [disp16], ax (int store)
        ops.append((p, "movm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0x3E:  # mov [disp16], di: deep spill
        ops.append((p, "spill_store", "di", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x8B and exe[p + 1] == 0x0E:  # mov cx, [disp16]: restore spill
        ops.append((p, "spill_load", "cx", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x8B and exe[p + 1] == 0x3E:  # mov di, [disp16]: restore spill
        ops.append((p, "spill_load", "di", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x89 and exe[p + 1] == 0x04:  # mov [si], ax: the store half of a
        ops.append((p, "movm_ax_si"))  # computed static int-array element
        p += 2  # index chain (shl si/addsi), the write sibling of the
        return p  # existing rt-0x9C read consumer (gap 32; wild number.exe)
    if b == 0x36 and exe[p + 1 : p + 3] == b"\x89\x04":
        ops.append((p, "movm_ax_temp"))  # mov ss:[si],ax: staged by-ref CALL arg
        p += 3
        return p
    if b == 0x36 and exe[p + 1 : p + 3] == b"\xc7\x04":
        # mov ss:[si],imm16: the literal-argument sibling of movm_ax_temp --
        # a nested DEF FN call used as another call's own argument stages
        # ITS OWN literal argument via SI+SP addressing (bp doesn't point at
        # this temp frame yet), instead of going through ax first (witnessed
        # t1_fnargcall: `FN Foo(A$, FN Bar(3))`).
        ops.append((p, "movm_imm_temp", struct.unpack_from("<H", exe, p + 3)[0]))
        p += 5
        return p
    if b == 0x01 and exe[p + 1] == 0x06:  # add [disp16], ax: int combine-store,
        ops.append((p, "addm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # e.g. `X% = X% + <expr>` (disp16 sibling of addm_ax_bp,
        return p  # witnessed q_addimm)
    if b == 0x29 and exe[p + 1] == 0x06:  # sub [disp16], ax: int combine-store,
        ops.append((p, "subm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # e.g. `X% = X% - <expr>` (subtract sibling of addm_ax;
        return p  # wild number.exe)
    if b == 0x89 and exe[p + 1] == 0x46:  # mov [bp+disp8], ax: LOCAL int store
        ops.append((p, "movm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # (witnessed t1_local2)
        return p
    if b == 0x89 and exe[p + 1] == 0x86:  # mov [bp+disp16],ax: large LOCAL
        ops.append((p, "movm_ax_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # store (wild cleanup/reformat)
        return p
    if b == 0x01 and exe[p + 1] == 0x46:  # add [bp+disp8], ax: LOCAL int
        ops.append((p, "addm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # combine-store, e.g. `X% = X% + 1` (witnessed t1_local1)
        return p
    if b == 0x29 and exe[p + 1] == 0x46:  # sub [bp+disp8], ax: LOCAL int
        ops.append((p, "subm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # combine-store, e.g. `X% = X% - <expr>` (subtract sibling
        return p  # of addm_ax_bp; wild horses.exe)
    if b == 0xA3:  # mov [imm16], ax (scratch bridge)
        ops.append((p, "movmem_ax", struct.unpack_from("<H", exe, p + 1)[0]))
        p += 3
        return p
    if b == 0x8B and exe[p + 1] == 0x36:  # mov si, [disp16] (loop var -> index)
        ops.append((p, "movsim", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
        return p
    if b == 0x8B and exe[p + 1] == 0x76:  # mov si, [bp+d8]: LOCAL int -> array
        ops.append((p, "movsi_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # index (witnessed q_locidx)
        return p
    if b == 0xFF and exe[p + 1] == 0x06:  # inc word [disp16]: the integer FOR
        ops.append((p, "inc_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # step, OR a bare `X = X + 1` (INCR) outside a loop (t1_incr1)
        return p
    if b == 0xFF and exe[p + 1] == 0x46:  # inc word [bp+d8]: the LOCAL int
        ops.append((p, "inc_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # FOR step (witnessed q_locidx)
        return p
    if b == 0xFF and exe[p + 1] == 0x4E:  # dec word [bp+d8]: the LOCAL int
        ops.append((p, "dec_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # STEP -1 FOR-NEXT decrement, the descending sibling of
        return p  # inc_bp (wild horses.exe, probe q_localforstepm1)
    if b == 0x83 and exe[p + 1] == 0x7E:  # cmp word [bp+d8], imm8: the LOCAL
        bp_off, i8 = struct.unpack_from("<bb", exe, p + 2)  # int FOR-NEXT
        ops.append((p, "cmp_bpi8", bp_off, i8))  # limit test (q_locidx)
        p += 4
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
    if b == 0x81 and exe[p + 1] == 0x3E:  # cmp word [disp16], imm16: the int FOR
        d16, i16 = struct.unpack_from("<Hh", exe, p + 2)  # test when the limit
        ops.append((p, "cmp_mi16", d16, i16))  # doesn't fit a signed imm8
        p += 6  # (witnessed q_forbig)
        return p
    if b == 0x83 and exe[p + 1] == 0x06:  # add word [disp16], imm8: the integer
        d16, i8 = struct.unpack_from("<Hb", exe, p + 2)  # FOR-NEXT increment for
        ops.append((p, "addm_i8", d16, i8))  # a literal STEP other than +-1
        p += 5  # (+-1 use inc_m/dec_m instead; witnessed q_forstep)
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
    if b == 0x8C and exe[p + 1] == 0x1E:  # mov [disp16], ds: DS spill ahead of a
        ops.append((p, "movm_ds", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # near->far ES alias (SWAP of two array elements; probe q_arrswap)
        return p
    if b == 0x99:  # cwd: sign-extend ax ahead of idiv
        ops.append((p, "cwd"))
        p += 1
        return p
    if b == 0xF7 and exe[p + 1] == 0xFB:  # idiv bx: ax \ bx -> ax (rem in dx)
        ops.append((p, "idivbx"))
        p += 2
        return p
    if b == 0xF7 and exe[p + 1] == 0x3E:  # idiv word [disp16]
        ops.append((p, "idiv_m", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4
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
    if b == 0x0B and exe[p + 1] == 0xC0:  # or ax,ax: sign test of a just-loaded
        ops.append((p, "orax_self"))  # value with no memory write -- the
        p += 2  # computed-STEP FOR-NEXT continuation gate (step's sign is
        return p  # unknown at compile time, so both ascending/descending
        # comparisons are emitted and this picks one at runtime;
        # wild menu.exe/stat.exe, q_forvarstep)
    if b == 0x03 and exe[p + 1] == 0x46:  # add ax, [bp+d8]: fold a LOCAL int
        ops.append((p, "addax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # into ax (witnessed q_loccmp)
        return p
    if b == 0x2B and exe[p + 1] == 0x46:  # sub ax,[bp+d8]: normalize a
        ops.append((p, "subax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # rank-1 whole-array SUB parameter by its lower-bound cell
        return p  # (probe arrayparam6; wild zip.exe)
    if b == 0x23 and exe[p + 1] == 0x46:  # and ax, [bp+d8]: bitwise fold of a
        ops.append((p, "andax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # LOCAL int, the bp-relative sibling of andax_m (wild filepatc.exe)
        return p
    if b == 0x3B and exe[p + 1] == 0x46:  # cmp ax, [bp+d8]: relational value
        ops.append((p, "cmpax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # against a LOCAL int (witnessed q_loccmp)
        return p
    if b == 0x3B and exe[p + 1] == 0x86:  # cmp ax,[bp+disp16]: large LOCAL
        ops.append((p, "cmpax_bp", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # relational operand (wild cleanup/reformat)
        return p
    if b == 0x3B and exe[p + 1] == 0xC3:  # cmp ax, bx: integer relational where
        ops.append((p, "cmpax_bx"))  # both sides are ax-computed -- source RHS
        p += 2  # evaluates first and shuttles to bx (witnessed t1_cmpax)
        return p
    if b == 0x39 and exe[p + 1] == 0x06:  # cmp [disp16], ax: the integer FOR
        ops.append((p, "cmpm_ax", struct.unpack_from("<H", exe, p + 2)[0]))
        p += 4  # test with a VARIABLE limit (witnessed t1_fori)
        return p
    if b == 0x39 and exe[p + 1] == 0x46:  # cmp [bp+d8], ax: the LOCAL-frame
        ops.append((p, "cmpm_ax_bp", struct.unpack_from("<b", exe, p + 2)[0]))
        p += 3  # mirror of cmpm_ax (a LOCAL int FOR test with a VARIABLE
        return p  # limit, wild bmaster.exe/ifi.exe)
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
    if vec == 0x8C and exe[p + 2] in (0xE9, 0xEB):
        # RETURN <line>: the runtime vector unwinds the active GOSUB/event
        # frame, then a near jump selects the requested line
        # (t1_returnline; wild baby/crossref/help/prtguide/readme).
        if exe[p + 2] == 0xE9:
            target = p + 5 + struct.unpack_from("<h", exe, p + 3)[0]
            size = 5
        else:
            target = p + 4 + struct.unpack_from("<b", exe, p + 3)[0]
            size = 4
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
    framed compiler/library routine is also retained as ``opaque_helper``;
    every other proc-enter-shaped body remains a hard failure."""
    for i in range(len(ops) - 1, -1, -1):
        if ops[i][1] != "jmp":
            continue
        target = ops[i][2]
        if not all(o[0] < target for o in ops[i + 1 :]):
            return None
        if exe[target - 1] != 0xCB:
            return None
        body_start = ops[i][0] + 3  # jmp is always `e9 rel16`, 3 bytes
        if exe[body_start] == 0x55 and exe[body_start + 1 : body_start + 3] in (
            b"\x8b\xec",
            b"\x89\xe5",
        ):  # push bp; mov bp,sp (either encoding): a genuine proc-enter
            body = exe[body_start:target]
            if body in _OPAQUE_HELPER_BODIES:
                del ops[i + 1 :]
                ops.append(
                    (
                        body_start,
                        "opaque_helper",
                        body,
                        _OPAQUE_HELPER_PARAM_OFFSETS,
                    )
                )
                return target
            if exe[target - 2] == 0xCB:
                # ...unless the byte BEFORE the terminating CB is itself a CB.
                # TB always appends a bare far RET to a SUB ... INLINE body, so
                # a $INLINE list that already ends in its own `retf` produces
                # the doubled `CB CB` -- which no framed procedure epilogue can
                # (`pop bp; retf` ends 5D CB, `pop bp; retf N` ends with the
                # immediate). That makes it safe to accept a proc-shaped body
                # here (probe t1_inlinebp, whose list is the `push bp; mov
                # bp,sp; les di,[bp+N]; pop bp; retf` shape TBWINDOW uses).
                del ops[i + 1 :]
                ops.append((body_start, "inline_sub", exe[body_start : target - 1]))
                return target
            return None  # shape, not $INLINE -- false positive witnessed
            # in wild CVT2TB.EXE, whose OWN (unrelated, gap-19) construct
            # ends in a legitimate `pop bp; retf` (5D CB) that coincidentally
            # also satisfies the bare-target-1-byte-is-CB check above
        del ops[i + 1 :]
        ops.append((body_start, "inline_sub", exe[body_start : target - 1]))
        return target
    return None


def _scan(
    exe: bytes, start: int, dia: Dialect = TB11, commits: set[int] | None = None
) -> list[tuple[Any, ...]]:
    """Pass 1 entry point: runs `_scan_pass`, rescuing explicitly recognized
    opaque bodies (see `_try_inline_rescue`) and resuming instead of failing."""
    p = start + 3
    ops: list[tuple[Any, ...]] = []
    while True:
        try:
            return _scan_pass(exe, start, dia, commits, ops, p)
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
) -> list[tuple[Any, ...]]:
    """The actual linear decode, prologue to END. Each op is (addr, kind,
    *args); no DS knowledge needed. Raises on anything outside the
    calibrated vocabulary. `ops`/`p` are pre-seeded by `_scan` so a rescued
    SUB...INLINE body can resume a failed pass instead of restarting it."""
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
            # Segment-zero calls use the user-code origin; relocated code
            # segments use the preceding byte as their logical origin (the
            # same one-byte convention seen in wild far-call targets).
            target = (start if seg == 0 else start - 1) + off
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
            if sub == 0x86:  # PALETTE (bare form: reset to default palette,
                ops.append((p, "palette_reset"))  # zero operands; wild
                p += 3  # rsltest.exe `7020 PALETTE`)
                continue
            if sub == 0x88:  # PALETTE attr(bx), color(ax)
                ops.append((p, "palette"))
                p += 3
                continue
            if sub == 0x8A:  # PALETTE USING integer-array element at ES:SI
                ops.append((p, "palette_using"))
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
            if sub == 0x64:  # LINE INPUT <prompt_desc> flags
                d16 = struct.unpack_from("<H", exe, p + 3)[0]
                flags = exe[p + 5]
                if flags not in (0x40, 0xC0):
                    raise ValueError(
                        f"LINE INPUT trailing byte {flags:02x} at {p:#x}"
                    )
                ops.append((p, "line_input", d16, flags == 0xC0))
                p += 6
                continue
            if sub == 0x66:  # LINE INPUT #n, var$: no prompt, [0060]=n
                ops.append((p, "line_input_file"))
                p += 3
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
            if sub == 0x3A:  # implicit free of a LOCAL DYNAMIC array's heap
                # block at SUB exit (movsi <handle disp> precedes, no BASIC
                # source spelling -- probe q_localarr)
                ops.append((p, "local_arr_free"))
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
            if sub == 0x42:  # bare FILES (no string operand)
                ops.append((p, "files_bare"))
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
            if sub == 0xEE:  # WIDTH device$, n: device string pushed, n in ax
                # (t1_widthdev; wild cal.exe/cal87.exe/kinetics.exe)
                ops.append((p, "width_dev"))
                p += 3
                continue
            if sub == 0xF0:  # WIDTH #filenum,n: [0060] channel, n in ax
                ops.append((p, "width_file"))  # (t1_widthfile; wild
                p += 3  # cleanup.exe/reformat.exe)
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
                if p + 3 >= len(exe) or exe[p + 3] not in (
                    0x03,  # SCREEN ,,apage,vpage (cleanup/reformat)
                    0x08,
                    0x0C,
                    0x0E,
                    0x0F,
                ):
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
            if sub == 0x4C:  # GET$ #n, count, string$
                ops.append((p, "get_str"))
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
            if sub == 0x04:  # BLOAD f$: the bare, no-offset form (distinct
                ops.append((p, "bload0"))  # compiled shape, not merely a
                p += 3  # default arg; wild varamort.exe, probe q_bload)
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
            if sub == 0x50:  # IOCTL #n, s$: filenum via the [0060] cell,
                ops.append((p, "ioctl"))  # string pushed (t1_ioctl)
                p += 3
                continue
            if sub == 0xAC:  # PUT$ #n, s$: filenum via the [0060] cell,
                ops.append((p, "put_str"))  # string pushed (t1_putstr)
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
                    (0xDA, 3): "icomp_si32",  # m32 long-int compare: a computed
                    # LONG (`&`) array element vs. an FP-stack value (mixed-type
                    # IF/loop test, e.g. `IF A&(J%) > 5 THEN`; the [si] sibling
                    # of icomp's disp16 scalar form; wild bmaster.exe/ifi.exe,
                    # probe q_licomp)
                    (0xDD, 0): "fld_si64",
                    (0xDD, 3): "fstp_si64",
                    (0xDB, 0): "fild_si32",
                    (0xDB, 3): "fstp_si32",
                    (0xDF, 0): "fild_si",  # m16 int onto the FP stack, e.g. a
                    (0xDE, 1): "imulax_si",  # FIMUL m16 by-ref integer
                    (0xDE, 3): "icomp_si",  # m16 int compare: a computed
                    # int-array element vs. an FP-stack value (mixed-type
                    # IF/loop test; the [si] sibling of icomp's disp16 form
                    # and icomp_si32's LONG form, wild hebrew.exe)
                }.get((esc, reg))  # by-ref int param for PRINT (t1_byref1)
                if kind:
                    ops.append((p, pre + kind))
                    p = mo + 1
                    continue
                if esc == 0xD8 and reg in _FOLD_OPS:
                    ops.append((p, pre + "fold_si", _FOLD_OPS[reg]))
                    p = mo + 1
                    continue
                if esc == 0xDC and reg in _FOLD_OPS:
                    ops.append((p, pre + "fold64_si", _FOLD_OPS[reg]))
                    p = mo + 1
                    continue
                if esc == 0xDC and reg in _FOLD_OPS_N:
                    ops.append((p, pre + "fold_n64_si", _FOLD_OPS_N[reg]))
                    p = mo + 1
                    continue
                if esc == 0xD8 and reg in _FOLD_OPS_N:
                    ops.append((p, pre + "fold_n_si", _FOLD_OPS_N[reg]))
                    p = mo + 1
                    continue
                if esc == 0xDE and reg in _FOLD_OPS:  # int var/pool-literal
                    ops.append((p, pre + "ifold_si", _FOLD_OPS[reg]))  # fold
                    p = mo + 1  # LEFT via a computed index (wild filepatc.exe)
                    continue
                if esc == 0xDE and reg in _FOLD_OPS_N:
                    ops.append((p, pre + "ifold_n_si", _FOLD_OPS_N[reg]))
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
