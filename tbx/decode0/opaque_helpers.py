"""Calibrated byte fingerprints for coverage-only opaque helpers.

Each body is matched in full and only when bracketed by its declaration-skip jump; see ``opaque.find_opaque_helpers``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpaqueHelperSpec:
    """One whole-body helper fingerprint and its recovered ABI slots.

    Offsets are ordered as Turbo Basic source formals: the first argument is
    furthest from BP because the caller pushes arguments left-to-right.
    """

    body: bytes
    param_offsets: tuple[int, ...]

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
# A second CVT2TB-specific framed helper, immediately following BODY_12.
# It receives two far-pointer arguments (BP+0A, BP+06), trims trailing
# spaces in the latter, and is retained only as a whole-body opaque witness.
_OPAQUE_HELPER_BODY_13 = bytes.fromhex(
    "5589e5061ec47e063e8b160000521f268b7502268b0d81e1ff7f01ce4e3e8a04"
    "3c2075044e4975f5c57e0a3e890d1f075dcb"
)
# Six further CVT2TB directory/string helpers, each independently skipped by
# the declaration-region JMP immediately before it. Their BP slots are read
# directly from the complete bodies below.
_OPAQUE_HELPER_BODY_14 = bytes.fromhex("5589e5061ec47e063e8b160000521f268b7502268b0d81e1ff7f31db3e8a043c20750546434975f4c57e0a3e891d1f075dcb")
_OPAQUE_HELPER_BODY_15 = bytes.fromhex("5589e5061ec47e0a268b0d81e1ff7f83f9017e0351eb0531c0e979003e8b160000521f268b750231d2c47e0e268b1d83fb00740ef7c30080740bb201fdf7d343eb03bb01004bc47e06268b05a900807502eb05f7d040b60180fa01750701ce4e29deeb0201de1e0789f729d980fe017406f2aee308eb0bf3aee302eb055931c0eb1389f829f059a90080740701c84029d8eb0201d8c57e0e3e8905fc1f075dcb")
_OPAQUE_HELPER_BODY_16 = bytes.fromhex("5589e5061ec47e06268b0d81e1ff7f83f9017e02eb0531c0e939003e8b160000521f268b7502c47e0a268b1d83fb017ee51e0789f739d97f0289cb30e489d9b022f2aee304fec4ebf830c086c42401b9fffff7e1c57e0a3e89051f075dcb")
_OPAQUE_HELPER_BODY_17 = bytes.fromhex("5589e5061ec47e0a268b1d81e3ff7f83fb017d03e98d003e8b160000521f268b7502c47e06268b053d000074774889c2b103d3e881e2070039d87d6801c61e0789f7ac83fa07744f83fa06744483fa05743983fa04742e83fa03742383fa02741883fa01740d83fa007402eb37a880752eeb28a8407528eb22a8207522eb1ca810751ceb16a8087516eb10a8047510eb0aa802750aeb04a801750431c0eb08b8ffffeb03b8feffc57e063e8905fc1f075dcb")
_OPAQUE_HELPER_BODY_18 = bytes.fromhex("5589e5061ec47e0a268b0d81e1ff7f83f9007f03e9fb003e8b160000521f268b7502c47e06268b053d00007f03b801004889c281e2070051b103d3e8591e0789f701c729c141b000f3aee302eb03e9bc004f8a0539f77f6d83fa00742683fa01742883fa02742a83fa03742c83fa04742e83fa05743083fa06743283fa077434e9c3ffbb0000a8807533bb0100a840752cbb0200a8207525bb0300a810751ebb0400a8087517bb0500a8047510bb0600a8027509bb0700a8017502eb8939d37c8589daeb3bba0000a8807534ba0100a840752dba0200a8207526ba0300a810751fba0400a8087518ba0500a8047511ba0600a802750aba0700a8017503e90d0089f829f0b103d3e001d040eb0ab80000eb05b8feff89c8c57e063e8905fc1f075dcb")
_OPAQUE_HELPER_BODY_19 = bytes.fromhex("5589e5061ec47e0a268b1d81e3ff7f83fb017e773e8b160000521f268b7502c47e06268b053d000074614889c2b103d3e881e2070039d87d5201c61e0789f7ac83fa07744183fa06743883fa05742f83fa04742683fa03741d83fa02741483fa01740b83fa007402eb210c80eb1a0c40eb160c20eb120c10eb0e0c08eb0a0c04eb060c02eb020c01aaeb0431c0eb03b8ffffc57e063e8905fc1f075dcb")
_OPAQUE_HELPER_BODY_20 = bytes.fromhex("5589e5061ec47e0a268b1d81e3ff7f83fb017e773e8b160000521f268b7502c47e06268b053d000074614889c2b103d3e881e2070039d87d5201c61e0789f7ac83fa07744183fa06743883fa05742f83fa04742683fa03741d83fa02741483fa01740b83fa007402eb21247feb1a24bfeb1624dfeb1224efeb0e24f7eb0a24fbeb0624fdeb0224feaaeb0431c0eb03b8ffffc57e063e8905fc1f075dcb")
_OPAQUE_HELPER_BODY_21 = bytes.fromhex("5589e5061ec47e06268b0d81e1ff7f83f90074153e8b160000521f268b75023e8a1446b406cd21e2f61f075dcb")
# BODY_3..8 are the TBWINDOW routines whose public declarations are known
# from TBWINDO.INC.  The remaining fingerprints have only a calibrated frame
# upper bound, so retain all seven observed slots rather than invent arities.
_SEVEN_SLOTS = (0x1E, 0x1A, 0x16, 0x12, 0x0E, 0x0A, 0x06)
OPAQUE_HELPERS = (
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY, _SEVEN_SLOTS),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_2, _SEVEN_SLOTS),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_3, (0x12, 0x0E, 0x0A, 0x06)),  # QPRINT
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_3_V10, (0x12, 0x0E, 0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_4, (0x16, 0x12, 0x0E, 0x0A, 0x06)),  # QPRINTC
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_4_V10, (0x16, 0x12, 0x0E, 0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_5, (0x1A, 0x16, 0x12, 0x0E, 0x0A, 0x06)),  # QFILL
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_5_V10, (0x1A, 0x16, 0x12, 0x0E, 0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_6, (0x1A, 0x16, 0x12, 0x0E, 0x0A, 0x06)),  # QATTR
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_6_V10, (0x1A, 0x16, 0x12, 0x0E, 0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_7, (0x16, 0x12, 0x0E, 0x0A, 0x06)),  # QSAVE
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_7_V10, (0x16, 0x12, 0x0E, 0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_8, (0x16, 0x12, 0x0E, 0x0A, 0x06)),  # QREST
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_8_V10, (0x16, 0x12, 0x0E, 0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_9, _SEVEN_SLOTS),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_10, _SEVEN_SLOTS),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_11, _SEVEN_SLOTS),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_12, _SEVEN_SLOTS),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_13, (0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_14, (0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_15, (0x0E, 0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_16, (0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_17, (0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_18, (0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_19, (0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_20, (0x0A, 0x06)),
    OpaqueHelperSpec(_OPAQUE_HELPER_BODY_21, (0x0A, 0x06)),
)
