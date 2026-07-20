"""The decoder: TB-compiled EXE -> typed IR statements.

Walks the user-code region of a Turbo Basic 1.1 or 1.0 EXE (dialect
auto-detected from the prologue and normalized at scan time). TB compiles with
FP *emulation*: INT 34h+n stands for x87 ESC opcode D8h+n, with the
modrm/displacement bytes following raw. Control flow is raw x86 interleaved
with the INT stream: `e9` (GOTO / FOR glue), `Jcc rel8` (IF / loop tests), and
`test word [m],imm` (FOR's step sign test). The user program starts at the
framework prologue INT ECh sub BAh and lives INSIDE DGROUP.

DGROUP layout: scalar variables at DS:0120 upward in 4-byte slots (textual
first-appearance order; FOR adds hidden limit/step slots at var-4/var-8); the
integer const pool window starts at align16(0x120 + 4*nvars) + 4, and that
window's FILE position is always EOF - 0x2C. The decoder scans instructions
first (collecting variable slots), derives the DS file base from the pool
rule, then builds IR with resolved pool literals.

The vocabulary is strictly calibrated: every recognized byte pattern is
witnessed by a corpus fixture whose decompile-recompile round trip reproduces
the original EXE byte-for-byte. Anything outside that vocabulary raises (fail
loudly, never decode wrong).
"""

from tbx.decode0.const import (
    ARR_BLOCK,
    MARKER,
    POOL_EOF_GAP,
    PROLOGUE,
    VAR_BASE,
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
    _FREAD,
    _IS_RELOP,
    _JCC_RELOP,
    _JCC_RELOP_TRUE,
    _JCC_RELOP_VALUE,
    _NEGATE_REL,
    _POP_OPS,
    _POP_OPS_N,
    _PREC,
    _PUT_ACTIONS,
    _READDATA,
    _STR2NUM_VECS,
    _STRFN_VECS,
    _TABSPC_VECS,
    _TOGGLE_BITS,
    _TOGGLE_NAMES,
    _TRANSCEND,
    _TRAP_CTL,
    _TRAP_GOSUB,
)
from tbx.decode0.dialect import DIALECTS, Dialect, TB10, TB11, _try_swap, find_prologue
from tbx.decode0.scan import (
    _OPAQUE_HELPER_BODY,
    _grp,
    _orient,
    _rgrp,
    _scan,
    _try_inline_rescue,
)
from tbx.decode0.datapool import (
    _data_find_frame,
    _data_find_sentinel,
    _is_rt_slot,
    _parse_static_slot,
    _read_data_pool,
)
from tbx.decode0.layout import (
    _blit_at,
    _fill_lines,
    _layout,
    _line_table,
    _pool_has_word,
)
from tbx.decode0.meta import Program, _meta_stmts, _toggles, toggle_names
from tbx.decode0.lift import (
    _apply_exit_folds,
    _fold_body,
    _fold_if,
    _has_jmps_back,
    _inline_safe,
    _is_for_header,
    _lift_bool_do_tail,
    _lift_bool_tail,
    _lift_do_tail,
    _lift_midblock_troff,
    _lift_next,
    _lift_while,
    _match_bool_term1,
    _resolve_targets,
)
from tbx.decode0.rename import _slot, _str_lit, canonical_rename
from tbx.decode0.core import decode_user_code

__all__ = [
    "ARR_BLOCK",
    "DIALECTS",
    "Dialect",
    "MARKER",
    "POOL_EOF_GAP",
    "PROLOGUE",
    "Program",
    "TB10",
    "TB11",
    "VAR_BASE",
    "canonical_rename",
    "decode_user_code",
    "find_prologue",
    "toggle_names",
]
