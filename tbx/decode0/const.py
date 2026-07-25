"""Shared opcode tables, framework constants and pool sentinels for the decoder."""

from __future__ import annotations

from tbx import ir


PROLOGUE = b"\xcd\xec\xba"  # INT ECh, sub BAh: TB 1.1 program-start framework
VAR_BASE = 0x120  # first scalar slot (DS offset); slots ascend by 4
COMMON_BASE = 0x110  # CHAIN-persistent COMMON band, ahead of the slot grid
POOL_EOF_GAP = 0x2C  # const-pool window starts at file EOF - 0x2C

# x87 reg-field -> source operator, for the memory-fold and stack-pop families. TB only
# ever emits the R-forms for - and / (the memory/pushed operand is always the LEFT operand),
# so /4 FSUB and /6 FDIV are deliberately absent (fail-loudly).
_FOLD_OPS = {0: "+", 1: "*", 5: "-", 7: "/"}  # D8: m32 var; DE mem: m16 const
_FOLD_OPS_N = {4: "-", 6: "/"}  # non-R FSUB/FDIV folds: mem is the RIGHT operand
_POP_OPS = {
    0xC1: "+",
    0xC9: "*",
    0xE1: "-",
    0xF1: "/",
}  # DE reg: FxxxP st(1),st (R forms)
_POP_OPS_N = {0xE9: "-", 0xF9: "/"}  # DE reg: non-R FSUBP/FDIVP -- first-pushed is LEFT

# Jcc byte -> the SOURCE relop R when the pair `Jcc +3; e9 T` encodes `IF R THEN line(T)`
# (the Jcc tests NOT R). Operands from FLD y; FCOMP [x]: x R y. The signed codes
# (7C-7F) are the integer `cmp ax,bx` form, flags = lhs - rhs (witnessed t1_cmpax).
_JCC_RELOP = {
    0x75: "=", 0x74: "<>", 0x76: "<", 0x72: "<=", 0x73: ">", 0x77: ">=",
    0x7D: "<", 0x7F: "<=", 0x7C: ">=", 0x7E: ">",
}
_NEGATE_REL = {"=": "<>", "<>": "=", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}

# String compares (INT 9A outside SELECT CASE, witnessed t1_strif): flags are
# FORWARD (lhs cmp rhs), unlike the FP shape's reversed orientation, so the
# unsigned Jcc codes need their own skip-relop rows.
_JCC_RELOP_STR = {0x75: "=", 0x74: "<>", 0x72: ">=", 0x73: "<", 0x76: ">", 0x77: "<="}
# ...and its inverse: the relop the Jcc tests TRUE, for a string compare
# MATERIALIZED as a value (`movax FFFF; Jcc; inc ax`) or consumed by a direct
# conditional GOTO. Distinct from _JCC_RELOP_TRUE's unsigned rows, which assume
# the FP shape's REVERSED (mem, top) pend_cmp: strcmp's flags are FORWARD, so
# the four ORDERING rows come out mirrored. `=`/`<>` coincide in both maps,
# which is why the only prior string-as-value shape (`V% = A$ = B$`, wild
# hebrew.exe) never distinguished them -- that path still reads
# _JCC_RELOP_TRUE and would mis-spell an ordering compare, latent and
# unwitnessed. Rows witnessed here: `=` by t1_boolstrgroup, and all four
# ordering rows (`<`, `>`, `<=`, `>=`) by t1_boolstrord.
_JCC_RELOP_STR_TRUE = {
    0x74: "=", 0x75: "<>", 0x73: ">=", 0x72: "<", 0x77: ">", 0x76: "<=",
}
# Materialization form (WHILE / boolean values): the Jcc tests the relop TRUE --
# the inverse mapping of _JCC_RELOP.
_JCC_RELOP_TRUE = {
    # unsigned rows: FP/string compares, whose pend_cmp is REVERSED (mem, top)
    0x77: "<", 0x73: "<=", 0x72: ">", 0x76: ">=", 0x74: "=", 0x75: "<>",
    # signed rows: integer cmpax_bx compares, whose pend_cmp is FORWARD
    # (lhs, rhs) -- jg taken iff lhs > rhs (witnessed t1_icmpmat, all four)
    0x7F: ">", 0x7C: "<", 0x7D: ">=", 0x7E: "<=",
}
# Relational-as-value (`C% = A% < B%`): signed jcc over `inc ax` -> source relop.
_JCC_RELOP_VALUE = {0x74: "=", 0x75: "<>", 0x7F: "<", 0x7D: "<=", 0x7C: ">", 0x7E: ">="}
# SELECT CASE IS-arm: materialized-boolean jcc cc -> source relop (selector IS <op> bound).
_IS_RELOP = {0x72: ">", 0x77: "<", 0x76: ">=", 0x73: "<=", 0x74: "=", 0x75: "<>"}

# Event-trap family (witnessed t1_ontimer/timeros/onkey/keyos/oncom/onpen/onplay):
# ON <event>[(n)] GOSUB = INT EC sub + i32 start-relative handler; per-event
# OFF/STOP/ON control triples at consecutive even subs. The n operand arrives in
# ax for COM/KEY/PLAY (and for COM/KEY control), on the FP stack for TIMER, and
# is absent for PEN. ON STRIG(n) GOSUB is REJECTED by TB 1.1 (Error 471) despite
# its handbook entry. Any trap statement also makes the compiler emit a CC (INT 3)
# event-poll hook before EVERY statement, and RETURN compiles as CB (retf).
_TRAP_GOSUB = {0x76: "COM", 0x78: "KEY", 0x7A: "PEN", 0x7C: "PLAY", 0x80: "TIMER"}

# PUT graphics-blit action byte (witnessed t1_putact/t1_putact2): 0 = XOR is the
# DEFAULT -- `PUT ..., XOR` is byte-identical to bare PUT, so 0 renders bare.
_PUT_ACTIONS = {0x00: None, 0x01: "OR", 0x02: "AND", 0x03: "PSET", 0x04: "PRESET"}
_TRAP_CTL = {
    0x1C: ("COM", "OFF"),
    0x1E: ("COM", "STOP"),
    0x20: ("COM", "ON"),
    0x5A: ("KEY", "OFF"),
    0x5C: ("KEY", "STOP"),
    0x5E: ("KEY", "ON"),
    0x8C: ("PEN", "OFF"),
    0x8E: ("PEN", "STOP"),
    0x90: ("PEN", "ON"),
    0x92: ("PLAY", "OFF"),
    0x94: ("PLAY", "STOP"),
    0x96: ("PLAY", "ON"),
    0xE2: ("TIMER", "OFF"),
    0xE4: ("TIMER", "STOP"),
    0xE6: ("TIMER", "ON"),
    # STRIG has no trap: ON STRIG GOSUB and STRIG STOP are rejected (Error 471)
    # by both TB 1.1 and TB 1.0; only the GW-BASIC-heritage ON/OFF forms exist.
    0xD8: ("STRIG", "OFF"),
    0xDA: ("STRIG", "ON"),
}

# Runtime intrinsic vectors (canonical 1.1 numbering): unary FP-top -> FP-top calls.
_FN_VECS = {0xAB: "INT"}

# INT EDh dispatcher subs (canonical; the EC sub-shift applies): unary
# FP-top -> ax-integer intrinsics, bridged back to FP via a3 2c / FILD.
_FNAX_SUBS = {0x46: "SGN", 0x2C: "PEEK"}
_AXARG_SUBS = {
    0x3C: "REG",
    0x2E: "PEN",  # ax-arg, ax-returning INT ED
    0x48: "STICK",
    0x4A: "STRIG",  # intrinsics
    0x10: "EOF",
    0x28: "LPOS",
    0x24: "LOC",  # file position, NOT INP -- INP(n) always compiles inline
    # (movdx/xorah/in_al; witnessed t1_inpf) and never reaches this vector;
    # oracle-confirmed via `X = LOC(1)` reproducing this exact byte shape
    # (probe q_loc1, wild be.exe/styllist.exe)
}
_AX0_SUBS = {
    0x0A: "CSRLIN",
    0x1A: "INSTAT",  # zero-arg, ax-returning (POS's and
    0x38: "POS",
    0x30: "PLAY",
}  # PLAY's dummy args are compile-time only)
_FP0_SUBS = {
    0x4C: "TIMER",
    0x2A: "MTIMER",  # zero-arg, FP-stack-returning
    0x3E: "RND",
}  # (bare RND; RND(x) is ED 40)
# INT 3E transcendental dispatcher: CD 3E <selector>, FP-stack unary (t1_trig/t1_explog)
_TRANSCEND = {
    0x00: "SIN",
    0x02: "COS",
    0x04: "TAN",
    0x06: "ATN",
    0x08: "LOG",
    0x0C: "LOG10",
    0x0E: "EXP",
}
# Two-FP-arg ax-returning intrinsics: x, y pushed on the FP stack (x first).
_FNAX2_SUBS = {0x36: "POINT"}

# String-arg numeric-result intrinsic vectors (raw INT vecs, not EC/ED-scoped).
# ASC/CVI return in ax (movmem_ax+fild bridge); VAL/CVD/CVL/CVS return on the FP stack.
_STR2NUM_VECS = {
    0xA6: "ASC",
    0xAC: "VAL",
    0xA7: "CVD",
    0xA8: "CVI",
    0xA9: "CVL",
    0xAF: "CVL",  # TB 1.0's raw A9 after service-vector canonicalization
    0xAA: "CVS",
}
# INT ED sub-vectors that are string-arg numeric-result intrinsics (LEN=0x22 in the
# compiled TB 1.1 bytecode; INSTR takes haystack+needle from the string stack).
_ED_STR_SUBS = {0x22: "LEN", 0x1C: "INSTR"}
# String-result intrinsic vectors (raw INT vecs) + INT EE dispatcher subs.
_STRFN_VECS = {
    0xB3: "CHR$",
    0xAD: "LEFT$",
    0xB2: "RIGHT$",
    0xB1: "MID$",
    0xB0: "MID$2",  # 2-arg MID$(s$, start): start in ax (witnessed t1_mid2)
    0xB4: "MKD$",
    0xB5: "MKI$",
    0xB6: "MKL$",
    0xB7: "MKS$",
}
_EE_STRFN_SUBS = {
    0x00: "BIN$",
    0x02: "COMMAND$",  # zero-arg (witnessed t1_cmd)
    0x0C: "HEX$",
    0x10: "INPUT$",  # keyboard form: n in ax (witnessed t1_inp5)
    0x12: "INPUT$F",  # file form INPUT$(n,f): n in bx, f in ax (t1_inp5)
    0x16: "LCASE$",
    0x1C: "OCT$",
    0x1E: "SPACE$",
    0x20: "STR$",
    0x22: "STRING$",
    0x24: "STRING$S",  # STRING$(n, s$): n in ax, s$ on sstack (t1_strs2)
    0x28: "UCASE$",
    0x0E: "INKEY$",
    0x04: "DATE$",
    0x08: "ENVIRON$",  # string arg via sstack (t1_envdev)
    0x0A: "ERDEV$",  # zero-arg device-error detail string (t1_envdev)
    0x26: "TIME$",
    0x14: "IOCTL$",  # IOCTL$(n): filenum in ax (t1_ioctlfn); sits alphabetically
    # between INPUT$F (0x12) and LCASE$ (0x16), the gap gap-17 flagged as
    # worth checking first when diagnosing an "unhandled INT EE sub" error
}

# TAB(n)/SPC(n) print item vectors (canonical): name + leg (None = console,
# True = file, "lprint" = printer). The arg rides in ax (literal b8 or the
# FISTP-[2C] bridge). Printer TAB witnessed t1_ltab.
_TABSPC_VECS = {
    0xC7: ("TAB", False),
    0xC9: ("TAB", True),
    0xC8: ("TAB", "lprint"),
    0xC4: ("SPC", False),
    0xC6: ("SPC", True),
    0xC5: ("SPC", "lprint"),
}


MARKER = b"\x00\x80\x16\x00"  # always immediately precedes the const pool
ARR_BLOCK = 0x36  # per-array DGROUP bookkeeping block size


def _pp_commas(pp) -> tuple[int, ...] | None:
    """gap-aligned comma counts for a pend_print dict (len(items)+1 slots:
    slot 0 = commas before the first item, slot i+1 = commas after item i),
    or None when every separator is the default ';' (see ir.Print.commas)."""
    cs = pp.get("commas")
    if not cs:
        return None
    return tuple(cs.get(i, 0) for i in range(len(pp["items"]) + 1))


_FREAD = ("fread",)  # sentinel: an INPUT#-parsed value awaiting its
# store; the consuming store names the target.
# Identity-compared, never an Expr.
_READDATA = ("readdata",)  # sentinel: a DATA item awaiting its READ store;
# the consuming store names the target.
_INPUTREAD = ("inputread",)  # sentinel: a console-INPUT-parsed value whose
# target is an array element -- the index computation runs between the
# read and the element store, so the store names the target (t1_inparr).
_LINEINPUTREAD = ("lineinputread",)  # sentinel: LINE INPUT's string sibling
# of _INPUTREAD -- a computed string-array-element target (wild cal87.exe).


_PREC = ir._PREC


# IDE compiler-flag toggles: bitmask byte at prologue-0x73, one bit per Options-menu
# entry in menu order (witnessed in both dialects), keyed by the menu hotkey letter.
_TOGGLE_BITS = ((0x80, "8"), (0x40, "K"), (0x20, "B"), (0x10, "O"), (0x08, "S"))
_TOGGLE_NAMES = {
    "8": "8087 required",
    "K": "Keyboard break",
    "B": "Bounds",
    "O": "Overflow",
    "S": "Stack test",
}
