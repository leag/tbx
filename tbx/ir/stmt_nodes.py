"""Statement IR nodes (frozen dataclasses).

Pure data -- the rendering logic (`unparse_stmt`) lives in the sibling `unparse`
module. Statement-level blocks (IfBlock/SelectCase/SubDef/DefFn) are emitted by
`tbx.emit0`, not `unparse_stmt`.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from tbx.ir.expr_nodes import Expr, Stmt


@dataclass(frozen=True)
class Assign:
    """target = value. `target` is a Var or ArrayRef; `value` is any Expr."""

    target: object  # Var | ArrayRef
    value: object  # Expr


@dataclass(frozen=True)
class End:
    """The END statement (TB framework INT ECh sub 32h)."""


@dataclass(frozen=True)
class Tron:
    """TRON: compile-time trace directive. Emits no code of its own; recovered from
    the CD 97 <lineno u16> hooks it injects before every statement in its region."""


@dataclass(frozen=True)
class Troff:
    """TROFF: closes a TRON region. Emits no code, but its own line still carries a
    trace hook -- the region's last hook -- which is how the decoder places it."""


@dataclass(frozen=True)
class Goto:
    target: object  # statement index (int); ("addr", a) sentinel pre-resolve


@dataclass(frozen=True)
class IfGoto:
    """Canonical IF: `IF cond THEN <line>`. Both TB sugars compile to the same byte
    shape, so this single form is byte-exact."""

    cond: object  # RelOp
    target: object  # statement index (int); ("addr", a) sentinel pre-resolve


@dataclass(frozen=True)
class For:
    var: object  # Var
    init: object  # Expr
    limit: object  # Expr
    step: object  # Expr (Lit(1) when implicit)


@dataclass(frozen=True)
class NextStmt:
    var: object  # Var


@dataclass(frozen=True)
class Gosub:
    target: object  # statement index (int); ("addr", a) sentinel pre-resolve


@dataclass(frozen=True)
class Return:
    """RETURN (x86 `c3` ret near)."""


@dataclass(frozen=True)
class While:
    """WHILE cond -- top-of-loop test via the boolean-materialization idiom."""

    cond: object  # RelOp


@dataclass(frozen=True)
class Wend:
    """WEND (jmp short back to the WHILE test)."""


@dataclass(frozen=True)
class Do:
    """DO loop head. kind None = bare `DO` (tail-test loop); "WHILE"/"UNTIL" = head-test
    `DO WHILE/UNTIL cond`. Pre-test WHILE loops canonicalize to `DO WHILE` (byte-identical
    to WHILE/WEND -- modern-BASIC form)."""

    kind: object  # None | "WHILE" | "UNTIL"
    cond: object = None  # RelOp/LogOp (head-test) | None (bare DO)


@dataclass(frozen=True)
class Loop:
    """DO loop foot. kind None = bare `LOOP` (head-test loop); "WHILE"/"UNTIL" = tail-test
    `LOOP WHILE/UNTIL cond`."""

    kind: object  # None | "WHILE" | "UNTIL"
    cond: object = None  # RelOp/LogOp (tail-test) | None (bare LOOP)


@dataclass(frozen=True)
class ExitFor:
    """EXIT FOR -- early jump to a FOR loop's exit (the address after NEXT)."""


@dataclass(frozen=True)
class ExitLoop:
    """EXIT LOOP -- early jump to a DO loop's exit (the address after LOOP)."""


@dataclass(frozen=True)
class ExitSub:
    """EXIT SUB -- early jump to a SUB's ProcRet."""


@dataclass(frozen=True)
class ExitDef:
    """EXIT DEF -- early jump to a multi-line DEF FN's FnRet."""


@dataclass(frozen=True)
class IfBlock:
    """Multi-line IF ... THEN / ELSEIF / ELSE / END IF. arms is a tuple of (cond, body);
    arms[0] is the IF, arms[1:] are ELSEIF arms. else_body is None or the ELSE body.
    Always rendered as a block (single-line IFs stay ir.IfInline)."""

    arms: tuple[Any, ...]  # (cond, tuple[Stmt, ...]) pairs
    else_body: object = None  # tuple[Stmt, ...] | None


@dataclass(frozen=True)
class CaseArm:
    """One `CASE` line: one or more guards sharing a body (`CASE 1, 3, 5` = 3 guards)."""

    guards: tuple[Any, ...]  # CaseValue | CaseRange | CaseIs
    body: tuple[Stmt, ...]


@dataclass(frozen=True)
class SelectCase:
    """SELECT CASE <selector> ... END SELECT. arms is a tuple of CaseArm; case_else is
    the trailing CASE ELSE body (tuple of Stmt) or None. Always a block."""

    selector: object  # Expr
    arms: tuple[CaseArm, ...]
    case_else: object = None  # tuple[Stmt, ...] | None


@dataclass(frozen=True)
class Run:
    """RUN — bare form restarts the program from the beginning (`eb`/`e9` jump
    to `start`); RUN file$ loads and runs a different program (push + EC sub
    C4), `file` is None for the bare form."""

    file: object = None  # StrLit | Var ($) | None


@dataclass(frozen=True)
class Dim:
    """DIM name(bounds)[, name2(bounds2)...]. Constant bounds emit no code
    (compile-time DGROUP allocation; bounds as ints); variable bounds compile
    to the runtime sub-2C/2E bracket (bounds as Exprs). A comma list is ONE
    statement -- one trailing commit marker -- so the extra arrays ride in
    `also` as (name, bounds) pairs."""

    name: str
    bounds: tuple[Any, ...]  # int | Expr (1 or 2 entries)
    also: tuple[Any, ...] = ()  # (name, bounds) comma-list tail
    dynamic: bool = field(default=False, repr=False)  # preserve explicit runtime allocation


@dataclass(frozen=True)
class Erase:
    """ERASE name -- DIM-style ES:SI block prefix + EC sub 36."""

    name: str


@dataclass(frozen=True)
class OptionBase:
    """OPTION BASE n. Emits no code; changes DIM lower-bound cells and far-IDX
    subtrahends, so it is byte-significant and must be re-emitted."""

    n: int  # 0 | 1


@dataclass(frozen=True)
class DefType:
    """DEFINT/DEFSTR/DEFSNG/DEFDBL <letter-range>: default-type declaration.
    Emits no code at all (confirmed via the oracle: DEFINT A-Z and DEFSTR S
    compile byte-IDENTICAL programs once every variable carries an explicit
    type suffix, which tbx's own emitted source always does) -- so which
    keyword/letter-range the original used is unrecoverable AND inconsequential
    for a byte-exact recompile. Recovered only from an error-trap line-table
    orphan with no DATA pool to explain it (wild metric.exe); always rendered
    as the fixed canonical spelling `DEFSNG A-Z`, chosen arbitrarily since any
    spelling recompiles identically."""


@dataclass(frozen=True)
class Print:
    """PRINT [#n,] item[; item...][;] -- item vectors (console: string BE / numeric BB;
    file: string C0 / numeric BD after [0060]=n), flush (B8/BA) only without a trailing
    ';'. A single non-tuple item is normalized to a 1-tuple."""

    items: Any  # tuple[StrLit | numeric Expr, ...]; a single item is normalized below
    newline: bool = True
    file: object = None  # int | None
    # zone-advance separators (INT C1, witnessed t1_pcomma/t1_pcomma2):
    # None = all ';', else a gap-aligned tuple[int] of len(items)+1 comma
    # counts -- slot 0 leads the first item (`PRINT ,,X`), slot i+1 follows
    # item i (2 = a skipped zone), and the last slot is the trailing
    # separator when newline=False
    commas: Any = None

    def __post_init__(self):
        if not isinstance(self.items, tuple):
            object.__setattr__(self, "items", (self.items,))


@dataclass(frozen=True)
class PrintUsing:
    """PRINT [#n,] USING fmt; v[; v...] -- push fmt desc + CA begin, then per value
    FLD + CB emit + the string item vector (BE console / C0 file / BF printer,
    the last spelling LPRINT USING, witnessed t1_lpusing)."""

    fmt: object  # StrLit | Var ($)
    values: tuple[Expr, ...]
    file: object = None  # int | None
    newline: bool = True
    lprint: bool = False  # LPRINT USING (printer item vector BF)


@dataclass(frozen=True)
class Kill:
    """KILL file$ -- push + EC sub 60."""

    file: object  # StrLit | Var ($)


@dataclass(frozen=True)
class Play:
    """PLAY music$ -- push + EC sub 98."""

    music: object  # StrLit | Var ($)


@dataclass(frozen=True)
class Chdir:
    """CHDIR path$ -- push + EC sub 10."""

    path: object  # StrLit | Var ($)


@dataclass(frozen=True)
class Mkdir:
    """MKDIR path$ -- push + EC sub 6A."""

    path: object  # StrLit | Var ($)


@dataclass(frozen=True)
class Rmdir:
    """RMDIR path$ -- push + EC sub C2."""

    path: object  # StrLit | Var ($)


@dataclass(frozen=True)
class Environ:
    """ENVIRON s$ -- push + EC sub 34 (s$ is "VAR=value")."""

    s: object  # StrLit | Var ($)


@dataclass(frozen=True)
class Shell:
    """SHELL cmd$ -- push + EC sub CE."""

    cmd: object  # StrLit | Var ($)


@dataclass(frozen=True)
class Chain:
    """CHAIN file$ -- push + EC sub 0E."""

    file: object  # StrLit | Var ($)


@dataclass(frozen=True)
class OnGoto:
    """ON <selector> GOTO l1, l2, ... -- computed jump (selector from ax, absolute
    target table). `targets` hold statement indices after resolve."""

    selector: object  # Expr
    targets: tuple[object, ...]  # int after resolve; ("addr", a) sentinel pre-resolve


@dataclass(frozen=True)
class OnGosub:
    """ON <selector> GOSUB l1, l2, ... -- computed call (selector from ax)."""

    selector: object  # Expr
    targets: tuple[object, ...]  # int after resolve; ("addr", a) sentinel pre-resolve


@dataclass(frozen=True)
class OnError:
    """ON ERROR GOTO <line|0> (INT ECh sub 70h + i32 start-relative handler
    address; -1 disables = GOTO 0). `target` is a statement index after
    resolve; None renders as GOTO 0."""

    target: object  # int | ("addr", a) | None


@dataclass(frozen=True)
class Resume:
    """RESUME [NEXT | <line>] (INT ECh sub BCh prefix, then sub BEh = bare /
    sub C0h = NEXT / a short jmp to the target statement = line form).
    `target` is a statement index after resolve."""

    next_: bool = False
    target: object = None  # int | ("addr", a) | None


@dataclass(frozen=True)
class ErrorStmt:
    """ERROR n -- raise error code n (code in ax + INT ECh sub 3Ch)."""

    code: object  # Expr


@dataclass(frozen=True)
class RegSet:
    """REG n, value -- store into the register buffer (n in ax, value on the FP
    stack, INT ECh sub B6h). The read side REG(n) is an ax-arg intrinsic (ED 3C)."""

    n: object  # Expr
    value: object  # Expr


@dataclass(frozen=True)
class CallInterrupt:
    """CALL INTERRUPT n -- software interrupt via the register buffer (n in ax,
    INT ECh sub 0Ch)."""

    n: object  # Expr


@dataclass(frozen=True)
class CallAbsolute:
    """CALL ABSOLUTE addr -- call a machine-code routine at DEF SEG:addr (address
    on the FP stack, INT ECh sub 0Ah)."""

    addr: object  # Expr


@dataclass(frozen=True)
class OnTrap:
    """ON <event>[(n)] GOSUB <line> -- event trap handler install (INT ECh subs
    76 COM / 78 KEY / 7A PEN / 7C PLAY / 80 TIMER + i32 start-relative handler;
    n in ax for COM/KEY/PLAY, on the FP stack for TIMER, absent for PEN).
    `target` is a statement index after resolve."""

    event: str  # "COM" | "KEY" | "PEN" | "PLAY" | "TIMER"
    n: object  # Expr | None
    target: object  # int | ("addr", a)


@dataclass(frozen=True)
class TrapCtl:
    """<event>[(n)] ON|OFF|STOP -- trap control (per-event INT ECh OFF/STOP/ON
    sub triple; n in ax for COM/KEY)."""

    event: str
    n: object  # Expr | None
    mode: str  # "ON" | "OFF" | "STOP"


@dataclass(frozen=True)
class KeyList:
    """KEY LIST (INT ECh sub 56h, zero operand)."""


@dataclass(frozen=True)
class Mtimer:
    """MTIMER -- reset the microtimer (INT ECh sub 6Ch, zero operand)."""


@dataclass(frozen=True)
class GetGfx:
    """GET (x1,y1)-(x2,y2), arr -- graphics blit read (coords on the FP stack,
    array descriptor via es:si prologue + INT ECh sub 4Ah + trail byte 00)."""

    x1: object
    y1: object
    x2: object
    y2: object
    array: str


@dataclass(frozen=True)
class PutGfx:
    """PUT (x,y), arr[, action] -- graphics blit write (INT ECh sub AAh + action
    byte: 0 = XOR, the default, rendered bare (byte-identical alias); 3 = PSET)."""

    x: object
    y: object
    array: str
    action: object = None  # str | None


@dataclass(frozen=True)
class DateTimeSet:
    """DATE$/TIME$ = s$ set-statement (string pushed via vec 9C; INT EC 24 / E0)."""

    name: str  # "DATE$" | "TIME$"
    value: object  # string Expr


@dataclass(frozen=True)
class IfInline:
    """IF cond THEN <stmt[: stmt...]> -- the inline-body form: dispatch pair
    `75 +3; e9 SKIP` (jump past the body when false), body statements follow.
    Required for compound conditions, whose negation does not
    materialize to the same bytes; simple conditions canonicalize to IfGoto."""

    cond: object  # RelOp | LogOp
    body: tuple[Stmt, ...]


@dataclass(frozen=True)
class Clear:
    """CLEAR (INT ECh sub 14h, zero operand) -- clears all variables / closes files."""


@dataclass(frozen=True)
class Beep:
    """BEEP (INT ECh sub 00h, zero operand)."""


@dataclass(frozen=True)
class Randomize:
    """RANDOMIZE seed (INT ECh sub B0h) -- the seed expression is on the FP stack."""

    seed: object  # Expr


@dataclass(frozen=True)
class Delay:
    """DELAY secs (INT ECh sub 28h init + 2Ah poll loop) -- the count is on the FP stack;
    the poll op and its backward Jcc are consumed as the loop tail."""

    secs: object  # Expr


@dataclass(frozen=True)
class Sound:
    """SOUND freq, dur (INT ECh sub D0h) -- freq in ax (mov ax,imm), dur on the FP stack."""

    freq: object  # Expr
    dur: object  # Expr


@dataclass(frozen=True)
class Out:
    """OUT port, value -- port via bx->dx (mov dx,bx), value in ax, `out dx,al`."""

    port: object  # Expr
    value: object  # Expr


@dataclass(frozen=True)
class Wait:
    """WAIT port, mask[, xor] -- mask via bx, port via ax->dx, inline poll loop
    `in al,dx; and al,bl; jz back`. Three-arg form shuffles and-mask to cx and
    xor-mask to bx (`mov cx,bx; mov bx,ax`); poll is `in; xor al,bl; and al,cl; jz`."""

    port: object  # Expr
    mask: object  # Expr
    xor: object = None  # Expr | None


@dataclass(frozen=True)
class Poke:
    """POKE addr, value (INT ECh sub A2h) -- addr on the FP stack, value in ax."""

    addr: object  # Expr
    value: object  # Expr


@dataclass(frozen=True)
class DefSeg:
    """DEF SEG [= seg]. Set form: seg on the FP stack + INT ECh sub 26h.
    Bare form (restore DS): `mov [001C], ds`."""

    seg: object  # Expr | None


@dataclass(frozen=True)
class Palette:
    """PALETTE attr, color (INT ECh sub 88h) -- attr in bx, color in ax."""

    attr: object  # Expr
    color: object  # Expr


@dataclass(frozen=True)
class View:
    """VIEW [SCREEN] (x1,y1)-(x2,y2)[, color][, border] -- integer coords staged
    through the system cells [0088]=x1 [0094]=y1 [00A0]=x2 [00AC]=y2, committed by
    INT ECh sub EAh + flag (04 base | 08 SCREEN | 02 color in [00B8] | 01 border
    in [00C4])."""

    x1: object
    y1: object
    x2: object
    y2: object
    screen: bool = False
    color: object = None  # Expr | None
    border: object = None  # Expr | None


@dataclass(frozen=True)
class Window:
    """WINDOW [SCREEN] (x1,y1)-(x2,y2) -- world coords are FP: pushed x1,y1,x2,y2 and
    FSTP'd into [00AC]=y2 [00A0]=x2 [0094]=y1 [0088]=x1, then INT ECh sub F2h + flag
    (01 base | 02 SCREEN)."""

    x1: object
    y1: object
    x2: object
    y2: object
    screen: bool = False


@dataclass(frozen=True)
class Pset:
    """PSET/PRESET [STEP] (x,y)[, color] (INT ECh sub A4h + flag: 02=PSET,
    01=PRESET, 04=with color in [0088], 08=STEP). PRESET-with-color is
    byte-identical to PSET-with-color (the color arg overrides the PSET/PRESET
    default) -- canonical render is PSET."""

    x: object
    y: object
    color: object = None  # Expr | None
    preset: bool = False
    step: bool = False


@dataclass(frozen=True)
class LineStmt:
    """LINE [[STEP] (x1,y1)]-[STEP] (x2,y2)[, color][, B|BF][, style] (INT ECh
    sub 62h + flag: 40 first point given explicitly | 20 STEP on first point |
    10 STEP on second | 08 color in [00A0] | 04 B | 02 F | 01 style word in
    [00AC]). When 40 is clear the first point is omitted entirely (`LINE
    -(x2,y2)`, using the last graphics position) and x1/y1 are None -- wild
    cal87.exe. When 40 is set, the first pair is FSTP'd into [0088]/[0094];
    the second pair is always left on the FP stack."""

    x1: object  # Expr | None (None = first point omitted)
    y1: object  # Expr | None (None = first point omitted)
    x2: object
    y2: object
    color: object = None  # Expr | None
    box: str = ""  # "" | "B" | "BF"
    step1: bool = False
    step2: bool = False
    style: object = None  # Expr | None (canonically &H-rendered)


@dataclass(frozen=True)
class Circle:
    """CIRCLE [STEP] (x,y), r[, color][, start][, end][, aspect] (INT ECh sub 12h
    + flag: 10 STEP | 08 color in [0088] | 04 start in [0094] | 02 end in [00A0]
    | 01 aspect in [00AC]). x, y, r all on the FP stack; start/end/aspect are FP
    cell stores."""

    x: object
    y: object
    r: object
    color: object = None  # Expr | None
    start: object = None  # Expr | None
    end: object = None  # Expr | None
    aspect: object = None  # Expr | None
    step: bool = False


@dataclass(frozen=True)
class Paint:
    """PAINT (x,y)[, paint][, border] (INT ECh sub 84h + flag: 0x01 = paint attr
    in [0088], 0x02 = border attr in [0094]). x, y on the FP stack."""

    x: object
    y: object
    paint: object = None  # Expr | None
    border: object = None  # Expr | None


@dataclass(frozen=True)
class Draw:
    """DRAW cmd$ (INT ECh sub 30h; string pushed like CHDIR's operand)."""

    cmd: object  # Expr (string)


@dataclass(frozen=True)
class Swap:
    """SWAP a, b (inline mov/xchg/mov template) -- two scalar Vars exchanged."""

    a: object  # Var
    b: object  # Var


@dataclass(frozen=True)
class Width:
    """WIDTH cols (INT ECh sub ECh) -- cols in ax (mov ax,imm).
    WIDTH device$, cols (INT ECh sub EEh) -- device string pushed first,
    cols in ax (device is not None; witnessed t1_widthdev)."""

    cols: object  # Expr
    device: object = None  # Expr | None -- device$ in `WIDTH device$, cols`


@dataclass(frozen=True)
class Key:
    """KEY ON / KEY OFF (INT ECh sub 54h/52h) -- soft-key display toggle."""

    on: bool


@dataclass(frozen=True)
class KeyDef:
    """KEY n, s$ (INT ECh sub 58h) -- define function-key macro n: n in ax,
    the macro string pushed (witnessed t1_key)."""

    num: object  # Lit
    text: object  # string Expr


@dataclass(frozen=True)
class Screen:
    """SCREEN mode[,burst][,apage][,vpage] (INT ECh sub C6h): the trailing tag
    byte is a presence mask (08 mode / 04 burst / 02 apage / 01 vpage) and the
    arguments ride in cells [88]/[94]/[A0]/[AC] (witnessed t1_screenb,
    t1_screenp; [88] is shared with COLOR fg)."""

    mode: object  # Expr
    burst: object = None  # Expr | None
    apage: object = None  # Expr | None
    vpage: object = None  # Expr | None


@dataclass(frozen=True)
class Write:
    """WRITE [#n,] item[, item...] (INT ECh sub F4h items, F8h separators, flushed on
    print-flush B8h/BAh). Comma-separated item vector; file leg via [0060]=n."""

    items: tuple[Expr, ...]
    file: object = None  # int | None


@dataclass(frozen=True)
class Lprint:
    """LPRINT [item[; item...]][;] (item vector BCh, flush B9h) -- printer output;
    semicolon-separated item vector like PRINT."""

    items: tuple[Expr, ...]
    newline: bool = True


@dataclass(frozen=True)
class Cls:
    """CLS (INT ECh sub 1Ah, identical in both dialects)."""


@dataclass(frozen=True)
class Locate:
    """LOCATE [row][,col][,cursor[,start,stop]] -- omitted leading arguments
    produce no row/column runtime call; cursor and shape are independent legs."""

    row: object  # Expr (Lit) | None
    col: object  # Expr (Lit) | None
    cursor: object = None  # Expr (Lit) | None
    start: object = None  # Expr (Lit) | None
    stop: object = None  # Expr (Lit) | None


@dataclass(frozen=True)
class Color:
    """COLOR [fg][,bg][,border] -- stores to fixed DGROUP cells + `cd ec 22 <mask>`."""

    fg: object = None  # Expr (Lit) | None
    bg: object = None  # Expr (Lit) | None
    border: object = None  # Expr (Lit) | None


@dataclass(frozen=True)
class Input:
    """INPUT [;] ["prompt"{;|,}] var[, var...] -- `cd ec 4e <prompt_desc> <flags>` +
    one read call per target; flags: 0x0040 comma separator (no "? "), 0x0080
    leading `INPUT;` (t1_inpsemi), low bits = extra-target count and
    `0x4000 >> k` set = target k numeric (t1_inpmulti/t1_inpmixed)."""

    prompt: object  # StrLit | None
    var: object  # Var | ArrayRef, or a tuple of them (multi-target)
    comma: bool = False  # prompt separator: True = ',' (suppresses "? ")
    semi: bool = False  # leading `INPUT;`


@dataclass(frozen=True)
class LineInput:
    """LINE INPUT [;] ["prompt";] var$ -- `cd ec 64 <prompt_desc> flags` +
    strassign. Flag 80 is the leading semicolon (combined value C0), mirroring
    INPUT's keep-cursor-on-line flag.

    LINE INPUT #n, var$ (file variant) is `cd ec 66` (no operand; [0060]
    carries the file number, same convention as OPEN/PRINT#/INPUT#) +
    strassign -- no prompt, so `prompt` and `file` are mutually exclusive
    (wild billadd.exe et al., probe q_lineinputf)."""

    prompt: object  # StrLit | None
    var: object  # Var ($)
    file: object = None  # int | None
    semi: bool = False


@dataclass(frozen=True)
class Open:
    """OPEN "m",#n,file$[,reclen] -- [0060]=n, push file + mode, ax=reclen, sub 82.

    ax carries the record length; 0x80 is the compiler default and lifts to
    reclen=None (an explicit ",128" is byte-identical, so it normalizes away;
    witnessed q_open2 -> t1_open2 with reclen 64).

    `OPEN file$ FOR mode AS #n` (for_as=True) compiles to genuinely different
    bytes than the comma form -- the FOR-keyword desugars to a packed 1-char
    string at a fixed scratch cell instead of a real pooled literal, and the
    push order/[0060] placement differ too -- so it is NOT normalized away;
    the emitter must reproduce the original spelling (wild nvginst.exe,
    witnessed q_openfor)."""

    mode: object  # StrLit
    num: int  # file number
    file: object  # StrLit | Var ($)
    reclen: object = None  # Lit | None (None = default 128)
    for_as: bool = False  # `OPEN file$ FOR mode AS #n` vs `OPEN "m",#n,file$`


@dataclass(frozen=True)
class InputFile:
    """INPUT #n, v[, v...] -- [0060]=n via ax, one read sub per target."""

    num: int  # file number
    vars: tuple[Expr, ...]  # Var or ArrayRef targets


@dataclass(frozen=True)
class Close:
    """CLOSE #n -- ax=n, sub 18; bare CLOSE (all channels) is its own sub 16
    and lifts to num=None (witnessed t1_close). n is usually a literal
    (int) but can be a variable/expression too (wild metric.exe: `CLOSE
    #N`, N an int variable -- probe q_closevar)."""

    num: object = None  # int | Expr | None (None = close all)


@dataclass(frozen=True)
class Reset:
    """RESET -- close all open files (no operands)."""


@dataclass(frozen=True)
class Files:
    """FILES [spec$] -- bare and filespec directory listings."""

    spec: object = None  # StrLit | Var ($) | None


@dataclass(frozen=True)
class Name:
    """NAME old$ AS new$ -- rename a file; push order is new then old (old on top)."""

    old: object  # StrLit | Var ($)
    new: object  # StrLit | Var ($)


@dataclass(frozen=True)
class Get:
    """GET #n, rec -- read a random-access record."""

    num: int  # file number
    pos: object  # Expr (record number)


@dataclass(frozen=True)
class GetString:
    """GET$ #n, count, string$ -- read a binary string."""

    num: int
    count: object
    target: object


@dataclass(frozen=True)
class PutString:
    """PUT$ #n, s$ -- write a binary string (INT ECh sub ACh): filenum via
    the [0060] cell, s$ pushed (witnessed t1_putstr). The BINARY-mode
    counterpart of GetString; found via the handbook's "GET$, PUT$, and
    SEEK provide a low-level alternative" cross-reference while chasing
    the shared filenum+string calling convention IOCTL also uses."""

    num: int
    text: object  # Expr (string)


@dataclass(frozen=True)
class Put:
    """PUT #n, rec -- write a random-access record."""

    num: int  # file number
    pos: object  # Expr (record number)


@dataclass(frozen=True)
class Seek:
    """SEEK #n, pos -- set the file position."""

    num: int  # file number
    pos: object  # Expr (position)


@dataclass(frozen=True)
class Ioctl:
    """IOCTL #n, s$ -- send a string to a device driver (INT ECh sub 50h):
    filenum via the [0060] cell, s$ pushed (witnessed t1_ioctl)."""

    num: int  # file number
    text: object  # Expr (string)


@dataclass(frozen=True)
class Bload:
    """BLOAD f$[, offset] -- load a memory image. offset=None: the bare
    (no-offset) form, INT EC sub 04 -- a distinct compiled shape from the
    sub-06 with-offset form, not merely a default argument (wild
    varamort.exe/kinder.exe, probe q_bload)."""

    file: object  # StrLit | Var ($)
    offset: object = None  # Expr | None


@dataclass(frozen=True)
class Bsave:
    """BSAVE f$, offset, length -- save a memory image."""

    file: object  # StrLit | Var ($)
    offset: object  # Expr
    length: object  # Expr


@dataclass(frozen=True)
class Field:
    """FIELD #n, w1 AS v1$[, w2 AS v2$...] -- define a random-access buffer layout."""

    num: int  # file number
    fields: tuple[Any, ...]  # (width Expr, var Var$) pairs


@dataclass(frozen=True)
class Lset:
    """LSET target$ = source$ -- left-justified fixed-field string assignment."""

    target: object  # Var ($)
    source: object  # Expr ($)


@dataclass(frozen=True)
class Rset:
    """RSET target$ = source$ -- right-justified fixed-field string assignment."""

    target: object  # Var ($)
    source: object  # Expr ($)


@dataclass(frozen=True)
class MidAssign:
    """MID$(target$, start) = source$ -- overwrite substring in place."""

    target: object  # Var ($)
    start: object  # Expr
    source: object  # Expr ($)


# --- procedures (SUB / DEF FN / CALL) ---


@dataclass(frozen=True)
class SubDef:
    """SUB name[(params)] ... END SUB -- procedure definition from the def region.
    A block: header + indented body + END SUB. Params are name strings ('A', 'A$').

    `SUB name INLINE ... END SUB` (raw embedded machine code, Appendix C of the
    handbook) has no proc_enter/proc_ret framing at all -- the compiler copies
    the $INLINE byte list verbatim with an auto-appended far RET, no params,
    and no recoverable per-line split -- so it's `body == (Inline(data),)`
    (params always empty); the emitter detects this shape and prints the
    `INLINE` header keyword instead of a parameter list (probe q_shriek)."""

    name: str
    params: tuple[str, ...]
    body: tuple[Stmt, ...]


@dataclass(frozen=True)
class Inline:
    """$INLINE byte, byte, ... -- raw machine code inside a SUB ... INLINE body,
    copied verbatim into the compiled output (no BASIC semantics to recover)."""

    data: bytes


@dataclass(frozen=True)
class OpaqueHelper:
    """Coverage-only marker for a known framed machine-code helper.

    Unlike ``Inline``, this was not recovered as a source-level ``$INLINE``
    declaration.  The bytes are retained so the decoder can advance without
    pretending it understands the helper's semantics.  Source emission makes
    that limitation explicit and native C emission rejects the node.
    """

    data: bytes


@dataclass(frozen=True)
class Shared:
    """SHARED v[, v(), ...] -- inside a SUB/DEF FN body, binds names to the main
    program's slots instead of procedure-local statics. Synthesized by the decoder
    for any slot a procedure body references that is also referenced outside it
    (TB gives every other procedure variable its own local-static slot, so a
    cross-region slot can only mean SHARED -- witnessed t1_subsh/t1_subarr).
    Array names carry a '()' suffix."""

    names: tuple[str, ...]


@dataclass(frozen=True)
class Local:
    """LOCAL v[, v...] -- inside a SUB body, declares true per-call stack
    variables (unlike the SUB's own default scoping, which is local AND
    static: see Shared). The compiler zero-fills them in the prologue right
    after the frame is opened, every call (witnessed t1_local1)."""

    names: tuple[str, ...]


@dataclass(frozen=True)
class Common:
    """COMMON v[, v...] -- declares variables passed across CHAIN in a
    DGROUP band of their own at DS:0110, below the ordinary scalars. The
    compiler is lossy about the declaration's shape: interleaving of numeric
    and string names, numeric width mixes of equal total size, and splitting
    across several COMMON statements all compile identically (witnessed
    t1_common1), so the decoder emits one canonical statement: numeric
    slots first, then strings, in band order."""

    names: tuple[str, ...]


@dataclass(frozen=True)
class BodyLine:
    """A jump target INSIDE a SUB/DEF FN body: physical line `phys` (1-based,
    counting the header as 0) of the block at top-level statement index `stmt`.
    emit0 numbers that body line `line[stmt] + phys` (witnessed t1_subgsb)."""

    stmt: int
    phys: int


@dataclass(frozen=True)
class CallStmt:
    """CALL name[(args)] -- invoke a SUB. Named CallStmt to avoid clashing with the
    expression `Call` (built-in intrinsics)."""

    name: str
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class DefFn:
    """DEF FNx[(params)] = expr  (inline, is_block=False)  -- single-line DEF FN;
    or DEF FNx[(params)] ... END DEF (is_block=True) -- multi-line.
    Inline body is an Expr; block body is a tuple[Stmt, ...]."""

    name: str
    params: tuple[str, ...]
    body: object  # Expr (inline) | tuple[Stmt, ...] (block)
    is_block: bool = False


@dataclass(frozen=True)
class FnResult:
    """The result store inside a multi-line DEF FN body; renders as `FNx = expr` in the
    enclosing DEF FN's emit."""

    value: object  # Expr


# --- DATA / READ / RESTORE ---


@dataclass(frozen=True)
class DataItem:
    """One DATA constant: its verbatim source text and whether it is a string literal
    (quoted on emit). Recovered from the DATA constant pool (data_pool)."""

    text: str
    is_str: bool


@dataclass(frozen=True)
class Data:
    """DATA <items> -- codeless constant block re-emitted at program top. Items render
    comma-joined (no spaces), string items quoted."""

    items: tuple[DataItem, ...]


@dataclass(frozen=True)
class Read:
    """READ <targets> -- consume successive DATA items (INT EC B2 num / B4 str)."""

    targets: tuple[Expr, ...]


@dataclass(frozen=True)
class Restore:
    """RESTORE [line] -- reset the DATA read cursor. target is None (bare RESTORE) or the
    statement index of the target DATA stmt (rendered as its line number)."""

    target: object  # None | int (stmt index)
