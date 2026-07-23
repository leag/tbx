"""Rendering: typed IR nodes back to byte-faithful Turbo Basic source text.

`unparse` is the inverse of `parse_expr`; `unparse_stmt` renders one statement.
Statement-level blocks (IfBlock/SelectCase/SubDef/DefFn) are emitted by
`tbx.emit0`, not here.
"""

from __future__ import annotations

from tbx.ir.expr_nodes import (
    ArrayRef,
    BinOp,
    Call,
    CaseIs,
    CaseRange,
    CaseValue,
    DblLit,
    Erl,
    Err,
    FnCall,
    Group,
    HexLit,
    Lit,
    LogOp,
    Neg,
    Not,
    Nullary,
    RelOp,
    SingleLit,
    StrLit,
    Unknown,
    Var,
    VarSeg,
    _PREC,
)
from tbx.ir.fmt import _fmt_float, fmt_double, fmt_plain
from tbx.ir.stmt_nodes import (
    Assign,
    Beep,
    Bload,
    Bsave,
    CallAbsolute,
    CallInterrupt,
    CallStmt,
    Chain,
    Chdir,
    Circle,
    Clear,
    Close,
    Cls,
    Color,
    Common,
    Data,
    DateTimeSet,
    DefFn,
    DefSeg,
    DefType,
    Delay,
    Dim,
    Do,
    Draw,
    End,
    Environ,
    Erase,
    ErrorStmt,
    ExitDef,
    ExitFor,
    ExitLoop,
    ExitSub,
    Field,
    Files,
    FnResult,
    For,
    Get,
    GetString,
    GetGfx,
    Inline,
    Input,
    InputFile,
    Ioctl,
    Key,
    KeyDef,
    KeyList,
    Kill,
    LineInput,
    LineStmt,
    Local,
    Locate,
    Loop,
    Lprint,
    Lset,
    MidAssign,
    Mkdir,
    Mtimer,
    Name,
    NextStmt,
    OnError,
    OnGosub,
    OnGoto,
    OnTrap,
    OpaqueHelper,
    Open,
    OptionBase,
    Out,
    Paint,
    Palette,
    PaletteUsing,
    Play,
    Poke,
    Print,
    PrintUsing,
    Pset,
    Put,
    PutGfx,
    PutString,
    Randomize,
    Read,
    RegSet,
    Reset,
    Restore,
    Resume,
    Return,
    Rmdir,
    Rset,
    Run,
    Screen,
    Seek,
    Shared,
    Shell,
    Sound,
    Swap,
    TrapCtl,
    Troff,
    Tron,
    View,
    Wait,
    Wend,
    Width,
    Window,
    Write,
)


def unparse(e) -> str:
    if isinstance(e, Lit):
        if isinstance(e.value, float):
            return _fmt_float(e.value)
        return str(e.value)
    if isinstance(e, DblLit):
        return fmt_double(e.value)
    if isinstance(e, SingleLit):
        return fmt_plain(e.value)
    if isinstance(e, HexLit):
        return f"&H{e.value:X}"
    if isinstance(e, Unknown):
        return "?"
    if isinstance(e, Err):
        return "ERR"
    if isinstance(e, Erl):
        return "ERL"
    if isinstance(e, Nullary):
        return e.name
    if isinstance(e, Var):
        return e.name
    if isinstance(e, ArrayRef):
        return f"{e.name}({','.join(unparse(i) for i in e.indices)})"
    if isinstance(e, Call):
        return f"{e.name}({','.join(unparse(a) for a in e.args)})"
    if isinstance(e, FnCall):
        return f"{e.name}({','.join(unparse(a) for a in e.args)})"
    if isinstance(e, Group):
        return f"({unparse(e.inner)})"
    if isinstance(e, BinOp):
        # Minimal parenthesization: add parens only where needed to
        # reproduce the same parse tree (lhs needs prec >= op; rhs needs prec > op).
        p = _PREC[e.op]
        lhs_s = unparse(e.lhs)
        rhs_s = unparse(e.rhs)
        if isinstance(e.lhs, BinOp) and _PREC[e.lhs.op] < p:
            lhs_s = f"({lhs_s})"
        if isinstance(e.rhs, BinOp) and _PREC[e.rhs.op] <= p:
            rhs_s = f"({rhs_s})"
        return f"{lhs_s} {e.op} {rhs_s}"
    if isinstance(e, Neg):
        if isinstance(e.operand, (BinOp, Neg)):
            return f"-({unparse(e.operand)})"
        return f"-{unparse(e.operand)}"
    if isinstance(e, Not):
        if isinstance(e.operand, (BinOp, Neg, Not)):
            return f"NOT ({unparse(e.operand)})"
        return f"NOT {unparse(e.operand)}"
    if isinstance(e, StrLit):
        return f'"{e.value}"'
    raise TypeError(f"not an Expr: {e!r}")


def unparse_cond(c) -> str:
    """Render an IF/WHILE condition (RelOp or LogOp tree, or a bare
    numeric-truthiness expression -- no explicit compare in source, e.g.
    `LOOP UNTIL LEN(K$)`, wild metric.exe) without parentheses."""
    if isinstance(c, LogOp):
        return f"{unparse_cond(c.lhs)} {c.op} {unparse_cond(c.rhs)}"
    if isinstance(c, RelOp):
        return f"{unparse(c.lhs)} {c.op} {unparse(c.rhs)}"
    return unparse(c)


def unparse_case_guard(g) -> str:
    if isinstance(g, CaseValue):
        return unparse(g.value)
    if isinstance(g, CaseRange):
        return f"{unparse(g.lo)} TO {unparse(g.hi)}"
    if isinstance(g, CaseIs):
        return f"IS {g.op} {unparse(g.value)}"
    raise TypeError(f"not a CaseGuard: {g!r}")


def params_sig(params) -> str:
    """Render a SUB/DEF FN parameter list: '' when empty, else '(A, B)'."""
    return f"({', '.join(params)})" if params else ""


def _us_decl(s) -> str | None:
    """Render assignment / control-flow / declaration statements; None if `s` is not one of them."""
    if isinstance(s, Assign):
        if isinstance(s.value, VarSeg):  # bare `mov ax,ds`: any DGROUP var
            t = unparse(s.target)  # round-trips; use the target itself
            return f"{t} = VARSEG({t})"
        return f"{unparse(s.target)} = {unparse(s.value)}"
    if isinstance(s, End):
        return "END"
    if isinstance(s, Tron):
        return "TRON"
    if isinstance(s, Troff):
        return "TROFF"
    if isinstance(s, For):
        step = "" if s.step == Lit(1) else f" STEP {unparse(s.step)}"
        return f"FOR {s.var.name} = {unparse(s.init)} TO {unparse(s.limit)}{step}"
    if isinstance(s, NextStmt):
        return f"NEXT {s.var.name}"
    if isinstance(s, Return):
        return "RETURN" if s.target is None else f"RETURN {s.target}"
    if isinstance(s, Wend):
        return "WEND"
    if isinstance(s, Do):
        return "DO" if s.kind is None else f"DO {s.kind} {unparse_cond(s.cond)}"
    if isinstance(s, Loop):
        return "LOOP" if s.kind is None else f"LOOP {s.kind} {unparse_cond(s.cond)}"
    if isinstance(s, ExitFor):
        return "EXIT FOR"
    if isinstance(s, ExitLoop):
        return "EXIT LOOP"
    if isinstance(s, ExitSub):
        return "EXIT SUB"
    if isinstance(s, ExitDef):
        return "EXIT DEF"
    if isinstance(s, Run):
        return "RUN" if s.file is None else f"RUN {unparse(s.file)}"
    if isinstance(s, Dim):

        def bound(b):
            if isinstance(b, tuple):
                hi = str(b[1]) if isinstance(b[1], int) else unparse(b[1])
                return f"{b[0]}:{hi}"
            return str(b) if isinstance(b, int) else unparse(b)

        def arr(name, bounds):
            return f"{name}({','.join(bound(b) for b in bounds)})"

        prefix = "DIM DYNAMIC " if s.dynamic else "DIM "
        return prefix + ", ".join(arr(n, b) for n, b in ((s.name, s.bounds), *s.also))
    if isinstance(s, OptionBase):
        return f"OPTION BASE {s.n}"
    if isinstance(s, DefType):
        return "DEFSNG A-Z"
    if isinstance(s, Erase):
        return f"ERASE {s.name}"
    if isinstance(s, Shared):
        return "SHARED " + ", ".join(s.names)
    if isinstance(s, Local):
        return "LOCAL " + ", ".join(s.names)
    if isinstance(s, Common):
        return "COMMON " + ", ".join(s.names)


def _us_output(s) -> str | None:
    """Render PRINT family, sound and misc actions; None if `s` is not one of them."""
    if isinstance(s, Print):
        txt = "PRINT" + (f" #{s.file}," if s.file is not None else "")
        cs = s.commas or (0,) * (len(s.items) + 1)
        if s.items:
            parts = []
            if cs[0]:
                parts.append("," * cs[0] + " ")
            for i, item in enumerate(s.items):
                parts.append(unparse(item))
                if i < len(s.items) - 1:
                    parts.append("," * cs[i + 1] + " " if cs[i + 1] else "; ")
            txt += " " + "".join(parts)
        if s.newline:
            return txt
        return txt + ("," * cs[-1] if s.items and cs[-1] else ";")
    if isinstance(s, PrintUsing):
        kw = "LPRINT" if s.lprint else "PRINT"
        pre = f"#{s.file}, " if s.file is not None else ""
        vals = "; ".join(unparse(v) for v in s.values)
        return f"{kw} {pre}USING {unparse(s.fmt)}; {vals}" + ("" if s.newline else ";")
    if isinstance(s, Kill):
        return f"KILL {unparse(s.file)}"
    if isinstance(s, Play):
        return f"PLAY {unparse(s.music)}"
    if isinstance(s, Clear):
        return "CLEAR"
    if isinstance(s, Beep):
        return "BEEP"
    if isinstance(s, Randomize):
        return f"RANDOMIZE {unparse(s.seed)}"
    if isinstance(s, Delay):
        return f"DELAY {unparse(s.secs)}"
    if isinstance(s, Sound):
        return f"SOUND {unparse(s.freq)}, {unparse(s.dur)}"
    if isinstance(s, Swap):
        return f"SWAP {unparse(s.a)}, {unparse(s.b)}"


def _us_graphics(s) -> str | None:
    """Render graphics and hardware statements; None if `s` is not one of them."""
    if isinstance(s, Pset):
        kw = "PRESET" if s.preset else "PSET"
        step = "STEP " if s.step else ""
        col = "" if s.color is None else f", {unparse(s.color)}"
        return f"{kw} {step}({unparse(s.x)},{unparse(s.y)}){col}"
    if isinstance(s, LineStmt):
        st1 = "STEP " if s.step1 else ""
        st2 = "STEP " if s.step2 else ""
        p1 = f"{st1}({unparse(s.x1)},{unparse(s.y1)})" if s.x1 is not None else ""
        txt = f"LINE {p1}-{st2}({unparse(s.x2)},{unparse(s.y2)})"
        # Trailing arg slots: color, box, style -- absent slots before a present
        # one render as bare `, ` (e.g. `LINE (..)-(..), 2, , &HAAAA`).
        slots = [
            None if s.color is None else unparse(s.color),
            s.box or None,
            None if s.style is None else unparse(s.style),
        ]
        while slots and slots[-1] is None:
            slots.pop()
        for v in slots:
            txt += ", " if v is None else f", {v}"
        return txt
    if isinstance(s, Circle):
        step = "STEP " if s.step else ""
        txt = f"CIRCLE {step}({unparse(s.x)},{unparse(s.y)}), {unparse(s.r)}"
        slots = [
            None if v is None else unparse(v)
            for v in (s.color, s.start, s.end, s.aspect)
        ]
        while slots and slots[-1] is None:
            slots.pop()
        for v in slots:
            txt += ", " if v is None else f", {v}"
        return txt
    if isinstance(s, Paint):
        txt = f"PAINT ({unparse(s.x)},{unparse(s.y)})"
        if s.paint is not None:
            txt += f", {unparse(s.paint)}"
        elif s.border is not None:
            txt += ", "  # PAINT (..), , border
        if s.border is not None:
            txt += f", {unparse(s.border)}"
        return txt
    if isinstance(s, Draw):
        return f"DRAW {unparse(s.cmd)}"
    if isinstance(s, Out):
        return f"OUT {unparse(s.port)}, {unparse(s.value)}"
    if isinstance(s, Wait):
        x = "" if s.xor is None else f", {unparse(s.xor)}"
        return f"WAIT {unparse(s.port)}, {unparse(s.mask)}{x}"
    if isinstance(s, Poke):
        return f"POKE {unparse(s.addr)}, {unparse(s.value)}"
    if isinstance(s, DefSeg):
        return "DEF SEG" if s.seg is None else f"DEF SEG = {unparse(s.seg)}"
    if isinstance(s, Palette):
        return f"PALETTE {unparse(s.attr)}, {unparse(s.color)}"
    if isinstance(s, PaletteUsing):
        return f"PALETTE USING {unparse(s.source)}"
    if isinstance(s, View):
        scr = "SCREEN " if s.screen else ""
        txt = (
            f"VIEW {scr}({unparse(s.x1)},{unparse(s.y1)})"
            f"-({unparse(s.x2)},{unparse(s.y2)})"
        )
        if s.color is not None:
            txt += f", {unparse(s.color)}"
        elif s.border is not None:
            txt += ", "  # VIEW (..)-(..), , border
        if s.border is not None:
            txt += f", {unparse(s.border)}"
        return txt
    if isinstance(s, Window):
        scr = "SCREEN " if s.screen else ""
        return (
            f"WINDOW {scr}({unparse(s.x1)},{unparse(s.y1)})"
            f"-({unparse(s.x2)},{unparse(s.y2)})"
        )
    if isinstance(s, Width):
        if s.device is not None:
            return f"WIDTH {unparse(s.device)},{unparse(s.cols)}"
        return f"WIDTH {unparse(s.cols)}"
    if isinstance(s, Key):
        return "KEY ON" if s.on else "KEY OFF"
    if isinstance(s, KeyDef):
        return f"KEY {unparse(s.num)},{unparse(s.text)}"
    if isinstance(s, Screen):
        args = [s.mode, s.burst, s.apage, s.vpage]
        while args and args[-1] is None:
            args.pop()
        return "SCREEN " + ",".join("" if a is None else unparse(a) for a in args)


def _us_console(s) -> str | None:
    """Render console I/O statements; None if `s` is not one of them."""
    if isinstance(s, Write):
        pre = f" #{s.file}," if s.file is not None else ""
        return "WRITE" + pre + " " + ", ".join(unparse(i) for i in s.items)
    if isinstance(s, Lprint):
        txt = "LPRINT"
        cs = s.commas or (0,) * (len(s.items) + 1)
        if s.items:
            parts = []
            if cs[0]:
                parts.append("," * cs[0] + " ")
            for i, item in enumerate(s.items):
                parts.append(unparse(item))
                if i < len(s.items) - 1:
                    parts.append("," * cs[i + 1] + " " if cs[i + 1] else "; ")
            txt += " " + "".join(parts)
        if s.newline:
            return txt
        return txt + ("," * cs[-1] if s.items and cs[-1] else ";")
    if isinstance(s, Cls):
        return "CLS"
    if isinstance(s, Locate):
        args = (s.row, s.col, s.cursor, s.start, s.stop)
        last = max((i for i, a in enumerate(args) if a is not None), default=1)
        parts = [unparse(a) if a is not None else "" for a in args[: last + 1]]
        return "LOCATE " + ",".join(parts)
    if isinstance(s, Color):
        args = (s.fg, s.bg, s.border)
        last = max((i for i, a in enumerate(args) if a is not None), default=-1)
        parts = [unparse(a) if a is not None else "" for a in args[: last + 1]]
        return f"COLOR {','.join(parts)}"
    if isinstance(s, Input):
        kw = "INPUT;" if s.semi else "INPUT"
        vs = (
            ", ".join(unparse(v) for v in s.var)
            if isinstance(s.var, tuple)
            else unparse(s.var)
        )
        if s.prompt is None:
            return f"{kw} {vs}"
        sep = "," if s.comma else ";"
        return f"{kw} {unparse(s.prompt)}{sep} {vs}"
    if isinstance(s, LineInput):
        if s.file is not None:
            return f"LINE INPUT #{s.file}, {unparse(s.var)}"
        kw = "LINE INPUT;" if s.semi else "LINE INPUT"
        if s.prompt is None:
            return f"{kw} {unparse(s.var)}"
        return f"{kw} {unparse(s.prompt)}; {unparse(s.var)}"


_OPEN_MODE_KW = {
    "O": "OUTPUT",
    "I": "INPUT",
    "A": "APPEND",
    "R": "RANDOM",
    "B": "BINARY",
}  # `OPEN f$ FOR mode AS #n` keyword -> packed mode letter (witnessed q_openfor
# and q_mode_{OUTPUT,INPUT,APPEND,RANDOM,BINARY})


def _us_fileio(s) -> str | None:
    """Render file I/O statements; None if `s` is not one of them."""
    if isinstance(s, Open):
        if s.for_as:
            kw = _OPEN_MODE_KW.get(s.mode.value)
            if kw is None or s.reclen is not None:
                raise ValueError(f"unsupported FOR-AS OPEN mode {s.mode!r}")
            return f"OPEN {unparse(s.file)} FOR {kw} AS #{s.num}"
        rl = "" if s.reclen is None else f",{unparse(s.reclen)}"
        return f"OPEN {unparse(s.mode)},#{s.num},{unparse(s.file)}{rl}"
    if isinstance(s, InputFile):
        return f"INPUT #{s.num}, {', '.join(unparse(v) for v in s.vars)}"
    if isinstance(s, Close):
        if s.num is None:
            return "CLOSE"
        n = s.num if isinstance(s.num, int) else unparse(s.num)
        return f"CLOSE #{n}"
    if isinstance(s, Reset):
        return "RESET"
    if isinstance(s, Files):
        return "FILES" if s.spec is None else f"FILES {unparse(s.spec)}"
    if isinstance(s, Name):
        return f"NAME {unparse(s.old)} AS {unparse(s.new)}"
    if isinstance(s, Get):
        return f"GET #{s.num}, {unparse(s.pos)}"
    if isinstance(s, GetString):
        return f"GET$ #{s.num}, {unparse(s.count)}, {unparse(s.target)}"
    if isinstance(s, Put):
        return f"PUT #{s.num}, {unparse(s.pos)}"
    if isinstance(s, PutString):
        return f"PUT$ #{s.num}, {unparse(s.text)}"
    if isinstance(s, Seek):
        return f"SEEK #{s.num}, {unparse(s.pos)}"
    if isinstance(s, Ioctl):
        return f"IOCTL #{s.num}, {unparse(s.text)}"
    if isinstance(s, Bload):
        off = f", {unparse(s.offset)}" if s.offset is not None else ""
        return f"BLOAD {unparse(s.file)}{off}"
    if isinstance(s, Bsave):
        return f"BSAVE {unparse(s.file)}, {unparse(s.offset)}, {unparse(s.length)}"
    if isinstance(s, Write):
        pre = f"#{s.file}, " if s.file is not None else ""
        return f"WRITE {pre}" + ", ".join(unparse(i) for i in s.items)
    if isinstance(s, Field):
        items = ", ".join(f"{unparse(w)} AS {unparse(v)}" for w, v in s.fields)
        return f"FIELD #{s.num}, {items}"
    if isinstance(s, Lset):
        return f"LSET {unparse(s.target)} = {unparse(s.source)}"
    if isinstance(s, Rset):
        return f"RSET {unparse(s.target)} = {unparse(s.source)}"
    if isinstance(s, MidAssign):
        return f"MID$({unparse(s.target)}, {unparse(s.start)}) = {unparse(s.source)}"


def _us_procdata(s) -> str | None:
    """Render procedures, OS, event-trap and DATA statements; None if `s` is not one of them."""
    if isinstance(s, Inline):
        return "$INLINE " + ", ".join(f"&H{b:02X}" for b in s.data)
    if isinstance(s, OpaqueHelper):
        # Framed helpers recovered from the wild corpus are external
        # `$INLINE "file"` payloads after linking.  The compiler contributes
        # the final far RET (CB), so emit the payload as byte-list INLINE and
        # let Turbo BASIC append CB again on recompilation.
        data = s.data[:-1] if s.data.endswith(b"\xCB") else s.data
        return "$INLINE " + ", ".join(f"&H{b:02X}" for b in data)
    if isinstance(s, CallStmt):
        if s.args:
            return f"CALL {s.name}({','.join(unparse(a) for a in s.args)})"
        return f"CALL {s.name}"
    if isinstance(s, DefFn) and not s.is_block:
        return f"DEF {s.name}{params_sig(s.params)} = {unparse(s.body)}"
    if isinstance(s, FnResult):
        return f"FN = {unparse(s.value)}"
    if isinstance(s, Chdir):
        return f"CHDIR {unparse(s.path)}"
    if isinstance(s, Mkdir):
        return f"MKDIR {unparse(s.path)}"
    if isinstance(s, Rmdir):
        return f"RMDIR {unparse(s.path)}"
    if isinstance(s, Environ):
        return f"ENVIRON {unparse(s.s)}"
    if isinstance(s, Shell):
        return f"SHELL {unparse(s.cmd)}"
    if isinstance(s, Chain):
        return f"CHAIN {unparse(s.file)}"
    if isinstance(s, OnGoto):
        lines = ", ".join(str(10 * (t + 1)) for t in s.targets)
        return f"ON {unparse(s.selector)} GOTO {lines}"
    if isinstance(s, OnGosub):
        lines = ", ".join(str(10 * (t + 1)) for t in s.targets)
        return f"ON {unparse(s.selector)} GOSUB {lines}"
    if isinstance(s, OnError):
        tgt = 0 if s.target is None else 10 * (s.target + 1)
        return f"ON ERROR GOTO {tgt}"
    if isinstance(s, Resume):
        if s.next_:
            return "RESUME NEXT"
        if s.target is None:
            return "RESUME"
        return f"RESUME {10 * (s.target + 1)}"
    if isinstance(s, ErrorStmt):
        return f"ERROR {unparse(s.code)}"
    if isinstance(s, RegSet):
        return f"REG {unparse(s.n)}, {unparse(s.value)}"
    if isinstance(s, DateTimeSet):
        return f"{s.name} = {unparse(s.value)}"
    if isinstance(s, CallInterrupt):
        return f"CALL INTERRUPT {unparse(s.n)}"
    if isinstance(s, CallAbsolute):
        return f"CALL ABSOLUTE {unparse(s.addr)}"
    if isinstance(s, OnTrap):
        n = "" if s.n is None else f"({unparse(s.n)})"
        return f"ON {s.event}{n} GOSUB {10 * (s.target + 1)}"
    if isinstance(s, TrapCtl):
        n = "" if s.n is None else f"({unparse(s.n)})"
        return f"{s.event}{n} {s.mode}"
    if isinstance(s, KeyList):
        return "KEY LIST"
    if isinstance(s, Mtimer):
        return "MTIMER"
    if isinstance(s, GetGfx):
        return (
            f"GET ({unparse(s.x1)},{unparse(s.y1)})"
            f"-({unparse(s.x2)},{unparse(s.y2)}), {s.array}"
        )
    if isinstance(s, PutGfx):
        act = "" if s.action is None else f", {s.action}"
        return f"PUT ({unparse(s.x)},{unparse(s.y)}), {s.array}{act}"
    if isinstance(s, Data):
        parts = (f'"{it.text}"' if it.is_str else it.text for it in s.items)
        return f"DATA {','.join(parts)}"
    if isinstance(s, Read):
        return f"READ {', '.join(unparse(t) for t in s.targets)}"
    if isinstance(s, Restore):
        return "RESTORE" if s.target is None else f"RESTORE {10 * (s.target + 1)}"


def unparse_stmt(s) -> str:
    for _group in (
        _us_decl,
        _us_output,
        _us_graphics,
        _us_console,
        _us_fileio,
        _us_procdata,
    ):
        r = _group(s)
        if r is not None:
            return r
    raise TypeError(f"not a Stmt: {s!r}")
