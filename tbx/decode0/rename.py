"""Canonical variable renaming and string-literal recovery."""

from __future__ import annotations
import struct
from typing import Any

from tbx import ir


def _str_lit(exe: bytes, ds: int, desc_disp: int, ss_base: int) -> ir.StrLit:
    """Read a string literal via its pool descriptor `<len|0x8000> <ptr16>`."""
    w0, ptr = struct.unpack_from("<HH", exe, ds + desc_disp)
    if not w0 & 0x8000:
        raise ValueError(f"bad string descriptor at [{desc_disp:#06x}]: {w0:#06x}")
    ln = w0 & 0x7FFF
    return ir.StrLit(
        exe[ds + ss_base + ptr : ds + ss_base + ptr + ln].decode("latin-1")
    )


def _slot(disp: int) -> str:
    return f"V{disp:04X}"  # placeholder; canonical_rename re-letters


def canonical_rename(stmts: list[Any]) -> list[Any]:
    """Re-letter V#### placeholders to A, B, C... in textual walk order (assignment target,
    then expression leaves left-to-right). Cosmetic: allocation follows the tree shape the
    emitter preserves, so any consistent naming is byte-safe.
    """
    names: dict[str, str] = {}
    # A..Z then AA..AZ, BA.. (Excel order), skipping TB reserved words. Names
    # contribute zero image bytes, so any consistent scheme is byte-safe.
    _RESERVED = {"AS", "AT", "DO", "FN", "GO", "IF", "LN", "ON", "OR", "PI", "TO"}

    def _letters(i: int) -> str:
        s = ""
        i += 1
        while i:
            i, r = divmod(i - 1, 26)
            s = chr(ord("A") + r) + s
        return s

    counter = [0]

    def name(old: str) -> str:
        if old not in names:
            cand = _letters(counter[0])
            while cand in _RESERVED:
                counter[0] += 1
                cand = _letters(counter[0])
            counter[0] += 1
            suffix = old[-1] if old[-1] in "%$&#" else ""
            names[old] = cand + suffix
        return names[old]

    def walk(e):
        if isinstance(e, ir.Var):
            return ir.Var(name(e.name))
        if isinstance(e, ir.BinOp):
            return ir.BinOp(e.op, walk(e.lhs), walk(e.rhs))
        if isinstance(e, ir.Template):
            return ir.Template(e.kind, walk(e.inner))
        if isinstance(e, ir.Neg):
            return ir.Neg(walk(e.operand))
        if isinstance(e, ir.Not):
            return ir.Not(walk(e.operand))
        if isinstance(e, ir.Group):
            # A Group can wrap a boolean condition too (an explicitly
            # parenthesized AND-group joined into an outer OR, wild
            # bmaster.exe/ifi.exe) -- route those through walk_cond so
            # names inside the LogOp/RelOp tree get renamed, not just
            # plain-expression Groups.
            if isinstance(e.inner, (ir.LogOp, ir.RelOp)):
                return ir.Group(walk_cond(e.inner))
            return ir.Group(walk(e.inner))
        if isinstance(e, ir.ArrayRef):  # ordinary array names are already
            # canonical; whole-array SUB params are Pxx placeholders entered
            # into `names` while their header is renamed.
            return ir.ArrayRef(
                names.get(e.name, e.name), tuple(walk(i) for i in e.indices)
            )
        if isinstance(e, ir.Call):
            return ir.Call(e.name, tuple(walk(a) for a in e.args))
        if isinstance(e, ir.FnCall):
            return ir.FnCall(e.name, tuple(walk(a) for a in e.args))
        return e  # Lit / Unknown

    def walk_cond(c):
        if isinstance(c, ir.LogOp):
            return ir.LogOp(c.op, walk_cond(c.lhs), walk_cond(c.rhs))
        if isinstance(c, ir.RelOp):
            return ir.RelOp(c.op, walk(c.lhs), walk(c.rhs))
        return walk(c)  # bare numeric-truthiness condition (no explicit
        # compare in source, e.g. `LOOP UNTIL LEN(K$)` -- wild metric.exe)

    def rn(s):
        if isinstance(s, ir.Assign):
            return ir.Assign(walk(s.target), walk(s.value))
        if isinstance(s, ir.IfGoto):
            return ir.IfGoto(walk_cond(s.cond), s.target)
        if isinstance(s, ir.IfInline):
            return ir.IfInline(walk_cond(s.cond), tuple(rn(b) for b in s.body))
        if isinstance(s, ir.IfBlock):
            arms = tuple(
                (walk_cond(c), tuple(rn(b) for b in body)) for c, body in s.arms
            )
            else_body = (
                None if s.else_body is None else tuple(rn(b) for b in s.else_body)
            )
            return ir.IfBlock(arms, else_body)
        if isinstance(s, ir.SelectCase):

            def _wg(g):
                if isinstance(g, ir.CaseValue):
                    return ir.CaseValue(walk(g.value))
                if isinstance(g, ir.CaseRange):
                    return ir.CaseRange(walk(g.lo), walk(g.hi))
                return ir.CaseIs(g.op, walk(g.value))

            sel = walk(s.selector)
            arms = tuple(
                ir.CaseArm(
                    tuple(_wg(g) for g in arm.guards), tuple(rn(b) for b in arm.body)
                )
                for arm in s.arms
            )
            ce = None if s.case_else is None else tuple(rn(b) for b in s.case_else)
            return ir.SelectCase(sel, arms, ce)
        if isinstance(s, ir.For):
            return ir.For(walk(s.var), walk(s.init), walk(s.limit), walk(s.step))
        if isinstance(s, ir.NextStmt):
            return ir.NextStmt(walk(s.var))
        if isinstance(s, ir.Incr):
            return ir.Incr(walk(s.var))
        if isinstance(s, ir.Decr):
            return ir.Decr(walk(s.var))
        if isinstance(s, ir.While):
            return ir.While(walk_cond(s.cond))
        if isinstance(s, ir.Do):
            return ir.Do(s.kind, walk_cond(s.cond) if s.cond is not None else None)
        if isinstance(s, ir.Loop):
            return ir.Loop(s.kind, walk_cond(s.cond) if s.cond is not None else None)
        if isinstance(s, ir.Print):
            return ir.Print(
                tuple(walk(i) for i in s.items),
                newline=s.newline,
                file=s.file,
                commas=s.commas,
            )
        if isinstance(s, ir.PrintUsing):
            return ir.PrintUsing(
                walk(s.fmt),
                tuple(walk(v) for v in s.values),
                file=s.file,
                newline=s.newline,
                lprint=s.lprint,
            )
        if isinstance(s, ir.Close):
            return ir.Close(None if s.num is None else walk(s.num))
        if isinstance(s, ir.Kill):
            return ir.Kill(walk(s.file))
        if isinstance(s, ir.Play):
            return ir.Play(walk(s.music))
        if isinstance(s, ir.Chdir):
            return ir.Chdir(walk(s.path))
        if isinstance(s, ir.Mkdir):
            return ir.Mkdir(walk(s.path))
        if isinstance(s, ir.Rmdir):
            return ir.Rmdir(walk(s.path))
        if isinstance(s, ir.Environ):
            return ir.Environ(walk(s.s))
        if isinstance(s, ir.Shell):
            return ir.Shell(walk(s.cmd))
        if isinstance(s, ir.Chain):
            return ir.Chain(walk(s.file))
        if isinstance(s, ir.Run):
            return ir.Run(None if s.file is None else walk(s.file))
        if isinstance(s, ir.OnGoto):
            return ir.OnGoto(walk(s.selector), s.targets)
        if isinstance(s, ir.OnGosub):
            return ir.OnGosub(walk(s.selector), s.targets)
        if isinstance(s, ir.Swap):
            return ir.Swap(walk(s.a), walk(s.b))
        if isinstance(s, ir.Randomize):
            return ir.Randomize(walk(s.seed))
        if isinstance(s, ir.Delay):
            return ir.Delay(walk(s.secs))
        if isinstance(s, ir.Sound):
            return ir.Sound(walk(s.freq), walk(s.dur))
        if isinstance(s, ir.Out):
            return ir.Out(walk(s.port), walk(s.value))
        if isinstance(s, ir.Pset):
            return ir.Pset(
                walk(s.x),
                walk(s.y),
                None if s.color is None else walk(s.color),
                s.preset,
                s.step,
            )
        if isinstance(s, ir.LineStmt):
            return ir.LineStmt(
                walk(s.x1),
                walk(s.y1),
                walk(s.x2),
                walk(s.y2),
                None if s.color is None else walk(s.color),
                s.box,
                s.step1,
                s.step2,
                None if s.style is None else walk(s.style),
            )
        if isinstance(s, ir.Circle):
            return ir.Circle(
                walk(s.x),
                walk(s.y),
                walk(s.r),
                None if s.color is None else walk(s.color),
                None if s.start is None else walk(s.start),
                None if s.end is None else walk(s.end),
                None if s.aspect is None else walk(s.aspect),
                s.step,
            )
        if isinstance(s, ir.Paint):
            return ir.Paint(
                walk(s.x),
                walk(s.y),
                None if s.paint is None else walk(s.paint),
                None if s.border is None else walk(s.border),
            )
        if isinstance(s, ir.Draw):
            return ir.Draw(walk(s.cmd))
        if isinstance(s, ir.Wait):
            return ir.Wait(
                walk(s.port), walk(s.mask), None if s.xor is None else walk(s.xor)
            )
        if isinstance(s, ir.Poke):
            return ir.Poke(walk(s.addr), walk(s.value))
        if isinstance(s, ir.DefSeg):
            return ir.DefSeg(None if s.seg is None else walk(s.seg))
        if isinstance(s, ir.Locate):
            return ir.Locate(
                None if s.row is None else walk(s.row),
                None if s.col is None else walk(s.col),
                None if s.cursor is None else walk(s.cursor),
                None if s.start is None else walk(s.start),
                None if s.stop is None else walk(s.stop),
            )
        if isinstance(s, ir.Color):
            return ir.Color(
                None if s.fg is None else walk(s.fg),
                None if s.bg is None else walk(s.bg),
                None if s.border is None else walk(s.border),
            )
        if isinstance(s, ir.Palette):
            return ir.Palette(walk(s.attr), walk(s.color))
        if isinstance(s, ir.PaletteUsing):
            return ir.PaletteUsing(walk(s.source))
        if isinstance(s, ir.View):
            return ir.View(
                walk(s.x1),
                walk(s.y1),
                walk(s.x2),
                walk(s.y2),
                s.screen,
                None if s.color is None else walk(s.color),
                None if s.border is None else walk(s.border),
            )
        if isinstance(s, ir.Window):
            return ir.Window(walk(s.x1), walk(s.y1), walk(s.x2), walk(s.y2), s.screen)
        if isinstance(s, ir.Width):
            return ir.Width(
                walk(s.cols),
                walk(s.device) if s.device is not None else None,
                s.file,
            )
        if isinstance(s, ir.Write):
            return ir.Write(tuple(walk(i) for i in s.items), file=s.file)
        if isinstance(s, ir.Lprint):
            return ir.Lprint(
                tuple(walk(i) for i in s.items),
                newline=s.newline,
                commas=s.commas,
            )
        if isinstance(s, ir.Input):
            var = (
                tuple(walk(v) for v in s.var)
                if isinstance(s.var, tuple)
                else walk(s.var)
            )
            return ir.Input(s.prompt, var, s.comma, s.semi)
        if isinstance(s, ir.LineInput):
            return ir.LineInput(s.prompt, walk(s.var), s.file, s.semi)
        if isinstance(s, ir.Open):
            return ir.Open(s.mode, s.num, walk(s.file), s.reclen, s.for_as)
        if isinstance(s, ir.InputFile):
            return ir.InputFile(s.num, tuple(walk(v) for v in s.vars))
        if isinstance(s, ir.Dim):

            def wb(b):
                if isinstance(b, tuple):
                    return (b[0], b[1] if isinstance(b[1], int) else walk(b[1]))
                return b if isinstance(b, int) else walk(b)

            return ir.Dim(
                s.name,
                tuple(wb(b) for b in s.bounds),
                tuple((n, tuple(wb(b) for b in bs)) for n, bs in s.also),
                s.dynamic,
            )
        if isinstance(s, ir.Screen):
            wn = lambda e: None if e is None else walk(e)  # noqa: E731
            return ir.Screen(walk(s.mode), wn(s.burst), wn(s.apage), wn(s.vpage))
        if isinstance(s, ir.KeyDef):
            return ir.KeyDef(walk(s.num), walk(s.text))
        if isinstance(s, ir.Files):
            return ir.Files(None if s.spec is None else walk(s.spec))
        if isinstance(s, ir.Name):
            return ir.Name(walk(s.old), walk(s.new))
        if isinstance(s, ir.Get):
            return ir.Get(s.num, walk(s.pos))
        if isinstance(s, ir.GetString):
            return ir.GetString(s.num, walk(s.count), walk(s.target))
        if isinstance(s, ir.Put):
            return ir.Put(s.num, walk(s.pos))
        if isinstance(s, ir.PutString):
            return ir.PutString(s.num, walk(s.text))
        if isinstance(s, ir.Seek):
            return ir.Seek(s.num, walk(s.pos))
        if isinstance(s, ir.Ioctl):
            return ir.Ioctl(s.num, walk(s.text))
        if isinstance(s, ir.Bload):
            return ir.Bload(walk(s.file), walk(s.offset))
        if isinstance(s, ir.Bsave):
            return ir.Bsave(walk(s.file), walk(s.offset), walk(s.length))
        if isinstance(s, ir.Write):
            return ir.Write(tuple(walk(i) for i in s.items), file=s.file)
        if isinstance(s, ir.Field):
            return ir.Field(s.num, tuple((walk(w), walk(v)) for w, v in s.fields))
        if isinstance(s, ir.Lset):
            return ir.Lset(walk(s.target), walk(s.source))
        if isinstance(s, ir.Rset):
            return ir.Rset(walk(s.target), walk(s.source))
        if isinstance(s, ir.MidAssign):
            return ir.MidAssign(walk(s.target), walk(s.start), walk(s.source))
        if isinstance(s, ir.Shared):
            # scalar names are V#### placeholders; array names ('V0()') are
            # already canonical
            return ir.Shared(
                tuple(n if n.endswith("()") else name(n) for n in s.names)
            )
        if isinstance(s, ir.Local):
            # first body statement (Local's placeholder names are never seen
            # before this point), so declaration order == first-store order.
            # LOCAL DYNAMIC array names ('V0()') are already canonical, same
            # convention as ir.Shared above.
            return ir.Local(
                tuple(n if n.endswith("()") else name(n) for n in s.names)
            )
        if isinstance(s, ir.Common):
            # always the program's first statement, so the COMMON band's
            # slots letter first, in band order. A COMMON'd ARRAY carries its
            # rank in parens (`V0(1)`, see core.py's synthesis) and keeps its
            # canonical V-name -- runtime array names are never lettered, same
            # convention as ir.Shared/ir.Local above (probe t1_commonarr).
            return ir.Common(tuple(n if "(" in n else name(n) for n in s.names))
        if isinstance(s, ir.SubDef):
            params = tuple(
                name(p[:-3]) + "(1)" if p.endswith("(1)") else name(p)
                for p in s.params
            )  # params first: A, B... in decl order
            return ir.SubDef(s.name, params, tuple(rn(b) for b in s.body))
        if isinstance(s, ir.CallStmt):
            return ir.CallStmt(s.name, tuple(walk(a) for a in s.args))
        if isinstance(s, ir.DefFn):
            params = tuple(name(p) for p in s.params)
            if s.is_block:
                return ir.DefFn(s.name, params, tuple(rn(b) for b in s.body), True)
            return ir.DefFn(s.name, params, walk(s.body))
        if isinstance(s, ir.FnResult):
            return ir.FnResult(walk(s.value))
        if isinstance(s, ir.Read):
            return ir.Read(tuple(walk(t) for t in s.targets))
        if isinstance(s, ir.ErrorStmt):
            return ir.ErrorStmt(walk(s.code))
        if isinstance(s, ir.RegSet):
            return ir.RegSet(walk(s.n), walk(s.value))
        if isinstance(s, ir.CallInterrupt):
            return ir.CallInterrupt(walk(s.n))
        if isinstance(s, ir.CallAbsolute):
            return ir.CallAbsolute(walk(s.addr))
        if isinstance(s, ir.DateTimeSet):
            return ir.DateTimeSet(s.name, walk(s.value))
        if isinstance(s, ir.OnTrap):
            return ir.OnTrap(s.event, None if s.n is None else walk(s.n), s.target)
        if isinstance(s, ir.GetGfx):  # array names are already canonical
            return ir.GetGfx(walk(s.x1), walk(s.y1), walk(s.x2), walk(s.y2), s.array)
        if isinstance(s, ir.PutGfx):
            return ir.PutGfx(walk(s.x), walk(s.y), s.array, s.action)
        if isinstance(s, ir.TrapCtl):
            return ir.TrapCtl(s.event, None if s.n is None else walk(s.n), s.mode)
        return s  # Goto / Gosub / Data / Restore / End

    return [rn(s) for s in stmts]
