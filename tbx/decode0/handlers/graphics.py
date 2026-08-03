"""Screen output handlers: graphics primitives, boxes, PRINT/console.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tbx import ir
from tbx.decode0.frames import InputChain, LineInputChain, PrintChain
from tbx.decode0.statement_log import editing
from tbx.decode0.const import (
    _LINEINPUTREAD,
    _TABSPC_VECS,
)
from tbx.decode0.matchers import match_using_chain_continues

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def _graphics_line(state: DecodeState, op, addr: int) -> bool:
    e, c = state.expr, state.control
    fl = op[2]
    if fl & ~0x7F or (fl & 0x02 and not fl & 0x04):
        raise ValueError(f"LINE flag {fl:02x} at {addr:#x} (unsupported)")
    if not fl & 0x40 and fl & 0x20:
        # STEP on an omitted first point is unwitnessed -- stay fail-loud
        # rather than guess what it would even mean.
        raise ValueError(f"LINE flag {fl:02x} at {addr:#x} (unsupported)")
    color = e.color_cells.pop(0xA0) if fl & 0x08 else None
    style = e.color_cells.pop(0xAC) if fl & 0x01 else None
    if isinstance(style, ir.Lit):  # style word reads as a bit pattern
        style = ir.HexLit(style.value & 0xFFFF)
    box = ("BF" if fl & 0x02 else "B") if fl & 0x04 else ""
    y2 = e.stack.pop()
    x2 = e.stack.pop()
    if fl & 0x40:
        x1 = e.color_cells.pop(0x88)
        y1 = e.color_cells.pop(0x94)
    else:  # first point omitted entirely: `LINE -(x2,y2)` from the last
        x1 = y1 = None  # graphics position (wild cal87.exe)
    state.put(
        ir.LineStmt(
            x1, y1, x2, y2, color, box,
            step1=bool(fl & 0x20), step2=bool(fl & 0x10), style=style,
        ),
        c.cur,
    )
    c.cur = None
    state.advance()
    return True


def graphics(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: screen, cls, line, pset, circle, paint, draw, palette,
    palette_using, color_commit, locate, cursor, width."""
    i, m, e, l, c, o = (state.image, state.machine, state.expr,
                        state.layout_state, state.control, state.output)
    if kind == "screen":  # SCREEN m[,b][,a][,v]: cells by presence mask
        tag = op[2]
        mode = e.color_cells.pop(0x88, None) if tag & 0x08 else None
        if tag & 0x08 and mode is None:
            raise ValueError(f"SCREEN without [0x88] mode store at {addr:#x}")
        burst = e.color_cells.pop(0x94, None) if tag & 0x04 else None
        apage = e.color_cells.pop(0xA0, None) if tag & 0x02 else None
        vpage = e.color_cells.pop(0xAC, None) if tag & 0x01 else None
        if (
            (tag & 0x04 and burst is None)
            or (tag & 0x02 and apage is None)
            or (tag & 0x01 and vpage is None)
            or e.color_cells
        ):
            raise ValueError(f"SCREEN arg cell missing for tag {tag:#x} at {addr:#x}")
        state.put(ir.Screen(mode, burst, apage, vpage), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "cls":
        state.put(ir.Cls(), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "line":  # LINE [[STEP](..)]-[STEP](..)[,c][,B|BF][,style]
        return _graphics_line(state, op, addr)
    if kind == "pset":  # PSET/PRESET [STEP] (x,y)[, color]
        fl = op[2]
        # Exactly one of 01=PRESET / 02=PSET / 04=color (color drops the
        # PSET/PRESET bit -- explicit color overrides the default attr);
        # 08=STEP composes with any of them.
        if fl & ~0x0F or bin(fl & 0x07).count("1") != 1:
            raise ValueError(f"PSET flag {fl:02x} at {addr:#x} (unsupported)")
        color = e.color_cells.pop(0x88) if fl & 0x04 else None
        y = e.stack.pop()
        x = e.stack.pop()
        state.put(
            ir.Pset(x, y, color, preset=bool(fl & 0x01), step=bool(fl & 0x08)),
            c.cur,
        )
        c.cur = None
        state.advance()
        return True
    if kind == "circle":  # CIRCLE [STEP] (x,y), r[,c][,s][,e][,asp]
        fl = op[2]
        if fl & ~0x1F:
            raise ValueError(f"CIRCLE flag {fl:02x} at {addr:#x} (unsupported)")
        color = e.color_cells.pop(0x88) if fl & 0x08 else None
        cstart = e.color_cells.pop(0x94) if fl & 0x04 else None
        cend = e.color_cells.pop(0xA0) if fl & 0x02 else None
        aspect = e.color_cells.pop(0xAC) if fl & 0x01 else None
        if isinstance(aspect, ir.DblLit):  # unsuffixed source literal:
            aspect = ir.SingleLit(aspect.value)  # pooled f64, rendered plain
        r = e.stack.pop()
        y = e.stack.pop()
        x = e.stack.pop()
        state.put(
            ir.Circle(x, y, r, color, cstart, cend, aspect, step=bool(fl & 0x10)),
            c.cur,
        )
        c.cur = None
        state.advance()
        return True
    if kind == "paint":  # PAINT (x,y)[, paint][, border]
        if op[2] & ~0x03:
            raise ValueError(f"PAINT flag {op[2]:02x} at {addr:#x} (unsupported)")
        paint = e.color_cells.pop(0x88) if op[2] & 0x02 else None
        border = e.color_cells.pop(0x94) if op[2] & 0x01 else None
        y = e.stack.pop()
        x = e.stack.pop()
        state.put(ir.Paint(x, y, paint, border), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "paint_tile":  # PAINT (x,y), tile$[, border] (witnessed t1_paintt)
        if op[2] & ~0x01:
            raise ValueError(f"PAINT tile flag {op[2]:02x} at {addr:#x} (unsupported)")
        border = e.color_cells.pop(0x94) if op[2] & 0x01 else None
        tile = e.sstack.pop()
        y = e.stack.pop()
        x = e.stack.pop()
        state.put(ir.Paint(x, y, tile, border), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "draw":  # DRAW cmd$
        state.put(ir.Draw(e.sstack.pop()), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "palette_reset":  # bare PALETTE: reset to default, no operands
        state.put(ir.Palette(None, None), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "palette":  # PALETTE attr(bx), color(ax)
        state.put(ir.Palette(m.bx, m.ax), c.cur)
        m.bx = m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "palette_using":
        # A constant zero subscript on a dynamic array is emitted as
        # mov ES,[block]; xor SI,SI; EC/8A.  The variable-index form is
        # consumed by arith.shlsi, while static constant elements use the
        # movsi continuation in core.py.
        if (
            m.pend_es is None
            or c.k == 0
            or i.ops[c.k - 1][1] != "bchk0"
        ):
            raise ValueError(f"PALETTE USING without array element at {addr:#x}")
        a = l.r_arrs[m.pend_es]
        if a.get("str") or a.get("esz") != 2 or a["rank"] != 1:
            raise ValueError(
                f"PALETTE USING non-INTEGER rank-{a['rank']} array at {addr:#x}"
            )
        state.put(
            ir.PaletteUsing(ir.ArrayRef(a["name"], (ir.Lit(a["lo"][0]),))),
            c.cur,
        )
        m.pend_es = None
        c.cur = None
        state.advance()
        return True
    if kind == "color_commit":  # COLOR fg(04)/bg(02)/border(01) mask
        fg, bg, border = (
            e.color_cells.pop(0x88, None),
            e.color_cells.pop(0x94, None),
            e.color_cells.pop(0xA0, None),
        )
        want_mask = (
            (4 if fg is not None else 0)
            | (2 if bg is not None else 0)
            | (1 if border is not None else 0)
        )
        if op[2] != want_mask or e.color_cells:
            raise ValueError(
                f"COLOR mask {op[2]:02x} != cells {want_mask:02x} "
                f"(+{e.color_cells}) at {addr:#x}"
            )
        state.put(ir.Color(fg, bg, border), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "locate":  # LOCATE row(bx),col(ax)
        state.put(ir.Locate(m.bx, m.ax), c.cur)
        m.bx = m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "cursor":  # trailing cursor arg -> attach
        if o.stmts and isinstance(o.stmts[-1], ir.Locate):
            prev = o.stmts[-1]
            if prev.cursor is not None:
                # A wild 1.0 runtime variant encodes LOCATE's shape bounds as
                # two consecutive cursor dispatches (start first, stop
                # second) instead of using the dedicated cursor-shape vector.
                # Preserve that statement shape when the first cursor value
                # is already attached.
                with editing(o.stmts, "patch_locate_cursor_shape"):
                    state.patch(
                        -1,
                        ir.Locate(
                            prev.row,
                            prev.col,
                            None,
                            prev.cursor,
                            m.ax,
                        ),
                    )
                m.ax = None
                c.cur = None
                state.advance()
                return True
            with editing(o.stmts, "patch_locate"):
                state.patch(-1, ir.Locate(prev.row, prev.col, m.ax))
        else:  # LOCATE ,,cursor: no row/column runtime call precedes it
            state.put(ir.Locate(None, None, m.ax), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "cursor_shape":  # trailing cursor start/stop -> attach
        if o.stmts and isinstance(o.stmts[-1], ir.Locate):
            prev = o.stmts[-1]
            if prev.start is not None or prev.stop is not None:
                raise ValueError(f"duplicate LOCATE cursor shape call at {addr:#x}")
            with editing(o.stmts, "patch_locate"):
                state.patch(
                    -1, ir.Locate(prev.row, prev.col, prev.cursor, m.bx, m.ax)
                )
        else:  # LOCATE ,,,start,stop: the shape call is the whole statement
            state.put(ir.Locate(None, None, None, m.bx, m.ax), c.cur)
        m.bx = m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "width":  # WIDTH cols (ax)
        if m.ax is None or isinstance(m.ax, tuple):
            raise ValueError(f"WIDTH without an ax argument at {addr:#x}")
        state.put(ir.Width(m.ax), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "width_dev":  # WIDTH device$, cols (device string pushed, ax=cols)
        if m.ax is None or isinstance(m.ax, tuple):
            raise ValueError(f"WIDTH without an ax argument at {addr:#x}")
        state.put(ir.Width(m.ax, e.sstack.pop()), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "width_file":  # WIDTH #filenum,cols ([0060] channel, ax=cols)
        if e.pend_fnum is None or m.ax is None or isinstance(m.ax, tuple):
            raise ValueError(
                f"WIDTH # without file/ax arguments at {addr:#x} "
                f"(fnum={e.pend_fnum}, ax={m.ax})"
            )
        state.put(ir.Width(m.ax, file=e.pend_fnum), c.cur)
        e.pend_fnum = m.ax = None
        c.cur = None
        state.advance()
        return True
    return False


def graphics_box(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: view, window."""
    e, c = state.expr, state.control
    if kind in ("view", "window"):  # coord cells -> (x1,y1)-(x2,y2)
        fl = op[2]
        base, scr_bit, extra = (
            (0x04, 0x08, 0x03) if kind == "view" else (0x01, 0x02, 0x00)
        )
        if not fl & base or fl & ~(base | scr_bit | extra):
            raise ValueError(
                f"{kind.upper()} flag {fl:02x} at {addr:#x} (unsupported variant)"
            )
        try:
            x1, y1, x2, y2 = (
                e.color_cells.pop(c) for c in (0x88, 0x94, 0xA0, 0xAC)
            )
        except KeyError:
            raise ValueError(f"{kind.upper()} coord cells incomplete at {addr:#x}")
        if kind == "view":
            vcolor = e.color_cells.pop(0xB8) if fl & 0x02 else None
            vborder = e.color_cells.pop(0xC4) if fl & 0x01 else None
            state.put(
                ir.View(
                    x1,
                    y1,
                    x2,
                    y2,
                    screen=bool(fl & scr_bit),
                    color=vcolor,
                    border=vborder,
                ),
                c.cur,
            )
        else:
            state.put(ir.Window(x1, y1, x2, y2, screen=bool(fl & scr_bit)), c.cur)
        c.cur = None
        state.advance()
        return True
    return False


def _console_input(state: DecodeState, op, addr: int) -> bool:
    l, e, c = state.layout_state, state.expr, state.control
    prompt = None if op[2] == l.lay["pool_base"] - 4 else state._pool_str(op[2])
    flags = op[3]
    count = flags & 0x3F  # extra targets beyond the first
    tmask = 0  # per-position numeric-type bits, 0x4000 >> k
    for i in range(count + 1):
        tmask |= 0x4000 >> i
    if flags & ~(0x00C0 | 0x3F | tmask):
        raise ValueError(
            f"INPUT flags {flags:#06x} with {count + 1} targets at {addr:#x}"
        )
    e.pend_input = InputChain(prompt=prompt, flags=flags, want=count + 1, start=c.cur)
    state.advance()
    return True


def _console_line_input(state: DecodeState, op, addr: int) -> bool:
    i, e, c = state.image, state.expr, state.control
    prompt = (
        None
        if op[2] == state.layout_state.lay["pool_base"] - 4
        else state._pool_str(op[2])
    )
    nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
    if nxt is not None and nxt[1] != "movsi":
        # Computed string-array-element target (wild cal87.exe), the
        # LINE INPUT sibling of read_str's _INPUTREAD case.
        e.pend_line_input = LineInputChain(prompt=prompt, semi=op[3], start=c.cur)
        e.sstack.append(_LINEINPUTREAD)
        state.advance()
        return True
    if nxt is None or i.ops[c.k + 2][1] != "strassign":
        raise ValueError(f"LINE INPUT template mismatch at {addr:#x}")
    state.put(ir.LineInput(prompt, state.loc(nxt[2]), semi=op[3]), c.cur)
    c.cur = None
    state.advance(3)
    return True


def _console_line_input_file(state: DecodeState, op, addr: int) -> bool:
    i, e, c = state.image, state.expr, state.control
    if e.pend_fnum is None:
        raise ValueError(f"LINE INPUT # without a file number at {addr:#x}")
    nxt1 = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
    if nxt1 is not None and nxt1[1] != "movsi":
        # Computed string-array-element target; the index computation runs
        # between the read and the element store.
        e.pend_line_input = LineInputChain(start=c.cur, file=e.pend_fnum)
        e.sstack.append(_LINEINPUTREAD)
        e.pend_fnum = None
        state.advance()
        return True
    nxt = [o[1] for o in i.ops[c.k + 1 : c.k + 3]]
    if nxt != ["movsi", "strassign"]:
        raise ValueError(f"LINE INPUT # template mismatch at {addr:#x}")
    state.put(ir.LineInput(None, state.loc(i.ops[c.k + 1][2]), e.pend_fnum), c.cur)
    e.pend_fnum = None
    c.cur = None
    state.advance(3)
    return True


def _console_tabspc(state: DecodeState, op, addr: int) -> bool:
    i, m, e, c = state.image, state.machine, state.expr, state.control
    name, leg = _TABSPC_VECS[op[2]]
    if m.ax is None or isinstance(m.ax, tuple):
        raise ValueError(f"{name} without an ax argument at {addr:#x}")
    if e.pend_using is not None:
        # TAB/SPC is an item inside a PRINT USING chain only when another
        # USING emit follows it. A trailing TAB starts the next statement
        # in existing wild output, so retain the old lazy flush there.
        if match_using_chain_continues(i.ops, c.k) is not None:
            e.pend_using.values.append(ir.Call(name, (m.ax,)))
            m.ax = None
            c.cur = None
            state.advance()
            return True
        # A TAB after a NESTED USING is an item of the chain that owns it,
        # not the start of a statement (t1_usingtwice's TAB between the two
        # USING clauses).
        if not state.close_nested_using():
            state.flush_pending()
    if leg == "lprint":  # printer leg joins/opens an LPRINT chain (t1_ltab)
        if e.pend_print is not None and e.pend_print.mode != "lprint":
            state.flush_pending()
        if e.pend_print is None:
            e.pend_print = PrintChain(
                items=[], file=None, start=c.cur, mode="lprint"
            )
    else:
        f = e.pend_fnum if leg else None
        if leg and f is None:
            raise ValueError(f"file {name} without [0060] at {addr:#x}")
        if e.pend_print is not None and e.pend_print.file != f:
            state.flush_pending()  # console/file leg change = new stmt
        if e.pend_print is None:
            e.pend_print = PrintChain(file=f, start=c.cur)
    assert e.pend_print is not None  # just established above
    e.pend_print.items.append(ir.Call(name, (m.ax,)))
    m.ax = None
    c.cur = None
    state.advance()
    return True


def console(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: input, line_input, key_list, tabspc, swap."""
    c = state.control
    if kind == "input":  # INPUT prologue
        return _console_input(state, op, addr)
    if kind == "line_input":  # LINE INPUT
        return _console_line_input(state, op, addr)
    if kind == "line_input_file":  # LINE INPUT #n, var$
        return _console_line_input_file(state, op, addr)
    if kind == "key_list":  # KEY LIST
        state.put(ir.KeyList(), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "tabspc":  # TAB(n)/SPC(n) item
        return _console_tabspc(state, op, addr)
    if kind == "swap":  # SWAP a, b (two scalar displacements)
        state.put(ir.Swap(state.loc(op[2]), state.loc(op[3])), c.cur)
        c.cur = None
        state.advance()
        return True
    return False
