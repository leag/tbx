"""Screen output handlers: graphics primitives, boxes, PRINT/console.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tbx import ir
from tbx.decode0.const import (
    _LINEINPUTREAD,
    _TABSPC_VECS,
)

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def graphics(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: screen, cls, line, pset, circle, paint, draw, palette,
    palette_using, color_commit, locate, cursor, width."""
    if kind == "screen":  # SCREEN m[,b][,a][,v]: cells by presence mask
        tag = op[2]
        mode = state.color_cells.pop(0x88, None) if tag & 0x08 else None
        if tag & 0x08 and mode is None:
            raise ValueError(f"SCREEN without [0x88] mode store at {addr:#x}")
        burst = state.color_cells.pop(0x94, None) if tag & 0x04 else None
        apage = state.color_cells.pop(0xA0, None) if tag & 0x02 else None
        vpage = state.color_cells.pop(0xAC, None) if tag & 0x01 else None
        if (
            (tag & 0x04 and burst is None)
            or (tag & 0x02 and apage is None)
            or (tag & 0x01 and vpage is None)
            or state.color_cells
        ):
            raise ValueError(f"SCREEN arg cell missing for tag {tag:#x} at {addr:#x}")
        state.put(ir.Screen(mode, burst, apage, vpage), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "cls":
        state.put(ir.Cls(), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "line":  # LINE [[STEP](..)]-[STEP](..)[,c][,B|BF][,style]
        fl = op[2]
        if fl & ~0x7F or (fl & 0x02 and not fl & 0x04):
            raise ValueError(f"LINE flag {fl:02x} at {addr:#x} (unsupported)")
        if not fl & 0x40 and fl & 0x20:
            # STEP on an omitted first point is unwitnessed -- stay fail-loud
            # rather than guess what it would even mean.
            raise ValueError(f"LINE flag {fl:02x} at {addr:#x} (unsupported)")
        color = state.color_cells.pop(0xA0) if fl & 0x08 else None
        style = state.color_cells.pop(0xAC) if fl & 0x01 else None
        if isinstance(style, ir.Lit):  # style word reads as a bit pattern
            style = ir.HexLit(style.value & 0xFFFF)
        box = ("BF" if fl & 0x02 else "B") if fl & 0x04 else ""
        y2 = state.stack.pop()
        x2 = state.stack.pop()
        if fl & 0x40:
            x1 = state.color_cells.pop(0x88)
            y1 = state.color_cells.pop(0x94)
        else:  # first point omitted entirely: `LINE -(x2,y2)` from the last
            x1 = y1 = None  # graphics position (wild cal87.exe)
        state.put(
            ir.LineStmt(
                x1,
                y1,
                x2,
                y2,
                color,
                box,
                step1=bool(fl & 0x20),
                step2=bool(fl & 0x10),
                style=style,
            ),
            state.cur,
        )
        state.cur = None
        state.k += 1
        return True
    if kind == "pset":  # PSET/PRESET [STEP] (x,y)[, color]
        fl = op[2]
        # Exactly one of 01=PRESET / 02=PSET / 04=color (color drops the
        # PSET/PRESET bit -- explicit color overrides the default attr);
        # 08=STEP composes with any of them.
        if fl & ~0x0F or bin(fl & 0x07).count("1") != 1:
            raise ValueError(f"PSET flag {fl:02x} at {addr:#x} (unsupported)")
        color = state.color_cells.pop(0x88) if fl & 0x04 else None
        y = state.stack.pop()
        x = state.stack.pop()
        state.put(
            ir.Pset(x, y, color, preset=bool(fl & 0x01), step=bool(fl & 0x08)),
            state.cur,
        )
        state.cur = None
        state.k += 1
        return True
    if kind == "circle":  # CIRCLE [STEP] (x,y), r[,c][,s][,e][,asp]
        fl = op[2]
        if fl & ~0x1F:
            raise ValueError(f"CIRCLE flag {fl:02x} at {addr:#x} (unsupported)")
        color = state.color_cells.pop(0x88) if fl & 0x08 else None
        cstart = state.color_cells.pop(0x94) if fl & 0x04 else None
        cend = state.color_cells.pop(0xA0) if fl & 0x02 else None
        aspect = state.color_cells.pop(0xAC) if fl & 0x01 else None
        if isinstance(aspect, ir.DblLit):  # unsuffixed source literal:
            aspect = ir.SingleLit(aspect.value)  # pooled f64, rendered plain
        r = state.stack.pop()
        y = state.stack.pop()
        x = state.stack.pop()
        state.put(
            ir.Circle(x, y, r, color, cstart, cend, aspect, step=bool(fl & 0x10)),
            state.cur,
        )
        state.cur = None
        state.k += 1
        return True
    if kind == "paint":  # PAINT (x,y)[, paint][, border]
        if op[2] & ~0x03:
            raise ValueError(f"PAINT flag {op[2]:02x} at {addr:#x} (unsupported)")
        paint = state.color_cells.pop(0x88) if op[2] & 0x02 else None
        border = state.color_cells.pop(0x94) if op[2] & 0x01 else None
        y = state.stack.pop()
        x = state.stack.pop()
        state.put(ir.Paint(x, y, paint, border), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "paint_tile":  # PAINT (x,y), tile$[, border] (witnessed t1_paintt)
        if op[2] & ~0x01:
            raise ValueError(f"PAINT tile flag {op[2]:02x} at {addr:#x} (unsupported)")
        border = state.color_cells.pop(0x94) if op[2] & 0x01 else None
        tile = state.sstack.pop()
        y = state.stack.pop()
        x = state.stack.pop()
        state.put(ir.Paint(x, y, tile, border), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "draw":  # DRAW cmd$
        state.put(ir.Draw(state.sstack.pop()), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "palette":  # PALETTE attr(bx), color(ax)
        state.put(ir.Palette(state.bx, state.ax), state.cur)
        state.bx = state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "palette_using":
        # A constant zero subscript on a dynamic array is emitted as
        # mov ES,[block]; xor SI,SI; EC/8A.  The variable-index form is
        # consumed by arith.shlsi, while static constant elements use the
        # movsi continuation in core.py.
        if (
            state.pend_es is None
            or state.k == 0
            or state.ops[state.k - 1][1] != "bchk0"
        ):
            raise ValueError(f"PALETTE USING without array element at {addr:#x}")
        a = state.r_arrs[state.pend_es]
        if a.get("str") or a.get("esz") != 2 or a["rank"] != 1:
            raise ValueError(
                f"PALETTE USING non-INTEGER rank-{a['rank']} array at {addr:#x}"
            )
        state.put(
            ir.PaletteUsing(ir.ArrayRef(a["name"], (ir.Lit(a["lo"][0]),))),
            state.cur,
        )
        state.pend_es = None
        state.cur = None
        state.k += 1
        return True
    if kind == "color_commit":  # COLOR fg(04)/bg(02)/border(01) mask
        fg, bg, border = (
            state.color_cells.pop(0x88, None),
            state.color_cells.pop(0x94, None),
            state.color_cells.pop(0xA0, None),
        )
        want_mask = (
            (4 if fg is not None else 0)
            | (2 if bg is not None else 0)
            | (1 if border is not None else 0)
        )
        if op[2] != want_mask or state.color_cells:
            raise ValueError(
                f"COLOR mask {op[2]:02x} != cells {want_mask:02x} "
                f"(+{state.color_cells}) at {addr:#x}"
            )
        state.put(ir.Color(fg, bg, border), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "locate":  # LOCATE row(bx),col(ax)
        state.put(ir.Locate(state.bx, state.ax), state.cur)
        state.bx = state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "cursor":  # trailing cursor arg -> attach
        if state.stmts and isinstance(state.stmts[-1], ir.Locate):
            prev = state.stmts[-1]
            if prev.cursor is not None:
                raise ValueError(f"duplicate LOCATE cursor call at {addr:#x}")
            state.stmts[-1] = ir.Locate(prev.row, prev.col, state.ax)
        else:  # LOCATE ,,cursor: no row/column runtime call precedes it
            state.put(ir.Locate(None, None, state.ax), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "cursor_shape":  # trailing cursor start/stop -> attach
        if state.stmts and isinstance(state.stmts[-1], ir.Locate):
            prev = state.stmts[-1]
            if prev.start is not None or prev.stop is not None:
                raise ValueError(f"duplicate LOCATE cursor shape call at {addr:#x}")
            state.stmts[-1] = ir.Locate(
                prev.row, prev.col, prev.cursor, state.bx, state.ax
            )
        else:  # LOCATE ,,,start,stop: the shape call is the whole statement
            state.put(ir.Locate(None, None, None, state.bx, state.ax), state.cur)
        state.bx = state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "width":  # WIDTH cols (ax)
        if state.ax is None or isinstance(state.ax, tuple):
            raise ValueError(f"WIDTH without an ax argument at {addr:#x}")
        state.put(ir.Width(state.ax), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "width_dev":  # WIDTH device$, cols (device string pushed, ax=cols)
        if state.ax is None or isinstance(state.ax, tuple):
            raise ValueError(f"WIDTH without an ax argument at {addr:#x}")
        state.put(ir.Width(state.ax, state.sstack.pop()), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "width_file":  # WIDTH #filenum,cols ([0060] channel, ax=cols)
        if state.pend_fnum is None or state.ax is None or isinstance(state.ax, tuple):
            raise ValueError(
                f"WIDTH # without file/ax arguments at {addr:#x} "
                f"(fnum={state.pend_fnum}, ax={state.ax})"
            )
        state.put(ir.Width(state.ax, file=state.pend_fnum), state.cur)
        state.pend_fnum = state.ax = None
        state.cur = None
        state.k += 1
        return True
    return False


def graphics_box(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: view, window."""
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
                state.color_cells.pop(c) for c in (0x88, 0x94, 0xA0, 0xAC)
            )
        except KeyError:
            raise ValueError(f"{kind.upper()} coord cells incomplete at {addr:#x}")
        if kind == "view":
            vcolor = state.color_cells.pop(0xB8) if fl & 0x02 else None
            vborder = state.color_cells.pop(0xC4) if fl & 0x01 else None
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
                state.cur,
            )
        else:
            state.put(ir.Window(x1, y1, x2, y2, screen=bool(fl & scr_bit)), state.cur)
        state.cur = None
        state.k += 1
        return True
    return False


def console(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: input, line_input, key_list, tabspc, swap."""
    if kind == "input":  # INPUT prologue
        prompt = None if op[2] == state.lay["pool_base"] - 4 else state._pool_str(op[2])
        flags = op[3]
        count = flags & 0x3F  # extra targets beyond the first
        tmask = 0  # per-position numeric-type bits, 0x4000 >> k
        for i in range(count + 1):
            tmask |= 0x4000 >> i
        if flags & ~(0x00C0 | 0x3F | tmask):
            raise ValueError(
                f"INPUT flags {flags:#06x} with {count + 1} targets at {addr:#x}"
            )
        state.pend_input = {
            "prompt": prompt,
            "flags": flags,
            "targets": [],
            "want": count + 1,
            "start": state.cur,
        }
        state.k += 1
        return True
    if kind == "line_input":  # LINE INPUT
        prompt = None if op[2] == state.lay["pool_base"] - 4 else state._pool_str(op[2])
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        if nxt is not None and nxt[1] != "movsi":
            # Computed string-array-element target (wild cal87.exe), the
            # LINE INPUT sibling of read_str's _INPUTREAD case: the index
            # computation runs between the read and the element store, so
            # the store (the shlsi element-access handler's strassign
            # branch) names the target.
            state.pend_line_input = {"prompt": prompt, "semi": op[3], "start": state.cur}
            state.sstack.append(_LINEINPUTREAD)
            state.k += 1
            return True
        if nxt is None or state.ops[state.k + 2][1] != "strassign":
            raise ValueError(f"LINE INPUT template mismatch at {addr:#x}")
        state.put(
            ir.LineInput(prompt, state.loc(nxt[2]), semi=op[3]),
            state.cur,
        )
        state.cur = None
        state.k += 3
        return True
    if kind == "line_input_file":  # LINE INPUT #n, var$
        if state.pend_fnum is None:
            raise ValueError(f"LINE INPUT # without a file number at {addr:#x}")
        nxt = [o[1] for o in state.ops[state.k + 1 : state.k + 3]]
        if nxt != ["movsi", "strassign"]:
            raise ValueError(f"LINE INPUT # template mismatch at {addr:#x}")
        state.put(
            ir.LineInput(
                None, state.loc(state.ops[state.k + 1][2]), state.pend_fnum
            ),
            state.cur,
        )
        state.pend_fnum = None
        state.cur = None
        state.k += 3
        return True
    if kind == "key_list":  # KEY LIST
        state.put(ir.KeyList(), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "tabspc":  # TAB(n)/SPC(n) item
        name, leg = _TABSPC_VECS[op[2]]
        if state.ax is None or isinstance(state.ax, tuple):
            raise ValueError(f"{name} without an ax argument at {addr:#x}")
        if state.pend_using is not None:
            # TAB/SPC is an item inside a PRINT USING chain only when another
            # USING emit follows it. A trailing TAB starts the next statement
            # in existing wild output, so retain the old lazy flush there.
            in_chain = False
            for look in state.ops[state.k + 1 : state.k + 18]:
                if look[1] == "rt" and look[2] in (0xCB, 0xCC):
                    in_chain = True
                    break
                if look[1] == "rt" and look[2] in (0xCA, 0xB8, 0xB9):
                    break
            if in_chain:
                state.pend_using["values"].append(ir.Call(name, (state.ax,)))
                state.ax = None
                state.cur = None
                state.k += 1
                return True
            state.flush_pending()
        if leg == "lprint":  # printer leg joins/opens an LPRINT chain (t1_ltab)
            if (
                state.pend_print is not None
                and state.pend_print.get("mode") != "lprint"
            ):
                state.flush_pending()
            if state.pend_print is None:
                state.pend_print = {
                    "items": [],
                    "file": None,
                    "start": state.cur,
                    "mode": "lprint",
                }
        else:
            f = state.pend_fnum if leg else None
            if leg and f is None:
                raise ValueError(f"file {name} without [0060] at {addr:#x}")
            if state.pend_print is not None and state.pend_print["file"] != f:
                state.flush_pending()  # console/file leg change = new stmt
            if state.pend_print is None:
                state.pend_print = {"items": [], "file": f, "start": state.cur}
        assert state.pend_print is not None  # just established above
        state.pend_print["items"].append(ir.Call(name, (state.ax,)))
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "swap":  # SWAP a, b (two scalar displacements)
        state.put(ir.Swap(state.loc(op[2]), state.loc(op[3])), state.cur)
        state.cur = None
        state.k += 1
        return True
    return False
