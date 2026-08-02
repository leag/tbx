"""File and DATA statement handlers: OPEN/GET/PUT/FIELD, WRITE, READ.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tbx import ir
from tbx.decode0.frames import FieldChain, PrintChain, ReadChain
from tbx.decode0.const import (
    _FREAD,
    _INPUTREAD,
    _READDATA,
)

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def fileio(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: open, close, field."""
    m, e, c = state.machine, state.expr, state.control
    if kind == "open":  # OPEN "m",#n,file[,reclen] -- ax = reclen, 0x80 default
        for_as = e.pend_mode_lit is not None  # `OPEN f$ FOR mode AS #n`:
        need = 1 if for_as else 2  # the keyword desugars to a shortstr-
        if e.pend_fnum is None or len(e.sstack) < need or m.ax is None:
            raise ValueError(
                f"OPEN state mismatch at {addr:#x} "
                f"(fnum={e.pend_fnum}, sstack={len(e.sstack)}, ax={m.ax})"
            )
        # reclen is usually a bare literal, but can be any numeric expression
        # (`OPEN f$ FOR RANDOM AS #1 LEN = 18 - 50 * X%`, wild hebrew.exe).
        reclen = None if m.ax == ir.Lit(0x80) else m.ax
        if for_as:
            mode, file = e.pend_mode_lit, e.sstack.pop()
        else:
            mode, file = e.sstack.pop(), e.sstack.pop()
        state.put(ir.Open(mode, e.pend_fnum, file, reclen, for_as), c.cur)
        e.pend_fnum = m.ax = e.pend_mode_lit = None
        c.cur = None
        state.advance()
        return True
    if kind == "close":  # CLOSE #ax -- usually a literal; a variable/
        # expression is passed through as-is (wild metric.exe, probe
        # q_closevar)
        if m.ax is None:
            raise ValueError(f"CLOSE without a file number at {addr:#x}")
        num = m.ax.value if isinstance(m.ax, ir.Lit) else m.ax
        state.put(ir.Close(num), c.cur)
        m.ax = None
        c.cur = None
        state.advance()
        return True
    if kind == "close_all":  # bare CLOSE: all channels, no operands
        state.put(ir.Close(None), c.cur)
        c.cur = None
        state.advance()
        return True
    if kind == "field":  # FIELD #n, w AS v$[, ...]
        if e.pend_fnum is None:
            raise ValueError(f"FIELD without file number at {addr:#x}")
        # Each width (a bare literal or a computed expression, wild
        # hebrew.exe) accumulates into m.ax through the ordinary per-op
        # dispatch like any other expression; the movsi/movdx/movesdx/
        # field_as terminal (core.py's main loop) closes out one AS-entry at
        # a time and flush_pending emits the ir.Field once the FIELD chain
        # is proven closed by the next statement, same lazy-close
        # convention as READ/INPUT#/PRINT chains.
        e.pend_field = FieldChain(fnum=e.pend_fnum, start=c.cur)
        e.pend_fnum = None
        state.advance()
        return True
    if kind == "ioctl":  # IOCTL #n, s$ -- filenum via [0060], string pushed
        if e.pend_fnum is None:
            raise ValueError(f"IOCTL without a file number at {addr:#x}")
        state.put(ir.Ioctl(e.pend_fnum, e.sstack.pop()), c.cur)
        e.pend_fnum = None
        c.cur = None
        state.advance()
        return True
    if kind == "put_str":  # PUT$ #n, s$ -- filenum via [0060], string pushed
        if e.pend_fnum is None:
            raise ValueError(f"PUT$ without a file number at {addr:#x}")
        state.put(ir.PutString(e.pend_fnum, e.sstack.pop()), c.cur)
        e.pend_fnum = None
        c.cur = None
        state.advance()
        return True
    return False


def file_write(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: write_file_num, write_file_str."""
    e, c = state.expr, state.control
    if kind in ("write_file_num", "write_file_str"):  # WRITE# item
        item = e.stack.pop() if kind == "write_file_num" else e.sstack.pop()
        if e.pend_print is not None and (
            e.pend_print.mode != "write" or e.pend_print.file is None
        ):
            raise ValueError(f"WRITE# item into non-WRITE# chain at {addr:#x}")
        if e.pend_print is None:
            if e.pend_fnum is None:
                raise ValueError(f"WRITE# without file number at {addr:#x}")
            e.pend_print = PrintChain(
                items= [],
                file= e.pend_fnum,
                start= c.cur,
                mode= "write",
            )
        e.pend_print.items.append(item)
        c.cur = None
        state.advance()
        return True
    return False


def file_read(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: read_file_num, read_file_str."""
    m, e, c = state.machine, state.expr, state.control
    if kind in ("read_file_num", "read_file_str"):  # INPUT #n:
        if e.pend_fnum is None:  # parse a value onto the FP/string
            raise ValueError(f"INPUT# read without file number at {addr:#x}")
        if e.pend_filein is None:  # stack; the consuming store (near
            e.pend_filein = ReadChain(  # or far) names the target
                num=e.pend_fnum, start=c.cur
            )
        (e.stack if kind == "read_file_num" else e.sstack).append(_FREAD)
        state.advance()
        return True
    if kind == "get_str":
        if e.pend_fnum is None or m.ax is None:
            raise ValueError(f"GET$ without file/count at {addr:#x}")
        e.pend_getstr = (e.pend_fnum, m.ax)
        e.pend_fnum = m.ax = None
        state.advance()
        return True
    return False


def file_random(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: get, put, seek."""
    e, c = state.expr, state.control
    if kind in ("get", "put", "seek"):  # random-access record ops
        if e.pend_fnum is None:
            raise ValueError(f"{kind.upper()} without file number at {addr:#x}")
        # PUT #n may omit the record expression and write the current record
        # (the older TB 1.0 dispatch revision used by catalog.exe).
        pos = e.stack.pop() if e.stack else None
        klass: Any = {"get": ir.Get, "put": ir.Put, "seek": ir.Seek}[kind]
        state.put(klass(e.pend_fnum, pos), c.cur)
        e.pend_fnum = None
        c.cur = None
        state.advance()
        return True
    return False


def data_read(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: read_num, read_str."""
    i, e, c = state.image, state.expr, state.control
    if kind == "read_num":  # INPUT numeric read -> FSTP var
        nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
        if e.pend_input is None or nxt is None:
            raise ValueError(f"numeric INPUT read without target at {addr:#x}")
        if nxt[1] in ("fstp", "fstp64"):  # SINGLE/DOUBLE variable target
            var, used = state.loc(nxt[2]), 2
        elif nxt[1] == "fstp_bp":  # LOCAL SINGLE target
            var, used = state.loc_local_fp(nxt[2]), 2
        elif nxt[1] == "fistp" and nxt[2] == 0x2C:
            # INTEGER target via the x87-to-AX bridge. FWAIT has a calibrated
            # two-NOP spelling in this runtime family; the terminal store may
            # name a DGROUP scalar or a BP-relative LOCAL.
            j = c.k + 2
            if j < len(i.ops) and i.ops[j][1] == "fwait":
                j += 1
            elif (
                j + 1 < len(i.ops)
                and i.ops[j][1] == "nop"
                and i.ops[j + 1][1] == "nop"
            ):
                j += 2
            else:
                raise ValueError(f"numeric INPUT integer bridge mismatch at {addr:#x}")
            if (
                j + 1 >= len(i.ops)
                or i.ops[j][1:] != ("movaxmem", 0x2C)
                or i.ops[j + 1][1] not in ("movm_ax", "movm_ax_bp")
            ):
                raise ValueError(f"numeric INPUT integer bridge mismatch at {addr:#x}")
            store = i.ops[j + 1]
            var = (
                state.loc(store[2])
                if store[1] == "movm_ax"
                else state.loc_local(store[2])
            )
            used = j + 2 - c.k
        elif (
            nxt[1] in ("fld", "fild", "fld64")
            or (
                nxt[1] == "moves_m"
                and c.k + 2 < len(i.ops)
                and i.ops[c.k + 2][1] in ("far_fstp", "far_fstp64")
            )
        ):
            # Array-element target (t1_inparr, wild schart.exe): the index
            # computation runs between the read and the element store, so the
            # parsed value waits on the FP stack as a sentinel and the store
            # terminal (fstp_si) names the target; pend_input stays open for
            # it. A DOUBLE-valued dynamic-array index begins with fld64
            # (t1_inpdynarr); a constant index starts directly with the
            # descriptor load `moves_m` (t1_inpdynconst; wild rs.exe).
            # Any other continuation still fails loudly below.
            e.stack.append(_INPUTREAD)
            state.advance()
            return True
        else:
            raise ValueError(f"numeric INPUT read without FSTP at {addr:#x}")
        state._input_target(var, is_str=False)
        c.cur = None
        state.advance(used)
        return True
    if kind == "read_str":  # INPUT string read (movsi+strassign
        nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
        if nxt is not None and nxt[1] != "movsi":
            # Computed string-array-element target (wild invent.exe, probe
            # q_inpsarr): the index expression's own evaluation runs
            # between the read and the element store -- an FP-typed index
            # needs the fistp/fwait/movaxmem bridge first (fld/fild
            # starts it), an already-integer one loads straight into si
            # (movsim/movsi_bp) -- so the parsed value waits on the
            # STRING stack as a sentinel meanwhile, the string sibling of
            # read_num's numeric _INPUTREAD case above. The only OTHER
            # continuation is the plain scalar target (movsi + strassign,
            # handled generically below); anything but a direct movsi at
            # this position must be an index computation starting. The
            # store terminal (the shlsi element-access handler's
            # strassign branch) names the target; pend_input stays open.
            e.sstack.append(_INPUTREAD)
            state.advance()
            return True
        state.advance()  # plain scalar target; handled by the movsi case)
        return True
    return False


def data_read2(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: data_read_num, data_read_str."""
    e, c = state.expr, state.control
    if kind in ("data_read_num", "data_read_str"):  # READ <var>: next DATA
        if e.pend_dataread is None:  # item -> FP/string stack; the
            e.pend_dataread = ReadChain(start=c.cur)  # consuming store names
        (e.stack if kind == "data_read_num" else e.sstack).append(
            _READDATA
        )  # target
        state.advance()
        return True
    return False


def write_ops(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: write_file_sep, write_item, write_sep."""
    e, c = state.expr, state.control
    if kind == "write_file_sep":  # WRITE# item separator
        if (
            e.pend_print is None
            or e.pend_print.mode != "write"
            or e.pend_print.file is None
        ):
            raise ValueError(f"WRITE# separator without open chain at {addr:#x}")
        state.advance()
        return True
    if kind == "write_item":  # WRITE numeric item (FP stack)
        item = e.stack.pop()
        if e.pend_print is not None and e.pend_print.mode != "write":
            state.flush_pending()
        if e.pend_print is None:
            e.pend_print = PrintChain(
                items= [],
                file= None,
                start= c.cur,
                mode= "write",
            )
        assert e.pend_print is not None  # just established above
        e.pend_print.items.append(item)
        c.cur = None
        state.advance()
        return True
    if kind == "write_sep":  # WRITE comma separator
        if e.pend_print is None or e.pend_print.mode != "write":
            raise ValueError(f"WRITE separator without open WRITE chain at {addr:#x}")
        state.advance()
        return True
    return False
