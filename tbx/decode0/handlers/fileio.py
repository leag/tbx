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


def _read_numeric_input(state: DecodeState, addr) -> bool:
    i, e, c = state.image, state.expr, state.control
    nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
    if e.pend_input is None or nxt is None:
        raise ValueError(f"numeric INPUT read without target at {addr:#x}")
    if nxt[1] in ("fstp", "fstp64"):
        var, used = state.loc(nxt[2]), 2
    elif nxt[1] == "fstp_bp":
        var, used = state.loc_local_fp(nxt[2]), 2
    elif nxt[1] == "fistp" and nxt[2] == 0x2C:
        var, used = _numeric_bridge_target(state, addr)
    elif _numeric_array_target(i.ops, c.k, nxt):
        e.stack.append(_INPUTREAD)
        state.advance()
        return True
    else:
        raise ValueError(f"numeric INPUT read without FSTP at {addr:#x}")
    state._input_target(var, is_str=False)
    c.cur = None
    state.advance(used)
    return True


def _numeric_bridge_target(state: DecodeState, addr):
    i, c = state.image, state.control
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
    var = state.loc(store[2]) if store[1] == "movm_ax" else state.loc_local(store[2])
    return var, j + 2 - c.k


def _numeric_array_target(ops, index, nxt) -> bool:
    return nxt[1] in ("fld", "fild", "fld64") or (
        nxt[1] == "moves_m"
        and index + 2 < len(ops)
        and ops[index + 2][1] in ("far_fstp", "far_fstp64")
    )


def _read_string_input(state: DecodeState) -> bool:
    i, e, c = state.image, state.expr, state.control
    nxt = i.ops[c.k + 1] if c.k + 1 < len(i.ops) else None
    if nxt is not None and nxt[1] != "movsi":
        e.sstack.append(_INPUTREAD)
    state.advance()
    return True


def data_read(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: read_num, read_str."""
    if kind == "read_num":
        return _read_numeric_input(state, addr)
    if kind == "read_str":
        return _read_string_input(state)
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


def _write_file_separator(state: DecodeState, addr) -> bool:
    e = state.expr
    if (
        e.pend_print is None
        or e.pend_print.mode != "write"
        or e.pend_print.file is None
    ):
        raise ValueError(f"WRITE# separator without open chain at {addr:#x}")
    state.advance()
    return True


def _write_item(state: DecodeState) -> bool:
    e, c = state.expr, state.control
    item = e.stack.pop()
    if e.pend_print is not None and e.pend_print.mode != "write":
        state.flush_pending()
    if e.pend_print is None:
        e.pend_print = PrintChain(items=[], file=None, start=c.cur, mode="write")
    e.pend_print.items.append(item)
    c.cur = None
    state.advance()
    return True


def _write_separator(state: DecodeState, addr) -> bool:
    e = state.expr
    if e.pend_print is None or e.pend_print.mode != "write":
        raise ValueError(f"WRITE separator without open WRITE chain at {addr:#x}")
    state.advance()
    return True


def write_ops(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: write_file_sep, write_item, write_sep."""
    if kind == "write_file_sep":
        return _write_file_separator(state, addr)
    if kind == "write_item":
        return _write_item(state)
    if kind == "write_sep":
        return _write_separator(state, addr)
    return False
