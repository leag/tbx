"""File and DATA statement handlers: OPEN/GET/PUT/FIELD, WRITE, READ.

Handlers for ``decode_user_code``'s dispatch loop; each handler takes
the shared :class:`~tbx.decode0.core.DecodeState` plus the current
``op``/``addr``/``kind`` and returns ``True`` when it consumed the op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tbx import ir
from tbx.decode0.const import (
    _FREAD,
    _INPUTREAD,
    _READDATA,
)

if TYPE_CHECKING:
    from tbx.decode0.core import DecodeState


def fileio(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: open, close, field."""
    if kind == "open":  # OPEN "m",#n,file[,reclen] -- ax = reclen, 0x80 default
        for_as = state.pend_mode_lit is not None  # `OPEN f$ FOR mode AS #n`:
        need = 1 if for_as else 2  # the keyword desugars to a shortstr-
        if state.pend_fnum is None or len(state.sstack) < need or state.ax is None:
            raise ValueError(
                f"OPEN state mismatch at {addr:#x} "
                f"(fnum={state.pend_fnum}, sstack={len(state.sstack)}, ax={state.ax})"
            )
        # reclen is usually a bare literal, but can be any numeric expression
        # (`OPEN f$ FOR RANDOM AS #1 LEN = 18 - 50 * X%`, wild hebrew.exe).
        reclen = None if state.ax == ir.Lit(0x80) else state.ax
        if for_as:
            mode, file = state.pend_mode_lit, state.sstack.pop()
        else:
            mode, file = state.sstack.pop(), state.sstack.pop()
        state.put(ir.Open(mode, state.pend_fnum, file, reclen, for_as), state.cur)
        state.pend_fnum = state.ax = state.pend_mode_lit = None
        state.cur = None
        state.k += 1
        return True
    if kind == "close":  # CLOSE #ax -- usually a literal; a variable/
        # expression is passed through as-is (wild metric.exe, probe
        # q_closevar)
        if state.ax is None:
            raise ValueError(f"CLOSE without a file number at {addr:#x}")
        num = state.ax.value if isinstance(state.ax, ir.Lit) else state.ax
        state.put(ir.Close(num), state.cur)
        state.ax = None
        state.cur = None
        state.k += 1
        return True
    if kind == "close_all":  # bare CLOSE: all channels, no operands
        state.put(ir.Close(None), state.cur)
        state.cur = None
        state.k += 1
        return True
    if kind == "field":  # FIELD #n, w AS v$[, ...]
        if state.pend_fnum is None:
            raise ValueError(f"FIELD without file number at {addr:#x}")
        # Each width (a bare literal or a computed expression, wild
        # hebrew.exe) accumulates into state.ax through the ordinary per-op
        # dispatch like any other expression; the movsi/movdx/movesdx/
        # field_as terminal (core.py's main loop) closes out one AS-entry at
        # a time and flush_pending emits the ir.Field once the FIELD chain
        # is proven closed by the next statement, same lazy-close
        # convention as READ/INPUT#/PRINT chains.
        state.pend_field = {"fnum": state.pend_fnum, "fields": [], "start": state.cur}
        state.pend_fnum = None
        state.k += 1
        return True
    if kind == "ioctl":  # IOCTL #n, s$ -- filenum via [0060], string pushed
        if state.pend_fnum is None:
            raise ValueError(f"IOCTL without a file number at {addr:#x}")
        state.put(ir.Ioctl(state.pend_fnum, state.sstack.pop()), state.cur)
        state.pend_fnum = None
        state.cur = None
        state.k += 1
        return True
    if kind == "put_str":  # PUT$ #n, s$ -- filenum via [0060], string pushed
        if state.pend_fnum is None:
            raise ValueError(f"PUT$ without a file number at {addr:#x}")
        state.put(ir.PutString(state.pend_fnum, state.sstack.pop()), state.cur)
        state.pend_fnum = None
        state.cur = None
        state.k += 1
        return True
    return False


def file_write(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: write_file_num, write_file_str."""
    if kind in ("write_file_num", "write_file_str"):  # WRITE# item
        item = state.stack.pop() if kind == "write_file_num" else state.sstack.pop()
        if state.pend_print is not None and (
            state.pend_print.get("mode") != "write" or state.pend_print["file"] is None
        ):
            raise ValueError(f"WRITE# item into non-WRITE# chain at {addr:#x}")
        if state.pend_print is None:
            if state.pend_fnum is None:
                raise ValueError(f"WRITE# without file number at {addr:#x}")
            state.pend_print = {
                "items": [],
                "file": state.pend_fnum,
                "start": state.cur,
                "mode": "write",
            }
        state.pend_print["items"].append(item)
        state.cur = None
        state.k += 1
        return True
    return False


def file_read(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: read_file_num, read_file_str."""
    if kind in ("read_file_num", "read_file_str"):  # INPUT #n:
        if state.pend_fnum is None:  # parse a value onto the FP/string
            raise ValueError(f"INPUT# read without file number at {addr:#x}")
        if state.pend_filein is None:  # stack; the consuming store (near
            state.pend_filein = {
                "num": state.pend_fnum,  # or far) names the target
                "targets": [],
                "start": state.cur,
            }
        (state.stack if kind == "read_file_num" else state.sstack).append(_FREAD)
        state.k += 1
        return True
    if kind == "get_str":
        if state.pend_fnum is None or state.ax is None:
            raise ValueError(f"GET$ without file/count at {addr:#x}")
        state.pend_getstr = (state.pend_fnum, state.ax)
        state.pend_fnum = state.ax = None
        state.k += 1
        return True
    return False


def file_random(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: get, put, seek."""
    if kind in ("get", "put", "seek"):  # random-access record ops
        if state.pend_fnum is None:
            raise ValueError(f"{kind.upper()} without file number at {addr:#x}")
        pos = state.stack.pop()
        klass: Any = {"get": ir.Get, "put": ir.Put, "seek": ir.Seek}[kind]
        state.put(klass(state.pend_fnum, pos), state.cur)
        state.pend_fnum = None
        state.cur = None
        state.k += 1
        return True
    return False


def data_read(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: read_num, read_str."""
    if kind == "read_num":  # INPUT numeric read -> FSTP var
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
        if state.pend_input is None or nxt is None:
            raise ValueError(f"numeric INPUT read without target at {addr:#x}")
        if nxt[1] in ("fstp", "fstp64"):  # SINGLE/DOUBLE variable target
            var, used = state.loc(nxt[2]), 2
        elif nxt[1] == "fistp" and nxt[2] == 0x2C:
            # INTEGER target via the x87-to-AX bridge. FWAIT has a calibrated
            # two-NOP spelling in this runtime family; the terminal store may
            # name a DGROUP scalar or a BP-relative LOCAL.
            j = state.k + 2
            if j < len(state.ops) and state.ops[j][1] == "fwait":
                j += 1
            elif (
                j + 1 < len(state.ops)
                and state.ops[j][1] == "nop"
                and state.ops[j + 1][1] == "nop"
            ):
                j += 2
            else:
                raise ValueError(f"numeric INPUT integer bridge mismatch at {addr:#x}")
            if (
                j + 1 >= len(state.ops)
                or state.ops[j][1:] != ("movaxmem", 0x2C)
                or state.ops[j + 1][1] not in ("movm_ax", "movm_ax_bp")
            ):
                raise ValueError(f"numeric INPUT integer bridge mismatch at {addr:#x}")
            store = state.ops[j + 1]
            var = (
                state.loc(store[2])
                if store[1] == "movm_ax"
                else state.loc_local(store[2])
            )
            used = j + 2 - state.k
        elif nxt[1] in ("fld", "fild"):
            # Array-element target (t1_inparr, wild schart.exe): the index
            # computation runs between the read and the element store, so the
            # parsed value waits on the FP stack as a sentinel and the store
            # terminal (fstp_si) names the target; pend_input stays open for
            # it. Any other continuation still fails loudly below.
            state.stack.append(_INPUTREAD)
            state.k += 1
            return True
        else:
            raise ValueError(f"numeric INPUT read without FSTP at {addr:#x}")
        state._input_target(var, is_str=False)
        state.cur = None
        state.k += used
        return True
    if kind == "read_str":  # INPUT string read (movsi+strassign
        nxt = state.ops[state.k + 1] if state.k + 1 < len(state.ops) else None
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
            state.sstack.append(_INPUTREAD)
            state.k += 1
            return True
        state.k += 1  # plain scalar target; handled by the movsi case)
        return True
    return False


def data_read2(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: data_read_num, data_read_str."""
    if kind in ("data_read_num", "data_read_str"):  # READ <var>: next DATA
        if state.pend_dataread is None:  # item -> FP/string stack; the
            state.pend_dataread = {
                "targets": [],
                "start": state.cur,
            }  # consuming store names the
        (state.stack if kind == "data_read_num" else state.sstack).append(
            _READDATA
        )  # target
        state.k += 1
        return True
    return False


def write_ops(state: DecodeState, op, addr, kind) -> bool:
    """Dispatch family: write_file_sep, write_item, write_sep."""
    if kind == "write_file_sep":  # WRITE# item separator
        if (
            state.pend_print is None
            or state.pend_print.get("mode") != "write"
            or state.pend_print["file"] is None
        ):
            raise ValueError(f"WRITE# separator without open chain at {addr:#x}")
        state.k += 1
        return True
    if kind == "write_item":  # WRITE numeric item (FP stack)
        item = state.stack.pop()
        if state.pend_print is not None and state.pend_print.get("mode") != "write":
            state.flush_pending()
        if state.pend_print is None:
            state.pend_print = {
                "items": [],
                "file": None,
                "start": state.cur,
                "mode": "write",
            }
        assert state.pend_print is not None  # just established above
        state.pend_print["items"].append(item)
        state.cur = None
        state.k += 1
        return True
    if kind == "write_sep":  # WRITE comma separator
        if state.pend_print is None or state.pend_print.get("mode") != "write":
            raise ValueError(f"WRITE separator without open WRITE chain at {addr:#x}")
        state.k += 1
        return True
    return False
