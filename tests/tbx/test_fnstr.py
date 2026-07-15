"""String DEF FN: single-line (t1_fnstr) and multi-line (t1_fnstrb).

The string protocol around a DEF FN body (all byte-exact verified):
string params push via `mov si,off; INT 9E`, the result descriptor stores
to [bp+0] via `mov si,0; INT A2`, the caller stages string args with
INT A2 into zero-inited [bp+n] slots and fetches the result with INT 9F,
and the body frees each string param temp with `les si,[bp+n]; INT D3`.
A single-line string FN zeroes only [bp+2], so only the [bp+0] init marks
the multi-line form.
"""

import os

from tbx import decode0, emit0, ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _decode(name):
    exe = open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()
    return decode0.decode_user_code(exe)


def test_single_line_string_fn():
    prog = _decode("t1_fnstr.exe")
    fn = prog[0]
    assert isinstance(fn, ir.DefFn) and not fn.is_block
    assert fn.name == "FNFN1$"
    assert fn.params == ("A$", "B")
    assert fn.body == ir.BinOp(
        "+", ir.Var("A$"), ir.Call("STR$", (ir.Var("B"),))
    )
    assert prog[1] == ir.Print(
        (ir.FnCall("FNFN1$", (ir.StrLit("X"), ir.Lit(3))),), newline=True
    )


def test_block_string_fn():
    prog = _decode("t1_fnstrb.exe")
    fn = prog[0]
    assert isinstance(fn, ir.DefFn) and fn.is_block
    assert fn.name == "FNFN1$" and fn.params == ("A$",)
    assert fn.body == (ir.FnResult(ir.BinOp("+", ir.Var("A$"), ir.StrLit("!"))),)
    assert emit0.emit(prog) == (
        "10 DEF FNFN1$(A$)\n  FNFN1$ = A$ + \"!\"\nEND DEF\n"
        '20 PRINT FNFN1$("HI")\n30 END\n'
    )
