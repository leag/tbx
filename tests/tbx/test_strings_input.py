"""String variables + INPUT / LINE INPUT (including `INPUT "prompt", X$`, flags 0x0040)."""

import os
from tbx import ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAIRS = [
    "t1_str",
    "t1_inp",
    "t1_inp2",
    "t1_inp3",
    "t1_inp4",
    "t1_inpsemi",
    "t1_inparr",
    "t1_icmpmat",
    "t1_inpmulti",
    "t1_inpmixed",
    "t1_relval",
    "t1_inpdbl",
    "t1_readsarr",
    "t1_inpsarr",
    "t1_envdev",
]


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_bare_value_or_advances_cal_and_cal87():
    from tbx import decode0, emit0

    from conftest import wild_hits_bytes

    for name in ("cal.exe", "cal87.exe"):
        try:
            program = decode0.decode_user_code(wild_hits_bytes(name))
        except ValueError as exc:
            assert "unhandled materialized test at 0x15eed" not in str(exc)
        else:
            source = emit0.emit(program)
            assert " OR " in source


def test_decode_t1_str():
    from tbx import decode0

    a, b = ir.Var("A$"), ir.Var("B$")
    want = [
        ir.Assign(a, ir.StrLit("HI")),
        ir.Assign(b, a),
        ir.Print(a),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_str.exe")) == want


def test_string_relational_value_clears_its_compare_type():
    """A following numeric IF must not inherit the assignment's string flag."""
    from tbx import decode0, emit0

    program = decode0.decode_user_code(_exe("v10_t1_strrelvalif.exe"))
    source = emit0.emit(program)

    assert "C% = A$ = B$" in source
    assert "IF C% = 0 THEN" in source


def test_string_relational_value_can_store_through_a_byref_integer():
    from tbx import decode0, emit0

    source = emit0.emit(
        decode0.decode_user_code(_exe("v10_t1_strrelvalbyref.exe"))
    )

    assert "F% = D$ = E$" in source


def test_bare_byref_value_can_feed_a_direct_if_goto():
    from tbx import decode0, emit0

    source = emit0.emit(decode0.decode_user_code(_exe("v10_t1_bareifgoto.exe")))

    assert "IF B% THEN" in source
    assert '"NONZERO"' in source


def test_numeric_input_targets_local_and_dynamic_array_elements():
    from tbx import decode0, emit0

    local = emit0.emit(decode0.decode_user_code(_exe("t1_inplocal.exe")))
    dynamic = emit0.emit(decode0.decode_user_code(_exe("t1_inpdynarr.exe")))

    assert "INPUT A" in local
    assert "INPUT V0#(B#)" in dynamic


def test_dynamic_double_array_elements_can_compare_directly():
    from tbx import decode0, emit0

    source = emit0.emit(decode0.decode_user_code(_exe("t1_dyndblcmp.exe")))

    assert "IF V0#(2) = V0#(1) THEN" in source


def test_numeric_input_can_target_constant_dynamic_array_element():
    from tbx import decode0, emit0

    source = emit0.emit(decode0.decode_user_code(_exe("t1_inpdynconst.exe")))

    assert "INPUT V0#(1)" in source


def test_decode_t1_inp():
    from tbx import decode0

    want = [
        ir.Input(None, ir.Var("A")),
        ir.Input(None, ir.Var("B$")),
        ir.Print(ir.Var("B$")),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_inp.exe")) == want


def test_decode_t1_inp2():
    from tbx import decode0

    want = [ir.Input(ir.StrLit("X"), ir.Var("A")), ir.End()]
    assert decode0.decode_user_code(_exe("t1_inp2.exe")) == want


def test_decode_t1_inp3():
    from tbx import decode0

    want = [
        ir.LineInput(None, ir.Var("A$")),
        ir.LineInput(ir.StrLit("X"), ir.Var("B$")),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_inp3.exe")) == want


def test_decode_t1_inp4():
    from tbx import decode0

    want = [ir.Input(ir.StrLit("X"), ir.Var("A$"), comma=True), ir.End()]
    assert decode0.decode_user_code(_exe("t1_inp4.exe")) == want


def test_decode_t1_inpsemi():
    # Flag bit 0x0080 = the leading `INPUT;` form (stay on the line after
    # entry); numeric leg carries 0x4000 too, string leg (t1_inpsemis) just
    # 0x0080 -- both witnessed against wild inv87/invoice's 0x40C0
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_inpsemi.exe"))
    assert prog[0] == ir.Input(ir.StrLit("GIVE"), ir.Var("A"), semi=True)
    prog = decode0.decode_user_code(_exe("t1_inpsemis.exe"))
    assert prog[0] == ir.Input(ir.StrLit("NAME"), ir.Var("A$"), semi=True)


def test_decode_t1_inparr():
    # INPUT into an array element at a computed index (wild schart.exe): the
    # index computation runs BETWEEN read_num and the element store, so the
    # parsed value waits on the FP stack as the _INPUTREAD sentinel and the
    # fstp_si terminal names the target
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_inparr.exe"))
    assert prog[2] == ir.Input(
        None, ir.ArrayRef("V0", (ir.Var("A"),))
    )


def test_decode_t1_readsarr():
    # READ into a computed STRING-array element (wild pfl.exe/invent.exe):
    # data_read_str pushes _READDATA onto the STRING stack same as the
    # scalar case, but the shlsi element-access handler's near-strassign
    # branch only checked for _FREAD (INPUT#), never _READDATA -- the
    # string sibling of gap 38's numeric array-READ support.
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_readsarr.exe"))
    assert prog[3] == ir.Read((ir.ArrayRef("V0$", (ir.Var("A%"),)),))


def test_decode_t1_inpsarr():
    # console INPUT into a computed STRING-array element (wild
    # invent.exe): read_str unconditionally assumed a plain scalar target
    # (movsi + strassign) and never recognized an index computation
    # starting instead -- the string sibling of t1_inparr's numeric
    # _INPUTREAD sentinel. An integer-typed index loads straight into si
    # (movsim); a float-typed one needs the fistp/fwait/movaxmem bridge
    # first (fld/fild) -- either way, anything but a direct movsi at this
    # position must be an index computation, not a plain scalar target.
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_inpsarr.exe"))
    assert prog[2] == ir.Input(None, ir.ArrayRef("V0$", (ir.Var("A%"),)))


def test_decode_t1_inpmulti():
    # Multi-target INPUT (wild schart.exe): the flag word's low bits carry
    # the EXTRA-target count and `0x4000 >> k` set = target k numeric --
    # `INPUT A, B` = 0x6001, `INPUT "VALS"; A, B, C` = 0x7002 (all numeric),
    # `INPUT A$, B` = 0x2001 (string first). One read op per target; the
    # statement emits when the last target lands, var = tuple.
    from tbx import decode0, emit0

    prog = decode0.decode_user_code(_exe("t1_inpmulti.exe"))
    assert prog[0] == ir.Input(None, (ir.Var("A"), ir.Var("B")))
    src = emit0.emit(decode0.decode_user_code(_exe("t1_inpmulti3.exe")))
    assert '10 INPUT "VALS"; A, B, C' in src
    prog = decode0.decode_user_code(_exe("t1_inpmixed.exe"))
    assert prog[0] == ir.Input(None, (ir.Var("A$"), ir.Var("B")))


def test_decode_t1_inpdbl():
    from tbx import decode0, emit0

    want = [
        ir.Input(None, ir.Var("A#")),
        ir.Print((ir.Var("A#"),)),
        ir.End(),
    ]
    assert decode0.decode_user_code(_exe("t1_inpdbl.exe")) == want
    assert emit0.emit(want) == "10 INPUT A#\n20 PRINT A#\n30 END\n"


def test_decode_t1_relval():
    # FP relational-as-VALUE inside arithmetic (wild schart.exe): `(A > 0)`
    # materializes -1/0 with no dispatch pair after the inc ax -- the next
    # op consumes ax directly (imulbx here, imul_m in the wild). The Group
    # is explicit: the source requires the parens for this parse.
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_relval.exe")))
    assert "30 C = (A > 0) * 3 + B" in src


def test_decode_t1_icmpmat():
    # Signed materialization jccs (7F/7C/7D/7E) in _JCC_RELOP_TRUE: an
    # integer cmpax_bx compare feeding a compound-IF term materializes with
    # signed jcc rows, FORWARD-oriented (pend_cmp is (lhs, rhs), unlike the
    # reversed FP rows) -- all four ops witnessed in this one fixture
    from tbx import decode0, emit0

    src = emit0.emit(decode0.decode_user_code(_exe("t1_icmpmat.exe")))
    assert "30 IF LEN(A$) > 2 AND LEN(A$) < 9 THEN B = 1" in src
    assert "40 IF LEN(A$) >= 3 OR LEN(A$) <= 1 THEN B = 2" in src


def test_dialect_invariant():
    from tbx import decode0

    for name in PAIRS:
        assert decode0.decode_user_code(
            _exe(f"v10_{name}.exe")
        ) == decode0.decode_user_code(_exe(f"{name}.exe")), name


def test_emit_strings_input():
    from tbx import decode0, emit0

    assert emit0.emit(decode0.decode_user_code(_exe("t1_str.exe"))) == (
        '10 A$ = "HI"\n20 B$ = A$\n30 PRINT A$\n40 END\n'
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_inp.exe"))) == (
        "10 INPUT A\n20 INPUT B$\n30 PRINT B$\n40 END\n"
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_inp4.exe"))) == (
        '10 INPUT "X", A$\n20 END\n'
    )
    assert emit0.emit(decode0.decode_user_code(_exe("t1_inp3.exe"))) == (
        '10 LINE INPUT A$\n20 LINE INPUT "X"; B$\n30 END\n'
    )


def test_decode_envdev():
    from tbx import decode0

    prog = decode0.decode_user_code(_exe("t1_envdev.exe"))
    assert prog[0].value == ir.Call("ENVIRON$", (ir.StrLit("PATH"),))
    assert prog[1].value == ir.Nullary("ERDEV$")


if __name__ == "__main__":
    test_decode_t1_str()
    test_decode_t1_inp()
    test_decode_t1_inp2()
    test_decode_t1_inp3()
    test_decode_t1_inp4()
    test_decode_t1_inpsemi()
    test_decode_t1_inparr()
    test_decode_t1_inpmulti()
    test_decode_t1_relval()
    test_decode_t1_icmpmat()
    test_dialect_invariant()
    test_emit_strings_input()
    print("ALL PASS")
