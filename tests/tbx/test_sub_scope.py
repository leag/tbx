"""SUB body variable scoping and procedure-region control flow.

The t1_sub* fixtures pin the semantics the Phase-2 probes established
against the real compilers (all byte-exact verified via the oracle):

- t1_subdef: a non-parameter SUB variable is LOCAL and STATIC by default
  (its slot is distinct from main's same-named variable and persists
  across calls -- the original ran S 1 / S 2 / M 5).
- t1_subsh: SHARED binds the name to the main program's slot; the decoder
  infers the declaration from the cross-region slot reference.
- t1_subst: STATIC is a byte-level no-op alias of the default -- the
  emitted source normalizes it away and still recompiles byte-identically.
- t1_subarr/t1_subad: arrays follow the same rule (SHARED A() vs an
  implicit local array, whose synthesized DIM goes inside the body).
- t1_subgsb: GOSUB to a line inside the SUB's own body (ir.BodyLine
  target; emit0 numbers that body line).
- t1_subgoto/t1_suberr: GOTO and ON ERROR out of a SUB body into main.
"""

import os

from tbx import decode0, emit0, ir

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _decode(name):
    exe = open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()
    return decode0.decode_user_code(exe)


def test_sub_default_local_static():
    prog = _decode("t1_subdef.exe")
    sub = prog[0]
    assert isinstance(sub, ir.SubDef) and sub.params == ()
    # body variable A is NOT main's B: distinct slots, no SHARED synthesized
    assert sub.body[0] == ir.Assign(
        ir.Var("A"), ir.BinOp("+", ir.Var("A"), ir.Lit(1))
    )
    assert not any(isinstance(b, ir.Shared) for b in sub.body)
    assert ir.Assign(ir.Var("B"), ir.Lit(5)) in list(prog)


def test_sub_shared_scalar_inferred():
    prog = _decode("t1_subsh.exe")
    sub = prog[0]
    assert sub.body[0] == ir.Shared(("A",))
    # same slot on both sides of the region boundary
    assert sub.body[1] == ir.Assign(
        ir.Var("A"), ir.BinOp("+", ir.Var("A"), ir.Lit(1))
    )
    assert ir.Assign(ir.Var("A"), ir.Lit(5)) in list(prog)


def test_sub_static_normalizes_to_default():
    # STATIC C compiles byte-identically to the default; the decoded IR is
    # exactly t1_subdef's SUB shape with no declaration
    prog = _decode("t1_subst.exe")
    sub = prog[0]
    assert not any(isinstance(b, ir.Shared) for b in sub.body)
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n"
        '  A = A + 1\n  PRINT "S"; A\nEND SUB\n'
        "20 CALL SUB1\n30 CALL SUB1\n"
    )


def test_sub_shared_array_inferred():
    prog = _decode("t1_subarr.exe")
    sub = prog[0]
    assert sub.body[0] == ir.Shared(("V0()",))
    assert isinstance(sub.body[1], ir.Assign)
    assert sub.body[1].target == ir.ArrayRef("V0", (ir.Lit(2),))


def test_sub_local_array_dim_inside_body():
    prog = _decode("t1_subad.exe")
    sub = prog[0]
    # the SUB's implicit B() is its own array: DIM synthesized in the body
    assert sub.body[0] == ir.Dim("V0", (10,))
    assert not any(isinstance(b, ir.Shared) for b in sub.body)
    # main's array is a different record
    assert ir.Dim("V1", (10,)) in list(prog)


def test_gosub_to_body_line():
    prog = _decode("t1_subgsb.exe")
    sub = prog[0]
    assert sub.body[0] == ir.Gosub(ir.BodyLine(0, 3))
    assert sub.body[1] == ir.ExitSub()  # bare (unconditional) EXIT SUB
    assert sub.body[3] == ir.Return()
    # the targeted body physical line is emitted numbered
    assert emit0.emit(prog) == (
        "10 SUB SUB1\n"
        "  GOSUB 13\n  EXIT SUB\n13 PRINT \"IN\"\n  RETURN\nEND SUB\n"
        "20 CALL SUB1\n30 END\n"
    )


def test_goto_out_of_sub():
    prog = _decode("t1_subgoto.exe")
    sub = prog[0]
    assert sub.body == (ir.Goto(2),)  # main statement index


def test_on_error_inside_sub():
    prog = _decode("t1_suberr.exe")
    sub = prog[0]
    assert sub.body[0] == ir.OnError(3)  # traps to a main label
    assert isinstance(sub.body[1], ir.ErrorStmt)
    # ERR reads through the FP bridge (fild [0074]) in PRINT context
    trap = prog[3]
    assert trap == ir.Print((ir.StrLit("TRAP"), ir.Err()), newline=True)


def test_dialect_parity_v10_subdef():
    a = _decode("t1_subdef.exe")
    b = _decode("v10_subdef.exe")
    assert [repr(s) for s in a] == [repr(s) for s in b]


def test_sub_local_array_dim_after_main_dims():
    # The mirror of test_sub_local_array_dim_inside_body above. There the SUB is
    # emitted FIRST and its array holds the HIGHEST base; here the SUB comes
    # AFTER the main code and its array holds the LOWEST. Static array data
    # allocates descending in DIM order, and emit0 keeps each SUB at its
    # original position, so both directions reproduce their own allocation
    # order -- both are byte-exact.
    #
    # A guard used to reject this second direction outright ("allocation order
    # would flip; no witness"). It was backwards, and asserting the opposite
    # inequality instead would reject t1_subad. Wild tbd73.exe (`SUB Showfile`,
    # DIM recarr$(5000)) and prtguide.exe are both this shape.
    prog = _decode("t1_sublocafter.exe")
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    assert ir.Dim("V2$", (50,)) in sub.body
    # main's two arrays stay at the top level, in descending-base (DIM) order
    top = [s for s in prog if isinstance(s, ir.Dim)]
    assert top == [ir.Dim("V0$", (10,)), ir.Dim("V1$", (10,))]
