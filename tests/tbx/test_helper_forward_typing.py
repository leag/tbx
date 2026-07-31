"""A forwarded arg takes its type from the CALLER when the callee has none.

`arg_push_fwd` stages a `P<off>` placeholder and normally takes its suffix from
the callee's parameter in the same position. A framed opaque helper has no such
evidence -- its offsets come from the BP frame, its types are unknown -- so the
argument landed unsuffixed while the enclosing SUB's own parameter kept its
suffix. `canonical_rename` then lettered two variables out of one parameter,
and the compiler allocated a DGROUP scalar for the second.

Wild resume.exe paid six by-ref temporaries for it, a numeric band 24 bytes too
wide, and every reference after it: 80.14% -> 95.53% identical once fixed.

The gate matters as much as the fix. A helper emits as `SUB name INLINE` with
NO parameter list, so nothing can contradict the caller's type. Doing the same
for an ordinary SUB whose parameter merely happens to be untyped produces a
header the callee's own contradicts, and TB rejects it outright -- ledger
RO-UNIFY-DEFERRED-PARAM records that attempt and its `Error 475`.
"""

import re

from tbx import decode0, emit0, ir


def test_no_split_parameter_survives_into_resume():
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("resume.exe"))
    # A SUB must not hold two names for one parameter offset. Before the fix
    # four of them did, 64 placeholders' worth.
    for sub in (s for s in prog if isinstance(s, ir.SubDef)):
        bases = [p.rstrip("%$&#") for p in sub.params if p.startswith("P")]
        assert len(bases) == len(set(bases)), (sub.name, sub.params)


def test_resume_emits_no_bare_placeholder():
    from conftest import wild_hits_bytes

    src = emit0.emit(decode0.decode_user_code(wild_hits_bytes("resume.exe")))
    assert not re.search(r"\bP[0-9A-F]{2}\b", src)


def test_helper_callees_are_the_only_ones_retyped():
    """The pass keys on a helper BODY, not on an untyped callee parameter."""
    from tbx.decode0.core import _type_helper_forwards

    helper = ir.SubDef("SUB9", ("P06",), (ir.OpaqueHelper(b"\x55"),))
    plain = ir.SubDef("SUB8", ("P06",), (ir.End(),))
    caller = ir.SubDef(
        "SUB1",
        ("P06%",),
        (ir.CallStmt("SUB9", (ir.Var("P06"),)), ir.CallStmt("SUB8", (ir.Var("P06"),))),
    )
    out = _type_helper_forwards([helper, plain, caller])
    body = out[2].body
    assert body[0].args == (ir.Var("P06%"),), "helper callee should be retyped"
    assert body[1].args == (ir.Var("P06"),), "plain callee must be left alone"


def test_an_ordinary_callee_is_retyped_at_both_ends():
    """The sibling case: retype the argument AND the callee's own header.

    Retyping only the argument is what produced `Error 475: Parameter
    mismatch`, because the callee's declared parameter then contradicted it.
    Doing both together is what makes it compile.
    """
    from tbx.decode0.core import _type_untyped_callee_params

    callee = ir.SubDef("SUB8", ("P06",), (ir.Print((ir.Var("P06"),)),))
    caller = ir.SubDef("SUB1", ("P0A%",), (ir.CallStmt("SUB8", (ir.Var("P0A"),)),))
    out = _type_untyped_callee_params([callee, caller])
    assert out[0].params == ("P06%",), "callee header must take the type"
    assert out[0].body[0].items == (ir.Var("P06%"),), "and its own body with it"
    assert out[1].body[0].args == (ir.Var("P0A%"),), "and the argument"


def test_callers_that_disagree_leave_it_alone():
    """Two suffixes for one position is not evidence."""
    from tbx.decode0.core import _type_untyped_callee_params

    callee = ir.SubDef("SUB8", ("P06",), (ir.End(),))
    a = ir.SubDef("SUB1", ("P0A%",), (ir.CallStmt("SUB8", (ir.Var("P0A"),)),))
    b = ir.SubDef("SUB2", ("P0A$",), (ir.CallStmt("SUB8", (ir.Var("P0A"),)),))
    out = _type_untyped_callee_params([callee, a, b])
    assert out[0].params == ("P06",)
    assert out[1].body[0].args == (ir.Var("P0A"),)
