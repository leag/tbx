"""A function result tested for truth stays bare: `IF EOF(1) THEN`, not `<> 0`.

The two spellings are not interchangeable, which the `orax` handler already
documents for the LOOP case and this is the IF sibling of:

    IF EOF(1) THEN 40        movax 1 ; fn EOF ; or ax,ax ; jz
    IF EOF(1) <> 0 THEN 40   xor ax,ax ; mov bx,ax ; movax 1 ; fn EOF ;
                             cmp ax,bx ; jz

The jcc handler's `direct_bool` path builds exactly the bare form, but it needs
AX still live and no pending compare. The `orax` handler kept AX alive only for
a by-ref param or an evidenced DGROUP scalar and fell through to
`pend_cmp(value, 0)` for everything else -- so a function result, which is just
as unambiguously a source-level value and never a compiler temp, took the
comparison path.

Wild pz.exe has four of these (`IF EOF(1)` / `IF EOF(2)`).
"""

from pathlib import Path

from tbx import decode0, emit0, ir

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def test_a_bare_function_truth_test_keeps_its_shape():
    prog = decode0.decode_user_code((_CORPUS / "t1_bareiffn.exe").read_bytes())
    guard = next(s for s in prog if isinstance(s, ir.IfGoto))
    assert guard.cond == ir.Call("EOF", (ir.Lit(1),)), repr(guard.cond)
    assert 'IF EOF(1) THEN 40\n' in emit0.emit(prog)


def test_an_explicit_comparison_is_still_a_comparison():
    # The `<> 0` spelling compiles differently, so it must not be normalized
    # into the bare form either.
    assert (
        ir.unparse_cond(ir.RelOp("<>", ir.Call("EOF", (ir.Lit(1),)), ir.Lit(0)))
        == "EOF(1) <> 0"
    )
