"""`VARPTR(A%(I%))` names an array the compiled bytes do not record.

VARPTR of an array element at a VARIABLE index compiles to just the scaled
index -- `mov si,[I%]; shl si,1; mov ax,si; mov [P%],ax` -- and adds NO array
base at all. Two consequences, and the second is the interesting one:

1. `8b c6` (mov ax,si) had no scan entry. Only `89 /r` (mov r/m, r) was ever
   witnessed as a register-register move; `8b /r` is the same move in the
   opposite direction, so the destination swaps between the encodings. Wild
   dirmain2.exe hits this twice.

2. The array is genuinely unrecoverable. `VARPTR(A%(I%))` and
   `VARPTR(B%(I%))` compile to BYTE-IDENTICAL EXEs (probes varptridx2 and
   varptridx3 in wild/probes), so nothing in the image distinguishes them.
   That makes the construct lossy in the same way COMMON's declaration
   spelling is, and it is canonicalized the same way: emit one array of the
   right element width and let the byte comparison be the judge. varptridx3
   is the proof -- its source says `VARPTR(A%(I%))`, the decoder emits
   `VARPTR(V1%(A%))` naming the OTHER array, and it still recompiles
   byte-exact.

Do not "fix" the canonical choice to match a particular source: there is no
evidence in the bytes to prefer one array, and the recompile is identical
either way. Both dialects verified byte-exact.
"""

import os

import pytest

from tbx import decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")
_PROBES = os.path.join(os.path.dirname(_ROOT), "wild", "probes")


@pytest.mark.parametrize("stem", ("t1_varptridx", "v10_t1_varptridx"))
def test_varptr_of_an_element_at_a_variable_index(stem):
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as handle:
        exe = handle.read()

    source = "\n".join(str(s) for s in decode0.decode_user_code(exe))

    assert "VARPTR" in source, source
    assert "ArrayRef" in source, source


def test_a_swapped_move_direction_would_not_decode():
    """The direction of `8b /r` is load-bearing, not cosmetic.

    Reading `8b c6` as `mov si,ax` instead of `mov ax,si` produces a
    plausible `movrr` with the registers backwards. That does not fail
    quietly: the VARPTR lift matches on `("ax", "si")` exactly, so a swapped
    direction turns this fixture back into `shl si outside an element access`.
    Asserted through a real decode rather than by re-deriving the operand
    order here, which would only restate the implementation.
    """
    with open(os.path.join(_CORPUS, "t1_varptridx.exe"), "rb") as handle:
        exe = handle.read()

    stmts = tuple(decode0.decode_user_code(exe))

    assign = [s for s in stmts if type(s).__name__ == "Assign"]
    varptr = [s for s in assign if "VARPTR" in str(s.value)]
    assert len(varptr) == 1, stmts
    # The index is the loop variable, not a register artefact.
    assert "Var(name='A%')" in str(varptr[0].value), str(varptr[0])


def test_the_lossy_pair_is_kept_as_evidence():
    """The two probes that prove the array is unrecoverable must stay."""
    for name in ("probe_varptridx2.bas", "probe_varptridx3.bas"):
        assert os.path.isfile(os.path.join(_PROBES, name)), name
