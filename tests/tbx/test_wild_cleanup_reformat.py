"""cleanup.exe and reformat.exe decode end to end.

They were the two witnesses of a long chain of gaps, each of which used to be
recorded in five separate `next_gap` parametrize lists: a definition bracket
sitting behind a user RETURN, a DEF FN assigning to its own string parameter,
the three-argument MID$ assignment mistaken for CVL, a bracket rule with no
direction test, a far RUN compiling near, a block DEF FN with no epilogue
walk-back, a LOCAL dynamic array's free not counted as epilogue, and finally
`fstp_temp` clearing the open statement's address.

Those rows are gone now -- a program that decodes has no next gap -- so this
file is what keeps the two from silently regressing into a raise.
"""

import pytest

from tbx import decode0, emit0, ir

#: Statement counts at the commit that closed the last of the chain. Not a
#: byte-exactness claim: neither program is in the comparable subset (both
#: carry Options toggles beyond the flags-only set), so the oracle cannot
#: judge their bytes and these numbers are a structural guard only.
_EXPECTED = {"cleanup.exe": 197, "reformat.exe": 219}


@pytest.mark.parametrize("stem", sorted(_EXPECTED))
def test_wild_program_decodes_end_to_end(stem):
    from conftest import wild_hits_bytes

    program = decode0.decode_user_code(wild_hits_bytes(stem))
    assert len(program) == _EXPECTED[stem]


@pytest.mark.parametrize("stem", sorted(_EXPECTED))
def test_wild_program_emits_source(stem):
    from conftest import wild_hits_bytes

    source = emit0.emit(decode0.decode_user_code(wild_hits_bytes(stem)))
    assert source.endswith("\n")
    assert "None" not in source


@pytest.mark.parametrize("stem", sorted(_EXPECTED))
def test_wild_program_keeps_the_constructs_that_closed_the_chain(stem):
    """The features this pair was closed for are actually present -- otherwise
    the counts above could hold while the decode lost them again."""
    from conftest import wild_hits_bytes

    program = decode0.decode_user_code(wild_hits_bytes(stem))
    kinds = {type(s).__name__ for s in _walk(program)}
    assert "DefFn" in kinds
    assert "MidAssign" in kinds
    assert "Run" in kinds


def _walk(body):
    """Every statement in `body`, nested bodies included.

    `arms` is two different shapes -- (cond, body) pairs on an IfBlock, CaseArm
    objects on a SelectCase -- so it is unpacked by looking at what is there
    rather than by assuming either.
    """
    for stmt in body:
        yield stmt
        for arm in getattr(stmt, "arms", ()) or ():
            yield from _walk(getattr(arm, "body", None) or arm[1])
        for attr in ("body", "else_body", "case_else"):
            inner = getattr(stmt, attr, None)
            if inner:
                yield from _walk(inner)


def test_the_three_argument_mid_assign_carries_its_length():
    """cleanup.exe's MID$ assignments are the three-argument form, which is
    what distinguishes them from the two-argument spelling in the source."""
    from conftest import wild_hits_bytes

    program = decode0.decode_user_code(wild_hits_bytes("cleanup.exe"))
    mids = [s for s in _walk(program) if isinstance(s, ir.MidAssign)]
    assert mids
    assert any(m.length is not None for m in mids)
