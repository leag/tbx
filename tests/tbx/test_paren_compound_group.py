"""A redundant parenthesis changes how Turbo Basic compiles a compound IF.

`A OR B AND C` and `A OR (B AND C)` are the same expression -- AND binds
tighter either way -- but they do not compile to the same code. The cascade is
calibrated; the parenthesised group, which owns its own convergence protocol,
is not.

What made that worth a guard rather than a note is that it was *silent*.
`match_bool_term1` recognises the outer term in both spellings, but on the
parenthesised path nothing consumes the match, so the group's `and ax,bx`
reaches the generic logical-value combine with `pend_bool` unset and folds AX
with BX as if those two relations were the whole condition. The outer term is
dropped and the operands reverse. Whether anything downstream notices depends
only on what the body needs: a `THEN <line>` body goes on to fail with
`unhandled jcc 74`, an inline body does not and yields plausible source that
recompiles to a different image.
"""

from pathlib import Path

import pytest

from tbx import decode0

_ROOT = Path(__file__).resolve().parents[2]

#: The calibrated spelling, `A OR B AND C`, at its three witnessed shapes.
#: These are folded by the compound-IF machinery and never reach the value
#: combine at all, which is why rejecting the drop there costs them nothing.
_CASCADE = ("t1_mixedbool", "t1_mixedbool2", "t1_mixedbool3")

#: The parenthesised spelling, in both body forms. Authored probes rather than
#: fixtures: the construct has no correct mapping yet, so there is nothing to
#: verify byte-exactly and they must not join the corpus.
_PARENTHESISED = (
    "probe_paren_or_and_goto",  # `THEN 70` -- used to fail as `unhandled jcc 74`
    "probe_paren_or_and_inline",  # `THEN PRINT` -- used to decode wrongly, quietly
)


@pytest.mark.parametrize("stem", _CASCADE)
def test_the_precedence_cascade_still_decodes(stem):
    prog = decode0.decode_user_code(
        (_ROOT / "tests" / "fixtures" / "corpus" / f"{stem}.exe").read_bytes()
    )
    conditions = [str(s) for s in prog]
    assert any("OR" in c and "AND" in c for c in conditions), stem


@pytest.mark.parametrize("stem", _PARENTHESISED)
def test_a_parenthesised_group_is_rejected_rather_than_guessed(stem):
    """Both body forms must fail, and for the reason that is actually true.

    The inline one is the point of the test. It did not raise at all, so its
    wrongness was invisible -- and no wild program witnesses it, because a wild
    program with an inline body simply decodes to something plausible.
    """
    exe = (_ROOT / "wild" / "probes" / f"{stem}.exe").read_bytes()

    with pytest.raises(ValueError, match=r"parenthesised compound group"):
        decode0.decode_user_code(exe)


def test_the_rejection_names_the_term_it_could_not_place():
    """A report that only said "unhandled jcc" pointed past the real fault.

    The jcc it used to blame is downstream of the drop, and two of the four
    wild programs carrying that message have a different shape -- so naming the
    recognised-but-uncombined term is what makes the two groups separable.
    """
    exe = (_ROOT / "wild" / "probes" / "probe_paren_or_and_goto.exe").read_bytes()

    with pytest.raises(ValueError) as caught:
        decode0.decode_user_code(exe)

    message = str(caught.value)
    assert "outer OR term" in message
    assert "never combined" in message
