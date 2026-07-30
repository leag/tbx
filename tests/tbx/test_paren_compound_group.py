"""A redundant parenthesis changes how Turbo Basic compiles a compound IF.

`A OR B AND C` and `A OR (B AND C)` are equivalent, but Turbo Basic gives the
parenthesized inner group its own register convergence protocol. These tests
pin both body forms so the outer term cannot be dropped and the inner operands
cannot silently reverse.
"""

from pathlib import Path

import pytest

from tbx import decode0, emit0

_ROOT = Path(__file__).resolve().parents[2]

#: The calibrated spelling, `A OR B AND C`, at its three witnessed shapes.
#: These are folded by the compound-IF machinery and never reach the value
#: combine at all, which is why rejecting the drop there costs them nothing.
_CASCADE = ("t1_mixedbool", "t1_mixedbool2", "t1_mixedbool3")

#: The parenthesised spelling, in both body forms.
_PARENTHESISED = (
    "t1_parenorandgoto",
    "t1_parenorandinline",
)


@pytest.mark.parametrize("stem", _CASCADE)
def test_the_precedence_cascade_still_decodes(stem):
    prog = decode0.decode_user_code(
        (_ROOT / "tests" / "fixtures" / "corpus" / f"{stem}.exe").read_bytes()
    )
    conditions = [str(s) for s in prog]
    assert any("OR" in c and "AND" in c for c in conditions), stem


@pytest.mark.parametrize("stem", _PARENTHESISED)
def test_a_parenthesised_group_preserves_outer_and_inner_source_order(stem):
    exe = (_ROOT / "tests" / "fixtures" / "corpus" / f"{stem}.exe").read_bytes()
    source = emit0.emit(decode0.decode_user_code(exe))

    assert "A% = 9 OR (B% = 15 AND C% = 1)" in source
