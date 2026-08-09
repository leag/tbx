"""Ownership guard for error-table sites admitted inside merged LPRINTs."""

from tbx import ir
from tbx.decode0.core import _expanded_offsets_belong_to_lprint


def test_expanded_site_must_belong_to_lprint():
    statements = [
        ir.Lprint((ir.StrLit("a"),)),
        ir.Print((ir.StrLit("b"),)),
    ]
    addresses = [100, 200]

    assert _expanded_offsets_belong_to_lprint(statements, addresses, 100, {42})
    assert not _expanded_offsets_belong_to_lprint(
        statements, addresses, 100, {107}
    )
    assert not _expanded_offsets_belong_to_lprint(statements, addresses, 100, set())
