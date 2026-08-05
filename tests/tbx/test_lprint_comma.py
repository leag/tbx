"""LPRINT comma-zone vector C2 and its gap-aligned IR representation."""

import pytest

from tbx import decode0, ir
from tbx.ir import unparse_stmt


@pytest.mark.parametrize(
    ("stem", "stmt_count"),
    [
        ("billadd.exe", 1948),
        ("rs.exe", 2329),
        ("prtguide.exe", 910),
    ],
)
def test_wild_lprint_comma_program_decodes_completely(stem, stmt_count):
    """All three independent C2 witnesses scan and lift past that vector, and
    decode end to end -- billadd.exe/rs.exe used to stop at a later gap
    (`displacement 0x76 is neither scalar nor array element` /
    `jump target 0xcee7 is not a statement start`, respectively), closed by
    other fixes since; prtguide.exe used to stop at `jump target 0x80bc`, the
    skip-jmp that brackets a SUB declaration, closed by t1_gotosubline."""
    from conftest import wild_hits_bytes

    data = wild_hits_bytes(stem)
    start, dialect = decode0.find_prologue(data)
    assert any(op[1:] == ("rt", 0xC2) for op in decode0._scan(data, start, dialect, set()))
    assert len(decode0.decode_user_code(data)) == stmt_count


def test_lprint_comma_render():
    stmt = ir.Lprint(
        (ir.StrLit("A"), ir.Lit(2)),
        newline=False,
        commas=(1, 2, 1),
    )
    assert unparse_stmt(stmt) == 'LPRINT , "A",, 2,'
