"""LPRINT comma-zone vector C2 and its gap-aligned IR representation."""

from pathlib import Path

import pytest

from tbx import c0, decode0, ir
from tbx.ir import unparse_stmt

_ROOT = Path(__file__).resolve().parents[2]
_HITS = _ROOT / "wild" / "hits"


@pytest.mark.parametrize(
    ("stem", "next_gap"),
    [
        ("billadd.exe", "displacement 0x76 is neither scalar nor array element"),
        ("prtguide.exe", "DELAY without poll op"),
        ("rs.exe", "unhandled INT EC sub 38"),
    ],
)
def test_wild_lprint_comma_advances_to_later_gap(stem, next_gap):
    """All three independent C2 witnesses scan and lift beyond that vector."""
    data = (_HITS / stem).read_bytes()
    start, dialect = decode0.find_prologue(data)
    try:
        ops = decode0._scan(data, start, dialect, set())
    except ValueError as exc:
        # rs reaches its unrelated EC/38 failure during scanning itself.
        assert stem == "rs.exe"
        assert next_gap in str(exc)
    else:
        assert any(op[1:] == ("rt", 0xC2) for op in ops)
    with pytest.raises(ValueError, match=next_gap):
        decode0.decode_user_code(data)


def test_lprint_comma_render_and_c0():
    stmt = ir.Lprint(
        (ir.StrLit("A"), ir.Lit(2)),
        newline=False,
        commas=(1, 2, 1),
    )
    assert unparse_stmt(stmt) == 'LPRINT , "A",, 2,'
    c_src = c0.emit_c([stmt, ir.End()])
    # One leading zone, two between the items, and one trailing.
    assert c_src.count("tb_zone();") == 4
