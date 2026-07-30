"""RESTORE targets use the emitter's actual line-number mapping."""

from tbx import emit0, ir


class _Statements(list):
    lines = (100, 350, 900)


def test_restore_uses_preserved_line_number_not_canonical_index_math():
    stmts = _Statements(
        [
            ir.Data((ir.DataItem("1", False),)),
            ir.Restore(2),
            ir.End(),
        ]
    )

    assert emit0.emit(stmts) == "100 DATA 1\n350 RESTORE 900\n900 END\n"
