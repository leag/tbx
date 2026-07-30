"""Folds record which fold they happened inside.

An inline IF inside a CASE arm inside a SUB body folds in a particular
sequence today, driven by where each handler calls the next. A pass that folds
from the graph instead has to reproduce that sequence, and cannot unless the
containment is recorded.

`origin` names only the innermost pass. `scope` is the whole stack, so a fold's
position in the nesting is explicit rather than inferred from where its edits
happen to fall in the log.
"""

from pathlib import Path

from tbx import decode0, ir
from tbx.decode0.statement_log import RecordedStatements, editing

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def test_an_unscoped_edit_has_an_empty_scope():
    stmts = RecordedStatements()

    stmts.append(ir.End())

    assert stmts.edits[-1].scope == ()


def test_a_single_pass_records_itself():
    stmts = RecordedStatements()

    with editing(stmts, "close_ifs"):
        stmts.append(ir.End())

    assert stmts.edits[-1].scope == ("close_ifs",)


def test_nested_passes_record_the_whole_stack():
    stmts = RecordedStatements()

    with editing(stmts, "fold_proc_body"):
        with editing(stmts, "select_case"):
            with editing(stmts, "close_ifs"):
                stmts.append(ir.End())

    assert stmts.edits[-1].scope == ("fold_proc_body", "select_case", "close_ifs")
    # origin stays the innermost, so existing readers are unaffected.
    assert stmts.edits[-1].origin == "close_ifs"


def test_the_stack_unwinds_with_the_blocks():
    stmts = RecordedStatements()

    with editing(stmts, "outer"):
        with editing(stmts, "inner"):
            stmts.append(ir.End())
        stmts.append(ir.Goto(1))
    stmts.append(ir.End())

    assert [e.scope for e in stmts.edits] == [
        ("outer", "inner"),
        ("outer",),
        (),
    ]


def test_the_stack_unwinds_after_an_exception():
    stmts = RecordedStatements()

    with editing(stmts, "outer"):
        try:
            with editing(stmts, "inner"):
                raise ValueError("decode failed mid-fold")
        except ValueError:
            pass
        stmts.append(ir.End())

    assert stmts.edits[-1].scope == ("outer",)


def test_a_real_program_records_nested_folds():
    prog = decode0.decode_user_code((CORPUS / "t1_selarmblockif.exe").read_bytes())

    nested = {e.scope for e in prog.statement_edits if len(e.scope) > 1}
    assert nested, "a block IF inside a CASE arm folds inside another fold"
