"""Every statement edit says which pass made it.

The edit log proves the statement list is reconstructible, but an anonymous
splice does not say whether folding moved a body, a handler patched a
statement, or finalization reconstructed a declaration from layout facts.
Chapter 6 has to tell those apart before it can move folding behind a graph.

Provenance is scoped rather than passed: a pass declares itself once, and
every edit made while it runs carries its name.
"""

from pathlib import Path

from tbx import decode0, ir
from tbx.decode0.statement_log import RecordedStatements, editing

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def test_an_edit_outside_any_pass_has_no_origin():
    stmts = RecordedStatements()

    stmts.append(ir.End())

    assert stmts.edits[-1].origin is None


def test_an_edit_inside_a_pass_carries_its_name():
    stmts = RecordedStatements()

    with editing(stmts, "fold_if"):
        stmts.append(ir.End())

    assert stmts.edits[-1].origin == "fold_if"


def test_the_origin_is_restored_when_the_pass_ends():
    stmts = RecordedStatements()

    with editing(stmts, "fold_if"):
        stmts.append(ir.End())
    stmts.append(ir.Goto(1))

    assert [e.origin for e in stmts.edits] == ["fold_if", None]


def test_nested_passes_report_the_innermost():
    stmts = RecordedStatements()

    with editing(stmts, "fold_body"):
        with editing(stmts, "fold_if"):
            stmts.append(ir.End())
        stmts.append(ir.Goto(1))

    assert [e.origin for e in stmts.edits] == ["fold_if", "fold_body"]


def test_an_origin_survives_an_exception():
    stmts = RecordedStatements()

    try:
        with editing(stmts, "fold_if"):
            raise ValueError("decode failed mid-fold")
    except ValueError:
        pass
    stmts.append(ir.End())

    assert stmts.edits[-1].origin is None


def test_editing_a_plain_list_is_a_no_op():
    # Lift helpers are called with plain lists in unit tests; declaring a pass
    # must not require the recorder.
    plain = [ir.End()]

    with editing(plain, "fold_if"):
        plain.append(ir.Goto(1))

    assert plain == [ir.End(), ir.Goto(1)]


def test_every_structural_edit_in_the_corpus_is_attributed():
    """Corpus-wide, not a sample.

    A pass added later that edits the list without declaring itself shows up
    here immediately. Two fixtures were not enough: they missed 165 edits
    across eleven sites that the full corpus caught.
    """
    unattributed = {}
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue  # a decode failure is not this test's subject
        for edit in prog.statement_edits:
            if edit.origin is None and edit.kind != "append":
                unattributed.setdefault(exe.name, set()).add(edit.kind)

    assert not unattributed, (
        "these fixtures edit the statement list without declaring a pass: "
        f"{dict(list(unattributed.items())[:5])}"
    )


def test_an_ordinary_commit_stays_unattributed():
    # `put` appending a decoded statement is not a pass; only transformations
    # carry an origin, which is what makes the origin meaningful.
    prog = decode0.decode_user_code((CORPUS / "t1_print2.exe").read_bytes())

    assert any(e.origin is None and e.kind == "append" for e in prog.statement_edits)


def test_reconstructed_declarations_are_attributed_to_finalization():
    # DIM comes from layout facts, not from a decoded statement. It must be
    # distinguishable from a fold.
    prog = decode0.decode_user_code((CORPUS / "f87_t1_arr1.exe").read_bytes())

    dim_edits = [
        e
        for e in prog.statement_edits
        if any(isinstance(s, ir.Dim) for s in e.payload)
    ]
    assert dim_edits
    assert all(e.origin is not None for e in dim_edits)
