"""The recorded evidence locates every fold region the handlers produce.

Folding still happens inside the handlers, driven by frame bookkeeping they
keep as they decode. Moving it to a pass over the graph means that pass has to
find the same regions from the record alone.

These tests check that it can. If the prediction matches what the handlers
actually did, everywhere, the frame bookkeeping is redundant and folding can be
deferred. A mismatch is a place the handler knows something the record does
not carry -- which is how the shared clock between the two logs was found
missing in the first place.
"""

from pathlib import Path

from tbx import decode0, ir
from tbx.decode0.control_graph import predict_fold_extents, predict_fold_starts

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _actual_inline_if_starts(prog):
    return [edit.index for edit in _fold_edits(prog)]


def _actual_inline_if_extents(prog):
    return [(edit.index, edit.stop) for edit in _fold_edits(prog)]


def _fold_edits(prog):
    """Each inline-IF fold, as the splice that removed the body from the list.

    The splice's own bounds are the region: `index` where the body began,
    `stop` the list length when the fold ran. Reading the extent off the edit
    rather than off the folded statement keeps the check independent of what
    the fold built.
    """
    return [
        edit
        for edit in prog.statement_edits
        if edit.origin == "close_ifs" and edit.kind == "splice"
    ]


def test_a_single_inline_if_region_is_located():
    prog = decode0.decode_user_code((CORPUS / "t1_ifgoto.exe").read_bytes())

    assert set(_actual_inline_if_starts(prog)) <= set(predict_fold_starts(prog))


def test_every_inline_if_region_in_the_corpus_is_located():
    """The check that makes deferring folding safe to attempt.

    A naive predictor -- counting statements committed before the branch --
    got 55 of 62 programs. The seven it missed were ones where an earlier fold
    had already shifted the indices, which the count cannot see. Replaying the
    edits up to the branch's own point in the event stream sees it, and needs
    the two logs to share a clock.
    """
    missed = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        actual = _actual_inline_if_starts(prog)
        if not actual:
            continue
        predicted = set(predict_fold_starts(prog))
        if not set(actual) <= predicted:
            missed.append((exe.name, sorted(predicted), actual))

    assert not missed, (
        f"{len(missed)} programs fold a region the record cannot locate: "
        f"{missed[:3]}"
    )


def test_edits_carry_the_event_they_followed():
    prog = decode0.decode_user_code((CORPUS / "t1_ifgoto.exe").read_bytes())

    assert prog.statement_edits
    stamps = [e.at_event for e in prog.statement_edits]
    assert stamps == sorted(stamps), "the clock must not run backwards"
    assert max(stamps) <= len(prog.events)


def test_a_program_with_no_inline_if_predicts_nothing():
    prog = decode0.decode_user_code((CORPUS / "t1_print2.exe").read_bytes())

    assert predict_fold_starts(prog) == ()
    assert predict_fold_extents(prog) == ()


def test_a_single_inline_if_region_extent_is_located():
    prog = decode0.decode_user_code((CORPUS / "t1_ifgoto.exe").read_bytes())

    assert set(_actual_inline_if_extents(prog)) <= set(predict_fold_extents(prog))


def test_every_inline_if_fold_extent_in_the_corpus_is_located():
    """The measurement that says a deferred fold can size its own region.

    A start says where a body begins; the extent says where it ends, and that
    is the harder half. An address-based rule -- take the statement that owns
    the branch's target -- locates 26 of the 62 programs that fold an inline
    IF. It cannot do better: 21 of them fold up to a procedure epilogue or an
    arm-close jmp, which is not a statement and owns no address, and in 15 more
    an earlier fold has already moved the position the address maps to.

    The missing thing is a moment, not an address. When decoding *arrives* at
    the boundary is recorded now, and the extent is the list length then.
    """
    missed = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        actual = _actual_inline_if_extents(prog)
        if not actual:
            continue
        predicted = set(predict_fold_extents(prog))
        if not set(actual) <= predicted:
            missed.append((exe.name, sorted(predicted), actual))

    assert not missed, (
        f"{len(missed)} programs fold a region the record cannot size: "
        f"{missed[:3]}"
    )


def test_the_fold_takes_its_condition_from_the_recorded_branch():
    """What an inline IF folds into comes from the record.

    The condition is decided at recognition, when the branch event is written.
    The walk used to carry its own copy on the frame stack, so the record
    could have drifted from what was folded and nothing would have said so.
    """
    prog = decode0.decode_user_code((CORPUS / "t1_ifin.exe").read_bytes())

    recorded = [
        e.payload.cond
        for e in prog.events
        if e.kind == "branch" and e.payload.frame == "if"
    ]
    # The fold's own output, before canonical renaming rewrites the variable
    # names: the event holds what recognition decided, so the comparison has
    # to be made on that side of the rename.
    folded = [
        edit.payload[0].cond
        for edit in prog.statement_edits
        if edit.origin == "close_ifs"
        and edit.kind in ("append", "splice")
        and edit.payload
        and isinstance(edit.payload[0], ir.IfInline)
    ]

    assert folded, "fixture should fold an inline IF"
    assert all(cond is not None for cond in recorded)
    for cond in folded:
        assert cond in recorded


def test_an_open_frame_carries_nothing_the_record_already_has():
    """The frame stack is an index into the log, not a second copy of it.

    An open inline-IF frame is the `seq` of the branch event that recognised
    it. `idx` rides along only as the cross-check that the region start read
    back from the record is the one the walk saw, and Chapter 7 removes it.
    A third key would be a fold input that the deferred pass cannot get.
    """
    import ast

    root = Path(__file__).resolve().parents[2]
    frames = []
    for relpath in ("tbx/decode0/core.py", "tbx/decode0/lift.py"):
        tree = ast.parse((root / relpath).read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append"
                and isinstance(node.func.value, ast.Attribute | ast.Name)
                and (
                    node.func.value.attr
                    if isinstance(node.func.value, ast.Attribute)
                    else node.func.value.id
                )
                == "ifs"
                and node.args
                and isinstance(node.args[0], ast.Dict)
            ):
                frames.append(
                    (
                        f"{relpath}:{node.lineno}",
                        {k.value for k in node.args[0].keys},
                    )
                )

    assert len(frames) == 4, f"expected four frame openers, found {frames}"
    for where, keys in frames:
        assert keys == {"seq", "idx"}, f"{where} carries {keys - {'seq', 'idx'}}"


def test_a_body_ending_in_a_pending_print_is_inside_the_region():
    """The shape no fixture has, and the reason arrival flushes first.

    `IF ... THEN PRINT "Approximately ";` -- the body's only statement is a
    trailing-';' PRINT, which has no flush vector and materializes only when
    something closes the chain. That something is the fold itself, one line
    after the boundary, so the statement reached the list *after* the moment
    its own region ended and the extent came out one short.

    The PRINT is decoded before the boundary, so the arrival flushes before it
    stamps. Wild be.exe is the only program in either corpus that folds one.
    """
    from conftest import wild_hits_bytes

    prog = decode0.decode_user_code(wild_hits_bytes("be.exe"))

    assert (42, 43) in predict_fold_extents(prog)
    assert set(_actual_inline_if_extents(prog)) <= set(predict_fold_extents(prog))
