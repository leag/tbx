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

from tbx import decode0
from tbx.decode0.control_graph import predict_fold_starts

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _actual_inline_if_starts(prog):
    return [
        edit.index
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
