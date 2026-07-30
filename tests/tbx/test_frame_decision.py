"""The construct is decided from recorded evidence, not chosen by the handler.

A handler recognises a byte template. Whether that template means an IF or a
loop is a separate judgement, and Chapter 6 wants it made by the control-flow
pass rather than inside the handler.

The two are not separable from the graph alone: an inline IF and a head-tested
loop both branch forward with no condition, 76 and 90 times across the corpus,
and nothing in the edge distinguishes them. What distinguishes them is the
evidence the handler already computed and threw away -- whether a jump back to
the test address sits before the exit.

So the event records the template it matched, and one table maps templates to
constructs. The handler stops deciding; it reports what it saw.
"""

from pathlib import Path

import pytest

from tbx import decode0
from tbx.decode0.control_graph import FRAME_BY_TEMPLATE, frame_for
from tbx.decode0.events import BranchEvent

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def test_a_loop_back_template_means_a_loop():
    assert frame_for("bool_tail_loopback") == "loop"


def test_a_skip_template_means_an_if():
    assert frame_for("bool_tail_skip") == "if"


def test_an_unknown_template_is_fail_loud():
    with pytest.raises(ValueError, match="unmapped branch template"):
        frame_for("something_uncalibrated")


def test_every_mapped_template_names_a_real_construct():
    assert set(FRAME_BY_TEMPLATE.values()) <= {"if", "loop", "case"}


def test_the_event_records_the_template_it_matched():
    prog = decode0.decode_user_code((CORPUS / "t1_boolflags.exe").read_bytes())

    branches = [e.payload for e in prog.events if e.kind == "branch"]
    assert branches
    assert all(isinstance(b, BranchEvent) for b in branches)
    assert all(b.template for b in branches), "a branch must say what it matched"


def test_the_table_reproduces_every_handler_decision():
    """The check that makes the swap safe.

    If deriving the construct from the recorded template agrees with what the
    handler chose, everywhere, then the decision can move without changing
    behaviour. A disagreement is a place the handler knows something the
    evidence does not capture.
    """
    disagreements = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        for event in prog.events:
            if event.kind != "branch":
                continue
            derived = frame_for(event.payload.template)
            if derived != event.payload.frame:
                disagreements.append(
                    (exe.name, event.payload.template, event.payload.frame, derived)
                )

    assert not disagreements, (
        f"{len(disagreements)} branches where the evidence and the handler "
        f"disagree: {disagreements[:5]}"
    )
