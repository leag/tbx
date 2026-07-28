"""A CASE arm's body is a region, recorded where it opens.

The arm snapshot is the second of the three folds Chapter 6 has to move. It
runs during the walk and takes `o.stmts[body_idx:]`, where `body_idx` is the
list length the recognizer noted when the body began -- the same private
bookkeeping the inline-IF fold used to keep.

Recording the arm as a region puts that position in the log: it is the list
length at the region event, replayed like any other. These tests check the two
are the same everywhere, which is what makes the bookkeeping removable.
"""

from pathlib import Path

from tbx import decode0, ir

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _arm_regions(prog):
    return [
        e for e in prog.events if e.kind == "region" and e.payload.kind == "case_arm"
    ]


def test_each_arm_records_a_region():
    prog = decode0.decode_user_code((CORPUS / "t1_selarmtarget.exe").read_bytes())

    select = next(
        s for s in _every_statement(tuple(prog)) if isinstance(s, ir.SelectCase)
    )
    regions = _arm_regions(prog)

    assert len(regions) == len(select.arms)
    assert all(r.payload.start is not None for r in regions)


def test_an_arm_region_ends_where_the_arm_closes():
    """The end is the arm's own close, not the END SELECT.

    An arm body ends at its trailing `jmp END SELECT`, and that address is
    what the fold uses as the region terminator -- an inline IF closing the
    arm skips to it, and a nested block IF's else-skip lands on it.
    """
    prog = decode0.decode_user_code((CORPUS / "t1_selarmtarget.exe").read_bytes())

    for region in _arm_regions(prog):
        assert region.payload.end is not None
        assert region.payload.end > region.payload.start


def test_a_case_else_records_its_own_region():
    prog = decode0.decode_user_code((CORPUS / "t1_selarmtarget.exe").read_bytes())

    kinds = [
        e.payload.kind
        for e in prog.events
        if e.kind == "region" and e.payload.kind.startswith("case_")
    ]

    assert "case_else" in kinds


def test_every_arm_in_the_corpus_is_recorded():
    """One region per arm, everywhere.

    An arm the log does not describe is one a deferred pass cannot fold, so
    the count is checked against what the program ended up with rather than
    against the recognizer's own frame.
    """
    missed = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        selects = [
            s for s in _every_statement(tuple(prog)) if isinstance(s, ir.SelectCase)
        ]
        arms = sum(len(s.arms) for s in selects)
        if not arms:
            continue
        recorded = len(_arm_regions(prog))
        if recorded != arms:
            missed.append((exe.name, arms, recorded))
        # A CASE ELSE region is recorded whenever the walk enters one, and an
        # empty else region is dropped rather than emitted -- a source with no
        # CASE ELSE at all still lands there. So the regions are a superset of
        # the clauses that survive, never fewer.
        surviving = sum(1 for s in selects if s.case_else)
        entered = len(
            [
                e
                for e in prog.events
                if e.kind == "region" and e.payload.kind == "case_else"
            ]
        )
        if entered < surviving:
            missed.append((exe.name, f"{surviving} CASE ELSE, {entered} recorded"))

    assert not missed, f"{len(missed)} programs mis-record their arms: {missed[:5]}"


def _every_statement(value):
    """Every node in the tree.

    Plain tuples have to be walked through, not just dataclass fields: an
    `IfBlock`'s arms are `(cond, body)` pairs, so a SELECT inside a block IF
    is two tuples deep and a walker that only descends named fields will
    report the program as having no arms at all.
    """
    if isinstance(value, (tuple, list)):
        for item in value:
            yield from _every_statement(item)
        return
    if hasattr(value, "__dataclass_fields__"):
        yield value
        for name in value.__dataclass_fields__:
            yield from _every_statement(getattr(value, name))
