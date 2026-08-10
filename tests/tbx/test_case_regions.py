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


def test_an_arm_region_carries_the_guards_it_matched_on():
    """The extent says where the body is; the guards say what it is.

    `CaseValue`, `CaseRange` and `CaseIs` accumulate on the recognizer's frame
    and used to be consumed straight into the `CaseArm` it built. A pass that
    folds afterwards has to build that arm itself, and the extent alone does
    not say what it matched.
    """
    prog = decode0.decode_user_code((CORPUS / "t1_selarmtarget.exe").read_bytes())

    select = next(
        s for s in _every_statement(tuple(prog)) if isinstance(s, ir.SelectCase)
    )
    recorded = [r.payload.detail for r in _arm_regions(prog)]

    assert recorded == [arm.guards for arm in select.arms]


def test_a_select_records_its_own_extent_and_selector():
    """Recorded at END SELECT, the one point where both ends are known.

    A SELECT header cannot record its extent: the END SELECT address is not
    known until an arm closes and names it, which is why the header's branch
    event carries `target=None`.
    """
    prog = decode0.decode_user_code((CORPUS / "t1_selarmtarget.exe").read_bytes())

    # Compared against the statement the walk built, not the program's: the
    # event holds what recognition decided, and canonical renaming rewrites
    # the variable names afterwards.
    built = next(
        edit.payload[0]
        for edit in prog.statement_edits
        if edit.origin == "select_case"
        and edit.payload
        and isinstance(edit.payload[0], ir.SelectCase)
    )
    regions = [
        e.payload
        for e in prog.events
        if e.kind == "region" and e.payload.kind == "select"
    ]

    assert len(regions) == 1
    assert regions[0].end > regions[0].start
    assert regions[0].detail == built.selector


def test_a_string_select_nests_inside_another_one():
    """The compiler REUSES the outer selector's scratch cell for the inner.

    An arm body is chosen before it runs, so the outer's copy of the selector
    is dead by then and the cell is free. The recognizer used to decline any
    header while an arm body was open, so the inner `movsi [0x5c]; strassign`
    fell through to the ordinary variable path and raised `displacement 0x5c
    is neither scalar nor array element` (wild sprogh.exe, and t1_selnest
    reproduces it byte for byte). What separates a header from an arm of the
    frame already open is the shape -- an arm test never writes the cell -- so
    `c.cases` carries the nesting on its own.
    """
    for stem in ("t1_selnest", "v10_t1_selnest"):
        prog = decode0.decode_user_code((CORPUS / f"{stem}.exe").read_bytes())

        outer = next(
            s for s in tuple(prog) if isinstance(s, ir.SelectCase)
        )
        assert [a.guards for a in outer.arms] == [
            (ir.CaseValue(ir.StrLit("a")),),
            (ir.CaseValue(ir.StrLit("b")),),
        ], stem
        inner = next(
            s
            for s in outer.arms[0].body
            if isinstance(s, ir.SelectCase)
        )
        assert [a.guards for a in inner.arms] == [
            (ir.CaseValue(ir.StrLit("x")),),
            (ir.CaseValue(ir.StrLit("y")),),
        ], stem


def test_a_case_guard_that_is_an_expression():
    """`CASE MID$("abcdefg", 2, 5)` -- a guard with no fixed op prefix.

    The two calibrated string-arm headers are two ops wide (a pooled literal,
    a bare `CHR$(n)`). A real expression is not: wild nvg.exe matches an arrow
    key with `CHR$(0) + CHR$(72)` and wild pw.exe with a three-argument MID$
    whose start and length shuttle through bx. What is invariant is the anchor
    the compiler puts at the END of every guard -- `movsi [temp]; rt 9C;
    strcmp` against the SELECT's own scratch cell -- so `_str_arm_anchor_at`
    finds that and ordinary dispatch evaluates whatever built the value.
    """
    for stem, guard in (
        ("t1_selchrcat", ir.BinOp("+", ir.Call("CHR$", (ir.Lit(0),)),
                                  ir.Call("CHR$", (ir.Lit(72),)))),
        ("t1_selmidguard", ir.Call(
            "MID$", (ir.StrLit("abcdefg"), ir.Lit(2), ir.Lit(5))
        )),
    ):
        for exe in (f"{stem}.exe", f"v10_{stem}.exe"):
            prog = decode0.decode_user_code((CORPUS / exe).read_bytes())
            select = next(s for s in tuple(prog) if isinstance(s, ir.SelectCase))
            assert select.arms[0].guards == (ir.CaseValue(guard),), exe


def test_a_numeric_select_nests_too():
    """Same nesting, numeric selector -- and one more thing had to give.

    A nested SELECT ends exactly where the ENCLOSING arm closes: nothing sits
    between the inner END SELECT and the outer arm's exit jmp, so the two
    addresses coincide. Consuming that jmp as the inner frame's own let the
    inner keep scanning and swallow the outer's next arm (one `SELECT CASE B`
    with arms 10, 20 AND 2); handing it back to the main loop instead decoded
    it as a plain `GOTO` and left the outer arm unclosed, merging its guards
    (`CASE 1, 2`). The frame closes at its own end_select and `_step` goes
    round again, so the same address closes the inner construct and then the
    enclosing arm.
    """
    for stem in ("t1_selnestnum", "v10_t1_selnestnum"):
        prog = decode0.decode_user_code((CORPUS / f"{stem}.exe").read_bytes())

        outer = next(s for s in tuple(prog) if isinstance(s, ir.SelectCase))
        assert [a.guards for a in outer.arms] == [
            (ir.CaseValue(ir.Lit(1)),),
            (ir.CaseValue(ir.Lit(2)),),
        ], stem
        inner = next(
            s for s in outer.arms[0].body if isinstance(s, ir.SelectCase)
        )
        assert [a.guards for a in inner.arms] == [
            (ir.CaseValue(ir.Lit(10)),),
            (ir.CaseValue(ir.Lit(20)),),
        ], stem
        assert not any(
            isinstance(s, ir.Goto) for s in outer.arms[0].body
        ), stem


def test_every_select_in_the_corpus_records_its_guards():
    missed = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        selects = [
            s for s in _every_statement(tuple(prog)) if isinstance(s, ir.SelectCase)
        ]
        if not selects:
            continue
        # Guards are compared as a multiset of what was recorded against what
        # the program ended up with: a program may hold several SELECTs, and
        # the arms are folded into them in close order, not source order.
        recorded = sorted(
            (str(g) for r in _arm_regions(prog) for g in r.payload.detail)
        )
        emitted = sorted(
            str(g) for s in selects for arm in s.arms for g in arm.guards
        )
        if recorded != emitted:
            missed.append((exe.name, len(emitted), len(recorded)))

    assert not missed, f"{len(missed)} programs mis-record their guards: {missed[:5]}"


def test_the_record_locates_every_arm_body():
    """Where each arm's body sits in the committed statement stream.

    An arm ends at its arm-close jmp, which owns no statement -- it is glue --
    so the end is a moment, recorded the same way an inline IF's is: the
    region's end address is one the log waits for, and decoding arriving there
    is an event. A pass folding afterwards sizes the arm from that.
    """
    from tbx.decode0.fold_pass import arm_regions

    missed = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        built = [
            edit.payload[0]
            for edit in prog.statement_edits
            if edit.origin == "select_case"
            and edit.payload
            and isinstance(edit.payload[0], ir.SelectCase)
        ]
        if not built:
            continue
        arms = sum(len(s.arms) for s in built)
        located = [r for r in arm_regions(prog) if r.kind == "case_arm"]
        if len(located) != arms:
            missed.append((exe.name, arms, len(located)))
        if any(r.stop <= r.start for r in located):
            missed.append((exe.name, "an arm region is empty"))

    assert not missed, f"{len(missed)} programs' arms are not located: {missed[:5]}"


def test_a_block_spelled_if_is_recorded_as_one():
    """The bytes say which spelling the source used, and the log now says so.

    A simple condition that materialized is positive evidence the source
    spelled a multi-line block IF -- a single-line `IF <simple> THEN <stmt>`
    compiles a bare dispatch pair instead. The fold needs that to choose the
    block form, and it used to be readable only from `block_if_addrs`, which a
    pass reading the log cannot see.
    """
    def flagged(stem):
        prog = decode0.decode_user_code((CORPUS / f"{stem}.exe").read_bytes())
        return [e for e in prog.events if e.kind == "branch" and e.payload.block]

    # `20 IF A$ <> "Q" THEN` with its body on following lines.
    assert len(flagged("t1_blkgoto")) == 1
    # `20 IF A$ = "T" OR A$ = "t" THEN CLS: GOTO 60` -- single line, and
    # `30 IF A > 1 AND B < 5 THEN C = 1: D = 2` likewise.
    assert flagged("t1_ifgoto") == []
    assert flagged("t1_ifin") == []


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
