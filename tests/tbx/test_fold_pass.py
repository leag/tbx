"""Folding an inline IF after the walk, from the record alone.

The walk folds as it goes, driven by frames it opens and closes. Chapter 6's
swap is to stop doing that and fold afterwards from the recorded graph. What
has to be true first is that a pass reading only the record produces the same
folds -- same regions, same conditions, same bodies, same order.

`fold_pass.fold_inline_ifs` is that pass, run here against what the walk
actually did. It is not wired into the decoder: this measures whether it
could be.
"""

from pathlib import Path

from tbx import decode0, ir
from tbx.decode0.fold_pass import fold_inline_ifs

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _eager_folds(prog):
    """Every inline IF the walk folded, in the order it folded them."""
    return [
        edit.payload[0]
        for edit in prog.statement_edits
        if edit.origin == "close_ifs"
        and edit.kind in ("append", "splice")
        and edit.payload
        and isinstance(edit.payload[0], ir.IfInline)
    ]


def _every_statement(value):
    """Every node in the tree, nested bodies included.

    Plain tuples are walked through, not just dataclass fields: an `IfBlock`'s
    arms are `(cond, body)` pairs, so a statement inside a block IF is two
    tuples deep and a walker that only descends named fields never sees it.
    """
    if isinstance(value, (tuple, list)):
        for item in value:
            yield from _every_statement(item)
        return
    if hasattr(value, "__dataclass_fields__"):
        yield value
        for name in value.__dataclass_fields__:
            yield from _every_statement(getattr(value, name))


def test_the_pass_folds_a_single_inline_if():
    prog = decode0.decode_user_code((CORPUS / "t1_ifgoto.exe").read_bytes())

    folded = [s for s in fold_inline_ifs(prog) if isinstance(s, ir.IfInline)]

    assert folded == _eager_folds(prog)


def test_the_pass_folds_a_nested_pair_innermost_first():
    """Two frames closing at one address are nested, and order decides both.

    Folded outermost-first the inner body would already be inside the outer
    statement, and there would be nothing left to fold. Folded the right way
    round the inner IF ends up *inside* the outer one, which is why the check
    is on the whole tree rather than on the top level.
    """
    prog = decode0.decode_user_code((CORPUS / "t1_nestif2.exe").read_bytes())

    produced = list(_every_statement(fold_inline_ifs(prog)))

    assert len(_eager_folds(prog)) == 2
    for statement in _eager_folds(prog):
        assert statement in produced


#: Statements another walk-time fold builds. None of them is ever committed --
#: `select_case` and the procedure-body fold synthesize them from statements
#: that were -- so a deferred pass cannot see one until those folds move too.
_BUILT_BY_ANOTHER_FOLD = (ir.SelectCase, ir.SubDef, ir.DefFn)

#: The fixtures whose inline-IF body holds such a statement. Listed rather than
#: counted: this is the exact set the swap has to take on, and it must not grow
#: without someone saying why.
_BODIES_HOLDING_ANOTHER_FOLD = {
    "t1_ifblockselect.exe",
    "t1_selelsetarget.exe",
    "v10_t1_ifblockselect.exe",
    "v10_t1_selelsetarget.exe",
}


def test_the_pass_reproduces_every_fold_it_can_see():
    """The measurement the swap turns on.

    A mismatch is a place the walk knows something the record does not carry
    -- with one understood exception. When an inline IF's body contains a
    SELECT CASE, the walk had already folded that SELECT into a single
    statement before closing the IF around it, and no SelectCase is ever
    committed, so the record offers the deferred pass the arm bodies flat.
    The region is right; the contents are a fold that has not happened yet.

    That is the concrete form of "the three folds have to move together".
    """
    missed, deferred_blind = [], set()
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        eager = _eager_folds(prog)
        if not eager:
            continue
        produced = list(_every_statement(fold_inline_ifs(prog)))
        for statement in eager:
            if any(
                isinstance(s, _BUILT_BY_ANOTHER_FOLD)
                for s in _every_statement(statement.body)
            ):
                deferred_blind.add(exe.name)
            elif statement not in produced:
                missed.append((exe.name, statement.cond))

    assert not missed, (
        f"{len(missed)} folds the deferred pass gets wrong: {missed[:5]}"
    )
    assert deferred_blind == _BODIES_HOLDING_ANOTHER_FOLD


def test_the_pass_reproduces_a_wild_program_the_corpus_cannot_speak_for():
    """The guard for shift arithmetic, which the fixture corpus cannot give.

    Every fold moves the regions after it, and the bookkeeping for that is the
    one part of this pass with no small witness: a fixture holds a handful of
    statements, so a boundary keyed on the wrong coordinate lands in the same
    place as one keyed on the right one, and all 1030 goldens agree either
    way. Wild `tbd73.exe` folds 43 inline IFs and 13 SELECTs, deep enough for
    the two to separate -- keying the shift on where a splice landed rather
    than on where its region ended cost 9 IFs and 2 SELECTs here.

    Pinned as counts rather than as "all", because the rest is real remaining
    work: the loop lifts still fold during the walk, and a region sitting in a
    list one of them has spliced comes out with statements the walk's does
    not have.
    """
    from conftest import wild_hits_bytes

    from tbx.decode0.fold_pass import fold_constructs

    prog = decode0.decode_user_code(wild_hits_bytes("tbd73.exe"))

    produced = list(_every_statement(fold_inline_ifs(prog)))
    built = list(_every_statement(fold_constructs(prog)))
    folds = _eager_folds(prog)
    selects = _walk_selects(prog)

    assert (len(folds), len(selects)) == (56, 13), "fixture drifted"
    assert sum(s in produced for s in folds) >= 38
    assert sum(s in built for s in selects) >= 12


def test_tbd73_segment_boundary_and_grouping_survive_synthesis():
    """Codeless declarations must not move executable-layout evidence."""
    from conftest import wild_hits_bytes

    from tbx import emit0

    prog = decode0.decode_user_code(wild_hits_bytes("tbd73.exe"))

    # The authored $SEGMENT precedes the first INLINE SUB. Recording the
    # transition as a walk-time list length placed it after SUB3 once four
    # static DIMs and COMMON were reconstructed.
    first_sub = next(i for i, stmt in enumerate(prog) if isinstance(stmt, ir.SubDef))
    assert prog.metas == ((first_sub, "$SEGMENT"),)

    # The original AX/CX/DI shuttle preserves the completed left sum as an
    # explicitly grouped value. Minimal parenthesization recompiles through a
    # different register template.
    src = emit0.emit(prog)
    assert "(((Q% - P%) \\ 2) + P%) - (LEN(U$) \\ 2)" in src
    assert (
        "V7%(E%) + V8%(E%) \\ 2 - (LEN(X$(AD%)) \\ 2)" in src
    )
    # A by-ref numeric parameter tested by OR AX,AX is source-level bare
    # truthiness. Normalizing its false-skip to `= 0` recompiles as XOR/CMP
    # and shifts the pool.
    assert "IF I% THEN CALL SUB6" in src
    assert "IF I% = 0 THEN" not in src
    assert "IF NOT AU% THEN" in src
    assert "IF NOT CL% THEN" in src
    assert "IF NOT CM% THEN" in src
    assert "IF NOT CO% THEN" in src
    assert "IF NOT AU% = 0 THEN" not in src


def _walk_selects(prog):
    """Every SELECT the walk built, in the order it built them."""
    return [
        edit.payload[0]
        for edit in prog.statement_edits
        if edit.origin == "select_case"
        and edit.payload
        and isinstance(edit.payload[0], ir.SelectCase)
    ]


def test_the_pass_builds_a_select_from_the_record():
    from tbx.decode0.fold_pass import fold_constructs

    prog = decode0.decode_user_code((CORPUS / "t1_selarmtarget.exe").read_bytes())

    built = [s for s in _every_statement(fold_constructs(prog)) if isinstance(s, ir.SelectCase)]

    assert built == _walk_selects(prog)


def test_the_pass_builds_every_select_in_the_corpus():
    """Guards, selector, arm bodies and CASE ELSE, all from the log.

    The arms are the part that was never in doubt -- they are committed
    statements. What this measures is whether the regions, the guards and the
    selector recorded alongside them are enough to put the construct back
    together without the recognizer's frame.

    All 26 in the corpus, and 13 of the 16 in wild `tbd73.exe`. All three that
    differ turn on the loop lifts, which are a fourth family of walk-time
    folds: a FOR header absorbs the loop-variable assignment that precedes it,
    and `lift_while` and its siblings *insert* a `Do` marker at an earlier
    position. Both move list positions relative to the commit stream this pass
    works in, so an arm around one comes out with statements the walk's arm
    does not have.
    """
    from tbx.decode0.fold_pass import fold_constructs

    missed = []
    for exe in sorted(CORPUS.glob("*.exe")):
        try:
            prog = decode0.decode_user_code(exe.read_bytes())
        except ValueError:
            continue
        walked = _walk_selects(prog)
        if not walked:
            continue
        built = [
            s
            for s in _every_statement(fold_constructs(prog))
            if isinstance(s, ir.SelectCase)
        ]
        for select in walked:
            if select not in built:
                missed.append((exe.name, str(select.selector)))

    assert not missed, (
        f"{len(missed)} SELECTs the deferred pass builds differently: {missed[:5]}"
    )


def test_a_program_with_no_inline_if_is_left_alone():
    prog = decode0.decode_user_code((CORPUS / "t1_print2.exe").read_bytes())

    from tbx.decode0.events import replay_events

    assert fold_inline_ifs(prog) == list(replay_events(prog.events))
