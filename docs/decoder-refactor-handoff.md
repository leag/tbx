# Decoder refactor — handoff

Where the migration in `decoder-refactor-brainstorm.md` stands, what is proven,
what is not, and what to do next. Every figure here was measured on the current
tree, not carried forward from when the work was done.

Branch `release/0.1.0`. Baseline for "no behavior change" is commit `36aa8a4`.

## Verify the current state

```sh
uv run pytest                 # 2665 pass
uv run ruff check             # clean
uv run python -m tbx.tools.scan_wild wild/hits
```

The wild scan must print `86 EXEs scanned: 28 TB decode-ok, 58 TB-but-fail`
**and produce a byte-identical failure report to the baseline**. The tally
alone is not the check — a refactor can move which programs fail while keeping
the count. Diff the full output against a run at `36aa8a4`.

`tests/fixtures/{ops,ir_snapshot.txt,usercode}` must be untouched by any commit
in this migration. `git status tests/fixtures/` after a change is the fastest
signal that something moved.

## Chapter status

| chapter | state |
| --- | --- |
| 0 baseline | done |
| 1 diagnostics | done (in the `wip` commits) |
| 2 `OpCursor` | done |
| 3 state ownership | **complete** |
| 4 recognition/mutation split | substantial, two families outstanding |
| 5 event stream | **complete** for statement construction |
| 6 control-flow extraction | inputs complete, the swap not attempted |
| 7 remove scaffolding | not started |

## What is proven, with numbers

Measured over the 1030-fixture corpus unless stated.

**State ownership (ch. 3).** A total, disjoint partition of the 100 persistent
`DecodeState` fields across six views. `tests/tbx/test_state_parts.py` fails if
a field gains a second owner or none; `test_migrated_modules.py` fails if a
listed module bypasses its views or writes the operation index directly. Every
decoder module is listed.

**Matchers (ch. 4).** Ten matchers over a shared `TemplateMatch`, 42 pure tests
on hand-built operation tuples with no fixture dependency.

**Statement construction is lossless (ch. 5).** `RecordedStatements` logs every
append, insert, replace, delete and splice; `_finalize` gates on
`replay(edits) == list(stmts)`. 16290 edits: 12213 append, 3828 splice, 117
delete, 75 replace, 57 insert. The gate holds for all 1030 fixtures and all 28
decodable wild programs.

**Every edit is attributed (ch. 6).** `StatementEdit.origin` names the pass,
`scope` the whole stack, `at_event` when it happened. **Zero** unattributed
non-append edits corpus-wide. Fold nesting is two paths only:
`select_case > close_ifs` (12 edits) and `finalize > apply_exit_folds` (8).

**Every branch is recorded (ch. 6).** 196 branch events — 80 `if`, 90 `loop`,
26 `case`. Fixtures whose structure the graph cannot see: **8 of 151**, down
from 103. The 8 are SELECT-only programs whose END SELECT is genuinely unknown
when the header is recognised, so the event records `target=None` and
contributes a node but no edge.

**The construct is a table, not a judgement (ch. 6).**
`control_graph.FRAME_BY_TEMPLATE` maps calibrated templates to constructs, and
`test_the_table_reproduces_every_handler_decision` derives the construct for
every branch in the corpus and checks it against the handler's own choice.
Zero disagreements.

**Fold starts are exact (ch. 6).** `predict_fold_starts` locates each inline-IF
fold region's start from the record alone: 62 of 62 programs that fold one.

## What is not proven

**Fold extents: 39 of 62.** The only measurement in this chapter that does not
reach 100%. 13 folds end at a boundary no statement address describes; 10 more
have a known region end that a naive rule places wrongly. The gap is a missing
*moment*, not a missing address — a region's end is the list length when
decoding reaches its boundary, and that instant is not derivable from statement
addresses. Recording region *closes* is the fix, and has the same shape as the
`at_event` clock that took fold starts from 55/62 to 62/62.

**The event stream is not lossless for statements.** 10764 of 11799 statement
events survive as top-level statements; 549 of 1030 programs reconcile clean.
The rest is folding and finalization, which is expected — but two classes are
not:

- Handlers patch already-committed statements in place (`stmt_addr[-1] =
  ir.Locate(...)` when the cursor argument arrives, and the same for
  INPUT/FIELD/PRINT chain targets), so the event holds a pre-patch statement.
- DIM and DATA are reconstructed at finalization from layout and pool facts and
  never pass through `put`, so no event describes them.
  `test_codeless_data_statements_are_synthesized_not_committed` pins this and
  fails when it is fixed.

**Chapter 4 has two families left.** The `shlsi` element-stride chain in
`handlers/arith.py` recognises the array-operand template while *deleting*
`into` operations from the stream it reads; splitting it needs either a
duplicated shape walk or a change to what the operation stream contains. The
floating-point folds in `core.fp_dispatch` are likewise still mixed.

## The swap, and why it has not been done

Chapter 6's remaining work is to stop folding during decoding and fold
afterwards from the graph. It was attempted and **fails**: deferring
`close_ifs` alone breaks 92 tests in three classes.

- **28 unresolved jump targets.** An inline IF that is the last statement of a
  SUB/DEF FN body skips to the epilogue, which is not a statement and never can
  be — `END SUB` carries no line number. The fold is what removes that target.
- **~100 output differences.** Bodies stayed open past the point a later fold
  snapshotted them. `select_case._fold_arm` documents this exactly: it calls
  `close_ifs` before snapshotting an arm because an inline IF closing an arm
  skips to the arm-close jmp (wild `tbd73.exe`, TBW73.INC:716).
- **6 trace-hook and line-table failures**, where the fold's address retention
  into `stmt_addr` keeps body lines visible.

So `close_ifs`, `_fold_arm` and the procedure-body fold have to move together.
Each timing requirement traces to a calibrated wild-program behaviour rather
than to convenience.

## Next steps, in order

1. **Record region closes.** Emit an event when a region actually closes, so a
   fold extent is read from the log rather than inferred. Expect this to take
   extents from 39/62 to exact, as `at_event` did for starts. Low risk: purely
   additive, no statement moves.
2. **Route in-place patches and finalization reconstruction through the commit
   path**, so the event stream becomes lossless for statements too. Medium
   risk: changes what is committed, but not the final list.
3. **The swap.** Move the three folds together, against a model where a region
   stays open until its enclosing construct closes it. Gate on the goldens and
   the wild-corpus report, not on a green suite — this is the first change in
   the chapter that will move statements. Expect the epilogue-target and
   address-retention cases to decide whether it works.
4. **Chapter 4's two families**, independently of the above.
5. **Chapter 7**, only after the swap lands.

## Tools

```sh
python -m tbx.tools.dump_events PROGRAM.EXE              # commit-time events
python -m tbx.tools.dump_events --branches PROGRAM.EXE   # each branch's fate
python -m tbx.tools.dump_events --edits PROGRAM.EXE      # which pass made each edit
python -m tbx.tools.dump_events --reconcile wild/hits/*.exe
```

## Working notes

Two habits earned their keep repeatedly and are worth keeping.

**Watch the guard fail.** The losslessness gate was silently absent on its
first wiring — a string anchor had not matched — and 2609 passing tests said
nothing. Sabotaging `replay` to drop a statement proved it fired. The
attribution test passed on two hand-picked fixtures while the corpus still had
165 unattributed edits across eleven sites.

**Measure before and after with the same predicate.** The branch-visibility
improvement was first computed as 103 → 40 by comparing a narrower structure
predicate after the change against a wider one before it. With the identical
predicate it was 103 → 79, and only after further instrumentation 103 → 8.

Several test premises in this work were wrong in ways the failure explained:
`reconcile` matching by identity when folding rebuilds objects, DATA assumed to
commit unaddressed when it does not commit at all, and a SELECT branch target
that was actually an x87 temp displacement. The failing test was worth more
than the passing one would have been each time.
