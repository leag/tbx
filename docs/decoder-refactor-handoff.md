# Decoder refactor — handoff

Where the migration in `decoder-refactor-brainstorm.md` stands, what is proven,
what is not, and what to do next. Every figure here was measured on the current
tree, not carried forward from when the work was done.

Branch `release/0.1.0`. Baseline for "no behavior change" is commit `36aa8a4`.

## Verify the current state

```sh
uv run pytest                 # 2685 pass
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
| 5 event stream | **complete**: every statement has an event |
| 6 control-flow extraction | inline-IF fold record-driven; two folds to go |
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

**Fold extents are exact (ch. 6).** `predict_fold_extents` sizes each region
from the record: **62 of 62** corpus programs and **18 of 18** decodable wild
programs that fold an inline IF. An address-only rule gets 26 of 62 — the end
is a moment, not an address, so `ArrivalEvent` records decoding reaching an
address a branch wants and the extent is the list length there. Two things the
closing turned up: nested frames sharing an arrival need the fold's own
arithmetic (an inner region collapses to one statement, so its enclosure ends
one past where it began, innermost-first), and a body ending in a pending chain
is flushed at the arrival because it was decoded before the boundary (wild
`be.exe`, the only program in either corpus with that shape).

**Every statement is accounted for (ch. 5).** Three paths used to reach the
program with nothing in the log describing them, and each is now an event kind:

- `flush_pending` appended a closed chain directly — a trailing-`;` PRINT, an
  INPUT#/READ target chain, a FIELD list. `commit` is the one way into the list
  now, and the 51 corpus-wide appends record an event like any other statement.
- Handlers revise a committed statement when a second runtime call completes it
  (a LOCATE's cursor argument, a FOR's real step, a second DIM joining the
  first). `PatchEvent` names the commit it supersedes rather than standing
  alone; 36 revisions, four of them revisions of revisions.
- DIM, DATA, OPTION BASE, COMMON and DEFtype are derived by finalization from
  layout and pool facts. `ReconstructedEvent` says so; replay skips it, since
  finalization runs after folding and its insert position means nothing in the
  walk.

Reconciliation: 436 synthesized statements, down from 756, and every one is now
a folding or lifting product — rebuilt SUB bodies, resolved CALLs, TRON/TROFF
lifting, structured forms. 239 are reported as reconstructed, and 702 of 1030
programs reconcile clean, up from 549.

## What is not proven

**Chapter 4 has two families left.** The `shlsi` element-stride chain in
`handlers/arith.py` recognises the array-operand template while *deleting*
`into` operations from the stream it reads; splitting it needs either a
duplicated shape walk or a change to what the operation stream contains. The
floating-point folds in `core.fp_dispatch` are likewise still mixed.

## The swap: half done, and the other half measured

**The fold's inputs now come from the record.** An open inline-IF frame is the
`seq` of the branch event that recognised it and nothing else — `close_ifs`
reads the condition, the start address and the target back out of the log, and
derives the region start by replaying the edits stamped up to that event. The
frame keeps `idx` only as a cross-check: if the record's answer disagrees with
the length the walk saw, decoding raises. It never has, across both corpora.
Chapter 7 deletes the check.

**The deferred pass exists and is measured.** `fold_pass.fold_inline_ifs`
folds every recorded region from the commit stream, in commit coordinates,
touching no decode state. Nothing calls it in the pipeline. Against what the
walk actually did:

| | folds | reproduced |
| --- | --- | --- |
| `tests/fixtures/corpus` | 80 | **76** |
| `wild/hits` | 403 | **388** |

Every difference is another walk-time fold, not a gap in the record: 4 in each
corpus fold a body holding a `SELECT CASE` the walk had already built (no
`SelectCase` is ever committed, so the record offers the arm bodies flat), and
11 wild ones sit in a list `select_case`, the procedure-body fold or a loop lift
had already spliced. Commit coordinates and list coordinates agree until one of
those runs.

So the remaining work is exactly: move `select_case`'s arm snapshot and the
procedure-body fold onto the same footing, then run all three after the walk.

## Why the timing is load-bearing

Deferring `close_ifs` alone was attempted and **fails**: it breaks 92 tests in
three classes.

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

1. **Defer the other two folds.** `select_case`'s arm snapshot and the
   procedure-body fold are what the deferred inline-IF pass trips over, and the
   19 differences name exactly where. Give each the same treatment the inline IF
   got: record what it recognises, then build the statement from the record.
   `SelectCase` and `SubDef` never being committed is the specific thing to fix
   — until they are, no deferred pass can see inside them.
2. **Then run all three after the walk.** Gate on the goldens and the
   wild-corpus report, not on a green suite — this is the first change in the
   chapter that will move statements. Expect the epilogue-target and
   address-retention cases to decide whether it works.
3. **Chapter 4's two families**, independently of the above.
4. **Chapter 7**, only after the swap lands.

## Tools

```sh
python -m tbx.tools.dump_events PROGRAM.EXE              # commit-time events
python -m tbx.tools.dump_events --branches PROGRAM.EXE   # each branch's fate
python -m tbx.tools.dump_events --edits PROGRAM.EXE      # which pass made each edit
python -m tbx.tools.dump_events --folds PROGRAM.EXE      # region predicted vs folded
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

**Run a new predicate over the wild corpus too.** Fold extents reached 62/62 on
the fixtures and 17/18 on the wild programs. The one miss was not noise: it was
a fold whose whole body is a pending trailing-`;` PRINT, a shape no fixture has,
and it named the flush timing the model actually needs.

Several test premises in this work were wrong in ways the failure explained:
`reconcile` matching by identity when folding rebuilds objects, DATA assumed to
commit unaddressed when it does not commit at all, and a SELECT branch target
that was actually an x87 temp displacement. The failing test was worth more
than the passing one would have been each time.
