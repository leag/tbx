# Decoder refactor — handoff

Where the migration in `decoder-refactor-brainstorm.md` stands, what is proven,
what is not, and what to do next. Every figure here was measured on the current
tree, not carried forward from when the work was done.

Branch `release/0.1.0`. Baseline for "no behavior change" is commit `36aa8a4`.

## Verify the current state

```sh
uv run pytest                 # 2698 pass
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
| 6 control-flow extraction | folds record-driven; timing moved and green on `experimental/deferred-fold` |
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

**All three folds now take their region from the record.** Each construct that
owns a body is identified by the event that recognised it, and the body's start
position is the list length at that event, replayed from the edits:

| fold | event | recorded where |
| --- | --- | --- |
| inline IF | branch, with its condition and spelling | `open_tail_if`, two lifts, one core site |
| CASE arm / CASE ELSE | `case_arm` / `case_else` region, with its guards | `_begin_body`, the else transition |
| SUB / DEF FN body | `proc` / `fn` region | `proc_enter`, the DEF FN auto-open |
| SELECT CASE | `select` region, with its selector | END SELECT, where both ends are known |

Each frame keeps its old `idx` purely as a cross-check: if the record's answer
disagrees with the length the walk saw, decoding raises. It never has, across
both corpora. Sabotaging the derivation by one fails fold, SELECT and procedure
tests, so all three guards are watched to fire. Chapter 7 deletes them.

The inline-IF frame goes further — it is the branch event's `seq` and nothing
else, so `close_ifs` reads the condition, the start address and the target out
of the log too.

**The deferred pass exists and is measured.** `fold_pass` folds inline IFs,
CASE arms and SELECTs from the commit stream, in commit coordinates, touching
no decode state. Nothing calls it in the pipeline. Against what the walk did:

| | folds | reproduced |
| --- | --- | --- |
| inline IFs, `tests/fixtures/corpus` | 80 | **76** |
| inline IFs, `wild/hits` | 403 | **388** |
| SELECTs, `tests/fixtures/corpus` | 26 | **26** |
| SELECTs, `wild/hits` | 16 | **13** |

Constructs are folded in the order they *close* — whatever finishes first is
innermost — which also settles the ties: an inline IF closing a CASE arm shares
the arm's arrival and goes first, exactly as `_fold_arm` calls `close_ifs`
before snapshotting, and a CASE ELSE goes after the arms, so a provisional else
region that a real arm overwrote comes out empty and becomes no CASE ELSE at
all. Two behaviours of the walk had to be reproduced rather than read: a fold
must claim its new statement's address, because `_fold_body` reconstructs an
ELSE by looking one up for statements that are no longer top level.

Every difference is another walk-time fold, not a gap in the record: 4 in each
corpus fold a body holding a `SELECT CASE` the walk had already built (no
`SelectCase` is ever committed, so the record offers the arm bodies flat), and
11 wild ones sit in a list `select_case`, the procedure-body fold or a loop lift
had already spliced. Commit coordinates and list coordinates agree until one of
those runs.

**A CASE arm is located too.** An arm ends at its arm-close jmp, which owns no
statement, so its extent is a moment like an inline IF's: a region's end is now
an address the log waits for, and `fold_pass.arm_regions` sizes every arm from
the arrival there — 35 of 35 in the corpus, 67 of 67 in wild `tbd73.exe`, none
empty. With the guards and the selector recorded, everything a pass needs to
*build* a `SelectCase` is in the log except the statements themselves.

So the remaining work is what a deferred pass still cannot reconstruct:

- **The loop lifts are a fourth family of walk-time folds.** `lift_while`,
  `lift_bool_do_tail`, `lift_do_tail` and the FOR/NEXT lifts rewrite the list
  as they go, exactly as the three folds above did, and in a way that moves
  list positions relative to the commit stream: a FOR header absorbs the
  assignment that initialises its loop variable, and `lift_while` *inserts* a
  `Do` marker at an earlier position. All three wild SELECT misses turn on
  that. They need the same treatment: record what they recognise, then fold
  from it.
- **`SelectCase` and `SubDef`/`DefFn` are never committed.** They are built by
  their fold from statements that were, so a pass cannot see inside one the
  walk has already built. This is what blocks the 4+4 inline-IF differences.
- **A procedure's name and parameters are not in the record.** They live in
  `proc_names`/`proc_params`, keyed by address. The `proc` region says where
  the body is, not what to call it.

## The timing move, done: `experimental/deferred-fold`

Branch `experimental/deferred-fold`, head `2d126e0`, off this one, **green and
ready to merge**. `close_ifs` queues its region at the arrival instead of
folding, and `drain_folds` folds the queue when the construct that owns it
closes -- the arm snapshot, the procedure return, the end of the walk.

The gates it passes: 2699 tests, Ruff clean, all 1030 corpus goldens and the IR
snapshot byte-identical, and a `scan_wild wild/hits` report byte-identical to
this branch's across all 86 EXEs -- same 32 decode-ok, same statement counts.

Six entanglements had to move, and they are all the same shape: a later
recognizer asking a question about the statement list that the eager fold used
to have already answered.

- **Four discriminators mean the folded list.** "Is this backward jmp's target
  a statement start?" is true for addresses a queued region is about to
  absorb, and false for the address the region's `IfInline` will stand at.
  `DecodeState.statement_index` composes the answer -- what is there now, minus
  `folded_away`, plus `fold_products` -- and returns the position, which the
  infinite-DO leg needs. Wild `ziptest.exe` at `0xa4bb` and `horses.exe` at
  `0x848a`.
- **A `DO` spliced ahead of a loop body moves every queued region after it.**
  Four sites do it; `shift_pending` is the bookkeeping, passed to the lifts as
  a `shift` callback. The bounds are half-open and move differently at their
  own index: an insert at `start` pushes the body down, an insert at `stop`
  lands outside and must not stretch it. Wild `horses.exe` for the first
  (its region drifted two statements early), `state.exe`'s IF at `0xeaca` for
  the second (its two statements became three, the extra being the `DO`).
- **`_fold_arm` needs both halves.** `state.close_ifs(merge)` is what *queues*
  the frame -- the dispatch loop never reaches the arm-close address, because
  `select_case.step` consumes the op first -- and the drain is what folds it.
  Replacing the close with the drain folds nothing, and `t1_iftailarm` loses
  its IF.
- **The drain's own shift arithmetic mixed two coordinate systems.** It keyed
  each subtraction on where a splice *landed* rather than on where the region
  *ended*. The two agree for the first fold in a batch and drift apart from
  there, so late in a long batch every earlier fold looked as though it
  preceded every later region -- including regions nested inside one still to
  be folded, whose body then started too early. Wild `invoice.exe`, the IF at
  `0xd316`: 11 statements folded where the walk saw 8.

Two things the swap changed rather than broke, both now recorded rather than
worked around:

- **Where a fold lands is no longer where its region was.** Everything folded
  in between has moved it. `Program.fold_regions` is the walk's own account of
  the region -- where the body began, and the list length when decoding
  reached the branch's target -- kept past the fold that consumes it. It is
  what a prediction from the record can be checked against.
- **`predict_fold_extents` no longer applies the collapse arithmetic.** Nested
  frames sharing an arrival all end at that one moment. What the enclosing
  region spans *after* the inner ones fold depends on the order the pass folds
  in and on what else it has folded since, so it belongs to the pass. Leaving
  it in the predictor made a reader of the record describe one particular
  folding schedule.

## Why the eager timing was load-bearing

The earlier attempt, deferring `close_ifs` alone with nothing else moved, broke
92 tests in three classes.

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

1. **Merge `experimental/deferred-fold`.** It is green on every gate this
   chapter uses. Worth running `docs/release-checklist.md`'s oracle sample
   against it first: the goldens say the emitted source did not move, and the
   oracle is what says it still recompiles byte-for-byte.
2. **Record the loop lifts' regions**, the way the inline IF, the CASE arm and
   the procedure body were recorded, and fold them in `fold_pass` -- they are
   the only walk-time fold family left, and the three wild SELECT misses are
   waiting on them. Then `SubDef`, which additionally needs the procedure's
   name and parameters recorded.
3. **Chapter 4's two families**, independently of the above.
4. **Chapter 7**, now unblocked by the swap: the frames' `idx` cross-check has
   done its job and can go, along with the three guards Chapter 6 kept.
