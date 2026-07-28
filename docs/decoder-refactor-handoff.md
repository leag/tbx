# Decoder refactor — handoff

Where the migration in `decoder-refactor-brainstorm.md` stands, what is proven,
what is not, and what to do next. Every figure here was measured on the current
tree, not carried forward from when the work was done.

Branch `release/0.1.0`. Baseline for "no behavior change" is commit `36aa8a4`.

## Verify the current state

```sh
uv run pytest                 # 2700 pass
uv run ruff check             # clean
uv run python -m tbx.tools.scan_wild wild/hits
```

The wild scan must print `86 EXEs scanned: 32 TB decode-ok, 54 TB-but-fail`
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
| 7 remove scaffolding | audit and measurement done; one deletion disputed |

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

## Emitted source has to be source the compiler could have taken

A gate this migration did not have, and the only one so far that needs no
oracle. The Owner's Handbook fixes two editor limits: **248 characters** per
line, and **64K** per source file, with `$INCLUDE` the documented way to
compile anything larger. Output past either is not a formatting preference --
it is provably not what the author wrote, because the compiler the program
came out of could not have been handed it. `tests/tbx/test_emitted_source_width.py`
reads that straight off the emitted text.

It found eight wild programs and zero fixtures, which is the same shape as
every other finding this chapter: the corpus is silent on anything that only
manifests at scale. Three causes, all now fixed, each verified by the oracle
rather than by argument:

- **A reconstructed `DATA` or `COMMON` emitted as one statement.** Dividing it
  costs nothing -- `ir.Common` already recorded that splitting across several
  statements compiles identically (t1_common1), and DATA items enter the pool
  in order either way. Fixed zip.exe (295), book.exe (396), baby.exe (6116).
- **An inline IF whose folded body does not fit.** The block spelling fits, and
  for the compound conditions these carry it compiles to the same bytes --
  measured, not assumed: t1_ifin and t1_orrel compile byte-identically either
  way and both match their EXE. A *simple* condition is not interchangeable
  (its inline form does not materialize, which is what `block_ifs` turns on).
  Fixed inv87/invoice (353) and state/state87 (265). Two of the four were
  nested, so the emitter now carries the column a statement starts at.
- **A line table with one distinct value.** metric.exe's is 1789 entries all
  reading 0, and statements sharing a line number are grouped onto it, so the
  whole program went out on one 43759-character line. Such a table is not the
  source's numbering; it is treated as absent and the program renumbered.

The oracle result is what makes these fixes rather than preferences. zip.exe
and metric.exe could not previously be loaded into the editor at all, so there
was nothing to compile and nothing to judge; both now compile. Neither is
byte-exact yet (metric.exe is 1008 bytes out), but an unmeasurable failure has
become a measurable one.

**Six wild programs still exceed 64K of emitted source** -- banker, horses,
inv87, invoice, state, state87. Their source was divided across `$INCLUDE`
files the emitter does not reconstruct, so they cannot round-trip as one file
however narrow their lines get. Pinned by size, and no fixture is near it.

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
| inline IFs, `wild/hits` | 771 | **755** |
| SELECTs, `tests/fixtures/corpus` | 26 | **26** |
| SELECTs, `wild/hits` | 16 | **15** |

Most of what used to sit in the miss column was the pass's own shift
arithmetic, not a gap in the record. It keyed each fold's boundary on where
the splice *landed* rather than on where the region *ended* — the same error
`drain_folds` had — which deep in a program makes every earlier fold look as
though it precedes every later region, nested ones included. Correcting it
moved wild inline IFs 730 → 755 and wild SELECTs 13 → 15; `tbd73.exe` alone
went 29 → 38 of 43 and 10 → 12 of 13.

The corpus said nothing either way: 76/80 and 26/26 before and after. A
fixture holds few enough statements that a boundary keyed on the wrong
coordinate lands in the same place as one keyed on the right one. **The shift
arithmetic has no small witness**, which is why the guard for it is a wild
program.

Constructs are folded in the order they *close* — whatever finishes first is
innermost — which also settles the ties: an inline IF closing a CASE arm shares
the arm's arrival and goes first, exactly as `_fold_arm` calls `close_ifs`
before snapshotting, and a CASE ELSE goes after the arms, so a provisional else
region that a real arm overwrote comes out empty and becomes no CASE ELSE at
all. Two behaviours of the walk had to be reproduced rather than read: a fold
must claim its new statement's address, because `_fold_body` reconstructs an
ELSE by looking one up for statements that are no longer top level.

Every remaining difference is another walk-time fold, not a gap in the record:
4 in the corpus fold a body holding a `SELECT CASE` the walk had already built
(no `SelectCase` is ever committed, so the record offers the arm bodies flat),
and 16 wild inline IFs across five programs plus the last `tbd73.exe` SELECT
sit in a list a loop lift had already spliced. Commit coordinates and list
coordinates agree until one of those runs.

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
  `Do` marker at an earlier position. They are what the pass's last 16 wild
  inline-IF misses and its one SELECT miss turn on — a fifth of what the
  earlier measurement blamed on them. They need the same treatment: record
  what they recognise, then fold from it.
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

## Chapter 7, measured

Two of its deliverables are done, and both came back better than the plan
assumed.

**The field and call-site audit.** Of the 96 fields the ownership partition
claims, **none** is written and never read. The least-used are down to a single
read, which is the point -- they can be found and judged rather than suspected.
So there are no obsolete mutable fields to delete: Chapter 3's partition has not
rotted. Kept as `tests/tbx/test_state_audit.py` so the answer stays true instead
of being a number in a document, with the surface size pinned so growing it is a
decision.

The rest of the chapter's deletion list is already empty or nearly so.
`DecodeState` has one property, and it is an accessor rather than a forwarding
alias. Direct `k` mutation is confined to the cursor's own implementation. No
handler bypasses its views.

**The performance measurement against Chapter 0.** Decoding the whole fixture
corpus, best of three:

| | total | per program |
| --- | --- | --- |
| baseline `36aa8a4` | 2.66s | 2.58 ms |
| now | 3.23s | 3.14 ms |

**+21%**, which is what the event stream, the statement-edit log and address
ownership cost. The plan puts correctness and diagnostic reproducibility ahead
of throughput during the migration, so this is the expected shape; it is
recorded here so that a later regression is distinguishable from it.

### The one deletion worth arguing about

The plan has Chapter 7 remove the frames' `idx` cross-check -- `frame_start`
raising when the region start read back from the record disagrees with the
length the walk saw. It has never fired across either corpus, which is the
usual reason to call something scaffolding.

It should stay. What this chapter learned the hard way is that the fixture
corpus is blind to position bookkeeping: two shift-arithmetic bugs, one in
`drain_folds` and one in `fold_pass`, were live while all 1030 goldens were
byte-identical, and only wild programs showed them. A wrong `frame_start` is
exactly that class of error. The cross-check is a cheap invariant guarding
something the goldens do not, and "it has never fired" is what a working guard
looks like.

Only the four inline-IF frame openers carry `idx` for the cross-check alone.
The proc/fn frames need theirs (`_drop_local_descriptor_initializers` slices on
it, and the `local_init` check reads it), and the FOR frames' `idx` indexes the
header they patch. So the deletion was never 15 sites; it is four, and they buy
a guard the corpus cannot replace.

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
4. **Chapter 7's remainder**: the architecture and replay-tool documentation.
   Its audit and measurement are done, its deletion list came back empty, and
   the one deletion it proposed should not happen -- see above.
