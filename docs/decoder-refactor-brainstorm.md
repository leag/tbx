# Decoder refactor plan

This plan turns the decoder-refactor brainstorm into an incremental migration
that can be reviewed and reverted chapter by chapter. The objective is not to
introduce abstraction for its own sake. It is to make ownership, phase
boundaries, and failure evidence explicit while preserving the calibrated byte
vocabulary and byte-exact output.

The current decoder is correct enough to release, but its top-level loop is
difficult to reason about. `DecodeState` combines machine registers,
expression values, layout facts, procedure bookkeeping, control-flow frames,
and output metadata. Handlers communicate through fields whose producer and
consumer may be many iterations apart. This plan addresses that problem
without changing the language supported by the decoder.

## Working rules

Every chapter must leave the decoder usable and must be independently
bisectable. A chapter may add internal APIs, adapters, and tests, but it must
not broaden the accepted byte vocabulary or silently reinterpret an unknown
pattern. Unknown patterns continue to raise `ValueError`.

The existing contracts remain the authority throughout the migration:

- `tests/fixtures/ops` is the scan contract.
- `tests/fixtures/ir_snapshot.txt` is the lift/IR contract.
- `tests/fixtures/usercode` is the emitted-source contract.
- hand-written tests under `tests/tbx/` protect known edge cases.
- compiled fixtures and `verify_fixture` remain the proof of byte-exactness
  for any intended semantic change.

Each chapter produces a before/after failure-corpus report. The report records
the full suite, Ruff, the wild-corpus tally, and any oracle fixtures exercised.
Fixture regeneration is allowed only when a chapter explicitly changes a
semantic contract; structural changes must keep the existing goldens intact.

## Chapter 0 — Establish the baseline

Before changing decoder behavior, make the current behavior measurable and
replayable.

### Scope

Capture the current dispatch path from `decode0.scan` through layout, lift,
IR, and emission. Identify the state fields read and written by the dispatch
loop and its handlers. Treat `DecodeState`, `OpStream`, and the existing
fixture loaders as the initial compatibility surface.

### Deliverables

- A checked-in or reproducibly generated baseline report containing the full
  pytest suite, Ruff, representative oracle verification, and wild-corpus
  results.
- A field-usage inventory grouped by current ownership: machine, expression,
  layout, control, output, or diagnostics.
- A small set of replayable failure cases for the highest-churn families:
  compound booleans, array operands, SUB/DEF FN frames, runtime vectors, and
  floating-point folds.
- Invariant assertions at existing phase boundaries, guarded so they explain
  the failure without changing successful decoding.

### Invariants

The operation cursor is within the operation stream; statement addresses are
unique where the current decoder requires them; pending values are consumed or
carried only through an existing documented path; and every emitted jump
target is resolvable by the same rules as before.

### Exit criteria

The baseline can be recreated by a future contributor, and every new
assertion either passes across the current corpus or identifies a pre-existing
unsupported path. No output fixture changes are expected in this chapter.

## Chapter 1 — Make failures explain themselves

Diagnostics come before structural movement. A better error report reduces the
risk of mistaking a refactor regression for a newly discovered compiler form.

### Scope

Introduce a diagnostic context that records the EXE/file offset, operation
index, current statement address, recent operations, active state component,
and candidate matchers. Thread it through the existing loop without changing
handler behavior.

### Deliverables

- A structured internal `DecodeError` payload, rendered as the existing
  `ValueError` style at the public boundary.
- A bounded cursor history containing the last 8–16 consumed operations.
- Candidate rejection records with a matcher name and concise reason.
- A replay command or library entry point that loads an ops golden, runs the
  current pass, and stops at a requested operation address/index.

### Invariants

Diagnostics must be observational: they cannot consume operations, mutate
decode state, or alter which matcher wins. Sensitive or unavailable source
metadata is represented as absent, never guessed.

### Exit criteria

The main existing failure classes—unknown byte/template mismatch, unresolved
jump target, and unsolved DGROUP layout—include enough context to identify the
first failing pass and the relevant state family. Existing error matching tests
continue to pass, with only deliberately widened diagnostic text where needed.

## Chapter 2 — Centralize operation consumption

The current handlers perform lookahead and advance `k` through implicit
conventions. This chapter makes operation windows explicit while retaining a
compatibility path for handlers that have not migrated.

### Scope

Add an `OpCursor` over the existing operation list with `peek`, `take`,
`expect`, `mark`, `rewind`, and bounded slicing. It owns bounds checks and
records consumption in the diagnostic context.

Use a small result vocabulary for migrated handlers:

```text
Handled(next_cursor, effects)
NoMatch(cursor)
DecodeError(cursor, expected, evidence)
```

### Deliverables

- `OpCursor` and unit tests for bounds, marks, rewinds, and address lookup.
- An adapter that maps the cursor position to the existing `ops`/`k` fields.
- Migration of one low-risk handler family and one lookahead-heavy family as
  reference implementations.
- A dispatch-loop assertion that the selected handler advances exactly as
  reported by the cursor.

### Invariants

A `NoMatch` leaves the cursor and all decode state unchanged. A successful
handler consumes precisely its declared range. Rewinding is valid only to a
local mark and cannot cross a committed statement boundary.

### Exit criteria

All operations goldens and IR/source goldens are unchanged. The migrated
families have no direct mutation of `k`, and the adapter proves that legacy
and cursor paths consume identical operation ranges on the corpus.

## Chapter 3 — Give state an owner

Once consumption is explicit, separate the large mutable register file by
responsibility. This is a shape change, not a semantic change.

### Scope

Introduce a `DecodeCtx` containing nested components:

```text
MachineState   registers, segments, stack temporaries, pending x87 state
ExprState      values, operands, pending comparisons, string temporaries
LayoutState    scalar/array slots, pools, descriptors, inferred types
ControlState   statement cursor, jumps, loops, IF/SUB/CASE frames
OutputState    statements, physical addresses, metadata, toggles, trace hooks
Diagnostics    cursor history, expectations, rejected alternatives
```

Move fields in ownership groups, keeping temporary forwarding properties on
`DecodeState` so handlers can migrate independently. Do not make ownership
claims based only on field names: verify each group against the field-usage
inventory from Chapter 0.

### Deliverables

- Nested dataclasses with explicit defaults and serialization/debug views.
- Forwarding properties marked as migration-only and covered by tests.
- Handler annotations or documentation stating which components a handler may
  read and mutate.
- A state consistency check at statement commit and procedure return.

### Invariants

The compatibility view and nested state refer to the same live values during
migration. Cross-component updates remain ordered exactly as before. Facts
discovered during a procedure are not retired or defaulted merely because a
handler has not yet visited their use site.

### Exit criteria

The dispatch loop uses `DecodeCtx`; forwarding properties are the only legacy
access path for migrated fields; and the complete corpus produces identical
ops, IR, and emitted source. Any state-ordering bug found here must be fixed by
making ownership or phase order explicit, not by adding a new positional
special case.

### Ownership decisions

Verifying the groups against real reads and writes changed three name-based
guesses and forced one addition to the component list:

- The pseudo-registers `ax`/`bx`/`cx`/`dx`/`di`/`si` hold IR nodes, not machine
  words, so they read like expression state. They stay in `MachineState`
  because their lifetime is the emulated register's: a runtime-call template
  leaves a value in AX and the next handler consumes it from AX. `ExprState`
  owns operands whose lifetime is the expression being folded.
- `ds` and `ss_base` are segment-shaped names but are resolved once from `lay`
  during setup and never written by the dispatch loop, so `LayoutState` owns
  them.
- `pend_es`, `cint_round`, and `fp64_bridge` carry `pend_`/`fp` prefixes but
  are latched machine elements — the ES array-descriptor selector and the two
  x87 round trips — so `MachineState` owns them.
- `ImageState` was added for `exe`, `start`, `dia`, `main_start`, and `ops`.
  These are written once during setup and read-only afterwards. They belong to
  no mutable owner, and putting them in one would have made the partition
  claim false rather than merely incomplete.

Ownership is a total, disjoint partition of the persistent decode fields, and
`tests/tbx/test_state_parts.py` fails if a field gains a second owner or none.
A view refuses reads and writes for fields it does not own: an absorbed write
would leave the shared state stale with no error at the write site, which is
the failure class this chapter exists to remove.

### Status

Complete. Every decoder module reaches state through its ownership views:
`core.py` (setup, dispatch loop, `fp_dispatch`, `_finalize`), all five handler
modules, and `select_case.py`. They are listed in
`tests/tbx/test_migrated_modules.py`, which fails if one reaches around its
views or writes the operation index directly.

Consumption has a single committing path. `advance` takes a relative count,
`seek` an absolute stop for lookahead helpers that compute where they landed,
and `begin` installs stream, index, and cursor together so they cannot be
established out of order. Nothing outside `DecodeState` writes `k`, so the
cursor witnesses every operation the decoder crosses — which is what makes the
bounded history in a failure report trustworthy.

Three things the work surfaced that the plan did not anticipate:

- `reg_spills` and `block_if_addrs` were only ever assigned dynamically during
  setup and had escaped the field inventory entirely. The partition test found
  them; both are now declared and owned.
- `tests/tbx/test_gap_tools.py` built its handler states as `SimpleNamespace`,
  which accepts any field name and would have kept passing while a handler read
  the wrong owner. Those tests now construct a real `DecodeState`.
- Three sites read `state.k += 4 if indirect else 3`. Any rewrite that treats
  the increment as a literal silently turns the statement into a conditional
  expression that does not advance. It cost 61 test failures to find; a
  mechanical pass over this file has to match whole statements.

## Chapter 4 — Separate recognition from mutation

The most error-prone handlers currently match a byte-template suffix while
mutating pseudo-registers and statement state. Pure recognition makes the
accepted vocabulary visible and testable.

### Scope

Split selected handlers into a matcher and an applier. A matcher receives an
operation window plus immutable facts and returns a typed match with its
consumed range. The applier applies that match to `DecodeCtx` and emits the
same intermediate result as today.

Prioritize these five families:

1. compound-boolean tails and pending comparisons;
2. array operands and array-parameter frames;
3. SUB/DEF FN calls and procedure frames;
4. runtime-vector dispatch families;
5. floating-point folds and materialized tests.

### Deliverables

- A matcher result type that names the template, operands, polarity, and
  consumed range.
- Pure unit tests built from small operation tuples for each migrated family.
- Rejection tests proving near-miss templates remain fail-loud.
- Applier tests covering state effects separately from byte recognition.

### Invariants

Matchers do not mutate `DecodeCtx`, advance the cursor, or infer missing
layout facts from positional guesses. A matcher may accept only a calibrated
template already supported by the decoder or explicitly introduced with a
compiled fixture and oracle verification.

### Exit criteria

The five families have no mixed recognition/mutation path in normal decoding.
Their pure tests explain the accepted alternatives and rejection reasons, and
all existing fixtures remain byte-exact.

### Status

`TemplateMatch` is the shared result: every match names its template and the
operation range the claim rests on. That range is the *template's* extent, not
what the applier consumes — a boolean header is six operations wide even when
folding the expression runs much further. Family-specific subclasses add
operands and polarity. Matchers take either `(ops, index)` or an `OpCursor`;
the cursor form is read-only, and a test pins that matching leaves the index
and history untouched.

Migrated, each with accept and rejection tests over hand-built operation
tuples (`tests/tbx/test_matchers.py`, 42 cases, no fixture dependency):

1. compound booleans — `match_bool_term1`, `match_bool_bare_term1`,
   `match_bool_outer_and_group`;
2. array-parameter frames — `match_array_param_type`;
3. procedure frames — `match_proc_body`, `match_fn_result_readback`;
4. runtime-vector dispatch — `match_using_emit`,
   `match_using_chain_continues`;
5. materialized tests — `match_for_header`, `match_loose_for_header`.

Two things worth recording:

- `match_proc_body` replaces a bare `next()` that raised `StopIteration` when
  no `proc_ret` closed a body. It is now a no-match the applier reports as a
  fail-loud `ValueError`, which is the contract the rest of the decoder keeps.
- `match_loose_for_header` returns None on a stream too short to hold the
  template. The old code unpacked a three-operation slice and crashed. A
  truncated window is not this template; saying so is not a guess.

Not migrated, and why: the `shlsi` element-stride chain in `handlers/arith.py`
recognizes the array-operand template while *deleting* `into` operations from
the stream it is reading, so that every downstream offset in the handler stays
valid. Recognition there mutates its own input, which is exactly what this
chapter targets — but splitting it means either duplicating the shape walk or
changing what the operation stream contains, and neither is worth doing
without the byte-exact re-verification a semantic change requires. The
floating-point folds in `core.fp_dispatch` are likewise still mixed. Family 2
is therefore half migrated (parameter frames yes, element operands no) and
family 5 half (materialized tests yes, folds no); Chapter 4 is not complete
until both are done.

## Chapter 5 — Introduce a lossless decoded-event stream

The decoder currently decodes operations and folds structured source at the
same time. Separate those concerns by first recording what happened, with
addresses and provenance intact.

### Scope

Define `DecodedEvent` records for statement openings, expression/value
events, branches, runtime calls, procedure boundaries, line metadata, and
commit markers. Events must preserve the information needed to reproduce the
current IR, including physical addresses and unresolved jump targets.

The pipeline becomes:

```text
EXE bytes -> OpStream -> LayoutFacts -> DecodedEvents -> StructuredIR -> source
```

Initially, events are emitted alongside the existing statement list and are
checked for equivalence. Then make event replay the input to the existing
lifting path.

### Deliverables

- Immutable, address-bearing event types with a versioned internal schema.
- An event dumper and replay loader for ops goldens.
- Equivalence checks between legacy direct emission and event replay.
- Event-level fixtures for one ordinary statement, one expression, one
  branch, one procedure, and one codeless/metadata case.

### Invariants

The event stream is lossless with respect to current IR construction. Events
retain unresolved addresses until the control-flow pass resolves them. No
event consumer may inspect raw bytes or recover facts by re-reading an earlier
handler's mutable fields.

### Exit criteria

IR snapshots and emitted source are generated from replayed events, while the
legacy path remains available for comparison. Replaying an ops golden reaches
the same first failure and produces the same output as decoding the EXE.

### Status

The first seam recorded events in `_finalize`, built from the finished
statements after folding and canonical renaming, and replayed them straight
back into `Program`. That proved the schema round-tripped and nothing else.
It has been replaced.

Events are now recorded in `DecodeState.put`, at commit time, with the
physical address still unresolved — the boundary this chapter actually asks
for. They run *alongside* the existing path: folding is untouched and the
program is still built the old way. `Program.event_reconciliation` measures
how far the two have diverged, via `events.reconcile`, which matches by
equality in emission order and separates three outcomes — a committed
statement folding *absorbed* into a body, one it *rewrote*, and a program
statement it *synthesized* with no committed counterpart.

That measurement is the point of the slice, and it said the event stream was
not yet lossless (closed below, "Every statement now has an event"):

| corpus | events | matched | clean programs |
| --- | --- | --- | --- |
| `tests/fixtures/corpus` (1030) | 11799 | 10764 (91.2%) | 549/1030 |
| `wild/hits` (23 decodable) | 12217 | 1934 (15.8%) | — |

Run it with `python -m tbx.tools.dump_events --reconcile <exes>`.

Two causes, both found by writing the tests first:

- **`put` is not the point a statement becomes final.** Several handlers patch
  an already-committed statement in place — `stmts[-1] = ir.Locate(prev.row,
  prev.col, ax)` when the cursor argument arrives, and the same shape for
  INPUT/FIELD/PRINT chain targets. Pending chains flush straight into the list
  without passing through `put` at all.
- **Some statements are reconstructed at finalization, never committed.** DATA
  comes from the data pool and DIM from layout facts, so no commit describes
  them. Across the fixture corpus the synthesized statements are led by
  `SubDef` (189), `Dim` (175), `CallStmt` (42), `Data` (36) and `Tron` (36).

### Losslessness, and how it was reached

Chasing those paths one call site at a time would have meant getting twenty of
them right and keeping them right. Instead the statement list records itself:
`statement_log.RecordedStatements` is a `list` that appends a `StatementEdit`
for every append, insert, replace, delete, and splice, and `replay` rebuilds
the list from those edits. Unsupported mutators raise rather than pass through
unrecorded.

`_finalize` runs `replay(out.stmts.edits) == list(out.stmts)` as a decode-time
gate. It holds for all 1030 fixtures and all 28 decodable wild programs, so
statement-list construction is now lossless by construction rather than by
inspection — 16290 recorded edits across the fixture corpus (12213 append,
3828 splice, 117 delete, 75 replace, 57 insert).

The gate was verified to actually fail: sabotaging `replay` to drop one
statement makes a clean fixture raise. A guard nobody has watched fail is not
a guard, and this one had in fact been silently absent on its first wiring.

The two logs answer different questions and both are on `Program`:
`events` is what the decoder *decided*, with addresses unresolved;
`statement_edits` is what *happened to the list*, complete. Interpreting an
edit as a fold, a patch, or a reconstruction is Chapter 6's job — the log
deliberately does not editorialize.

Reconciliation costs 6–15% of decode time on the largest wild programs
(12–95 ms); the edit recorder and its gate add nothing measurable on top. Kept
eager per this plan's rule that reproducibility outranks throughput until
Chapter 7; revisit it there with a real figure rather than a guess.

### Every statement now has an event

The two causes above are closed, and each turned out to be a different *kind*
of arrival rather than a missing call to `put`:

- **A chain closes late.** A trailing-`;` PRINT, an INPUT#/READ target chain
  and a FIELD list have no flush vector, so `flush_pending` appended them
  directly. `commit` is now the one way into the list — `put` closes any
  pending chain and lands there, and `flush_pending` lands there too. 51
  appends corpus-wide.
- **A statement is revised after it is committed.** Two runtime calls make one
  statement: a LOCATE's cursor or shape argument, a FOR's real step against its
  provisional `Lit(1)`, a second DIM joining the first as a comma list.
  `PatchEvent` names the commit it supersedes, since a revision replaces a
  statement rather than adding one; the event it revises is found by identity,
  scanning back, and revising something nothing committed raises. 36 revisions,
  four of them revisions of revisions.
- **A statement is derived, not decoded.** DIM, DATA, OPTION BASE, COMMON and
  DEFtype come from array bookkeeping, the data pool and the error-trap line
  table. `ReconstructedEvent` accounts for them; replay skips it, because
  finalization runs after folding and the position it inserts at describes the
  finished program rather than the walk.

`committed` is the single place supersession is applied, and replay,
reconciliation and the graph all read through it — so a target the decoder
corrected is never read off the draft.

| | before | after |
| --- | --- | --- |
| statement events | 11799 | 11850 |
| synthesized | 756 | 436 |
| reconstructed | — | 239 |
| clean programs | 549/1030 | 702/1030 |

The 436 left are folding and lifting products: rebuilt SUB bodies, resolved
CALLs, TRON/TROFF lifting, and the structured forms. That divergence is what
Chapter 6's swap moves, and it is now the *only* one — no statement reaches a
decoded program without an event saying how it got there.

## Chapter 6 — Extract control-flow recovery

Control-flow recovery is the largest structural change and should happen only
after state, consumption, and events are stable.

### Scope

Build a `ControlGraph` from branch and boundary events. Move jump-target
collection, line-table recovery, codeless statements, trace hooks, procedure
boundaries, and block folding behind that graph. Expression handlers emit
branch events; they do not decide whether a branch is an IF, loop, CASE arm,
or procedure boundary.

The graph should preserve both physical addresses and statement/event
identity. Folding must update address ownership through graph operations rather
than relying on object identity or hand-maintained side tables.

### Deliverables

- A graph representation for nodes, branch edges, region boundaries, and
  source-line metadata.
- Separate passes for target resolution, region classification, and structured
  folding.
- Regression tests for inline/block IF, WHILE, DO/LOOP, SELECT CASE, SUB/DEF
  FN bodies, TRON hooks, and codeless DATA statements.
- A graph dump that explains why each branch became a structured construct or
  remained a raw jump.

### Invariants

Every target is resolved against the same address ownership rules as before.
Folding cannot lose a statement, metadata hook, or address when moving a node
into a body. A branch that cannot be classified remains explicit and fail-loud
according to the existing contract.

### Exit criteria

Structured IR is produced from the graph, and all current control-flow
fixtures pass unchanged. The graph dump can explain the historical classes of
failures where folding moved statements, dropped addresses, or misclassified
an epilogue as a statement.

### Status

The first task Chapter 5 left was to classify the 3828 splices and 117 deletes
in the edit log. They are now classified, and by the pass that made them rather
than by guessing from their shape.

`StatementEdit.origin` names the responsible pass. It is scoped, not passed:
`statement_log.editing(stmts, "fold_if")` labels every edit made while that
block runs, so a pass declares itself once at its own entry instead of every
call site remembering to. Nesting reports the innermost pass, which is what
makes a fold inside finalization read as a fold. A plain list is accepted and
ignored, so lift helpers stay callable with one in unit tests.

Attribution across the 1030-fixture corpus, 16290 edits:

| origin | edits | what it is |
| --- | --- | --- |
| *(none)* | 11979 (73.5%) | ordinary decode-time commit through `put` |
| `finalize` | 3234 (19.9%) | reconstruction from layout and pool facts |
| `fold_proc_body` | 411 (2.5%) | SUB/DEF FN body folded into its definition |
| `close_ifs` | 160 (1.0%) | inline IF bodies drained at their target |
| `select_case` | 142 (0.9%) | CASE arm folding |
| `fold_for_header` | 107 (0.7%) | three staged assigns collapsed into `ir.For` |
| `lift_*` | 148 (0.9%) | the structured-control lifts |
| `patch_for_step` / `patch_locate` | 20 (0.1%) | handler patching a committed statement |
| `dim_declaration` | 16 (0.1%) | DIM from layout facts |

Every non-commit edit is attributed;
`test_every_structural_edit_in_the_corpus_is_attributed` enforces that over the
whole corpus, so a pass added later that edits the list without declaring
itself fails immediately. Two fixtures were not enough to find the gap — they
missed 165 edits across eleven sites that only the full corpus caught, which
is why the test sweeps rather than samples.

`python -m tbx.tools.dump_events --edits <exe>` prints the classification in
order. This is Chapter 6's "graph dump that explains why each branch became a
structured construct or remained a raw jump", at the level the decoder
actually operates: an unattributed append is a decoded statement, and
everything else names the transformation and the pass behind it.

### The graph, built before the decisions

`ControlGraph.from_events` builds the graph from the commit-time event log
with targets still unresolved, alongside the existing `from_statements`
validation. `classify_branches` then reports what became of each committed
branch — `raw` when it survives as a jump, `absorbed` when folding moved it
into a body, `folded` when folding rewrote it — and attributes each one to the
pass responsible, taken from the edit log rather than inferred from the
branch's shape. `dump_events --branches` prints it.

Across the fixture corpus that classifies 321 committed branches: 185 raw, 97
folded, 39 absorbed, attributed to `close_ifs`, `fold_proc_body`,
`select_case`, `lift_while`, `lift_next`, `apply_exit_folds`,
`fold_loop_header` and `finalize`.

### Every branch is now recorded

The commit log did not contain every branch. 103 of the 151 fixtures with
structured control flow committed **no branch statement at all** — the
handlers recognised and folded those branches without ever committing one, so
the graph could not see a decision that was never recorded.

Handlers now *emit* a branch event where they open a frame:
`DecodeState.branch(frame, target=..., address=...)` records a `BranchEvent`
in the same ordered log as the statements. Emitting is deliberately separate
from committing — the statement list does not change, so no golden moves —
and `ControlGraph.from_events` turns those events into edges.

Instrumented: `open_tail_if`, the direct-flag inline IF, the head-tested loop
template, both SELECT CASE headers, all six FOR headers, and the two frames
`_lift_bool_tail`/`_lift_while` open. The lifts take `ifs`/`whiles` as plain
lists and cannot reach the decode state, so they take an optional `branch`
recorder alongside the `put`/`flush` callbacks they already had — which is how
the compound-boolean IF path was found at all.

Blind fixtures: **103 → 8**. Branch events across the corpus: 80 `if`, 90
`loop`, 26 `case`.

The remaining 8 are SELECT-only programs. A SELECT header's END SELECT is not
known when the header is recognised — the arms resolve it — so the event
records `target=None` and contributes a node but no edge. The first version
recorded the x87 temp displacement there instead, which the `--branches` dump
exposed immediately as an unresolvable `0x5c`. A guessed target is worse than
an absent one.

Reporting the improvement honestly took three measurements. The first said 103
to 40, because the after-count used a narrower structure predicate than the
before-count; re-run with the identical predicate it was 103 to 79, and only
after the lifts and FOR headers were instrumented did it reach 103 to 8.

### The construct is a table, not a handler's judgement

Recording the branches exposed why the decision could not simply be moved: the
graph does not carry enough to make it. An inline IF and a head-tested loop are
indistinguishable as edges — both branch forward with no condition, 76 and 90
times across the corpus. Nothing in the shape separates them.

What separates them is evidence the handler computed and discarded: whether a
jump back to the test address sits before the exit. So the branch event now
records the *template* it matched, and `control_graph.FRAME_BY_TEMPLATE` maps
templates to constructs in one place:

| template | construct |
| --- | --- |
| `inline_if_target`, `direct_flag_skip`, `bool_tail_skip`, `materialized_test_skip` | `if` |
| `bool_tail_loopback`, `poll_loop`, `for_header` | `loop` |
| `select_header` | `case` |

`frame_for` is fail-loud on an unmapped template: a new branch template must
say what it denotes rather than defaulting to the commonest construct.

`test_the_table_reproduces_every_handler_decision` derives the construct from
the recorded template for every branch in the corpus and checks it against
what the handler chose. Zero disagreements — which is the evidence that made
the swap safe to attempt.

`_lift_bool_tail` now performs it. It used to choose between `whiles.append`
and `ifs.append` from `_has_jmps_back` directly; it now names the template
from that same evidence and asks the table what it means. That is the
separation this chapter asks for, at the one site where the choice was
genuinely being made.

### The record locates every fold region

What is still coupled is *when* folding happens: handlers push onto `ifs`,
`whiles`, `dos` and `cases` as they decode, and those frames drive folding
immediately. Deferring that to a pass over the graph means the pass must find
the same regions from the record alone.

It can. `control_graph.predict_fold_starts` locates each inline-IF frame's
fold region by replaying the statement edits that preceded the branch in the
event stream; the length of the resulting list is where its body begins. That
matches the handlers' own `"idx": len(self.stmts)` bookkeeping on every one of
the 62 corpus programs that fold an inline IF.

Getting there needed one thing the record did not carry. A first predictor
counted the statements committed before the branch and agreed on 55 of the 62
— it missed the seven where an earlier fold had already shortened the list.
The two logs had no shared ordering, so "how long was the list when that
branch was recognised" was unanswerable. `StatementEdit.at_event` now records
how many events preceded each edit, which makes the interleaving exact and
takes the prediction to 62 of 62.

### Fold nesting, measured rather than feared

The last unknown was the ordering between nested constructs -- an inline IF
inside a CASE arm inside a SUB body. `StatementEdit.scope` now records the
whole pass stack rather than only the innermost, so containment is explicit.

Measured, that ordering is far simpler than it looked. Across the corpus only
**two** distinct nested fold paths occur, over 20 edits in total:

| nesting | edits |
| --- | --- |
| `select_case > close_ifs` | 12 |
| `finalize > apply_exit_folds` | 8 |

Nothing nests three deep. The reason is structural: slicing a
`RecordedStatements` returns a plain `list`, and several folds take a slice,
rebuild it, and splice the result back — `_fold_if(out.stmts[i0:], ...)` is the
common shape. The log therefore records the net effect of such a fold rather
than its internal steps, which is the right granularity for reproducing
behaviour and is why the observed nesting stays shallow.

### The swap was attempted, and the eager timing is load-bearing

With every input recorded and verified, the swap was tried directly: stop
folding inline IFs in the dispatch loop and fold once at the end. If the eager
timing were incidental, output would not move.

It moves. 92 tests fail, in three distinct classes:

- 28 unresolved jump targets. An inline IF that is the last statement of a
  SUB/DEF FN body skips to the epilogue, which is not a statement and never
  can be — `END SUB` carries no line number. The fold is what removes that
  target; defer it and the target has nothing to resolve against.
- ~100 output differences, from bodies that stayed open past the point a later
  fold snapshotted them. `select_case._fold_arm` documents this exactly: it
  calls `close_ifs` before snapshotting an arm because an inline IF closing an
  arm skips to the arm-close jmp (wild tbd73.exe, TBW73.INC:716).
- 6 trace-hook and line-table failures, where the fold's address retention into
  `stmt_addr` is what keeps body lines visible.

So `close_ifs` cannot be deferred on its own. Its two consumers —
`_fold_arm` and the `proc_ret` path — each require inline-IF bodies closed at a
precise point *during* decoding, and each requirement traces to a calibrated
wild-program behaviour rather than to convenience. Deferring one fold without
the others is not deferral but redistribution.

This is a negative result, and it is the useful kind: the next attempt should
move `close_ifs`, `_fold_arm` and the procedure-body fold together, against a
model where a region stays open until its enclosing construct closes it, and
should expect the epilogue-target and address-retention cases to be the two
that decide whether it works.

### Address ownership no longer rests on an id staying unique

The chapter requires that "folding must update address ownership through graph
operations rather than relying on object identity or hand-maintained side
tables". The side table was `stmt_addr`: a plain dict keyed by
`id(statement)`, holding no reference to the statement.

Folding discards statements constantly and CPython reuses the ids of freed
objects, so a statement created after a fold could land on a freed one's id and
inherit its address. Pinning every committed statement alive and re-decoding
the corpus changes no output, so nothing triggers it today — but that is a
property of which objects happen to be alive, not of the design, and the
symptom would be one wrong line number in one wild program.

`addresses.AddressOwnership` keeps the statement alive alongside its address,
so the id cannot be recycled while the claim stands. `pop` releases a claim
when folding moves an address to a rebuilt statement, which is the point the
id may safely be reused. Identity remains the key deliberately: two equal
statements on different source lines own different addresses, and equality
would merge them.

Writing by raw id is refused rather than shimmed — a raw id cannot keep its
statement alive, which is exactly the bug. Reads still accept one, since a
read cannot create a claim that outlives its owner.

### Region boundaries, and how far extents are recoverable

The chapter asks the graph to carry "region boundaries" alongside nodes and
branch edges. `RegionEvent` records a construct's extent in the same ordered
log, emitted at `proc_enter` with the body extent `match_proc_body` already
computes. The event stream now has three kinds — `statement`, `branch`,
`region` — and replay skips the latter two, since neither carries a statement.

That boundary matters because an inline IF closing a SUB body folds up to the
epilogue, which is not a statement and never can be. Measuring how far a fold
region is recoverable from the record:

| | inline-IF folds |
| --- | --- |
| extent predicted from statement addresses | 39 / 62 |
| end is a boundary no statement describes | 13 / 62 |
| region end known but the naive rule is wrong | 10 / 62 |

Region events took the unknown-end cases from 21 to 13. The remaining ones are
not a missing address but a missing *moment*: a region's end is the list length
when decoding reaches its boundary, and that instant is not derivable from
statement addresses alone. The fix has the same shape as the shared clock that
made fold starts exact — record when a region actually closes, rather than
trying to infer it afterwards.

Note this is the first measurement in the chapter that did not reach 100%. Fold
*starts* are exact at 62/62; extents are not, and the gap is specific.

### Recording the moment a region closes

The missing moment is now recorded. `ArrivalEvent` marks decoding reaching an
address a recorded branch targets, emitted from the dispatch loop before any
fold runs — including before `select_case.step`, which closes arms of its own.
The log itself decides whether an address is worth an event: it already knows
which addresses branches want, so nothing is taken from the handlers' frame
bookkeeping, and the emission site survives the swap.

An extent is then the statement list's length at that event, replayed from the
edits stamped up to it — the same construction that made starts exact.
Measured with one predicate before and after:

| | inline-IF folds |
| --- | --- |
| extent from statement addresses (corpus) | 26 / 62 |
| extent from the recorded arrival (corpus) | **62 / 62** |
| extent from the recorded arrival (wild) | **18 / 18** |

The 26 is the same address-only rule the 39 above reports; the difference is
that 39 counted a region-described boundary as located without computing a
position, and this predicate computes one for every fold. Two findings came out
of closing the gap:

- **Nested frames sharing an arrival need the fold's own arithmetic.** An
  inner region collapses to the one statement replacing it, so its enclosing
  region ends one past where the inner one began. They close innermost-first,
  the order the frame stack pops in. This is what the pass *does*, not
  something the record can be asked for.
- **A body ending in a pending chain closes after its own boundary.** Wild
  `be.exe` folds `IF ... THEN PRINT "Approximately ";` — a trailing-`;` PRINT
  with no flush vector, materialized only when `close_ifs` flushes it, one line
  after the arrival. So the arrival flushes first: the statement was decoded
  before the boundary and belongs inside the region. No fixture has this shape,
  and the wild corpus is the only reason it was found.

### The fold now reads the record, and a deferred pass exists

The swap has two halves — *what drives the fold* and *when it runs* — and they
are worth separating, because only the first can be proven byte-exact.

The first is done, for all three folds. Each construct that owns a body is
identified by the event that recognised it, and the body's start position is
the list length at that event, replayed from the edits:

| fold | event | recorded where |
| --- | --- | --- |
| inline IF | branch, with its condition and spelling | `open_tail_if`, two lifts, one core site |
| CASE arm / CASE ELSE | `case_arm` / `case_else` region, with its guards | `_begin_body`, the else transition |
| SUB / DEF FN body | `proc` / `fn` region | `proc_enter`, the DEF FN auto-open |
| SELECT CASE | `select` region, with its selector | END SELECT, where both ends are known |

The inline-IF frame goes furthest: it was a dict carrying the target, the
condition, the start address and the list position, and all four are in the
log, so it is now the branch event's `seq` and nothing else. A CASE arm's
region is recorded in `_begin_body`, where the body's start and the arm-close
jmp it runs to are both known and nowhere earlier. A DEF FN recorded nothing at
all before this — it is recognised by exclusion, as the first op in the
definition region with no frame open.

A CASE arm's guards, a SELECT's selector, and whether the bytes say an IF was
spelled multi-line all ride along with the region or branch that recognised
them -- each was decode state a pass reading the log could not see. An arm's
own extent is a moment like an inline IF's, since its arm-close jmp owns no
statement, so a region's end is now an address the log waits for and arriving
there is an event: `fold_pass.arm_regions` sizes 35 of 35 corpus arms and 67 of
67 in wild tbd73.exe from that alone.

Each frame keeps its old position purely as a cross-check: disagreeing raises,
and across both corpora it never has. Chapter 7 deletes them. Sabotaging the
derivation by one fails fold, SELECT and procedure tests, so all three guards
are watched to fire.

The second half is measured but not made. `fold_pass` folds inline IFs, CASE
arms and SELECTs from the committed statement stream, in commit coordinates,
touching no decode state; nothing calls it in the pipeline. It reproduces 76 of
the fixture corpus's 80 inline-IF folds and 388 of the wild corpus's 403 — same
conditions, same bodies, same nesting — and rebuilds all 26 corpus SELECTs and
13 of wild tbd73.exe's 16, guards, selector, arms and CASE ELSE included.

Constructs fold in the order they *close*: whatever finishes first is
innermost. That settles the ties too — an inline IF closing a CASE arm shares
the arm's arrival and goes first, which is what `_fold_arm` does by calling
`close_ifs` before it snapshots, and a CASE ELSE goes after the arms, so a
provisionally-opened else region that a real arm overwrote comes out empty and
becomes no CASE ELSE at all. Two behaviours had to be reproduced rather than
read: a fold must claim its new statement's address, since `_fold_body`
reconstructs an ELSE arm by looking one up for statements that are no longer
top level.

Every difference is another walk-time fold rather than a gap in the record:

- **4 in each corpus** fold a body that holds a `SELECT CASE`. The walk had
  already collapsed that SELECT into one statement before closing the IF around
  it, and no `SelectCase` is ever committed, so the record offers the deferred
  pass the arm bodies flat. The region is right; the contents are a fold that
  has not happened yet.
- **11, wild only**, sit in a list that `select_case` (7), the procedure-body
  fold (3) or a loop lift (1) had already spliced. Commit coordinates and list
  coordinates agree until one of those runs.

Which is "the three folds have to move together", made quantitative and
localized. A fold needs nothing from the walk except that no other fold has
moved the list under it -- and the three wild SELECT misses say the same thing
about a fourth family: `lift_while`, `lift_bool_do_tail` and the FOR/NEXT lifts
rewrite the list as they go too, and every one of those misses is an arm
holding a loop.

### What remains

Two things, in order:

1. Record the loop lifts' regions, the way the inline IF, the CASE arm and the
   procedure body were recorded, and fold them in `fold_pass`. They are the
   last walk-time fold family, and the three wild SELECT misses wait on them.
   What is left after that is that neither `SelectCase` nor `SubDef` is ever
   committed, so a pass cannot see inside one a fold has already built, and
   that a procedure's name and parameters live in `proc_names`/`proc_params`
   rather than in the log.
2. Then run all three after the walk, gated on the goldens and the wild-corpus
   report. The measured account of what breaks when they move separately is its
   specification.

## Chapter 7 — Remove the migration scaffolding

Only after the new path has survived the full corpus should compatibility
layers be removed.

### Scope

Delete forwarding properties, direct `k` mutation, obsolete mutable fields,
duplicate legacy folding paths, and comparison-only code. Keep stable public
interfaces and the fail-loud behavior. Update contributor documentation so new
handlers use the ownership, cursor, matcher, event, and graph APIs by default.

### Deliverables

- A final field and call-site audit showing no obsolete state access remains.
- Removal of compatibility adapters and dead tests.
- Updated decoder architecture documentation and replay-tool usage notes.
- A final performance measurement against the Chapter 0 baseline.

### Exit criteria

The full pytest suite, Ruff, representative oracle sample, and wild-corpus
report pass. Any fixture change is tied to an intentional semantic change and
has byte-exact verification. The decoder meets the following operational
definition of simpler: a failure report identifies the first diverging pass,
the owning state component, the rejected template, and whether the change is
in scan, layout, lift, control recovery, or rendering.

## Review and release gates

Land chapters as small commits, preferably one seam or family at a time. At
each commit, review the failure-corpus diff before reviewing implementation
details. A structural refactor is not complete if it merely moves a failure or
turns an unknown pattern into a guessed construct.

Before release, run the complete project checks and the representative oracle
sample in `docs/release-checklist.md`. Profile only after Chapter 7; diagnostic
reproducibility and byte-exact correctness take precedence over throughput
during the migration.
