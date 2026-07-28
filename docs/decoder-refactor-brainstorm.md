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

That measurement is the point of the slice, and it says the event stream is
not yet lossless:

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

### The gap that remains

The commit log does not contain every branch. 103 fixtures end up with
structured control flow while committing **no branch statement at all** —
`t1_ifblockselect` produces a block IF and a SELECT CASE from branches the
handlers recognised and folded without ever committing one. The graph cannot
show a decision that was never recorded.

That is precisely the change this chapter asks for and has not yet made:
expression handlers must emit branch events instead of deciding whether a
branch is an IF, a loop, a CASE arm, or a procedure boundary.
`test_some_structure_is_built_from_branches_that_never_commit` pins the gap
and fails once they do, which is the signal the graph can take over.

So the remaining work is now specific rather than architectural: make the
handlers that currently fold in place — `close_ifs`, `select_case.step`, the
inline-IF and loop-header paths — commit a branch first and fold second. Every
transformation they perform is already recorded, named, and replayable, so
each one can be moved and checked against the old behaviour edit by edit
rather than by diffing final source.

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
