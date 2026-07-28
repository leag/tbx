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
