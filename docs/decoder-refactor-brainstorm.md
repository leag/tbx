# Decoder refactor brainstorm

The decoder is correct enough to release, but its top-level loop is difficult
to reason about. `DecodeState` is a large mutable register file shared by scan,
lift, handlers, and control-flow recovery. A failure often depends on a field
written many iterations earlier, and the current state shape makes it hard to
tell which invariants a handler requires or establishes.

The goal for a future release is not to make the decoder more abstract. It is
to make state ownership, phase boundaries, and failure evidence explicit while
preserving the calibrated byte vocabulary and golden outputs.

## Current sources of complexity

- One state object mixes machine registers (`ax`, `bx`, `si`, `ds`), expression
  stacks, pending comparisons, procedure-frame bookkeeping, layout facts,
  control-flow frames, and output metadata.
- Handlers communicate through implicit conventions: a handler may consume
  several operations, leave a value in a pseudo-register, or set a pending
  field for a later handler.
- The dispatch loop is both a parser and an evaluator. It recognizes local
  byte templates while simultaneously folding expressions and structured flow.
- Lookahead is scattered across handlers. A failure can report the final
  mismatch without showing the template alternatives that were rejected.
- Recovery of source structure (line tables, trace hooks, codeless statements,
  SUB bodies) is interleaved with ordinary expression decoding.

## Design directions

### 1. Split state by ownership

Replace the monolithic state with explicit components, passed as a `DecodeCtx`:

```text
MachineState   registers, segments, stack temporaries, pending x87 state
ExprState      values, operands, pending comparisons, string temporaries
LayoutState    scalar/array slots, pools, descriptors, inferred types
ControlState   statement cursor, jumps, loops, IF/SUB/CASE frames
OutputState    statements, physical addresses, metadata, toggles, trace hooks
Diagnostics    cursor history, expected templates, rejected alternatives
```

Start with wrappers or nested dataclasses so behavior does not change. The
first win is discoverability: a handler should declare which component it
mutates, and unrelated fields stop appearing as ambient global state.

### 2. Make operation consumption explicit

Introduce an `OpCursor` with `peek`, `take`, `expect`, `mark`, and `rewind`.
Handlers return a small result rather than mutating `k` directly:

```text
Handled(next_cursor, effects)
NoMatch(cursor)
DecodeError(cursor, expected, evidence)
```

This centralizes bounds checks and operation windows, makes lookahead visible,
and allows failures to print the exact bytes/ops considered by a template.
During migration, adapt the cursor to the existing op list and retain the
current handler signatures.

### 3. Separate recognition from mutation

Refactor complicated handlers into two steps:

1. a pure matcher that returns a typed template plus consumed range;
2. an applier that updates the relevant state component and emits IR.

This is especially valuable for compound booleans, array access, procedure
frames, and runtime dispatch families. Matchers can be unit-tested with small
op tuples, without constructing a complete EXE or `DecodeState`.

### 4. Use typed intermediate values

Replace loosely typed pseudo-register fields (`ax: Any`, `pend_cmp: Any`) with
small tagged values:

```text
Value = IntValue | FloatValue | StringValue | AddressValue | BoolValue
PendingCompare(lhs, rhs, source_kind, polarity)
ArrayRefValue(slot, rank, element_type, index_values)
```

The type should carry provenance (DGROUP slot, BP offset, source address) so
later handlers do not rediscover it from names or displacement guesses.

### 5. Split the pipeline into committed passes

Keep the existing scan/layout/lift phases, but make their boundaries real:

```text
bytes -> OpStream -> LayoutFacts -> DecodedEvents -> StructuredIR -> source
```

`DecodedEvents` would be a lossless, address-bearing statement/event stream.
Structured control-flow folding would consume events without also decoding raw
register templates. This permits replaying later passes from an ops golden and
reduces debugging to the earliest pass that diverged.

### 6. Make control-flow recovery its own subsystem

Move jump-target collection, line-table recovery, codeless statements, trace
hooks, and block folding behind a `ControlGraph`. Expression handlers should
emit branch events; they should not decide whether a branch is an IF, loop,
CASE arm, or procedure boundary. This is the largest payoff, but should follow
the state split and event stream work.

### 7. Improve diagnostics before changing semantics

Every failure should include:

- EXE/file offset and op cursor position;
- the last 8–16 consumed operations;
- the current state component relevant to the matcher;
- candidate template names and why each was rejected;
- the source fixture/probe, when known.

Add a replay tool that loads an ops golden, runs one pass, and stops at a chosen
address. This makes wild-gap investigation independent of the oracle.

## Suggested migration order

1. Add invariant checks and structured diagnostics without changing APIs.
2. Introduce `OpCursor` as a compatibility wrapper around `ops` and `k`.
3. Group `DecodeState` fields into nested components, keeping forwarding
   properties temporarily for handlers.
4. Extract pure matchers for the five highest-churn families: boolean tails,
   array operands, SUB frames, runtime vectors, and FP folds.
5. Add the lossless `DecodedEvents` stream and move statement emission behind it.
6. Extract `ControlGraph` and structured-flow folding.
7. Remove compatibility properties and obsolete mutable fields only after the
   full fixture, snapshot, wild-probe, and oracle suites stay unchanged.

## Guardrails

- Do not broaden the accepted byte vocabulary during a structural refactor.
- Keep `tests/fixtures/ops` as the scan contract and `ir_snapshot.txt` as the
  lift contract; regenerate only for intended semantic changes.
- Require a before/after failure corpus report for each migration step.
- Land changes in small commits that can be bisected and reverted.
- Treat performance as secondary to reproducible diagnostics; profile only
  after the new boundaries are stable.

## Success criteria

A future contributor should be able to answer, from one failure report:

1. which pass first diverged;
2. which state component owned the missing fact;
3. which template matcher rejected the bytes; and
4. whether the fix changes scan, layout, lift, or only rendering.

That is a better definition of “simpler” for this decoder than merely reducing
the number of lines or classes.
