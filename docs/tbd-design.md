# `tbd` fact-engine design

This document is normative for new `tbd` analysis work. `tbd` is a compact,
best-effort analyzer: it should recover increasingly useful IR without copying
the calibrated, fail-loud architecture of `tbx`.

## Goals

- Preserve every decoded byte and the evidence behind each conclusion.
- Improve monotonically as independent passes discover new facts.
- Represent uncertainty instead of choosing an unsupported interpretation.
- Keep the engine ordinary, dependency-free Python.
- Keep compiler-specific knowledge in small profiles and signature tables.
- Produce useful partial IR for unknown, damaged, or only partly supported code.

`tbd` does not promise byte-exact source reproduction and does not import the
`tbx` decoder or emitter. `tbx` remains the calibration and comparison oracle.

## Pipeline

```text
image bytes
    -> recursive instruction discovery
    -> immutable evidence IR
    -> monotonic fact passes to a fixed point
    -> semantic operation IR
    -> source-shaped statement IR
    -> final canonicalization
```

Instruction discovery runs once. Semantic passes may run repeatedly, but they
read the same evidence and only add facts. Operations and statements are views
built from the resulting fact set; they are not the storage for analysis state.

## Required design choices

### 1. Evidence is immutable

Decoded instructions, raw bytes, blocks, and cross-references are never replaced
by a higher-level interpretation. A lift records a fact that refers back to its
source addresses. Merging instructions for display must not discard the original
nodes.

### 2. Facts grow monotonically

A pass may add a new fact or stronger support for an existing fact. It must not
delete evidence or make correctness depend on a previous pass destructively
rewriting an operation. Re-running a pass with unchanged inputs is idempotent.

A minimal representation is intentionally plain:

```python
@dataclass(frozen=True)
class Fact:
    kind: str
    subject: tuple[object, ...]
    value: tuple[object, ...]
    evidence: tuple[int, ...]
    confidence: str
```

Fact fields must remain hashable so the store can be a Python `set[Fact]`.
Addresses are the stable identity for instructions, memory cells, branch
targets, and statements until final naming.

### 3. Passes are small and pure

The pass interface uses one immutable evidence bundle:

```python
def analyze(evidence, facts) -> Iterable[Fact]: ...
```

A pass:

- recognizes one mechanism;
- returns facts instead of mutating shared state;
- is deterministic and idempotent;
- preserves provenance addresses;
- treats an unrecognized shape as no result, not an exception;
- emits a diagnostic fact for malformed or conflicting evidence when useful.

Pass order may improve speed but must not change the final fixed point.

### 4. Ambiguity remains explicit

Several layout, type, signature, or control-flow candidates may coexist. A
semantic view selects a value only when one candidate has uniquely stronger
support. Incompatible equally supported candidates produce an unresolved node
with their evidence; they are not resolved by list order or a fixture-specific
default.

Confidence describes the kind of support, using a small ordered vocabulary:

```text
candidate < structural < signature < anchored
```

Repeated independent evidence may strengthen support. A confidence label never
substitutes for provenance.

### 5. Mechanism is separate from compiler knowledge

The engine owns discovery, the fact store, fixed-point iteration, candidate
resolution, diagnostics, and IR construction. A compiler profile owns runtime
vectors, byte signatures, layout constraints, and naming conventions.

Turbo Basic 1.0/1.1 is the first profile, not a collection of conditions spread
through the engine. Adding a profile must not require changing the fixed-point
machinery.

### 6. Evidence IR and semantic IR are distinct

The evidence view contains instructions, blocks, xrefs, raw bytes, signatures,
and facts. It answers “why did the analyzer conclude this?”

The semantic view contains expressions and statements such as `Assign`,
`Print`, and `IfGoto`. It may be incomplete. Every semantic node refers to the
facts and addresses that justify it.

Unknown evidence remains visible even when neighboring instructions lift
successfully. An unsupported region must not prevent unrelated regions from
producing semantic IR.

### 7. Canonicalization is last

Variable renaming, commutative operand ordering, cosmetic type spelling, and
source formatting happen only after semantic facts stabilize. Earlier passes
use address-based identities such as `slot(0x128)`, never inferred source names.

Canonicalization may make two equivalent results easier to compare, but it must
not create semantic facts or hide ambiguity.

## Fixed-point execution

The intended driver remains small:

```python
facts: set[Fact] = set()

for round_number in range(limit):
    additions = {
        fact
        for analysis_pass in passes
        for fact in analysis_pass(image, instructions, frozenset(facts))
    }
    unseen = additions - facts
    if not unseen:
        break
    facts.update(unseen)
```

Each round records its pass name, additions, and total fact count. Reaching the
round limit returns the best available IR with a diagnostic; it does not fail.

## Pass families

The expected analysis families are:

1. Compiler and runtime signature recognition.
2. Local register and emulated FP-stack interpretation.
3. Layout candidates and memory-role classification.
4. Constant, string, slot, and type facts.
5. Runtime-call summaries and argument recovery.
6. Branch conditions and control-flow regions.
7. Source statement reconstruction.
8. Final naming and expression canonicalization.

This is a dependency outline, not a mandatory execution order. Fixed-point
iteration connects the families when one pass exposes evidence for another.

## Failure behavior

Unknown bytes, unsupported templates, conflicting candidates, truncated data,
and exhausted limits produce opaque nodes or diagnostics. They do not raise from
normal analysis. Programmer errors and invalid API arguments may still raise.

No pass may invent a source construct merely to avoid an unknown region. Partial
IR is preferred to an attractive unsupported guess.

## Comparison and calibration

Tests may decode the same fixture with `tbd` and `tbx`, but production `tbd`
code must not import `tbx`. Comparisons should check progressively stronger
properties:

1. statement count and kinds;
2. branch targets and region structure;
3. literal and variable identity;
4. expression equivalence after canonicalization;
5. exact typed IR where both analyzers claim the same semantics.

A mismatch is evidence for a missing or ambiguous fact. It is not permission to
special-case a fixture name, address, or byte sequence without a reusable
mechanism.

Run the corpus-wide comparison with:

```sh
uv run python -m tbx.tools.compare_tbd_ir tests/fixtures/corpus
```

The report distinguishes recovered statement coverage, aligned statement kinds,
whole-file kind agreement, and exact canonical trees. Exact-tree counts include
only files made entirely of migrated fact-IR statement kinds whose statement
sequences already align; unsupported constructs therefore remain coverage gaps
instead of being mislabeled semantic mismatches.

## Migration from the current implementation

The existing iterative rewriters are a working prototype. Migration should be
incremental:

Current status: `Program.facts` and the monotonic fact runner are active beside
the legacy operation rewriters. Instruction, signature, basic-block, and xref
facts retain discovery provenance. Direct memory accesses now feed an anchored
pool-layout fact and integer, single-precision, and string constant facts.
The anchored boundary also produces address-stable scalar-slot and type facts.
Block-local register and emulated FP-stack interpretation produces value,
store, update, and comparison facts with complete instruction provenance.
Fully resolved stores and updates produce anchored source-shaped assignment
facts; unresolved memory identities deliberately produce no semantic guess.
Complete runtime PRINT chains likewise produce anchored semantic facts, while
an item without its matching flush remains only runtime and expression evidence.
`Program.fact_operations` now materializes migrated assignment and PRINT facts
directly into operation IR. Conditional branch pairs and their resolved operands
now produce `IfGoto` facts and operations as well. `Program.operations` remains
the legacy compatibility view until the remaining runtime consumers migrate.
Recognized source statements and complete DELAY loops are also additive facts;
`Program.fact_statements` reconstructs statement indexes and branch targets only
from the fact-built operation view. `Program.canonical_statements` is a final,
non-destructive view that assigns stable source names and orders commutative
expressions; the address-bearing fact statements remain unchanged.

1. Add `Fact` and a fact store alongside `Program.instructions`.
2. Port constant-pool, slot, and symbolic results to additive facts.
3. Build current `Program.operations` from evidence plus facts.
4. Port runtime and control-flow lifts, retaining their current output shapes.
5. Stop destructive operation rewriting once all consumers use facts.
6. Move Turbo Basic tables and layout rules behind a profile boundary.
7. Add final variable naming and expression canonicalization.

Each migration step must preserve forgiving behavior and keep the existing
`tbd` fixture comparisons passing.

## Acceptance criteria for a new lift

A new lift is complete when it:

- adds reusable facts from explicit evidence;
- remains silent on unsupported shapes;
- retains provenance and competing interpretations;
- has a focused fixture or hand-built operation test;
- improves at least one semantic comparison without degrading existing ones;
- keeps `tbd` independent of `tbx` at runtime;
- satisfies the project complexity and lint checks.
