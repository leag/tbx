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
`tbx` decoder or emitter. `tbx` remains the calibration and comparison oracle,
and its already-calibrated operation vocabulary and pure matcher decisions are
ported into small `tbd` fact passes instead of being independently rediscovered.

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

Near CALL/JMP displacements are normalized in the compiler's 16-bit code
segment. When a wrapped forward jump skips physically present compiled source,
discovery records the fallthrough as an `orphan` cross-reference and analyzes
it as an additional root. Raw inputs without a compiler profile retain ordinary
recursive reachability and do not acquire speculative orphan roots.
Compiler-profile procedure entry and return templates are decoded before their
component x86 instructions. This keeps `END SUB` distinct from source RETURN;
near calls, and far calls whose target is not a procedure entry, can then add
GOSUB facts with stable CFG targets while raw RET/RETF instructions add RETURN
facts.
Targeted RETURN has two separate signatures: the event-safe runtime-vector form
contains its jump inside one instruction, while an ordinary GOSUB frame uses an
adjacent `ADD SP,2` and jump pair. Both add a RETURN fact only when the complete
template is present, and retain the jump target for final statement-index
resolution.
RESUME likewise remains phase evidence until its `RESUME_BEGIN` dispatch is
immediately followed by a complete bare, NEXT, or jump tail. The pair adds one
source fact and retains a jump target for final index resolution. A profiled
RESUME jump also makes its physical fallthrough a discovery root: the compiler
may retain unreachable source after the transfer, and the adjacent prefix is
the positive evidence that distinguishes this from a generic unconditional
jump. A truncated prefix or unrelated tail adds no RESUME fact or orphan root.
Profiled stack-check GOSUB and RETURN vectors are complete source-control
instructions: the checked call owns its four-byte target payload, while the
checked return is a two-byte terminal. Dynamic ON GOTO/GOSUB dispatch tables
likewise register every embedded target plus the out-of-range fallthrough as
CFG edges, so adjacent one-byte targets remain independently discoverable.
Bare RUN is classified only from the profile's entry-jump spelling; its jump
target is control evidence and its physical fallthrough is an orphan discovery
root because the compiler retains following source such as END. Truncated or
out-of-image checked-call payloads remain source-less evidence. When a 1.0
entry jump is immediately preceded by `RESUME_BEGIN`, that stronger enclosing
signature owns the jump and suppresses a separate RUN fact.
The stack-room guard emitted by the compiler's stack-check toggle is one
source-less profiled instruction: `cmp sp,limit; jae skip; mov ax,7; ERROR`.
Only the complete 12-byte template is claimed. Its embedded ERROR dispatch is
not a source ErrorStmt; an authored ERROR outside that exact guard remains a
normal statement, while truncated or unprofiled bytes remain structural.
Framed SUB definitions similarly require a procedure-entry signature and one
procedure-return signature before the next entry. Their compiler skip jump,
when present, supplies the declaration address. A forward skip whose physical
successor decodes as the procedure-entry signature opens that otherwise
unreachable body as a separate discovery root; this covers both main-code
fallthrough into trailing declarations and branches to a SUB declaration line
without treating ordinary forward jumps as reachable fallthrough. Calls
targeting a recovered entry and semantic body facts inside the complete region
then form a nested source view without consuming any of that evidence. A
nonzero return-frame pop is retained as unresolved parameter and argument
metadata until independent frame facts can distinguish caller arguments from
procedure-local storage.
An unframed `$INLINE` SUB requires three independent pieces of compiler
evidence: a declaration skip jump whose fallthrough is the entry, a later far
call to that entry, and the compiler-appended bare RETF immediately before the
skip target. If the bytes also imitate a framed procedure, the appended RETF
must extend past the decoded frame return; the byte-identical tail stays framed
unless a complete instruction sequence known to be unspellable in BASIC is
present. The calibrated sequence is `mov al,imm8; out imm8,al`, never a bare
opcode search. The enclosed bytes become one opaque Inline statement and
remain byte-preserved; other apparent statements covered by that region stay
out of the source view. The call and definition become ordinary procedure
facts, suppressing false GOSUB/RETURN readings of the far call and appended
RETF. A `RET imm16` is likewise structural control, not a source RETURN: source
RETURN signatures are bare RET/RETF, checked RETURN, or one of the complete
targeted-return templates.
TRON trace hooks are also profile instructions, not a two-byte runtime call
followed by ordinary x86: their embedded line word is part of the immutable
four-byte signature. A hook run positively establishes a codeless TRON before
its first traced statement. An unhooked semantic statement between two hooks,
with no control-transfer instruction in that byte interval, establishes TROFF
and the next TRON; the same evidence after the final hook establishes TROFF.
A complete final `trace hook; END` adjacency establishes a top-level tail even
when an earlier block IF contains control transfers. Other controlled regions
retain the whole-region guard until their nested source structure can own a
TROFF fact instead of flattening it into an incorrect top-level statement.
Complex or single-hook shapes that do not prove a boundary remain unresolved.

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
Scalar slot validation follows the compiler's two-byte packing unit and each
evidenced value kind's actual width, so mixed integer and four-byte string or
numeric slots need not begin on the same four-byte grid. An address already
anchored inside a static array remains an array element and is not also
invented as a scalar slot.
The pool sentinel is accepted at its unique evidenced file position rather than
at a fixed distance from EOF: numeric payload width changes the trailing file
distance, while multiple sentinels leave layout unresolved.
Block-local register and emulated FP-stack interpretation produces value,
store, update, and comparison facts with complete instruction provenance.
Direct string-stack push/store pairs now produce string memory-role and store
facts as well; incomplete or interrupted pairs remain unresolved. Turbo Basic
1.0 dispatcher subs and service vectors are normalized by a compiler profile
before any fact pass matches them.
The profile separately names complete single-dispatch source statements and
runtime phases. A complete dispatch may add a source-statement fact; phases
such as DIM, READ, DATA, and WRITE components remain signature evidence until
a pass proves their whole source construct. Equivalent compiler spellings,
including bare and static variants, normalize to the same source kind rather
than becoming synthetic `SubXX` statements. Inline option bytes, relative
targets, and dynamic target tables belong to the dispatch instruction itself;
discovery consumes the entire evidenced signature, while a truncated payload
stays structural and cannot add a semantic statement.
The profile also owns the DEF SEG compiler cell. Turbo Basic 1.0's complete
direct immediate store, 1.1's FP-expression dispatch, and both dialects' DS
restore instruction add the same source fact with an explicit value or bare
reset. The same bytes without a matching profile, a truncated store, or an
unresolved FP expression remain structural rather than producing a partial
DEF SEG statement.
The same profile names direct emulated-FP memory widths. Long-integer and wide
loads, stores, folds, and comparisons therefore retain their 32- or 64-bit
memory role, and finite pooled values can support assignments and expressions
without replacing the underlying instruction evidence. Direct folds preserve
the compiler's memory/stack source ordering before final equivalence
normalization.
Validated static-array descriptors now produce anchored layout facts without
turning array storage into constants. Those facts recover codeless static
`DIM` statements in source order, including explicit lower bounds, and resolve
constant element addresses to array references while leaving unsupported
indexing unresolved.
The string descriptor immediately below the anchored pool (`pool_base - 4`) is
the compiler's canonical empty string. It becomes an empty-string constant, not
a scalar slot; INPUT also uses that same descriptor as its no-prompt sentinel.
Complete string concatenation stacks produce ordered binary-expression facts;
canonicalization preserves that order instead of treating string `+` as numeric
commutative addition.
Fully resolved stores and updates produce anchored source-shaped assignment
facts; unresolved memory identities deliberately produce no semantic guess.
Assignment resolution caches repeated address and expression identities inside
one pure pass, so large compiler-generated runs remain linear without changing
the immutable fact inputs or emitted provenance.
Complete runtime PRINT and LPRINT chains likewise produce anchored semantic
facts, with the runtime mode deciding their distinct source kinds. An item
without its matching flush remains only runtime and expression evidence.
An unresolved earlier item prevents a suffix of the same chain from becoming a
statement in an early fixed-point round; later facts can therefore complete the
whole PRINT without leaving a stale partial statement behind.
An additional consecutive printer flush is a complete empty LPRINT statement:
the first B9 has already closed the preceding chain, so every directly adjacent
B9 after it adds one empty statement fact with both flushes as evidence.
USING clauses are reusable reference facts over the resolved format, every
CB/CC value emit, intervening TAB/SPC items that lead to another emit, and the
matching console/file/printer leg. A mode-specific flush makes a standalone
newline `PrintUsing`; the printer's following runtime commit makes its
no-newline form. File mode reuses the independently resolved `[0060]` channel
store. Directly preceding ordinary items close as a separate no-newline PRINT
or LPRINT. Two clauses with no intervening commit or flush instead remain
ordered items of the one outer chain.
File PRINT chains require the uniquely resolved adjacent store to the compiler's
0x60 channel cell and retain that channel instead of a generic file-mode label.
For an empty file PRINT, that store followed immediately by the file flush is
the complete statement signature; a flush without the store remains runtime
evidence only.
PRINT item chains retain intervening mode-specific separator calls and their
provenance rather than dropping the items before a comma-zone advance.
Immediate TAB/SPC controls are ordered items in the same chain for console,
file, and printer modes. Their complete `mov ax,imm; runtime` pair becomes a
call-shaped expression with both instruction addresses as provenance. The
compiler's complete FP-expression-to-AX bridge is also accepted when its store
fact, reload address, and resolved source all agree. Any other unresolved
control remains a chain boundary, preventing a trailing suffix from becoming a
partial statement.
WRITE uses the same immutable expression and string evidence but keeps its own
item and separator phases. A console or file WRITE fact requires every item,
the mode-specific flush, and, for file mode, the immediately preceding resolved
`[0060]` file-number store; incomplete chains remain phase evidence.
LSET and RSET share another complete string scaffold: resolved source and
target descriptors, the compiler's `ES=0x96` field-segment setup, and the final
A4/A5 mode vector. Only the whole contiguous template adds a justified-assignment
fact; the source store and slot evidence remain independent.
FIELD item scaffolds add string memory-role facts for their descriptor targets,
allowing the ordinary slot pass to anchor names. A complete consecutive item
run plus its immediately preceding resolved file-number store then adds one
FIELD fact; missing descriptors or unresolved targets remain structural.
Scalar MID$ assignment similarly requires one of its two complete runtime
scaffolds. The AE form carries a start expression and an omitted length; the AF
form stages the start in BX and carries a separately resolved length expression.
Both require resolved source and target string descriptors plus the adjacent
relocated-DGROUP `mov DX,imm; mov ES,DX` pair. The immediate segment value is
deliberately not fixed because link layout changes it. A recognized scaffold
adds a string write role for its scalar target, while only fully resolved
operands add the anchored MID$ statement fact. The calibrated three-argument
static-array form consumes a shared string array-address fact before applying
the same ES setup and AF ABI; the MID$ pass does not repeat index or layout
recovery.
Scalar SWAP is a complete 24-byte inline signature: two low-word
load/exchange/store triples followed by the corresponding high-word triples.
Those component operations remain instruction evidence but do not create six
false integer memory roles. When independent facts anchor both four-byte base
slots, the signature adds one SWAP statement with all six instruction addresses
as provenance. Static numeric array SWAP is a separate composition: reusable
array-address facts own the index conversion, element width, and static layout;
the SWAP pass joins two such facts only across the compiler's DS-save/ES-restore
pair and the complete one- or two-word exchange tail. The mixed scalar/static
string-array form likewise consumes an array-address fact, while a whole
two-word descriptor matcher claims its integer-looking component operations so
they do not pollute the scalar's string type. Dynamic string and DOUBLE arrays
reuse runtime-array address facts and require the calibrated ES-save/DS-alias
sequence, every exchanged descriptor/value word, and the final DS restore.
LOCATE groups its independent runtime legs before adding a fact: CF carries
row/column (with 0x8000 as the compiler's omitted-row sentinel), D0 carries the
optional cursor flag, and CE carries cursor start/stop. A shape leg closes the
statement itself; shorter forms require a following instruction that cannot
begin an extension, or another complete row/column leg, as positive boundary
evidence. An unresolved or truncated extension therefore cannot leave a stale
partial LOCATE fact.
The calibrated string-length column form is a separate complete template:
row in AX, a resolved string descriptor pushed into LEN, row staged in BX,
then `neg ax; add ax,[constant]` before the LOCATE dispatch. It becomes the
source subtraction `constant - LEN(string)` only when all eight operations
are contiguous and both operands resolve uniquely.
Rank-1 INTEGER element reads are likewise owned by array-reference facts. The
same pass translates both the static DS-relative template and the far
`COMMON` template anchored by a runtime-array layout fact; a runtime-grid fact
anchors typed scalar index slots when that form has no static pool boundary.
Two adjacent reads become LOCATE row/column operands only when the second
access contains the compiler's `mov bx,ax` row-preservation shuttle and is
immediately followed by the LOCATE dispatch. The LOCATE pass never repeats the
index, width, or array-layout calculation.
Computed float, double, and string loads similarly extend an array-address fact
through the single calibrated load/push operation. Runtime PRINT consumes that
array-value fact exactly like a scalar expression; it does not inspect the
index chain, element width, or static/runtime layout.
Computed array-store facts likewise own their whole target, including the
runtime string form's descriptor displacement. The assignment pass only joins
a uniquely adjacent numeric expression or string push to that resolved target;
input and READ producers cannot be mistaken for assignments.
READ groups consecutive DATA_NUMBER and DATA_STRING phases into one target
chain. Direct scalar stores, the shared FP-to-INTEGER bridge, and shared
computed-array store facts all resolve through their owning passes. Any chain
containing a numeric target requires the final statement-commit call; a
string-only chain closes at its last complete store. Every target must resolve,
and an incomplete following phase suppresses the whole statement rather than
exposing a valid-looking suffix.
Console INPUT uses its inline prompt descriptor and flags as the chain header.
The low six flag bits give the exact number of additional targets, per-position
high bits distinguish numeric from string targets, and 0x40/0x80 retain the
prompt separator and leading semicolon. A fact requires exactly that many
consecutive direct numeric or string target items, a final commit for any chain
containing numeric input, a resolved literal prompt (or the profiled no-prompt
descriptor), and resolved scalar destinations. Integer scratch conversion,
frame-relative targets, and computed arrays remain separate mechanisms rather
than becoming partial INPUT statements.
Scalar INPUT # uses the analogous numeric and string target items, preceded by
one uniquely resolved file-number store in the compiler cell at 0x60. Numeric
items require the final commit; string-only chains require a following boundary,
and any incomplete next phase suppresses the whole statement. INTEGER targets
reuse the console INPUT pass's calibrated FP-to-INTEGER scratch bridge, with
the file-input phase as the only parameter. Computed-array targets likewise
reuse array-reference facts: the array pass owns the descriptor span,
column-major subscript accumulation, element-width scaling, and near/far
terminal store, while INPUT # only supplies the source phase and groups the
resolved targets.
The same ownership applies to ordinary INTEGER element assignments and reads.
The array pass recognizes the compiler's paired `mov bx,ax` / `mov ax,bx`
preservation around index conversion, names the complete store, and carries a
subsequent `mov ax,[si]` through the exact integer-to-FP print bridge. Assignment
and PRINT consumers use those reference facts rather than decoding the index a
second time.
The INTEGER terminal vocabulary also composes `add`, `sub`, and `imul` element
reads with the AX expression preserved across index calculation. Scalar stores
and complete compare/commit/branch/jump conditionals consume that composed value
or address fact; an incomplete control tail remains structural.
FP element terminals follow the same split: array-address facts own runtime
lower-bound normalization and near/far addressing, array-value facts compose
the calibrated `fold [si]` operation, and assignments or PRINT consume the
result. This covers static and COMMON arrays without either consumer learning
descriptor layout.
OPEN requires one of two complete contiguous scaffolds. The comma form stores
the immediate file number at 0x60, pushes the resolved filename and one-character
mode strings, loads the immediate record length in AX, and dispatches. The
`FOR ... AS` form instead pushes the filename first and constructs its
one-character mode in the compiler's short-string cell before the same file
number, record-length, and dispatch tail. Record length 128 canonicalizes to the
omitted default. A slot-shaped filename also needs independent earlier write
evidence, which keeps a misanchored literal descriptor from becoming a plausible
variable. A missing or unresolved leg leaves the whole OPEN structural.
Dedicated CLOSE facts preserve the distinction between bare sub 16 and numbered
sub 18. A numbered channel requires either an adjacent immediate AX load or the
complete typed FP-source/integer-scratch/AX-reload bridge used for an expression;
the generic profile statement no longer invents an operandless CLOSE when that
source is unresolved.
COLOR and SCREEN facts likewise require every cell selected by the dispatch's
presence mask, in source-operand order, immediately before the commit. COLOR
accepts its calibrated immediate and typed-FP-to-AX store forms; SCREEN is
limited to the immediate stores witnessed across its calibrated masks. Missing,
misaddressed, dynamic, or truncated SCREEN cells remain structural rather than
producing a partial statement.
FILES facts preserve the distinct bare dispatch and require the complete
adjacent string-push scaffold for a filespec. An unresolved descriptor or a
missing setup leg leaves the specified form structural.
The same complete string-push scaffold supplies the sole operand for CHDIR,
DATE$/TIME$ assignment, DRAW, ENVIRON, KILL, MKDIR, PLAY, RMDIR, and SHELL;
none becomes a source statement from its dispatch alone. An empty-string
reading that also fits an unwritten string slot remains unresolved; this
prevents an uninitialized variable from becoming a plausible literal.
Dedicated trap-control facts retain the profiled event and ON/OFF/STOP mode.
COM and KEY additionally require their adjacent immediate AX event number;
unnumbered PEN, PLAY, STRIG, and TIMER forms use the dispatch signature alone.
Trap-handler installation likewise keeps the profiled event and relative handler
target. COM, KEY, and PLAY require their adjacent immediate AX event number,
TIMER requires one uniquely resolved adjacent FP expression, and PEN has no
number. An incomplete numbered scaffold remains structural instead of producing
an operand-truncated ON event GOSUB statement.
Device I/O likewise requires its whole compiler scaffold. OUT resolves each
AX operand from either an immediate or a uniquely named direct INTEGER load;
the port and value are separated by the exact `mov bx,ax` staging move and
followed contiguously by `mov dx,bx; out dx,al` in one basic block. An
unresolved load, altered move, or truncated tail remains structural.
Three-argument WAIT requires the complete mask/xor register shuffle and
`in; xor; and` polling body. Its two-argument sibling requires the shorter
mask/port shuffle and `in; and` body. Both require the exact decoded backward
`JE` plus its branch and fallthrough CFG edges. In every case, the individual
instructions and their byte evidence are never replaced.
`Program.fact_operations` now materializes migrated assignment, PRINT, LPRINT,
and device-I/O facts directly into operation IR. Conditional branch
pairs and their resolved operands now produce `IfGoto` facts and operations as
well. `Program.operations` remains the legacy compatibility view until the
remaining runtime consumers migrate.
Direct INTEGER FOR/NEXT facts require one resolved loop-variable assignment,
an unconditional jump to the test, a matching increment, an immediate or
uniquely snapshotted variable limit, and the correctly oriented CFG back edge.
Both a direct conditional back edge and the compiler's inverted-condition plus
unconditional-jump trampoline are accepted when every target closes the same
region.
The header and tail facts cover their compiler scaffolds so those assignments
do not leak as source statements. A normalized compiler-operation view mirrors
the calibrated `tbx` vocabulary without importing it. Ported pure matchers use
that view for variable INTEGER STEP (including long branches) and for SINGLE or
DOUBLE FP loops, requiring their complete sign split and both consistent limit
arms. Inconsistent or competing regions remain structural.
Recognized source statements and complete DELAY loops are also additive facts;
`Program.fact_statements` reconstructs statement indexes and branch targets only
from the fact-built operation view. `Program.canonical_statements` is a final,
non-destructive view that assigns stable source names and orders commutative
expressions; it reads type suffixes from anchored slot facts rather than relying
on a later typed use in operation IR. The address-bearing fact statements remain
unchanged.
Complete framed SUBs and calls to their entry addresses are additive facts as
well. Statement reconstruction nests already-recovered body facts inside their
region, while final canonicalization gives definition and call addresses the
same stable procedure name. Frame cleanup that cannot yet distinguish parameters
from LOCAL storage remains explicit unresolved metadata.
Profiled trace-hook facts now recover supported codeless TRON/TROFF regions.
Several independent facts may support the same toggle conclusion; the fact
store retains each provenance chain while semantic operation materialization
emits the source statement once.

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
