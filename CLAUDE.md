# tbx contributor guidance

`tbx` is a byte-exact decompiler for Borland Turbo Basic 1.0/1.1 DOS EXEs.
The core package (`tbx.decode0`, `tbx.ir`, `tbx.emit0`, `tbx.cli`) has no
runtime dependencies and supports Python 3.11+.

## Commands

```sh
uv sync
uv run pytest
uv run ruff check
tbx PROGRAM.EXE
tbx PROGRAM.EXE --ops
```

Use `pip install '.[debug]'` for the iced-x86 CFG tools.

## Pipeline

`docs/decoder-architecture.md` is the map: the pipeline, who owns which piece
of decode state, how to read a failure report, and what the fixture corpus does
not cover. Start there when a wild EXE fails.

The decoder pipeline is EXE bytes → operation stream → typed IR → canonical
BASIC source:

- `decode0.scan` recognizes the compiler's x86 templates, runtime INT
  dispatches, and dialect differences.
- `decode0.layout` reconstructs DGROUP and compiler data pools.
- `decode0.core`, `decode0.handlers`, and `decode0.lift` decode and structure
  statements; `tbx.ir` is the shared immutable representation.
- `emit0` emits source that must recompile byte-for-byte.

## Writing a handler

Use the migrated APIs; the older spellings they replaced are gone, so reaching
for one is a sign of copying from an old commit.

- **State** goes through its owning view -- `state.machine`, `state.expr`,
  `state.layout_state`, `state.control`, `state.output`, `state.image`. Every
  field has exactly one owner and writing an unowned name through a view
  raises. `tests/tbx/test_state_parts.py` enforces the partition and
  `test_state_audit.py` proves every field is still read somewhere.
- **Operations** are consumed through `state.advance`/`state.seek`, never by
  assigning the index. `OpCursor` records what was consumed, which is what a
  failure report shows you as `recent=`.
- **Recognition** belongs in a matcher (`decode0.matchers`) returning a
  `TemplateMatch`; the applier mutates. A matcher must not touch decode state
  or advance the cursor, and it is testable on hand-built operation tuples
  with no fixture.
- **Frames** -- anything the loop holds open across operations -- are
  dataclasses in `decode0.frames`, never dicts. `tests/tbx/test_frames.py`
  rejects a dict literal, a subscripted field, and an undocumented one. Put
  the compiler convention behind a field in its comment: that is where a
  reader will look for it.
- **Committing a statement** goes through `state.put`/`state.commit` so it is
  recorded. A statement that reaches the program without an event is invisible
  to the control-flow pass, and `reconcile` will report it as synthesized.
- **Recognising a branch or a region** records an event (`state.branch`,
  `state.region`, `state.arrive`). Folding reads those back rather than
  taking a second copy from the frame.

## Calibration rule

The decoder is fail-loud. Unknown byte patterns must raise `ValueError`; never
guess a construct or add a speculative fallback. A new mapping requires a
compiled fixture in `tests/fixtures/corpus/` and byte-exact verification with
the vendored v86 oracle harness (with locally provisioned compiler assets):

```sh
uv run python -m tbx.tools.verify_fixture STEM
```

The oracle is used for calibration only, not at runtime. See
`vendor/turbo_basic_oracle/README.tbx.md` and `docs/release-checklist.md`.

The oracle is also the only acceptance test that counts. A change can pass the
suite, satisfy a structural check and still emit source that is wrong -- the
fixture corpus cannot cover a wild shape it has no fixture for, and a checker
you wrote alongside the fix shares its assumptions. Use those to find
candidates; believe a byte comparison. When the change touches a *comparable*
wild program (`excluded: null` in `tests/fixtures/wild_roundtrip.json`), a
delta is measurable, so measure it before claiming the fix works.

## Baselines

`tests/fixtures/wild_roundtrip.json`, the goldens and `ir_snapshot.txt` are
baselines: they record what was true when it was last verified.

**Never re-record a baseline to absorb a regression.** If a wild program's
round trip degrades, the entry is evidence, not an inconvenience -- fix the
decoder and re-measure, so the recorded delta means the same thing it did
before. Two changes are legitimate: an intended decoder change, re-measured
through the oracle and reviewed in the diff like code; and a newly decoding
program being added. Both leave the file describing reality; absorbing a
regression leaves it describing nothing.

## Triage before diving into a gap

Not every wild-corpus failure is worth the same investment. Before working a
gap, spend a few minutes reading the raise site and its containing function,
and let that predict the cost:

- A short, isolated function with a simple guard or condition (an adjacency
  check, a missing sentinel thread-through) is cheap -- fix it now.
- A function threading several shared mutable flags across many branches
  (`direct_bool_gate`, `pend_bool`, `direct_bool_group`, ...), or a heuristic
  search over many candidate parameters (DGROUP layout recovery), is
  expensive regardless of how narrow the symptom looks on the surface. Budget
  for that consciously, or defer it.

Set an explicit probe budget before committing to a hypothesis: two or three
oracle probes to reproduce the exact byte shape. If none match, that is not a
cue to try a fourth guess -- it is the signal that the construct is rarer or
structurally different than assumed. Write down what was ruled out (see
below) and stop, rather than continuing to iterate past the budget.

Prefer gaps with multiple independent wild witnesses over a single instance:
a fix confirmed against one file's exact bytes can be an overfit, while a fix
that closes several files at once is much stronger evidence it is the real
mechanism.

When more than one hypothesis fits the failing bytes, prefer the weaker one:
the one that commits to fewer specifics of this file, not the one with the
shortest diff. A hypothesis scoped to "this exact displacement, in this exact
frame shape" explains the byte in front of you but predicts nothing else; a
hypothesis scoped to "any BP-relative store of this kind, in this kind of
frame" is falsifiable against more of the corpus and is what actually
generalizes when the fix lands. Shortness and generality are different axes --
a short special case is still a special case. Prefer the version that stakes
out more ground and can still be shown wrong by a probe over the version that
merely fits.

When a hypothesis needs checking, build the oracle probe first and diff its
op stream against the failing file's, rather than reading deeply into the
surrounding decoder logic before writing anything. Verifying empirically is
usually faster than reasoning abstractly from code, and it tells you exactly
which branch needs to change.

## Negative results

A hypothesis that was investigated and rejected is expensive evidence, and it
is lost the moment a session ends unless it is written down. Two ledgers under
`gap_reports/` hold them, validated by `tests/tbx/test_ledgers.py`:

- `runtime-revision-assessments.json` -- the answer is a property of the
  compiler or runtime, including patterns this oracle can never witness.
- `ruled-out-hypotheses.json` -- decoder-side: a cause that was not the cause,
  or a fix written, tested and reverted. Each entry says what was tried, what
  killed it, and what to do instead.

Record the dead end before moving on, and reach for the ledgers before
re-deriving a diagnosis. `PLAN.md` remains the chronological archive; the
ledgers are the deduplicated index into it.

## Tests and fixtures

Golden operations, IR snapshots, and emitted source live under
`tests/fixtures/{ops,ir_snapshot.txt,usercode}`. Regenerate them only after an
intended decoder/emitter change, and review the diff. Hand-written tests under
`tests/tbx/` are the strongest regression guards.

When investigating a wild-corpus gap, successfully compiled authored probes
belong in `wild/probes/` with their `.bas` source and a recorded first failure.
Do not promote compilation failures or uncalibrated guesses to the fixture
corpus.

## Release

Before tagging, run the full suite, Ruff, and the representative oracle sample
listed in `docs/release-checklist.md`. Keep the release branch focused on the
decoder; the native C backend is maintained on `experimental/c0`.
