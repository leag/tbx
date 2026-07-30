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
