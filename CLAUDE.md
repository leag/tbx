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

The decoder pipeline is EXE bytes → operation stream → typed IR → canonical
BASIC source:

- `decode0.scan` recognizes the compiler's x86 templates, runtime INT
  dispatches, and dialect differences.
- `decode0.layout` reconstructs DGROUP and compiler data pools.
- `decode0.core`, `decode0.handlers`, and `decode0.lift` decode and structure
  statements; `tbx.ir` is the shared immutable representation.
- `emit0` emits source that must recompile byte-for-byte.

## Calibration rule

The decoder is fail-loud. Unknown byte patterns must raise `ValueError`; never
guess a construct or add a speculative fallback. A new mapping requires a
compiled fixture in `tests/fixtures/corpus/` and byte-exact verification with
the vendored v86 Turbo Basic oracle:

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
