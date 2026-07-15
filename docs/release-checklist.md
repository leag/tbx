# Release checklist

Per-PR CI (ruff, ty, pytest, the c0 platform matrix) is necessary but not
sufficient: the goldens it sweeps encode *past* oracle verifications, and
oracle runs are minutes-per-fixture, so they deliberately stay out of CI.
Before tagging a release, re-verify a sample against the REAL toolchain on
a machine with the oracle (`TBX_ORACLE`, see `tbx/tools/oracle.py`; the
default location is `../frame/oracle`).

## 1. Byte-exact round trip (the decompiler's contract)

```sh
uv run python -m tbx.tools.verify_fixture t1_print t1_gosub t1_subsh \
    t1_dim3v zz_sc3 v10_subdef tier2_sieve
```

- Pick ~10 stems spanning what the release touched, always including at
  least one `v10_` stem (TB 1.0 dialect) and one `zz_`/`tier` program.
- Every line must end `ok` (or `skip: Options toggles ...` for `f*_`
  stems, which compile with non-default IDE Options and can never match).
- A full-corpus audit (`--all`, hours) is warranted after emitter-wide
  canonicalization changes, not for every release.

## 2. DOS behavior goldens (c0's contract)

```sh
uv run python -m tbx.tools.dump_dos_output t1_tab t1_field zz_sub1 t1_suberr
git diff tests/fixtures/dosout/
```

- Re-capture a handful of dosout goldens and confirm `git diff` is empty:
  the original EXEs still do on the emulated machine exactly what the
  committed goldens say (guards against oracle/harness drift).
- Then `uv run pytest tests/tbx/test_c0.py` holds the recompiled native
  binaries to those goldens.

## 3. Runtime interface

- If anything in `tbx/c0_runtime/tb_runtime.h` or a documented surrogate
  behavior changed, confirm `TB_RT_VERSION` was bumped and
  `c0_runtime/README.md` updated (see the surrogate contract there).
- Rebuild the runtime library both ways: `make -C tbx/c0_runtime` and
  `make -C tbx/c0_runtime SDL=1`, then compile one `--no-runtime` program
  against each.

## 4. Paper trail

- Golden regenerations in the release diff each trace to an intended
  decoder/emitter change (review them like code -- see CLAUDE.md).
- New corpus fixtures each had their byte-exact verification recorded in
  the commit that added them.
