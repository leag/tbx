# Release checklist

Per-PR CI (ruff and pytest) is necessary but not
sufficient: the goldens it sweeps encode *past* oracle verifications, and
oracle runs are minutes-per-fixture, so they deliberately stay out of CI.
Before tagging a release, re-verify a sample against the REAL toolchain on
a machine with the oracle (`TBX_ORACLE`, see `tbx/tools/oracle.py`; the
default location is `../frame/oracle`).

## 1. Byte-exact round trip (the decompiler's contract)

```sh
uv run python -m tbx.tools.verify_fixture t1_print t1_gosub t1_subsh \
    t1_dim3v zz_sc3 v10_subdef tier1_expr
```

- Pick ~10 stems spanning what the release touched, always including at
  least one `v10_` stem (TB 1.0 dialect) and one `zz_`/`tier` program.
- The repository-vendored oracle is used by default. Set `TBX_ORACLE` only
  when pointing at a compatible harness; older sibling checkouts may not
  support the per-run workspace option used by `verify_fixture`.
- Every line must end `ok` (or `skip: Options toggles ...` for `f*_`
  stems, which compile with non-default IDE Options and can never match).
- A full-corpus audit (`--all`, hours) is warranted after emitter-wide
  canonicalization changes, not for every release.

## 2. Paper trail

- Golden regenerations in the release diff each trace to an intended
  decoder/emitter change (review them like code -- see CLAUDE.md).
- New corpus fixtures each had their byte-exact verification recorded in
  the commit that added them.
