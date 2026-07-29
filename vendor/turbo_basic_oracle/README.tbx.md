# Vendored Turbo BASIC oracle

This directory contains the headless v86 harness used by tbx for byte-exact
probes. The repository includes the harness and patched emulator, but does not
include Borland's proprietary `TB.EXE` or the compiler floppy images. Supply
those ignored assets locally, then install the JavaScript dependency with
`npm install` in this directory and set `TBX_ORACLE` to this path when invoking
`tbx.tools.oracle`.

The harness stages source-relative external `$INLINE "file"` operands into the
compiler floppy before starting Turbo BASIC. This is required by Turbo BASIC's
file form of inline assembly; without it the compiler reports Error 496.

The small `examples/inline_file_probe.bas` program and `examples/QPRINT.BIN`
file are a smoke test for that behavior:

```sh
TBX_ORACLE=$PWD/vendor/turbo_basic_oracle \
  python -c 'from tbx.tools.oracle import compile_bas; compile_bas("vendor/turbo_basic_oracle/examples/inline_file_probe.bas")'
```

`examples/opaque1_probe.bas` and `opaque2_probe.bas` use `OPQ1.BIN` and
`OPQ2.BIN`, the two recovered opaque-helper payloads (without their final
`CB`). The fixed harness compiles each payload and the compiler appends `CB`,
reproducing the exact 116-byte and 125-byte executable bodies byte-for-byte.

Compiler floppy images (`*.img`) and generated outputs are intentionally
gitignored and are not distributed. The v86 dependency is installed from
`package-lock.json`.

## Performance and concurrency

The harness uses screen/disk readiness checks instead of fixed boot, load, and
compile sleeps. `--run-ms N` is now the maximum time allowed for an EXE to
appear and stabilize on the guest floppy, not an unconditional delay.

Each Python `compile_bas` call supplies a private `--workspace`, so concurrent
oracle processes do not race through `work.img`, `work_out.img`, temporary
source, or `SOLVER_v86.EXE`. Probe matrices can use this directly:

```sh
uv run python tbx/tools/batch_probe.py /tmp/probes --jobs 4 --keep /tmp/exes
```

`batch_probe.py` preflights Node, mtools, and the locked `v86` dependency before
booting, prints each result as soon as it completes, and optionally retains each
compiled executable outside the repository. On the project fixtures, a small
compile fell from roughly 25 seconds to 8.8 seconds; two concurrent compiles
also complete in about 8.9 seconds on the reference development machine.
