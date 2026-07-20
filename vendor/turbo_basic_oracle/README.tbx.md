# Vendored Turbo BASIC oracle

This directory contains the headless v86 Turbo BASIC compiler harness used by
tbx for byte-exact probes. Install its JavaScript dependency with `npm install`
in this directory, then set `TBX_ORACLE` to this path when invoking
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

Generated disk images and compiler outputs are intentionally not part of the
vendored set. The v86 dependency is installed from `package-lock.json`.
