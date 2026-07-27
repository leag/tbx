# tbx — a byte-exact Borland Turbo Basic decompiler

This branch contains the decoder plus the experimental native C backend. The
decoder recovers Turbo Basic 1.0/1.1 source from DOS EXEs and is correct only
when the emitted source recompiles byte-for-byte in the original toolchain.

```sh
tbx PROGRAM.EXE
tbx PROGRAM.EXE -o PROGRAM.BAS
tbx PROGRAM.EXE --emit-c -o program.c
```

The core pipeline is EXE bytes → operation stream → typed IR → canonical
BASIC. It detects both compiler dialects, reconstructs DGROUP layout, folds
structured control flow, and emits fail-loud canonical source. See the main
decoder documentation in the release branch for calibration and fixture
details.

## Experimental native backend

The c0 C recompiler is documented in [docs/c0.md](docs/c0.md). It is a
behavioral backend, not a byte-exact replacement for the decoder, and requires
GCC or Clang. Its runtime and SDL library live under `tbx/c0_runtime/`.

## Development

```sh
uv sync
uv run pytest
uv run ruff check
```

The vendored v86 Turbo Basic oracle is under `vendor/turbo_basic_oracle/` and
is used for fixture calibration and round-trip verification.

## License

MIT — see [LICENSE](LICENSE).
