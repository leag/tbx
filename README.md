# tbx — a byte-exact Borland Turbo Basic decompiler

[![CI](https://github.com/leag/tbx/actions/workflows/ci.yml/badge.svg)](https://github.com/leag/tbx/actions/workflows/ci.yml)

> **Parked 2026-07-29 and unattended.** The decoder works as described below and
> the test suite is green, but the wild-corpus campaign is stopped mid-tail and no
> release was cut. Read [`STATUS.md`](STATUS.md) before starting any work here.

`tbx` recovers source from 16-bit MS-DOS executables compiled by Borland Turbo
Basic 1.0 or 1.1. A recovery is considered correct only when recompiling the
emitted source with the original Borland toolchain reproduces the input EXE
byte-for-byte.

## Quick start

```sh
pip install .
tbx PROGRAM.EXE                 # recovered source on stdout
tbx PROGRAM.EXE -o PROGRAM.BAS  # write recovered source
tbx PROGRAM.EXE --ops           # inspect the canonical op stream
```

The core package has no runtime dependencies and requires Python 3.11 or
newer. For development:

```sh
uv sync
uv run pytest
uv run ruff check
```

The optional `debug` extra installs [iced-x86](https://pypi.org/project/iced-x86/)
for CFG/disassembly triage tools:

```sh
pip install '.[debug]'
```

Python callers can use the same pipeline directly:

```python
from tbx import decode0, emit0

exe = open("PROGRAM.EXE", "rb").read()
source = emit0.emit(decode0.decode_user_code(exe))
```

## What it recovers

Turbo Basic combines compact x86 templates with runtime-dispatch calls. The
decoder recognizes the x87 emulation encoding, INT ECh/EDh/EEh statement
sub-vectors, and raw x86 control flow. It automatically detects TB 1.0 versus
1.1 and normalizes their dispatch-number differences.

The pipeline is:

1. Scan the user-code region into a canonical operation stream.
2. Solve DGROUP layout from code references and the executable's tail data.
3. Lift operations into typed IR, folding structured control flow.
4. Emit canonical BASIC with stable formatting and byte-significant line
   numbers preserved where required.

The corpus covers the handbook's statements, intrinsic functions, arrays,
SUB/DEF FN procedures, graphics, files, events, error handling, and TRON
regions across both compiler dialects.

## Correctness model

The decoder is deliberately fail-loud: an uncalibrated byte pattern raises an
error instead of being guessed. New syntax is admitted only after a compiled
fixture witnesses its encoding and an oracle round trip verifies the result.
Compiler losses are normalized only when the canonical spelling recompiles
identically (for example, `STOP`/`SYSTEM` to `END`).

The committed fixtures contain operation-stream, IR, and emitted-source
goldens. Run the full regression suite with:

```sh
uv run pytest
```

## Oracle verification

The repository vendors the headless v86 harness and its patched emulator, but
does **not** distribute Borland's proprietary `TB.EXE` or the compiler floppy
images. Those ignored assets must be provisioned locally before calibration.
The oracle is used for new fixtures and release checks, never at runtime.
Install its Node dependencies and follow [the oracle guide](vendor/turbo_basic_oracle/README.tbx.md), then:

```sh
uv run python -m tbx.tools.verify_fixture \
  t1_print t1_gosub t1_subsh t1_dim3v zz_sc3 v10_subdef tier1_expr
```

Set `TBX_ORACLE` only when using another compatible v86 harness. See the
[release checklist](docs/release-checklist.md) for the required sample and
paper trail.

## Debugging a decode failure

`tbx PROGRAM.EXE --ops` shows how far scanning progressed. For a missing raw
instruction template, install the `debug` extra and use:

```sh
python -m tbx.tools.cfgview PROGRAM.EXE [--out cfg.dot]
```

`dump_ops.py` and `dump_user_code.py` regenerate committed goldens after an
intended decoder change. Wild-corpus probes belong in `wild/probes/` only after
they compile successfully with the oracle and their first failure is recorded.

## Experimental native backend

The C recompiler and its runtime are maintained separately on the
[`experimental/c0` branch](https://github.com/leag/tbx/tree/experimental/c0).
They are not included in this decoder release.

## License

MIT — see [LICENSE](LICENSE).
